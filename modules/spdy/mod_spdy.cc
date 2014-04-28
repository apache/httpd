// Copyright 2010 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// References to "TAMB" below refer to _The Apache Modules Book_ by Nick Kew
// (ISBN: 0-13-240967-4).

#include "mod_spdy/mod_spdy.h"

#include <algorithm>  // for std::min

#include "httpd.h"
#include "http_connection.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_optional.h"
#include "apr_optional_hooks.h"
#include "apr_tables.h"

#include "base/basictypes.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "mod_spdy/apache/apache_spdy_session_io.h"
#include "mod_spdy/apache/apache_spdy_stream_task_factory.h"
#include "mod_spdy/apache/config_commands.h"
#include "mod_spdy/apache/config_util.h"
#include "mod_spdy/apache/id_pool.h"
#include "mod_spdy/apache/filters/server_push_filter.h"
#include "mod_spdy/apache/log_message_handler.h"
#include "mod_spdy/apache/master_connection_context.h"
#include "mod_spdy/apache/pool_util.h"
#include "mod_spdy/apache/slave_connection_context.h"
#include "mod_spdy/apache/slave_connection_api.h"
#include "mod_spdy/apache/ssl_util.h"
#include "mod_spdy/common/executor.h"
#include "mod_spdy/common/protocol_util.h"
#include "mod_spdy/common/spdy_server_config.h"
#include "mod_spdy/common/spdy_session.h"
#include "mod_spdy/common/thread_pool.h"
#include "mod_spdy/common/version.h"

extern "C" {

// Declaring mod_so's optional hooks here (so that we don't need to
// #include "mod_so.h").
APR_DECLARE_OPTIONAL_FN(module*, ap_find_loaded_module_symbol,
                        (server_rec*, const char*));

// Declaring modified mod_ssl's optional hooks here (so that we don't need to
// #include "mod_ssl.h").
APR_DECLARE_EXTERNAL_HOOK(modssl, AP, int, npn_advertise_protos_hook,
                          (conn_rec *connection, apr_array_header_t *protos));
APR_DECLARE_EXTERNAL_HOOK(modssl, AP, int, npn_proto_negotiated_hook,
                          (conn_rec *connection, const char *proto_name,
                           apr_size_t proto_name_len));

}  // extern "C"

namespace {

const char kFakeModSpdyProtocolName[] =
    "x-mod-spdy/" MOD_SPDY_VERSION_STRING "-" LASTCHANGE_STRING;
COMPILE_ASSERT(arraysize(kFakeModSpdyProtocolName) <= 255,
               fake_protocol_name_is_not_too_long_for_npn);
const char kFakeModSpdyProtocolNameNoVersion[] = "x-mod-spdy/no-version";
COMPILE_ASSERT(arraysize(kFakeModSpdyProtocolNameNoVersion) <= 255,
               fake_protocol_name_no_version_is_not_too_long_for_npn);

const char* const kHttpProtocolName = "http/1.1";
const char* const kSpdy2ProtocolName = "spdy/2";
const char* const kSpdy3ProtocolName = "spdy/3";
const char* const kSpdy31ProtocolName = "spdy/3.1";
const char* const kSpdyVersionEnvironmentVariable = "SPDY_VERSION";

const char* const kPhpModuleNames[] = {
  "php_module",
  "php2_module",
  "php3_module",
  "php4_module",
  "php5_module",
  "php6_module"
};

// This global variable stores the filter handle for our push filter.  Normally,
// global variables would be very dangerous in a concurrent environment like
// Apache, but this one is okay because it is assigned just once, at
// start-up (during which Apache is running single-threaded; see TAMB 2.2.1),
// and are read-only thereafter.
ap_filter_rec_t* gServerPushFilterHandle = NULL;

// A process-global thread pool for processing SPDY streams concurrently.  This
// is initialized once in *each child process* by our child-init hook.  Note
// that in a non-threaded MPM (e.g. Prefork), this thread pool will be used by
// just one SPDY connection at a time, but in a threaded MPM (e.g. Worker) it
// will shared by several SPDY connections at once.  That's okay though,
// because ThreadPool objects are thread-safe.  Users just have to make sure
// that they configure SpdyMaxThreadsPerProcess depending on the MPM.
mod_spdy::ThreadPool* gPerProcessThreadPool = NULL;

// Optional function provided by mod_spdy.  Return zero if the connection is
// not using SPDY, otherwise return the SPDY version number in use.  Note that
// unlike our private functions, we use Apache C naming conventions for this
// function because we export it to other modules.
int spdy_get_version(conn_rec* connection) {
  if (mod_spdy::HasMasterConnectionContext(connection)) {
    mod_spdy::MasterConnectionContext* master_context =
        mod_spdy::GetMasterConnectionContext(connection);
    if (master_context->is_using_spdy()) {
      return mod_spdy::SpdyVersionToFramerVersion(
          master_context->spdy_version());
    }
  }

  if (mod_spdy::HasSlaveConnectionContext(connection)) {
    mod_spdy::SlaveConnectionContext* slave_context =
        mod_spdy::GetSlaveConnectionContext(connection);
    if (slave_context->spdy_version() != mod_spdy::spdy::SPDY_VERSION_NONE) {
      return mod_spdy::SpdyVersionToFramerVersion(
          slave_context->spdy_version());
    }
  }

  return 0;
}

apr_status_t ServerPushFilterFunc(ap_filter_t* filter,
                                  apr_bucket_brigade* input_brigade) {
  mod_spdy::ServerPushFilter* server_push_filter =
      static_cast<mod_spdy::ServerPushFilter*>(filter->ctx);
  return server_push_filter->Write(filter, input_brigade);
}

// Called on server startup, after all modules have loaded.
void RetrieveOptionalFunctions() {
  mod_spdy::RetrieveModSslFunctions();
}

// Called after configuration has completed.
int PostConfig(apr_pool_t* pconf, apr_pool_t* plog, apr_pool_t* ptemp,
               server_rec* server_list) {
  mod_spdy::ScopedServerLogHandler log_handler(server_list);

  // Check if any of the virtual hosts have mod_spdy enabled.
  bool any_enabled = false;
  for (server_rec* server = server_list; server != NULL;
       server = server->next) {
    if (mod_spdy::GetServerConfig(server)->spdy_enabled()) {
      any_enabled = true;
      break;
    }
  }

  // Log a message indicating whether mod_spdy is enabled or not.  It's all too
  // easy to install mod_spdy and forget to turn it on, so this may be helpful
  // for debugging server behavior.
  if (!any_enabled) {
    LOG(WARNING) << "mod_spdy is installed, but has not been enabled in the "
                 << "Apache config. SPDY will not be used by this server.  "
                 << "See http://code.google.com/p/mod-spdy/wiki/ConfigOptions "
                 << "for how to enable.";
  }


  // Modules which may not be thread-safe shouldn't be used with mod_spdy.
  // That mainly seems to be mod_php.  If mod_php is installed, log a warning
  // pointing the user to docs on how to use PHP safely with mod_spdy.
  if (any_enabled) {
    module* (*get_module)(server_rec*, const char*) =
        APR_RETRIEVE_OPTIONAL_FN(ap_find_loaded_module_symbol);
    if (get_module != NULL) {
      for (size_t i = 0; i < arraysize(kPhpModuleNames); ++i) {
        if (get_module(server_list, kPhpModuleNames[i]) != NULL) {
          LOG(WARNING)
              << kPhpModuleNames[i] << " may not be thread-safe, and "
              << "should not be used with mod_spdy.  Instead, see "
              << "https://developers.google.com/speed/spdy/mod_spdy/php for "
              << "how to configure your server to use PHP safely.";
        }
      }
    }
  }

  return OK;
}

// Called exactly once for each child process, before that process starts
// spawning worker threads.
void ChildInit(apr_pool_t* pool, server_rec* server_list) {
  mod_spdy::ScopedServerLogHandler log_handler(server_list);

  // Check whether mod_spdy is enabled for any server_rec in the list, and
  // determine the most verbose log level of any server in the list.
  bool spdy_enabled = false;
  int max_apache_log_level = APLOG_EMERG;  // the least verbose log level
  COMPILE_ASSERT(APLOG_INFO > APLOG_ERR, bigger_number_means_more_verbose);
  for (server_rec* server = server_list; server != NULL;
       server = server->next) {
    spdy_enabled |= mod_spdy::GetServerConfig(server)->spdy_enabled();
    if (server->loglevel > max_apache_log_level) {
      max_apache_log_level = server->loglevel;
    }
  }

  // There are a couple config options we need to check (vlog_level and
  // max_threads_per_process) that are only settable at the top level of the
  // config, so it doesn't matter which server in the list we read them from.
  const mod_spdy::SpdyServerConfig* top_level_config =
      mod_spdy::GetServerConfig(server_list);

  // We set mod_spdy's global logging level to that of the most verbose server
  // in the list.  The scoped logging handlers we establish will sometimes
  // restrict things further, if they are for a less verbose virtual host.
  mod_spdy::SetLoggingLevel(max_apache_log_level,
                            top_level_config->vlog_level());

  // If mod_spdy is not enabled on any server_rec, don't do any other setup.
  if (!spdy_enabled) {
    return;
  }

  // Create the per-process thread pool.
  const int max_threads = top_level_config->max_threads_per_process();
  const int min_threads =
      std::min(max_threads, top_level_config->min_threads_per_process());
  scoped_ptr<mod_spdy::ThreadPool> thread_pool(
      new mod_spdy::ThreadPool(min_threads, max_threads));
  if (thread_pool->Start()) {
    gPerProcessThreadPool = thread_pool.release();
    mod_spdy::PoolRegisterDelete(pool, gPerProcessThreadPool);
  } else {
    LOG(DFATAL) << "Could not create mod_spdy thread pool; "
                << "mod_spdy will not function.";
  }
}

// A pre-connection hook, to be run _before_ mod_ssl's pre-connection hook.
// Disables mod_ssl for our slave connections.
int DisableSslForSlaves(conn_rec* connection, void* csd) {
  mod_spdy::ScopedConnectionLogHandler log_handler(connection);

  if (!mod_spdy::HasSlaveConnectionContext(connection)) {
    // For master connections, the context object should't have been created
    // yet (it gets created in PreConnection).
    DCHECK(!mod_spdy::HasMasterConnectionContext(connection));
    return DECLINED;  // only do things for slave connections.
  }

  // If a slave context has already been created, mod_spdy must be enabled.
  DCHECK(mod_spdy::GetServerConfig(connection)->spdy_enabled());

  // Disable mod_ssl for the slave connection so it doesn't get in our way.
  if (!mod_spdy::DisableSslForConnection(connection)) {
    // Hmm, mod_ssl either isn't installed or isn't enabled.  That should be
    // impossible (we wouldn't _have_ a slave connection without having SSL for
    // the master connection), unless we're configured to assume SPDY for
    // non-SSL connections.  Let's check if that's the case, and LOG(DFATAL) if
    // it's not.
    if (mod_spdy::GetServerConfig(connection)->
        use_spdy_version_without_ssl() == mod_spdy::spdy::SPDY_VERSION_NONE) {
      LOG(DFATAL) << "mod_ssl missing for slave connection";
    }
  }
  return OK;
}

// A pre-connection hook, to be run _after_ mod_ssl's pre-connection hook, but
// just _before_ the core pre-connection hook.  For master connections, this
// checks if SSL is active; for slave connections, this adds our
// connection-level filters and prevents core filters from being inserted.
int PreConnection(conn_rec* connection, void* csd) {
  mod_spdy::ScopedConnectionLogHandler log_handler(connection);

  // If a slave context has not yet been created, this is a "real" connection.
  if (!mod_spdy::HasSlaveConnectionContext(connection)) {
    // Master context should not have been created yet, either.
    DCHECK(!mod_spdy::HasMasterConnectionContext(connection));

    // If mod_spdy is disabled on this server, don't allocate our context
    // object.
    const mod_spdy::SpdyServerConfig* config =
        mod_spdy::GetServerConfig(connection);
    if (!config->spdy_enabled()) {
      return DECLINED;
    }

    // We'll set this to a nonzero SPDY version number momentarily if we're
    // configured to assume a particular SPDY version for this connection.
    mod_spdy::spdy::SpdyVersion assume_spdy_version =
        mod_spdy::spdy::SPDY_VERSION_NONE;

    // Check if this connection is over SSL; if not, we can't do NPN, so we
    // definitely won't be using SPDY (unless we're configured to assume SPDY
    // for non-SSL connections).
    const bool using_ssl = mod_spdy::IsUsingSslForConnection(connection);
    if (!using_ssl) {
      // This is not an SSL connection, so we can't talk SPDY on it _unless_ we
      // have opted to assume SPDY over non-SSL connections (presumably for
      // debugging purposes; this would normally break browsers).
      assume_spdy_version = config->use_spdy_version_without_ssl();
      if (assume_spdy_version == mod_spdy::spdy::SPDY_VERSION_NONE) {
        return DECLINED;
      }
    }

    // Okay, we've got a real connection over SSL, so we'll be negotiating with
    // the client to see if we can use SPDY for this connection.  Create our
    // connection context object to keep track of the negotiation.
    mod_spdy::MasterConnectionContext* master_context =
        mod_spdy::CreateMasterConnectionContext(connection, using_ssl);
    // If we're assuming SPDY for this connection, it means we know NPN won't
    // happen at all, and we're just going to assume a particular SPDY version.
    if (assume_spdy_version != mod_spdy::spdy::SPDY_VERSION_NONE) {
      master_context->set_assume_spdy(true);
      master_context->set_spdy_version(assume_spdy_version);
    }
    return OK;
  }
  // If the context has already been created, this is a slave connection.
  else {
    mod_spdy::SlaveConnectionContext* slave_context =
        mod_spdy::GetSlaveConnectionContext(connection);

    DCHECK(mod_spdy::GetServerConfig(connection)->spdy_enabled());

    // Add our input and output filters.
    ap_add_input_filter_handle(
        slave_context->input_filter_handle(),  // filter handle
        slave_context->input_filter_context(), // context (any void* we want)
        NULL,                     // request object
        connection);              // connection object

    ap_add_output_filter_handle(
        slave_context->output_filter_handle(),    // filter handle
        slave_context->output_filter_context(),   // context (any void* we want)
        NULL,                       // request object
        connection);                // connection object

    // Prevent core pre-connection hooks from running (thus preventing core
    // filters from being inserted).
    return DONE;
  }
}

// Called to see if we want to take care of processing this connection -- if
// so, we do so and return OK, otherwise we return DECLINED.  For slave
// connections, we want to return DECLINED.  For "real" connections, we need to
// determine if they are using SPDY; if not we returned DECLINED, but if so we
// process this as a master SPDY connection and then return OK.
int ProcessConnection(conn_rec* connection) {
  mod_spdy::ScopedConnectionLogHandler log_handler(connection);

  // If mod_spdy is disabled on this server, don't use SPDY.
  const mod_spdy::SpdyServerConfig* config =
      mod_spdy::GetServerConfig(connection);
  if (!config->spdy_enabled()) {
    return DECLINED;
  }

  // We do not want to attach to non-inbound connections (e.g. connections
  // created by mod_proxy).  Non-inbound connections do not get a scoreboard
  // hook, so we abort if the connection doesn't have the scoreboard hook.  See
  // http://mail-archives.apache.org/mod_mbox/httpd-dev/201008.mbox/%3C99EA83DCDE961346AFA9B5EC33FEC08B047FDC26@VF-MBX11.internal.vodafone.com%3E
  // for more details.
  if (connection->sbh == NULL) {
    return DECLINED;
  }

  // Our connection context object will have been created by now, unless our
  // pre-connection hook saw that this was a non-SSL connection, in which case
  // we won't be using SPDY so we can stop now. It may also mean that this is
  // a slave connection, in which case we don't want to deal with it here --
  // instead we will let Apache treat it like a regular HTTP connection.
  if (!mod_spdy::HasMasterConnectionContext(connection)) {
    return DECLINED;
  }

  mod_spdy::MasterConnectionContext* master_context =
      mod_spdy::GetMasterConnectionContext(connection);

  // In the unlikely event that we failed to create our per-process thread
  // pool, we're not going to be able to operate.
  if (gPerProcessThreadPool == NULL) {
    return DECLINED;
  }

  // Unless we're simply assuming SPDY for this connection, we need to do NPN
  // to decide whether to use SPDY or not.
  if (!master_context->is_assuming_spdy()) {
    // We need to pull some data through mod_ssl in order to force the SSL
    // handshake, and hence NPN, to take place.  To that end, perform a small
    // SPECULATIVE read (and then throw away whatever data we got).
    apr_bucket_brigade* temp_brigade =
        apr_brigade_create(connection->pool, connection->bucket_alloc);
    const apr_status_t status =
        ap_get_brigade(connection->input_filters, temp_brigade,
                       AP_MODE_SPECULATIVE, APR_BLOCK_READ, 1);
    apr_brigade_destroy(temp_brigade);

    // If we were unable to pull any data through, give up and return DECLINED.
    if (status != APR_SUCCESS) {
      // Depending on exactly what went wrong, we may want to log something
      // before returning DECLINED.
      if (APR_STATUS_IS_EOF(status)) {
        // EOF errors are to be expected sometimes (e.g. if the connection was
        // closed), and we should just quietly give up.  No need to log in this
        // case.
      } else if (APR_STATUS_IS_TIMEUP(status)) {
        // TIMEUP errors also seem to happen occasionally.  I think we should
        // also give up in this case, but I'm not sure yet; for now let's VLOG
        // when it happens, to help with debugging [mdsteele].
        VLOG(1) << "Couldn't read from SSL connection (TIMEUP).";
      } else {
        // Any other error could be a real issue, so let's log it (slightly)
        // more noisily.
        LOG(INFO) << "Couldn't read from SSL connection; failed with status "
                  << status << ": " << mod_spdy::AprStatusString(status);
      }
      return DECLINED;
    }

    // If we did pull some data through, then NPN should have happened and our
    // OnNextProtocolNegotiated() hook should have been called by now.  If NPN
    // hasn't happened, it's probably because we're using an old version of
    // mod_ssl that doesn't support NPN, in which case we should probably warn
    // the user that mod_spdy isn't going to work.
    if (master_context->npn_state() ==
        mod_spdy::MasterConnectionContext::NOT_DONE_YET) {
      LOG(WARNING)
          << "NPN didn't happen during SSL handshake.  You're probably using "
          << "a version of mod_ssl that doesn't support NPN. Without NPN "
          << "support, the server cannot use SPDY. See "
          << "http://code.google.com/p/mod-spdy/wiki/GettingStarted for more "
          << "information on installing a version of mod_spdy with NPN "
          << "support.";
    }
  }

  // If NPN didn't choose SPDY, then don't use SPDY.
  if (!master_context->is_using_spdy()) {
    return DECLINED;
  }

  const mod_spdy::spdy::SpdyVersion spdy_version =
      master_context->spdy_version();
  LOG(INFO) << "Starting SPDY/" <<
      mod_spdy::SpdyVersionNumberString(spdy_version) << " session";

  // At this point, we and the client have agreed to use SPDY (either that, or
  // we've been configured to use SPDY regardless of what the client says), so
  // process this as a SPDY master connection.
  mod_spdy::ApacheSpdySessionIO session_io(connection);
  mod_spdy::ApacheSpdyStreamTaskFactory task_factory(connection);
  scoped_ptr<mod_spdy::Executor> executor(
      gPerProcessThreadPool->NewExecutor());
  mod_spdy::SpdySession spdy_session(
      spdy_version, config, &session_io, &task_factory, executor.get());
  // This call will block until the session has closed down.
  spdy_session.Run();

  LOG(INFO) << "Terminating SPDY/" <<
      mod_spdy::SpdyVersionNumberString(spdy_version) << " session";

  // Return OK to tell Apache that we handled this connection.
  return OK;
}

// Called by mod_ssl when it needs to decide what protocols to advertise to the
// client during Next Protocol Negotiation (NPN).
int AdvertiseSpdy(conn_rec* connection, apr_array_header_t* protos) {
  // If mod_spdy is disabled on this server, then we shouldn't advertise SPDY
  // to the client.
  if (!mod_spdy::GetServerConfig(connection)->spdy_enabled()) {
    return DECLINED;
  }

  // Advertise SPDY to the client.  We push protocol names in descending order
  // of preference; the one we'd most prefer comes first.
  APR_ARRAY_PUSH(protos, const char*) = kSpdy31ProtocolName;
  APR_ARRAY_PUSH(protos, const char*) = kSpdy3ProtocolName;
  APR_ARRAY_PUSH(protos, const char*) = kSpdy2ProtocolName;
  return OK;
}

// Called by mod_ssl (along with the AdvertiseSpdy function) when it needs to
// decide what protocols to advertise to the client during Next Protocol
// Negotiation (NPN).  These two functions are separate so that AdvertiseSpdy
// can run early in the hook order, and AdvertiseHttp can run late.
int AdvertiseHttp(conn_rec* connection, apr_array_header_t* protos) {
  const mod_spdy::SpdyServerConfig* config =
      mod_spdy::GetServerConfig(connection);
  // If mod_spdy is disabled on this server, don't do anything.
  if (!config->spdy_enabled()) {
    return DECLINED;
  }

  // Apache definitely supports HTTP/1.1, and so it ought to advertise it
  // during NPN.  However, the Apache core HTTP module doesn't yet know about
  // this hook, so we advertise HTTP/1.1 for them.  But to be future-proof, we
  // don't add "http/1.1" to the list if it's already there.
  bool http_not_advertised = true;
  for (int i = 0; i < protos->nelts; ++i) {
    if (!strcmp(APR_ARRAY_IDX(protos, i, const char*), kHttpProtocolName)) {
      http_not_advertised = false;
      break;
    }
  }
  if (http_not_advertised) {
    // No one's advertised HTTP/1.1 yet, so let's do it now.
    APR_ARRAY_PUSH(protos, const char*) = kHttpProtocolName;
  }

  // Advertise a fake protocol, indicating the mod_spdy version in use.  We
  // push this last, so the client doesn't think we prefer it to HTTP.
  if (config->send_version_header()) {
    APR_ARRAY_PUSH(protos, const char*) = kFakeModSpdyProtocolName;
  } else {
    // If the user prefers not to send a version number, leave out the version
    // number.
    APR_ARRAY_PUSH(protos, const char*) = kFakeModSpdyProtocolNameNoVersion;
  }

  return OK;
}

// Called by mod_ssl after Next Protocol Negotiation (NPN) has completed,
// informing us which protocol was chosen by the client.
int OnNextProtocolNegotiated(conn_rec* connection, const char* proto_name,
                             apr_size_t proto_name_len) {
  mod_spdy::ScopedConnectionLogHandler log_handler(connection);

  // If mod_spdy is disabled on this server, then ignore the results of NPN.
  if (!mod_spdy::GetServerConfig(connection)->spdy_enabled()) {
    return DECLINED;
  }

  // We disable mod_ssl for slave connections, so NPN shouldn't be happening
  // unless this is a non-slave connection.
  if (mod_spdy::HasSlaveConnectionContext(connection)) {
    LOG(DFATAL) << "mod_ssl was aparently not disabled for slave connection";
    return DECLINED;
  }

  // Given that mod_spdy is enabled, our context object should have already
  // been created in our pre-connection hook, unless this is a non-SSL
  // connection.  But if it's a non-SSL connection, then NPN shouldn't be
  // happening, and this hook shouldn't be getting called!  So, let's
  // LOG(DFATAL) if context is NULL here.
  if (!mod_spdy::HasMasterConnectionContext(connection)) {
    LOG(DFATAL) << "NPN happened, but there is no connection context.";
    return DECLINED;
  }

  mod_spdy::MasterConnectionContext* master_context =
      mod_spdy::GetMasterConnectionContext(connection);

  // NPN should happen only once, so npn_state should still be NOT_DONE_YET.
  if (master_context->npn_state() !=
      mod_spdy::MasterConnectionContext::NOT_DONE_YET) {
    LOG(DFATAL) << "NPN happened twice.";
    return DECLINED;
  }

  // If the client chose the SPDY version that we advertised, then mark this
  // connection as using SPDY.
  const base::StringPiece protocol_name(proto_name, proto_name_len);
  if (protocol_name == kSpdy2ProtocolName) {
    master_context->set_npn_state(
        mod_spdy::MasterConnectionContext::USING_SPDY);
    master_context->set_spdy_version(mod_spdy::spdy::SPDY_VERSION_2);
  } else if (protocol_name == kSpdy3ProtocolName) {
    master_context->set_npn_state(
        mod_spdy::MasterConnectionContext::USING_SPDY);
    master_context->set_spdy_version(mod_spdy::spdy::SPDY_VERSION_3);
  } else if (protocol_name == kSpdy31ProtocolName) {
    master_context->set_npn_state(
        mod_spdy::MasterConnectionContext::USING_SPDY);
    master_context->set_spdy_version(mod_spdy::spdy::SPDY_VERSION_3_1);
  }
  // Otherwise, explicitly mark this connection as not using SPDY.
  else {
    master_context->set_npn_state(
        mod_spdy::MasterConnectionContext::NOT_USING_SPDY);
  }
  return OK;
}

int SetUpSubprocessEnv(request_rec* request) {
  conn_rec* connection = request->connection;
  mod_spdy::ScopedConnectionLogHandler log_handler(connection);

  // If mod_spdy is disabled on this server, then don't do anything.
  if (!mod_spdy::GetServerConfig(connection)->spdy_enabled()) {
    return DECLINED;
  }

  // Don't do anything unless this is a slave connection.
  if (!mod_spdy::HasSlaveConnectionContext(connection)) {
    return DECLINED;
  }

  mod_spdy::SlaveConnectionContext* slave_context =
      mod_spdy::GetSlaveConnectionContext(connection);

  // If this request is over SPDY (which it might not be, if this slave
  // connection is being used by another module through the slave connection
  // API), then for the benefit of CGI scripts, which have no way of calling
  // spdy_get_version(), set an environment variable indicating what SPDY
  // version is being used, allowing them to optimize the response for SPDY.
  // See http://code.google.com/p/mod-spdy/issues/detail?id=27 for details.
  const mod_spdy::spdy::SpdyVersion spdy_version =
      slave_context->spdy_version();
  if (spdy_version != mod_spdy::spdy::SPDY_VERSION_NONE) {
    apr_table_set(request->subprocess_env, kSpdyVersionEnvironmentVariable,
                  mod_spdy::SpdyVersionNumberString(spdy_version));
  }

  // Normally, mod_ssl sets the HTTPS environment variable to "on" for requests
  // served over SSL.  We turn mod_ssl off for our slave connections, but those
  // requests _are_ (usually) being served over SSL (via the master
  // connection), so we set the variable ourselves if we are in fact using SSL.
  // See http://code.google.com/p/mod-spdy/issues/detail?id=32 for details.
  if (slave_context->is_using_ssl()) {
    apr_table_setn(request->subprocess_env, "HTTPS", "on");
  }

  return OK;
}

void InsertRequestFilters(request_rec* request) {
  conn_rec* const connection = request->connection;
  mod_spdy::ScopedConnectionLogHandler log_handler(connection);

  // If mod_spdy is disabled on this server, then don't do anything.
  if (!mod_spdy::GetServerConfig(connection)->spdy_enabled()) {
    return;
  }

  // Don't do anything unless this is a slave connection.
  if (!mod_spdy::HasSlaveConnectionContext(connection)) {
    return;
  }

  mod_spdy::SlaveConnectionContext* slave_context =
      mod_spdy::GetSlaveConnectionContext(connection);

  // Insert a filter that will initiate server pushes when so instructed (such
  // as by an X-Associated-Content header). This is conditional on this
  // connection being managed entirely on mod_spdy, and not being done on
  // behalf of someone else using the slave connection API.
  if (slave_context->slave_stream() != NULL) {
    mod_spdy::ServerPushFilter* server_push_filter =
        new mod_spdy::ServerPushFilter(slave_context->slave_stream(), request,
                                       mod_spdy::GetServerConfig(request));
    PoolRegisterDelete(request->pool, server_push_filter);
    ap_add_output_filter_handle(
        gServerPushFilterHandle,  // filter handle
        server_push_filter,       // context (any void* we want)
        request,                  // request object
        connection);              // connection object
  }
}

apr_status_t InvokeIdPoolDestroyInstance(void*) {
  mod_spdy::IdPool::DestroyInstance();
  return APR_SUCCESS;
}

// Called when the module is loaded to register all of our hook functions.
void RegisterHooks(apr_pool_t* pool) {
  mod_spdy::InstallLogMessageHandler(pool);
  mod_spdy::IdPool::CreateInstance();
  apr_pool_cleanup_register(pool, NULL, InvokeIdPoolDestroyInstance,
                            apr_pool_cleanup_null /* no cleanup on fork*/);

  static const char* const modules_core[] = {"core.c", NULL};
  static const char* const modules_mod_ssl[] = {"mod_ssl.c", NULL};

  // Register a hook to be called after all modules have been loaded, so we can
  // retrieve optional functions from mod_ssl.
  ap_hook_optional_fn_retrieve(
      RetrieveOptionalFunctions,  // hook function to be called
      NULL,                       // predecessors
      NULL,                       // successors
      APR_HOOK_MIDDLE);           // position

  // Register a hook to be called after configuration has completed.  We use
  // this hook to log whether or not mod_spdy is enabled on this server.
  ap_hook_post_config(PostConfig, NULL, NULL, APR_HOOK_MIDDLE);

  // Register a hook to be called once for each child process spawned by
  // Apache, before the MPM starts spawning worker threads.  We use this hook
  // to initialize our per-process thread pool.
  ap_hook_child_init(ChildInit, NULL, NULL, APR_HOOK_MIDDLE);

  // Register a pre-connection hook to turn off mod_ssl for our slave
  // connections.  This must run before mod_ssl's pre-connection hook, so that
  // we can disable mod_ssl before it inserts its filters, so we name mod_ssl
  // as an explicit successor.
  ap_hook_pre_connection(
      DisableSslForSlaves,        // hook function to be called
      NULL,                       // predecessors
      modules_mod_ssl,            // successors
      APR_HOOK_FIRST);            // position

  // Register our pre-connection hook, which will be called shortly before our
  // process-connection hook.  The hooking order is very important here.  In
  // particular:
  //   * We must run before the core pre-connection hook, so that we can return
  //     DONE and stop the core filters from being inserted.  Thus, we name
  //     core.c as a successor.
  //   * We should run after almost all other modules (except core.c) so that
  //     our returning DONE doesn't prevent other modules from working.  Thus,
  //     we use APR_HOOK_LAST for our position argument.
  //   * In particular, we MUST run after mod_ssl's pre-connection hook, so
  //     that we can ask mod_ssl if this connection is using SSL.  Thus, we
  //     name mod_ssl.c as a predecessor.  This is redundant, since mod_ssl's
  //     pre-connection hook uses APR_HOOK_MIDDLE, but it's good to be sure.
  // For more about controlling hook order, see TAMB 10.2.2 or
  // http://httpd.apache.org/docs/trunk/developer/hooks.html#hooking-order
  ap_hook_pre_connection(
      PreConnection,              // hook function to be called
      modules_mod_ssl,            // predecessors
      modules_core,               // successors
      APR_HOOK_LAST);             // position

  // Register our process-connection hook, which will handle SPDY connections.
  // The first process-connection hook in the chain to return OK gets to be in
  // charge of handling the connection from start to finish, so we put
  // ourselves in APR_HOOK_FIRST so we can get an early look at the connection.
  // If it turns out not to be a SPDY connection, we'll get out of the way and
  // let other modules deal with it.
  ap_hook_process_connection(ProcessConnection, NULL, NULL, APR_HOOK_FIRST);

  // For the benefit of e.g. PHP/CGI scripts, we need to set various subprocess
  // environment variables for each request served via SPDY.  Register a hook
  // to do so; we use the fixup hook for this because that's the same hook that
  // mod_ssl uses for setting its subprocess environment variables.
  ap_hook_fixups(SetUpSubprocessEnv, NULL, NULL, APR_HOOK_MIDDLE);

  // Our server push filter is a request-level filter, so we insert it with the
  // insert-filter hook.
  ap_hook_insert_filter(InsertRequestFilters, NULL, NULL, APR_HOOK_MIDDLE);

  // Register a hook with mod_ssl to be called when deciding what protocols to
  // advertise during Next Protocol Negotiatiation (NPN); we'll use this
  // opportunity to advertise that we support SPDY.  This hook is declared in
  // mod_ssl.h, for appropriately-patched versions of mod_ssl.  See TAMB 10.2.3
  // for more about optional hooks.
  APR_OPTIONAL_HOOK(
      modssl,                     // prefix of optional hook
      npn_advertise_protos_hook,  // name of optional hook
      AdvertiseSpdy,              // hook function to be called
      NULL,                       // predecessors
      NULL,                       // successors
      APR_HOOK_MIDDLE);           // position
  // If we're advertising SPDY support via NPN, we ought to also advertise HTTP
  // support.  Ideally, the Apache core HTTP module would do this, but for now
  // it doesn't, so we'll do it for them.  We use APR_HOOK_LAST here, since
  // http/1.1 is our last choice.  Note that our AdvertiseHttp function won't
  // add "http/1.1" to the list if it's already there, so this is future-proof.
  APR_OPTIONAL_HOOK(modssl, npn_advertise_protos_hook,
                    AdvertiseHttp, NULL, NULL, APR_HOOK_LAST);

  // Register a hook with mod_ssl to be called when NPN has been completed and
  // the next protocol decided upon.  This hook will check if we're actually to
  // be using SPDY with the client, and enable this module if so.  This hook is
  // declared in mod_ssl.h, for appropriately-patched versions of mod_ssl.
  APR_OPTIONAL_HOOK(
      modssl,                     // prefix of optional hook
      npn_proto_negotiated_hook,  // name of optional hook
      OnNextProtocolNegotiated,   // hook function to be called
      NULL,                       // predecessors
      NULL,                       // successors
      APR_HOOK_MIDDLE);           // position

  // Create the various filters that will be used to route bytes to/from us
  // on slave connections.
  mod_spdy::ApacheSpdyStreamTaskFactory::InitFilters();

  // Also create the filter we will use to detect us being instructed to
  // do server pushes.
  gServerPushFilterHandle = ap_register_output_filter(
      "SPDY_SERVER_PUSH",         // name
      ServerPushFilterFunc,       // filter function
      NULL,                       // init function (n/a in our case)
      // We use PROTOCOL-1 so that we come in just before the core HTTP_HEADER
      // filter serializes the response header table.  That way we have a
      // chance to remove the X-Associated-Content header before it is sent to
      // the client, while still letting us run as late as possible so that we
      // can catch headers set by a variety of modules (for example,
      // mod_headers doesn't run until the CONTENT_SET stage, so if we ran at
      // the RESOURCE stage, that would be too early).
      static_cast<ap_filter_type>(AP_FTYPE_PROTOCOL - 1));

  // Register our optional functions, so that other modules can retrieve and
  // use them.  See TAMB 10.1.2.
  APR_REGISTER_OPTIONAL_FN(spdy_get_version);
  ModSpdyExportSlaveConnectionFunctions();
}

}  // namespace

extern "C" {

  // Export our module so Apache is able to load us.
  // See http://gcc.gnu.org/wiki/Visibility for more information.
#if defined(__linux)
#pragma GCC visibility push(default)
#endif

  // Declare our module object (note that "module" is a typedef for "struct
  // module_struct"; see http_config.h for the definition of module_struct).
  module AP_MODULE_DECLARE_DATA spdy_module = {
    // This next macro indicates that this is a (non-MPM) Apache 2.0 module
    // (the macro actually expands to multiple comma-separated arguments; see
    // http_config.h for the definition):
    STANDARD20_MODULE_STUFF,

    // These next four arguments are callbacks for manipulating configuration
    // structures (the ones we don't need are left null):
    NULL,  // create per-directory config structure
    NULL,  // merge per-directory config structures
    mod_spdy::CreateSpdyServerConfig,  // create per-server config structure
    mod_spdy::MergeSpdyServerConfigs,  // merge per-server config structures

    // This argument supplies a table describing the configuration directives
    // implemented by this module:
    mod_spdy::kSpdyConfigCommands,

    // Finally, this function will be called to register hooks for this module:
    RegisterHooks
  };

#if defined(__linux)
#pragma GCC visibility pop
#endif

}  // extern "C"
