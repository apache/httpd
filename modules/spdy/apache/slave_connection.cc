// Copyright 2011 Google Inc.
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

#include "mod_spdy/apache/slave_connection.h"

#include "apr_strings.h"
// Temporarily define CORE_PRIVATE so we can see the declarations for
// ap_create_conn_config (in http_config.h), ap_process_connection (in
// http_connection.h), and core_module (in http_core.h).
#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#undef CORE_PRIVATE

#include "base/basictypes.h"
#include "base/logging.h"
#include "mod_spdy/apache/config_util.h"
#include "mod_spdy/apache/id_pool.h"
#include "mod_spdy/apache/log_message_handler.h"
#include "mod_spdy/apache/master_connection_context.h"
#include "mod_spdy/apache/slave_connection_context.h"
#include "mod_spdy/apache/sockaddr_util.h"
#include "mod_spdy/apache/ssl_util.h"

namespace mod_spdy {

SlaveConnectionFactory::SlaveConnectionFactory(conn_rec* master_connection) {
  // If the parent connection is using mod_spdy, we can extract relevant info
  // on whether we're using it there.
  if (HasMasterConnectionContext(master_connection)) {
    MasterConnectionContext* master_context =
        GetMasterConnectionContext(master_connection);
    is_using_ssl_ = master_context->is_using_ssl();
    spdy_version_ = (master_context->is_using_spdy() ?
                     master_context->spdy_version() :
                     spdy::SPDY_VERSION_NONE);
  } else {
    is_using_ssl_ = IsUsingSslForConnection(master_connection);
    spdy_version_ = spdy::SPDY_VERSION_NONE;
  }

  base_server_ = master_connection->base_server;
  local_addr_ = DeepCopySockAddr(master_connection->local_addr, pool_.pool());
  local_ip_ = apr_pstrdup(pool_.pool(), master_connection->local_ip);
  remote_addr_ = DeepCopySockAddr(master_connection->remote_addr, pool_.pool());
  remote_ip_ = apr_pstrdup(pool_.pool(), master_connection->remote_ip);
  master_connection_id_ = master_connection->id;
}

SlaveConnectionFactory::~SlaveConnectionFactory() {
  // Nothing to do --- pool_ dtor will clean everything up.
}

SlaveConnection* SlaveConnectionFactory::Create() {
  return new SlaveConnection(this);
}

SlaveConnection::SlaveConnection(SlaveConnectionFactory* factory) {
  apr_pool_t* pool = pool_.pool();

  slave_connection_ =
      static_cast<conn_rec*>(apr_pcalloc(pool, sizeof(conn_rec)));

  // Initialize what fields of the connection object we can (the rest are
  // zeroed out by apr_pcalloc).  In particular, we should set at least those
  // fields set by core_create_conn() in core.c in Apache.
  // -> id will be set once we are actually running the connection, in
  // ::Run().
  slave_connection_->clogging_input_filters = 0;
  slave_connection_->sbh = NULL;
  // We will manage this connection and all the associated resources with the
  // pool we just created.
  slave_connection_->pool = pool;
  slave_connection_->bucket_alloc = apr_bucket_alloc_create(pool);
  slave_connection_->conn_config = ap_create_conn_config(pool);
  slave_connection_->notes = apr_table_make(pool, 5);
  // Use the same server settings and client address for the slave connection
  // as for the master connection --- the factory saved them for us.
  slave_connection_->base_server = factory->base_server_;
  slave_connection_->local_addr = factory->local_addr_;
  slave_connection_->local_ip = factory->local_ip_;
  slave_connection_->remote_addr = factory->remote_addr_;
  slave_connection_->remote_ip = factory->remote_ip_;

  // One of the other things we will need in slave_connection is a
  // connection id. One of the bits of info we will need for it is the
  // id of the master connection. We save it here, and use it inside ::Run().
  master_connection_id_ = factory->master_connection_id_;

  // We're supposed to pass a socket object to ap_process_connection below, but
  // there's no meaningful object to pass for this slave connection, because
  // we're not really talking to the network.  Our pre-connection hook will
  // prevent the core filters, which talk to the socket, from being inserted,
  // so they won't notice anyway; nonetheless, we can't pass NULL to
  // ap_process_connection because that can cause some other modules to
  // segfault if they try to muck with the socket's settings.  So, we'll just
  // allocate our own socket object for those modules to mess with.  This is a
  // kludge, but it seems to work.
  slave_socket_ = NULL;
  apr_status_t status = apr_socket_create(
      &slave_socket_, APR_INET, SOCK_STREAM, APR_PROTO_TCP, pool);
  DCHECK(status == APR_SUCCESS);
  DCHECK(slave_socket_ != NULL);

  // In our context object for this connection, mark this connection as being
  // a slave.  Our pre-connection and process-connection hooks will notice
  // this, and act accordingly, when they are called for the slave
  // connection.
  SlaveConnectionContext* slave_context =
      CreateSlaveConnectionContext(slave_connection_);

  // Now store the SSL and SPDY info.
  slave_context->set_is_using_ssl(factory->is_using_ssl_);
  slave_context->set_spdy_version(factory->spdy_version_);
}

SlaveConnection::~SlaveConnection() {
  // pool_ destructor will take care of everything.
}

SlaveConnectionContext* SlaveConnection::GetSlaveConnectionContext() {
  return mod_spdy::GetSlaveConnectionContext(slave_connection_);
}

void SlaveConnection::Run() {
  // Pick a globally-unique ID for the slave connection; this must be unique
  // at any given time.  Normally the MPM is responsible for assigning these,
  // and each MPM does it differently, so we're cheating in a dangerous way by
  // trying to assign one here.  However, most MPMs seem to do it in a similar
  // way: for non-threaded MPMs (e.g. Prefork, WinNT), the ID is just the
  // child ID, which is a small nonnegative integer (i.e. an array index into
  // the list of active child processes); for threaded MPMs (e.g. Worker,
  // Event) the ID is typically ((child_index * thread_limit) + thread_index),
  // which will again be a positive integer, most likely (but not necessarily,
  // if thread_limit is set absurdly high) smallish.
  //
  // Therefore, the approach that we take is to concatenate the Apache
  // connection ID for the master connection with a small integer from IDPool
  // that's unique within the process, and, to avoid conflicts with
  // MPM-assigned connection IDs, we make our slave connection ID negative.
  // We only have so many bits to work with
  // (especially if long is only four bytes instead of eight), so we could
  // potentially run into trouble if the master connection ID gets very large
  // or we have too many active tasks simultaneously (i.e. more than 2^16).
  // So, this approach definitely isn't any kind of robust; but it will
  // probably usually work. It would, of course, be great to replace this
  // with a better strategy, if we find one.
  //
  // TODO(mdsteele): We could also consider using an #if here to widen the
  //   masks and the shift distance on systems where sizeof(long)==8.
  //   We might as well use those extra bits if we have them.
  COMPILE_ASSERT(sizeof(long) >= 4, long_is_at_least_32_bits);
  const uint16 in_process_id = IdPool::Instance()->Alloc();
  const long slave_connectionid =
      -(((master_connection_id_ & 0x7fffL) << 16) | in_process_id);
  slave_connection_->id = slave_connectionid;

  // Normally, the core pre-connection hook sets the core module's connection
  // context to the socket passed to ap_process_connection; certain other
  // modules, such as mod_reqtimeout, read the core module's connection
  // context directly so as to read this socket's settings.  However, we
  // purposely don't allow the core pre-connection hook to run, because we
  // don't want the core connection filters to be inserted.  So, to avoid
  // breaking other modules, we take it upon oursevles to set the core
  // module's connection context to the socket we are passing to
  // ap_process_connection.  This is ugly, but seems to work.
  ap_set_module_config(slave_connection_->conn_config,
                       &core_module, slave_socket_);

  // Invoke Apache's usual processing pipeline.  This will block until the
  // connection is complete.
  ap_process_connection(slave_connection_, slave_socket_);

  IdPool::Instance()->Free(in_process_id);
}

}  // namespace mod_spdy
