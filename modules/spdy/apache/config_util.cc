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

#include "mod_spdy/apache/config_util.h"

#include "httpd.h"
#include "http_config.h"

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"

#include "mod_spdy/apache/master_connection_context.h"
#include "mod_spdy/apache/pool_util.h"
#include "mod_spdy/apache/slave_connection_context.h"
#include "mod_spdy/common/spdy_server_config.h"

extern "C" {
  extern module AP_MODULE_DECLARE_DATA spdy_module;
}

namespace mod_spdy {

namespace {

struct ConnectionContext {
  // Exactly one of the fields below should be set.
  scoped_ptr<MasterConnectionContext> master_context;
  scoped_ptr<SlaveConnectionContext> slave_context;
};

SpdyServerConfig* GetServerConfigInternal(server_rec* server) {
  void* ptr = ap_get_module_config(server->module_config, &spdy_module);
  CHECK(ptr) << "mod_spdy server config pointer is NULL";
  return static_cast<SpdyServerConfig*>(ptr);
}

ConnectionContext* GetConnContextInternal(conn_rec* connection) {
  return static_cast<ConnectionContext*>(
      ap_get_module_config(connection->conn_config, &spdy_module));
}

ConnectionContext* SetConnContextInternal(
    conn_rec* connection,
    MasterConnectionContext* master_context,
    SlaveConnectionContext* slave_context) {
  DCHECK((master_context == NULL) ^ (slave_context == NULL));
  DCHECK(GetConnContextInternal(connection) == NULL);
  ConnectionContext* context = new ConnectionContext;
  PoolRegisterDelete(connection->pool, context);
  context->master_context.reset(master_context);
  context->slave_context.reset(slave_context);

  // Place the context object in the connection's configuration vector, so that
  // other hook functions with access to this connection can get hold of the
  // context object.  See TAMB 4.2 for details.
  ap_set_module_config(connection->conn_config,  // configuration vector
                       &spdy_module,  // module with which to associate
                       context);      // pointer to store (any void* we want)

  return context;
}

MasterConnectionContext* GetMasterConnectionContextInternal(
    conn_rec* connection) {
  ConnectionContext* context = GetConnContextInternal(connection);
  return (context != NULL) ? context->master_context.get() : NULL;
}

SlaveConnectionContext* GetSlaveConnectionContextInternal(
    conn_rec* connection) {
  ConnectionContext* context = GetConnContextInternal(connection);
  return (context != NULL) ? context->slave_context.get() : NULL;
}

}  // namespace

const SpdyServerConfig* GetServerConfig(server_rec* server) {
  return GetServerConfigInternal(server);
}

const SpdyServerConfig* GetServerConfig(conn_rec* connection) {
  return GetServerConfigInternal(connection->base_server);
}

const SpdyServerConfig* GetServerConfig(request_rec* request) {
  return GetServerConfigInternal(request->server);
}

SpdyServerConfig* GetServerConfig(cmd_parms* command) {
  return GetServerConfigInternal(command->server);
}

MasterConnectionContext* CreateMasterConnectionContext(conn_rec* connection,
                                                 bool using_ssl) {
  ConnectionContext* context = SetConnContextInternal(
      connection, new MasterConnectionContext(using_ssl), NULL);
  return context->master_context.get();
}

SlaveConnectionContext* CreateSlaveConnectionContext(conn_rec* connection) {
  ConnectionContext* context = SetConnContextInternal(
      connection, NULL, new SlaveConnectionContext());
  return context->slave_context.get();
}

bool HasMasterConnectionContext(conn_rec* connection) {
  return GetMasterConnectionContextInternal(connection) != NULL;
}

bool HasSlaveConnectionContext(conn_rec* connection) {
  return GetSlaveConnectionContextInternal(connection) != NULL;
}

MasterConnectionContext* GetMasterConnectionContext(conn_rec* connection) {
  MasterConnectionContext* context =
      GetMasterConnectionContextInternal(connection);
  DCHECK(context != NULL);
  return context;
}

SlaveConnectionContext* GetSlaveConnectionContext(conn_rec* connection) {
  SlaveConnectionContext* context =
      GetSlaveConnectionContextInternal(connection);
  DCHECK(context != NULL);
  return context;
}

}  // namespace mod_spdy
