/* Copyright 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_spdy/apache/slave_connection_api.h"

#include "base/memory/scoped_ptr.h"
#include "mod_spdy/apache/slave_connection.h"
#include "mod_spdy/apache/slave_connection_context.h"

using mod_spdy::SlaveConnection;
using mod_spdy::SlaveConnectionContext;
using mod_spdy::SlaveConnectionFactory;

struct spdy_slave_connection_factory {
  explicit spdy_slave_connection_factory(SlaveConnectionFactory* impl)
      : impl(impl) {}
  scoped_ptr<SlaveConnectionFactory> impl;
};

struct spdy_slave_connection {
  explicit spdy_slave_connection(SlaveConnection* impl)
      : impl(impl) {}
  scoped_ptr<SlaveConnection> impl;
};

spdy_slave_connection_factory* spdy_create_slave_connection_factory(
    conn_rec* master_connection) {
  return new spdy_slave_connection_factory(
      new SlaveConnectionFactory(master_connection));
}

void spdy_destroy_slave_connection_factory(
    spdy_slave_connection_factory* factory) {
  delete factory;
}

spdy_slave_connection* spdy_create_slave_connection(
    spdy_slave_connection_factory* factory,
    ap_filter_rec_t* input_filter,
    void* input_filter_ctx,
    ap_filter_rec_t* output_filter,
    void* output_filter_ctx) {
  spdy_slave_connection* wrapper =
      new spdy_slave_connection(factory->impl->Create());

  SlaveConnectionContext* ctx = wrapper->impl->GetSlaveConnectionContext();
  ctx->SetInputFilter(input_filter, input_filter_ctx);
  ctx->SetOutputFilter(output_filter, output_filter_ctx);

  return wrapper;
}

void spdy_run_slave_connection(spdy_slave_connection* conn) {
  conn->impl->Run();
}

void spdy_destroy_slave_connection(spdy_slave_connection* conn) {
  delete conn;
}

void ModSpdyExportSlaveConnectionFunctions() {
  APR_REGISTER_OPTIONAL_FN(spdy_create_slave_connection_factory);
  APR_REGISTER_OPTIONAL_FN(spdy_destroy_slave_connection_factory);
  APR_REGISTER_OPTIONAL_FN(spdy_create_slave_connection);
  APR_REGISTER_OPTIONAL_FN(spdy_run_slave_connection);
  APR_REGISTER_OPTIONAL_FN(spdy_destroy_slave_connection);
}
