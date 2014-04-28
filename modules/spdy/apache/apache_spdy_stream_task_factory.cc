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

#include "mod_spdy/apache/apache_spdy_stream_task_factory.h"

#include "apr_buckets.h"
#include "apr_network_io.h"
#include "http_log.h"
#include "util_filter.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "mod_spdy/apache/config_util.h"
#include "mod_spdy/apache/filters/http_to_spdy_filter.h"
#include "mod_spdy/apache/filters/spdy_to_http_filter.h"
#include "mod_spdy/apache/log_message_handler.h"
#include "mod_spdy/apache/pool_util.h"
#include "mod_spdy/apache/slave_connection.h"
#include "mod_spdy/apache/slave_connection_context.h"
#include "mod_spdy/common/spdy_stream.h"
#include "net/instaweb/util/public/function.h"

namespace mod_spdy {

namespace {

// These global variables store the filter handles for our filters.  Normally,
// global variables would be very dangerous in a concurrent environment like
// Apache, but these ones are okay because they are assigned just once, at
// start-up (during which Apache is running single-threaded; see TAMB 2.2.1),
// and are read-only thereafter.
ap_filter_rec_t* gHttpToSpdyFilterHandle = NULL;
ap_filter_rec_t* gSpdyToHttpFilterHandle = NULL;

// See TAMB 8.4.2
apr_status_t SpdyToHttpFilterFunc(ap_filter_t* filter,
                                  apr_bucket_brigade* brigade,
                                  ap_input_mode_t mode,
                                  apr_read_type_e block,
                                  apr_off_t readbytes) {
  mod_spdy::SpdyToHttpFilter* spdy_to_http_filter =
      static_cast<mod_spdy::SpdyToHttpFilter*>(filter->ctx);
  return spdy_to_http_filter->Read(filter, brigade, mode, block, readbytes);
}

// See TAMB 8.4.1
apr_status_t HttpToSpdyFilterFunc(ap_filter_t* filter,
                                  apr_bucket_brigade* input_brigade) {
  mod_spdy::HttpToSpdyFilter* http_to_spdy_filter =
      static_cast<mod_spdy::HttpToSpdyFilter*>(filter->ctx);
  return http_to_spdy_filter->Write(filter, input_brigade);
}

// A task to be returned by ApacheSpdyStreamTaskFactory::NewStreamTask().
class ApacheStreamTask : public net_instaweb::Function {
 public:
  // The task does not take ownership of the arguments.
  ApacheStreamTask(SlaveConnectionFactory* conn_factory,
                   SpdyStream* stream);
  virtual ~ApacheStreamTask();

 protected:
  // net_instaweb::Function methods:
  virtual void Run();
  virtual void Cancel();

 private:
  SpdyStream* const stream_;
  scoped_ptr<SlaveConnection> slave_connection_;

  DISALLOW_COPY_AND_ASSIGN(ApacheStreamTask);
};

ApacheStreamTask::ApacheStreamTask(SlaveConnectionFactory* conn_factory,
                                   SpdyStream* stream)
    : stream_(stream),
      slave_connection_(conn_factory->Create()) {
  const SpdyServerConfig* config =
      GetServerConfig(slave_connection_->apache_connection());

  // SlaveConnectionFactory::Create must have attached a slave context.
  SlaveConnectionContext* slave_context =
      slave_connection_->GetSlaveConnectionContext();
  slave_context->set_slave_stream(stream);

  // Create our filters to hook us up to the slave connection.
  SpdyToHttpFilter* spdy_to_http_filter = new SpdyToHttpFilter(stream);
  PoolRegisterDelete(slave_connection_->apache_connection()->pool,
                     spdy_to_http_filter);
  slave_context->SetInputFilter(gSpdyToHttpFilterHandle, spdy_to_http_filter);

  HttpToSpdyFilter* http_to_spdy_filter = new HttpToSpdyFilter(config, stream);
  PoolRegisterDelete(slave_connection_->apache_connection()->pool,
                     http_to_spdy_filter);
  slave_context->SetOutputFilter(gHttpToSpdyFilterHandle, http_to_spdy_filter);
}

ApacheStreamTask::~ApacheStreamTask() {
}

void ApacheStreamTask::Run() {
  ScopedStreamLogHandler log_handler(
      slave_connection_->apache_connection(), stream_);
  VLOG(3) << "Starting stream task";
  if (!stream_->is_aborted()) {
    slave_connection_->Run();
  }
  VLOG(3) << "Finishing stream task";
}

void ApacheStreamTask::Cancel() {
  if (VLOG_IS_ON(3)) {
    ScopedStreamLogHandler log_handler(
        slave_connection_->apache_connection(), stream_);
    VLOG(3) << "Cancelling stream task";
  }
}

}  // namespace

ApacheSpdyStreamTaskFactory::ApacheSpdyStreamTaskFactory(conn_rec* connection)
    : connection_factory_(connection) {}

ApacheSpdyStreamTaskFactory::~ApacheSpdyStreamTaskFactory() {}

void ApacheSpdyStreamTaskFactory::InitFilters() {
  // Register our input filter, and store the filter handle into a global
  // variable so we can use it later to instantiate our filter into a filter
  // chain.  The "filter type" argument below determines where in the filter
  // chain our filter will be placed.  We use AP_FTYPE_NETWORK so that we will
  // be at the very end of the input chain for slave connections, in place of
  // the usual core input filter.
  gSpdyToHttpFilterHandle = ap_register_input_filter(
      "SPDY_TO_HTTP",             // name
      SpdyToHttpFilterFunc,       // filter function
      NULL,                       // init function (n/a in our case)
      AP_FTYPE_NETWORK);          // filter type

  // Now register our output filter, analogously to the input filter above.
  gHttpToSpdyFilterHandle = ap_register_output_filter(
      "HTTP_TO_SPDY",             // name
      HttpToSpdyFilterFunc,       // filter function
      NULL,                       // init function (n/a in our case)
      AP_FTYPE_NETWORK);          // filter type
}

net_instaweb::Function* ApacheSpdyStreamTaskFactory::NewStreamTask(
    SpdyStream* stream) {
  return new ApacheStreamTask(&connection_factory_, stream);
}

}  // namespace mod_spdy
