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

#include "mod_spdy/common/spdy_server_config.h"

#include "mod_spdy/common/protocol_util.h"

namespace {

const bool kDefaultSpdyEnabled = false;
const int kDefaultMaxStreamsPerConnection = 100;
const int kDefaultMinThreadsPerProcess = 2;
const int kDefaultMaxThreadsPerProcess = 10;
const int kDefaultMaxServerPushDepth = 1;
const bool kDefaultSendVersionHeader = true;
const mod_spdy::spdy::SpdyVersion kDefaultUseSpdyVersionWithoutSsl =
    mod_spdy::spdy::SPDY_VERSION_NONE;
const int kDefaultVlogLevel = 0;

}  // namespace

namespace mod_spdy {

SpdyServerConfig::SpdyServerConfig()
    : spdy_enabled_(kDefaultSpdyEnabled),
      max_streams_per_connection_(kDefaultMaxStreamsPerConnection),
      min_threads_per_process_(kDefaultMinThreadsPerProcess),
      max_threads_per_process_(kDefaultMaxThreadsPerProcess),
      max_server_push_depth_(kDefaultMaxServerPushDepth),
      send_version_header_(kDefaultSendVersionHeader),
      use_spdy_version_without_ssl_(kDefaultUseSpdyVersionWithoutSsl),
      vlog_level_(kDefaultVlogLevel) {}

SpdyServerConfig::~SpdyServerConfig() {}

void SpdyServerConfig::MergeFrom(const SpdyServerConfig& a,
                                 const SpdyServerConfig& b) {
  spdy_enabled_.MergeFrom(a.spdy_enabled_, b.spdy_enabled_);
  max_streams_per_connection_.MergeFrom(a.max_streams_per_connection_,
                                        b.max_streams_per_connection_);
  min_threads_per_process_.MergeFrom(a.min_threads_per_process_,
                                     b.min_threads_per_process_);
  max_threads_per_process_.MergeFrom(a.max_threads_per_process_,
                                     b.max_threads_per_process_);
  max_server_push_depth_.MergeFrom(a.max_server_push_depth_,
                                   b.max_server_push_depth_);
  send_version_header_.MergeFrom(
      a.send_version_header_, b.send_version_header_);
  use_spdy_version_without_ssl_.MergeFrom(
      a.use_spdy_version_without_ssl_, b.use_spdy_version_without_ssl_);
  vlog_level_.MergeFrom(a.vlog_level_, b.vlog_level_);
}

}  // namespace mod_spdy
