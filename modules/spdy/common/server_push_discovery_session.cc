// Copyright 2013 Google Inc.
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

#include "mod_spdy/common/server_push_discovery_session.h"

namespace mod_spdy {

const int64_t kServerPushSessionTimeout = 1000000;  // 1 second in microseconds.

ServerPushDiscoverySessionPool::ServerPushDiscoverySessionPool()
    : next_session_id_(0) {
}

ServerPushDiscoverySession* ServerPushDiscoverySessionPool::GetExistingSession(
    SessionId session_id,
    int64_t request_time) {
  base::AutoLock lock(lock_);
  std::map<SessionId, ServerPushDiscoverySession>::iterator it =
      session_cache_.find(session_id);
  if (it == session_cache_.end() ||
      it->second.TimeFromInit(request_time) > kServerPushSessionTimeout) {
    return NULL;
  }

  return &(it->second);
}

ServerPushDiscoverySessionPool::SessionId
ServerPushDiscoverySessionPool::CreateSession(
    int64_t request_time,
    const std::string& request_url,
    bool took_push) {
  base::AutoLock lock(lock_);
  CleanExpired(request_time);
  // Create a session to track this request chain
  SessionId session_id = ++next_session_id_;
  session_cache_.insert(
      std::make_pair(session_id,
                     ServerPushDiscoverySession(
                         session_id, request_time, request_url, took_push)));
  return session_id;
}

void ServerPushDiscoverySessionPool::CleanExpired(int64_t request_time) {
  lock_.AssertAcquired();

  std::map<int64_t, ServerPushDiscoverySession>::iterator it =
      session_cache_.begin();
  while (it != session_cache_.end()) {
    if (it->second.TimeFromInit(request_time) > kServerPushSessionTimeout) {
      session_cache_.erase(it++);
    } else {
      ++it;
    }
  }
}

ServerPushDiscoverySession::ServerPushDiscoverySession(
    ServerPushDiscoverySessionPool::SessionId session_id,
    int64_t initial_request_time,
    const std::string& master_url,
    bool took_push)
    : session_id_(session_id),
      initial_request_time_(initial_request_time),
      master_url_(master_url),
      took_push_(took_push),
      last_access_(initial_request_time) {}

}  // namespace mod_spdy
