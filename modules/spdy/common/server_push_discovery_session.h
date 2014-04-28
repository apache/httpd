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

#ifndef MOD_SPDY_COMMON_SERVER_PUSH_DISCOVERY_SESSION_H_
#define MOD_SPDY_COMMON_SERVER_PUSH_DISCOVERY_SESSION_H_

#include <map>
#include <string>

#include "base/basictypes.h"
#include "base/synchronization/lock.h"

namespace mod_spdy {

class ServerPushDiscoverySession;

extern const int64_t kServerPushSessionTimeout;

// This class manages a pool of sessions used to discover X-Associated-Content.
// It tracks an initial request, i.e., for  'index.html', and all its child
// requests, i.e., 'logo.gif', 'style.css'. This should be created during
// per-process initialization. Class may be called from multiple threads.
class ServerPushDiscoverySessionPool {
 public:
  typedef int64_t SessionId;

  ServerPushDiscoverySessionPool();

  // Retrieves an existing session. Returns NULL if it's been timed out already.
  // In which case the module should create a new session. The returned pointer
  // is an object owned by the pool and must not be deleted by the caller.
  ServerPushDiscoverySession* GetExistingSession(SessionId session_id,
                                                 int64_t request_time);

  // Creates a new session. |took_push| denotes if the the initial request
  // response included an auto-learned X-Associated-Content header, since we
  // don't want to self-reinforce our URL statistics. Returns the session_id
  // for user agent storage.
  int64_t CreateSession(int64_t request_time,
                        const std::string& request_url,
                        bool took_push);

 private:
  // Caller should be holding |lock_|.
  void CleanExpired(int64_t request_time);

  SessionId next_session_id_;
  std::map<SessionId, ServerPushDiscoverySession> session_cache_;

  base::Lock lock_;
};

// Represents an initial page request and all its child resource requests.
class ServerPushDiscoverySession {
 public:
  // Update the last access time on this session, extending its lifetime.
  void UpdateLastAccessTime(int64_t now) { last_access_ = now; }

  // Returns the elapsed microseconds between the initial request and this one.
  int64_t TimeFromInit(int64_t request_time) const {
    return request_time - initial_request_time_;
  }

  const std::string& master_url() const { return master_url_; }
  bool took_push() const { return took_push_; }

 private:
  friend class ServerPushDiscoverySessionPool;

  ServerPushDiscoverySession(
      ServerPushDiscoverySessionPool::SessionId session_id,
      int64_t initial_request_time,
      const std::string& master_url,
      bool took_push);

  ServerPushDiscoverySessionPool::SessionId session_id_;
  int64_t initial_request_time_;
  std::string master_url_;
  int64_t took_push_;

  int64_t last_access_;
};

}  // namespace mod_spdy

#endif  // MOD_SPDY_COMMON_SERVER_PUSH_DISCOVERY_SESSION_H_
