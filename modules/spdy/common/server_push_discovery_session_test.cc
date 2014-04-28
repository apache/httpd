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

#include "gtest/gtest.h"

namespace mod_spdy {

TEST(ServerPushDiscoverySessionTest, NoSession) {
  ServerPushDiscoverySessionPool pool;
  EXPECT_EQ(NULL, pool.GetExistingSession(0, 0));
}

TEST(ServerPushDiscoverySessionTest, GetSession) {
  ServerPushDiscoverySessionPool pool;
  std::vector<int64_t> session_ids;
  for (int i = 0; i < 40; i++)
    session_ids.push_back(pool.CreateSession(0, "", false));

  for (int i = 0; i < 40; i++)
    EXPECT_TRUE(pool.GetExistingSession(session_ids[i], 0));
}

TEST(ServerPushDiscoverySessionTest, ExpiryTest) {
  ServerPushDiscoverySessionPool pool;
  std::vector<int64_t> session_ids;
  for (int i = 0; i < 20; i++) {
    session_ids.push_back(pool.CreateSession(0, "", false));
  }

  for (int i = 0; i < 20; i++) {
    int64_t time = i * kServerPushSessionTimeout / 10;
    bool expired = time > kServerPushSessionTimeout;
    session_ids.push_back(pool.CreateSession(0, "", false));

    if (expired) {
      EXPECT_FALSE(pool.GetExistingSession(session_ids[i], time));
    } else {
      EXPECT_TRUE(pool.GetExistingSession(session_ids[i], time));
    }
  }
}

}  // namespace mod_spdy
