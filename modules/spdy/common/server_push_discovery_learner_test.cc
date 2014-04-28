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

#include "mod_spdy/common/server_push_discovery_learner.h"

#include "gtest/gtest.h"

namespace mod_spdy {

TEST(ServerPushDiscoveryLearnerTest, TrivialNoPush) {
  ServerPushDiscoveryLearner learner;

  EXPECT_TRUE(learner.GetPushes("a").empty());

  learner.AddFirstHit("a");
  learner.AddFirstHit("a");
  learner.AddFirstHit("a");
  learner.AddFirstHit("a");

  EXPECT_TRUE(learner.GetPushes("a").empty());

  // Add an adjacent hit, but it should not be enough to generate a push.
  learner.AddAdjacentHit("a", "b", 0);

  EXPECT_TRUE(learner.GetPushes("a").empty());
}

TEST(ServerPushDiscoveryLearnerTest, TrivialYesPush) {
  ServerPushDiscoveryLearner learner;

  learner.AddFirstHit("a");
  learner.AddAdjacentHit("a", "b", 0);

  std::vector<ServerPushDiscoveryLearner::Push> pushes = learner.GetPushes("a");
  EXPECT_FALSE(pushes.empty());
  EXPECT_EQ("b", pushes.front().adjacent_url);
}

TEST(ServerPushDiscoveryLearnerTest, PushOrder) {
  ServerPushDiscoveryLearner learner;

  learner.AddFirstHit("a");
  learner.AddAdjacentHit("a", "b", 1);
  learner.AddAdjacentHit("a", "c", 2);

  learner.AddFirstHit("a");
  learner.AddAdjacentHit("a", "b", 2);
  learner.AddAdjacentHit("a", "c", 3);

  learner.AddFirstHit("a");
  learner.AddAdjacentHit("a", "b", 3);
  learner.AddAdjacentHit("a", "c", 4);

  std::vector<ServerPushDiscoveryLearner::Push> pushes = learner.GetPushes("a");
  EXPECT_EQ(2u, pushes.size());
  EXPECT_EQ("b", pushes.front().adjacent_url);
  EXPECT_EQ("c", pushes.back().adjacent_url);
}

TEST(ServerPushDiscoveryLearnerTest, TurnoverPoint) {
  ServerPushDiscoveryLearner learner;

  uint64_t a_requests = 0;
  uint64_t b_requests = 0;

  // Put in 20 initial requests with no child requests.
  for (int i = 0; i < 20; ++i) {
    learner.AddFirstHit("a");
    ++a_requests;
  }

  // Put in more b requests until it tips over
  for (int i = 0; i < 50; ++i) {
    learner.AddAdjacentHit("a", "b", 0);
    ++b_requests;
    std::vector<ServerPushDiscoveryLearner::Push> pushes =
        learner.GetPushes("a");

    if (b_requests >= (a_requests / 2)) {
      ASSERT_TRUE(pushes.size() == 1) << "(a, b) = " << a_requests << ","
                                      << b_requests;
      EXPECT_EQ("b", pushes.front().adjacent_url);
    } else {
      EXPECT_TRUE(pushes.empty()) << "(a, b) = " << a_requests << ","
                                  << b_requests;
    }
  }
}

}  // namespace mod_spdy
