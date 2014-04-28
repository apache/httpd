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

#include "mod_spdy/apache/id_pool.h"

#include <set>

#include "base/basictypes.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

using mod_spdy::IdPool;

TEST(IdPoolTest, Lifetime) {
  EXPECT_EQ(NULL, IdPool::Instance());
  IdPool::CreateInstance();
  EXPECT_TRUE(IdPool::Instance() != NULL);
  IdPool::DestroyInstance();
  EXPECT_EQ(NULL, IdPool::Instance());
}

TEST(IdPoolTest, BasicAllocation) {
  IdPool::CreateInstance();
  IdPool* instance = IdPool::Instance();
  uint16 id_1 = instance->Alloc();
  uint16 id_2 = instance->Alloc();
  uint16 id_3 = instance->Alloc();
  EXPECT_NE(0, id_1);
  EXPECT_NE(0, id_2);
  EXPECT_NE(0, id_3);
  EXPECT_NE(id_1, id_2);
  EXPECT_NE(id_1, id_3);
  EXPECT_NE(id_2, id_3);
  instance->Free(id_1);
  instance->Free(id_2);
  instance->Free(id_3);
  IdPool::DestroyInstance();
}

TEST(IdPoolTest, AllocatingMany) {
  // We should be able to allocate 2^16-2 unique ids.
  IdPool::CreateInstance();
  IdPool* instance = IdPool::Instance();

  std::set<uint16> in_use;
  for (int run = 0; run < 0xFFFE; ++run) {
    uint16 new_id = instance->Alloc();
    EXPECT_NE(0, new_id);
    EXPECT_NE(IdPool::kOverFlowId, new_id);
    EXPECT_TRUE(in_use.find(new_id) == in_use.end());
    in_use.insert(new_id);
  }

  // All attempts after this point should return kOverFlowId.
  for (int run = 0; run < 100; ++run) {
    EXPECT_EQ(IdPool::kOverFlowId, instance->Alloc());
  }

  // Trying to free the overflow ID is harmless.
  instance->Free(IdPool::kOverFlowId);

  // Now delete half of them.
  int deleted = 0;
  std::set<uint16>::iterator i = in_use.begin();
  while (deleted != 0xFFFE / 2) {
    ASSERT_TRUE(i != in_use.end());
    instance->Free(*i);
    ++deleted;
    in_use.erase(i);
    i = in_use.begin();
  }

  // Should now be able to allocate that many again.
  for (int run = 0; run < 0xFFFE / 2; ++run) {
    uint16 new_id = instance->Alloc();
    EXPECT_NE(0, new_id);
    EXPECT_NE(IdPool::kOverFlowId, new_id);
    EXPECT_TRUE(in_use.find(new_id) == in_use.end());
    in_use.insert(new_id);
  }

  IdPool::DestroyInstance();
}

}  // namespace
