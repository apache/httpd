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

#include "mod_spdy/apache/pool_util.h"

#include "base/basictypes.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

// Class to help us detect when it is deleted.
class SetOnDelete {
 public:
  SetOnDelete(int value, int* ptr) : value_(value), ptr_(ptr) {}
  ~SetOnDelete() { *ptr_ = value_; }
 private:
  const int value_;
  int* const ptr_;
  DISALLOW_COPY_AND_ASSIGN(SetOnDelete);
};

TEST(PoolUtilTest, LocalPoolRegisterDelete) {
  int value = 3;
  {
    mod_spdy::LocalPool local;
    SetOnDelete* setter = new SetOnDelete(5, &value);
    mod_spdy::PoolRegisterDelete(local.pool(), setter);
    ASSERT_EQ(3, value);
  }
  ASSERT_EQ(5, value);
}

TEST(PoolUtilTest, LocalPoolUnregisterDelete) {
  int value = 2;
  SetOnDelete* setter = new SetOnDelete(7, &value);
  {
    mod_spdy::LocalPool local;
    mod_spdy::PoolRegisterDelete(local.pool(), setter);
    ASSERT_EQ(2, value);
    mod_spdy::PoolUnregisterDelete(local.pool(), setter);
    ASSERT_EQ(2, value);
  }
  ASSERT_EQ(2, value);
  delete setter;
  ASSERT_EQ(7, value);
}

}  // namespace
