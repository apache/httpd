// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "mod_spdy/common/testing/notification.h"

#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace mod_spdy {

namespace testing {

Notification::Notification() : condvar_(&lock_), is_set_(false) {}

Notification::~Notification() {
  Set();
}

void Notification::Set() {
  base::AutoLock autolock(lock_);
  is_set_ = true;
  condvar_.Broadcast();
}

void Notification::Wait() {
  base::AutoLock autolock(lock_);
  while (!is_set_) {
    condvar_.Wait();
  }
}

void Notification::ExpectNotSet() {
  base::AutoLock autolock(lock_);
  EXPECT_FALSE(is_set_);
}

void Notification::ExpectSetWithin(const base::TimeDelta& timeout) {
  base::AutoLock autolock(lock_);
  const base::TimeDelta zero = base::TimeDelta();
  base::TimeDelta time_remaining = timeout;
  while (time_remaining > zero && !is_set_) {
    const base::TimeTicks start = base::TimeTicks::HighResNow();
    condvar_.TimedWait(time_remaining);
    time_remaining -= base::TimeTicks::HighResNow() - start;
  }
  EXPECT_TRUE(is_set_);
}

void Notification::ExpectSetWithinMillis(int millis) {
  ExpectSetWithin(base::TimeDelta::FromMilliseconds(millis));
}

}  // namespace testing

}  // namespace mod_spdy
