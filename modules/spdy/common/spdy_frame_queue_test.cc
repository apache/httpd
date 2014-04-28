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

#include "mod_spdy/common/spdy_frame_queue.h"

#include "base/basictypes.h"
#include "base/threading/platform_thread.h"
#include "mod_spdy/common/testing/async_task_runner.h"
#include "mod_spdy/common/testing/notification.h"
#include "mod_spdy/common/testing/spdy_frame_matchers.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

const int kSpdyVersion = 2;

void ExpectPop(bool block, net::SpdyStreamId expected,
               mod_spdy::SpdyFrameQueue* queue) {
  net::SpdyFrameIR* raw_frame = NULL;
  const bool success = queue->Pop(block, &raw_frame);
  scoped_ptr<net::SpdyFrameIR> scoped_frame(raw_frame);
  EXPECT_TRUE(success);
  ASSERT_TRUE(scoped_frame != NULL);
  EXPECT_THAT(*scoped_frame, mod_spdy::testing::IsPing(expected));
}

void ExpectEmpty(mod_spdy::SpdyFrameQueue* queue) {
  net::SpdyFrameIR* frame = NULL;
  EXPECT_FALSE(queue->Pop(false, &frame));
  EXPECT_TRUE(frame == NULL);
}

TEST(SpdyFrameQueueTest, Simple) {
  mod_spdy::SpdyFrameQueue queue;
  ExpectEmpty(&queue);

  queue.Insert(new net::SpdyPingIR(4));
  queue.Insert(new net::SpdyPingIR(1));
  queue.Insert(new net::SpdyPingIR(3));

  ExpectPop(false, 4, &queue);
  ExpectPop(false, 1, &queue);

  queue.Insert(new net::SpdyPingIR(2));
  queue.Insert(new net::SpdyPingIR(5));

  ExpectPop(false, 3, &queue);
  ExpectPop(false, 2, &queue);
  ExpectPop(false, 5, &queue);
  ExpectEmpty(&queue);
}

TEST(SpdyFrameQueueTest, AbortEmptiesQueue) {
  mod_spdy::SpdyFrameQueue queue;
  ASSERT_FALSE(queue.is_aborted());
  ExpectEmpty(&queue);

  queue.Insert(new net::SpdyPingIR(4));
  queue.Insert(new net::SpdyPingIR(1));
  queue.Insert(new net::SpdyPingIR(3));

  ExpectPop(false, 4, &queue);

  queue.Abort();

  ExpectEmpty(&queue);
  ASSERT_TRUE(queue.is_aborted());
}

class BlockingPopTask : public mod_spdy::testing::AsyncTaskRunner::Task {
 public:
  explicit BlockingPopTask(mod_spdy::SpdyFrameQueue* queue) : queue_(queue) {}
  virtual void Run() { ExpectPop(true, 7, queue_); }
 private:
  mod_spdy::SpdyFrameQueue* const queue_;
  DISALLOW_COPY_AND_ASSIGN(BlockingPopTask);
};

TEST(SpdyFrameQueueTest, BlockingPop) {
  mod_spdy::SpdyFrameQueue queue;

  // Start a task that will do a blocking pop from the queue.
  mod_spdy::testing::AsyncTaskRunner runner(new BlockingPopTask(&queue));
  ASSERT_TRUE(runner.Start());

  // Even if we wait for a little bit, the task shouldn't complete, because
  // that thread is blocked, because the queue is still empty.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(50));
  runner.notification()->ExpectNotSet();
  ExpectEmpty(&queue);

  // Now, if we push something into the queue, the task should soon unblock and
  // complete, and the queue should then be empty.
  queue.Insert(new net::SpdyPingIR(7));
  runner.notification()->ExpectSetWithinMillis(100);
  ExpectEmpty(&queue);
}

}  // namespace
