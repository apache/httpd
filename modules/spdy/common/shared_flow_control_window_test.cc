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

#include "mod_spdy/common/shared_flow_control_window.h"

#include "base/threading/platform_thread.h"
#include "mod_spdy/common/spdy_frame_priority_queue.h"
#include "mod_spdy/common/testing/async_task_runner.h"
#include "mod_spdy/common/testing/notification.h"
#include "mod_spdy/common/testing/spdy_frame_matchers.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

// Test that when we receive input data, the input window size decreases, and
// if we try to receive more data than the window allows, then
// OnReceiveInputData returns false.
TEST(SharedFlowControlWindowTest, ReceiveInput) {
  mod_spdy::SharedFlowControlWindow shared_window(1000, 1000);
  ASSERT_EQ(1000, shared_window.current_input_window_size());

  EXPECT_TRUE(shared_window.OnReceiveInputData(320));
  ASSERT_EQ(680, shared_window.current_input_window_size());

  EXPECT_TRUE(shared_window.OnReceiveInputData(600));
  ASSERT_EQ(80, shared_window.current_input_window_size());

  EXPECT_FALSE(shared_window.OnReceiveInputData(100));
  ASSERT_EQ(80, shared_window.current_input_window_size());

  EXPECT_TRUE(shared_window.OnReceiveInputData(80));
  ASSERT_EQ(0, shared_window.current_input_window_size());

  EXPECT_FALSE(shared_window.OnReceiveInputData(1));
  ASSERT_EQ(0, shared_window.current_input_window_size());
}

// Test that when we consume input data that we've already received, the input
// window size goes up, but only once we've consumed enough total data for it
// to be worth it to send a WINDOW_UPDATE.
TEST(SharedFlowControlWindowTest, ConsumeInput) {
  mod_spdy::SharedFlowControlWindow shared_window(1000, 1000);
  ASSERT_FALSE(shared_window.is_aborted());
  ASSERT_EQ(1000, shared_window.current_input_window_size());

  EXPECT_TRUE(shared_window.OnReceiveInputData(1000));
  EXPECT_EQ(0, shared_window.current_input_window_size());

  EXPECT_EQ(0, shared_window.OnInputDataConsumed(10));
  EXPECT_EQ(0, shared_window.current_input_window_size());
  EXPECT_EQ(10, shared_window.input_bytes_consumed());

  EXPECT_EQ(0, shared_window.OnInputDataConsumed(40));
  EXPECT_EQ(0, shared_window.current_input_window_size());
  EXPECT_EQ(50, shared_window.input_bytes_consumed());

  EXPECT_EQ(550, shared_window.OnInputDataConsumed(500));
  EXPECT_EQ(550, shared_window.current_input_window_size());
  EXPECT_EQ(0, shared_window.input_bytes_consumed());

  EXPECT_EQ(0, shared_window.OnInputDataConsumed(10));
  EXPECT_EQ(550, shared_window.current_input_window_size());
  EXPECT_EQ(10, shared_window.input_bytes_consumed());

  EXPECT_EQ(450, shared_window.OnInputDataConsumed(440));
  EXPECT_EQ(1000, shared_window.current_input_window_size());
  EXPECT_EQ(0, shared_window.input_bytes_consumed());

  shared_window.Abort();
  ASSERT_TRUE(shared_window.is_aborted());

  EXPECT_TRUE(shared_window.OnReceiveInputData(1));
  EXPECT_EQ(0, shared_window.OnInputDataConsumed(1000));
}

// Test that OnInputDataConsumedSendUpdateIfNeeded sends WINDOW_UPDATE frames
// correctly.
TEST(SharedFlowControlWindowTest, ConsumeInputSendUpdate) {
  mod_spdy::SharedFlowControlWindow shared_window(1000, 1000);
  ASSERT_EQ(1000, shared_window.current_input_window_size());

  EXPECT_TRUE(shared_window.OnReceiveInputData(1000));
  EXPECT_EQ(0, shared_window.current_input_window_size());

  mod_spdy::SpdyFramePriorityQueue queue;
  net::SpdyFrameIR* raw_frame;

  shared_window.OnInputDataConsumedSendUpdateIfNeeded(5, &queue);
  EXPECT_EQ(0, shared_window.current_input_window_size());
  EXPECT_EQ(5, shared_window.input_bytes_consumed());
  ASSERT_FALSE(queue.Pop(&raw_frame));

  shared_window.OnInputDataConsumedSendUpdateIfNeeded(933, &queue);
  EXPECT_EQ(938, shared_window.current_input_window_size());
  EXPECT_EQ(0, shared_window.input_bytes_consumed());
  ASSERT_TRUE(queue.Pop(&raw_frame));
  scoped_ptr<net::SpdyFrameIR> frame(raw_frame);
  EXPECT_THAT(*frame, mod_spdy::testing::IsWindowUpdate(0, 938));
  ASSERT_FALSE(queue.Pop(&raw_frame));
}

// Test basic usage of RequestOutputQuota and IncreaseOutputWindowSize.
TEST(SharedFlowControlWindowTest, OutputBasic) {
  mod_spdy::SharedFlowControlWindow shared_window(1000, 1000);
  EXPECT_FALSE(shared_window.is_aborted());
  EXPECT_EQ(1000, shared_window.current_output_window_size());

  EXPECT_TRUE(shared_window.IncreaseOutputWindowSize(0));
  EXPECT_EQ(1000, shared_window.current_output_window_size());

  EXPECT_TRUE(shared_window.IncreaseOutputWindowSize(47));
  EXPECT_EQ(1047, shared_window.current_output_window_size());

  EXPECT_EQ(800, shared_window.RequestOutputQuota(800));
  EXPECT_EQ(247, shared_window.current_output_window_size());

  EXPECT_EQ(247, shared_window.RequestOutputQuota(800));
  EXPECT_EQ(0, shared_window.current_output_window_size());

  EXPECT_TRUE(shared_window.IncreaseOutputWindowSize(2000));
  EXPECT_EQ(2000, shared_window.current_output_window_size());

  // After aborting, RequestOutputQuota always returns zero (without blocking).
  EXPECT_FALSE(shared_window.is_aborted());
  shared_window.Abort();
  EXPECT_TRUE(shared_window.is_aborted());
  EXPECT_EQ(0, shared_window.RequestOutputQuota(800));
  EXPECT_EQ(0, shared_window.RequestOutputQuota(9999));
}

// When run, a RequestOutputQuotaTask requests quota from the given
// SharedFlowControlWindow.
class RequestOutputQuotaTask : public mod_spdy::testing::AsyncTaskRunner::Task {
 public:
  RequestOutputQuotaTask(mod_spdy::SharedFlowControlWindow* window,
                         int32 request)
      : window_(window), request_(request), received_(-1) {}
  virtual void Run() {
    received_ = window_->RequestOutputQuota(request_);
  }
  int32 received() const { return received_; }
 private:
  mod_spdy::SharedFlowControlWindow* const window_;
  const int32 request_;
  int32 received_;
  DISALLOW_COPY_AND_ASSIGN(RequestOutputQuotaTask);
};

// Test that RequestOutputQuota blocks if the window is completely empty.
TEST(SharedFlowControlWindowTest, OutputBlocking) {
  mod_spdy::SharedFlowControlWindow shared_window(1000, 350);

  EXPECT_EQ(200, shared_window.RequestOutputQuota(200));
  EXPECT_EQ(150, shared_window.current_output_window_size());

  EXPECT_EQ(150, shared_window.RequestOutputQuota(200));
  EXPECT_EQ(0, shared_window.current_output_window_size());

  // Start an async task to request 200 bytes.  It should block, because the
  // window is empty.
  RequestOutputQuotaTask* task =
      new RequestOutputQuotaTask(&shared_window, 200);
  mod_spdy::testing::AsyncTaskRunner runner(task);
  ASSERT_TRUE(runner.Start());
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(50));
  runner.notification()->ExpectNotSet();

  // Now increase the window size.  RequestOutputQuota should unblock and return
  // what's available.
  EXPECT_TRUE(shared_window.IncreaseOutputWindowSize(63));
  runner.notification()->ExpectSetWithinMillis(100);
  EXPECT_EQ(63, task->received());
}

// Test that RequestOutputQuota unblocks if we abort.
TEST(SharedFlowControlWindowTest, OutputAborting) {
  mod_spdy::SharedFlowControlWindow shared_window(1000, 350);

  EXPECT_EQ(350, shared_window.RequestOutputQuota(500));
  EXPECT_EQ(0, shared_window.current_output_window_size());

  // Start an async task to request 200 bytes.  It should block, because the
  // window is empty.
  RequestOutputQuotaTask* task =
      new RequestOutputQuotaTask(&shared_window, 200);
  mod_spdy::testing::AsyncTaskRunner runner(task);
  ASSERT_TRUE(runner.Start());
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(50));
  runner.notification()->ExpectNotSet();

  // Now abort.  RequestOutputQuota should unblock and return zero.
  EXPECT_FALSE(shared_window.is_aborted());
  shared_window.Abort();
  runner.notification()->ExpectSetWithinMillis(100);
  EXPECT_EQ(0, task->received());
  EXPECT_TRUE(shared_window.is_aborted());

  // Abort again, to check that it's idempotent.
  shared_window.Abort();
  EXPECT_TRUE(shared_window.is_aborted());
  EXPECT_EQ(0, shared_window.RequestOutputQuota(800));
}

}  // namespace
