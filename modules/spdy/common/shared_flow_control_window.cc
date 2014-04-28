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

#include "base/logging.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "mod_spdy/common/spdy_frame_priority_queue.h"
#include "net/spdy/spdy_protocol.h"

namespace mod_spdy {

SharedFlowControlWindow::SharedFlowControlWindow(
    int32 initial_input_window_size, int32 initial_output_window_size)
    : condvar_(&lock_),
      aborted_(false),
      init_input_window_size_(initial_input_window_size),
      input_window_size_(initial_input_window_size),
      input_bytes_consumed_(0),
      output_window_size_(initial_output_window_size) {}

SharedFlowControlWindow::~SharedFlowControlWindow() {}

void SharedFlowControlWindow::Abort() {
  base::AutoLock autolock(lock_);
  aborted_ = true;
  condvar_.Broadcast();
}

bool SharedFlowControlWindow::is_aborted() const {
  base::AutoLock autolock(lock_);
  return aborted_;
}

int32 SharedFlowControlWindow::current_input_window_size() const {
  base::AutoLock autolock(lock_);
  return input_window_size_;
}

int32 SharedFlowControlWindow::current_output_window_size() const {
  base::AutoLock autolock(lock_);
  return output_window_size_;
}

int32 SharedFlowControlWindow::input_bytes_consumed() const {
  base::AutoLock autolock(lock_);
  return input_bytes_consumed_;
}

bool SharedFlowControlWindow::OnReceiveInputData(size_t length) {
  base::AutoLock autolock(lock_);
  if (aborted_) {
    return true;
  }
  DCHECK_GE(input_window_size_, 0);
  if (static_cast<size_t>(input_window_size_) < length) {
    return false;
  }
  input_window_size_ -= length;
  return true;
}

int32 SharedFlowControlWindow::OnInputDataConsumed(size_t length) {
  base::AutoLock autolock(lock_);
  if (aborted_) {
    return 0;
  }

  DCHECK_GE(input_bytes_consumed_, 0);

  // Check for overflow; this should never happen unless there is a bug in
  // mod_spdy, since we should never say we've consumed more data than we've
  // actually received.
  {
    const int64 new_input_bytes_consumed =
        static_cast<int64>(input_bytes_consumed_) + static_cast<int64>(length);
    CHECK_LE(new_input_bytes_consumed,
             static_cast<int64>(init_input_window_size_));
    CHECK_LE(new_input_bytes_consumed + static_cast<int64>(input_window_size_),
             static_cast<int64>(init_input_window_size_));
    input_bytes_consumed_ = new_input_bytes_consumed;
  }

  // Only send a WINDOW_UPDATE when we've consumed 1/16 of the maximum shared
  // window size, so that we don't send lots of small WINDOW_UDPATE frames.
  if (input_bytes_consumed_ < init_input_window_size_ / 16) {
    return 0;
  } else {
    input_window_size_ += input_bytes_consumed_;
    const int32 consumed = input_bytes_consumed_;
    input_bytes_consumed_ = 0;
    return consumed;
  }
}

void SharedFlowControlWindow::OnInputDataConsumedSendUpdateIfNeeded(
    size_t length, SpdyFramePriorityQueue* output_queue) {
  const int32 update = OnInputDataConsumed(length);
  if (update > 0) {
    output_queue->Insert(SpdyFramePriorityQueue::kTopPriority,
                         new net::SpdyWindowUpdateIR(0, update));
  }
}

int32 SharedFlowControlWindow::RequestOutputQuota(int32 amount_requested) {
  base::AutoLock autolock(lock_);
  DCHECK_GT(amount_requested, 0);

  while (!aborted_ && output_window_size_ <= 0) {
    condvar_.Wait();
  }

  if (aborted_) {
    return 0;
  }

  // Give as much output quota as we can, but not more than is asked for.
  DCHECK_GT(output_window_size_, 0);
  const int32 amount_to_give = std::min(amount_requested, output_window_size_);
  output_window_size_ -= amount_to_give;
  DCHECK_GE(output_window_size_, 0);
  return amount_to_give;
}

bool SharedFlowControlWindow::IncreaseOutputWindowSize(int32 delta) {
  base::AutoLock autolock(lock_);
  DCHECK_GE(delta, 0);
  if (aborted_) {
    return true;
  }

  // Check for overflow; this can happen if the client is misbehaving.
  const int64 new_size =
      static_cast<int64>(output_window_size_) + static_cast<int64>(delta);
  if (new_size > static_cast<int64>(net::kSpdyMaximumWindowSize)) {
    return false;
  }

  // Increase the shared output window size, and wake up any stream threads
  // that are waiting for output quota.
  output_window_size_ += delta;
  DCHECK_LE(output_window_size_, net::kSpdyMaximumWindowSize);
  if (output_window_size_ > 0) {
    condvar_.Broadcast();
  }
  return true;
}

}  // namespace mod_spdy
