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

#ifndef MOD_SPDY_COMMON_SHARED_FLOW_CONTROL_WINDOW_H_
#define MOD_SPDY_COMMON_SHARED_FLOW_CONTROL_WINDOW_H_

#include "base/basictypes.h"
#include "base/compiler_specific.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"

namespace mod_spdy {

class SpdyFramePriorityQueue;

// SPDY/3.1 introduces an additional session-wide flow control window shared by
// all streams, and represented in WINDOW_UPDATE frames as "stream 0".  The
// SharedFlowControlWindow class is a thread-safe object for tracking the size
// of this shared flow control window and enforcing flow-control rules, in both
// the input and output directions.
class SharedFlowControlWindow {
 public:
  SharedFlowControlWindow(int32 initial_input_window_size,
                          int32 initial_output_window_size);
  ~SharedFlowControlWindow();

  // Wake up all threads blocked on other methods.  Future method calls to this
  // class will return immediately with no effect.
  void Abort();

  // Return true if Abort() has been called.
  bool is_aborted() const;

  // Get the current input/ouput window sizes (of course, it might very soon
  // change if other threads are accessing this object).  This is primarily
  // useful for testing/debugging.
  int32 current_input_window_size() const;
  int32 current_output_window_size() const;
  // How many input bytes have been consumed that _haven't_ yet been
  // acknowledged by a WINDOW_UPDATE (signaled by OnInputDataConsumed)?  This
  // is primarily useful for testing/debugging.
  int32 input_bytes_consumed() const;

  // Called by the connection thread when input data is received from the
  // client.  Returns true (and reduces the input window size) on success, or
  // false if the input window is too small to accept that much data, in which
  // case the client has committed a flow control error and should be sent a
  // GOAWAY.  If the SharedFlowControlWindow has already been aborted
  // (i.e. because the session is shutting down), returns true with no effect.
  bool OnReceiveInputData(size_t length) WARN_UNUSED_RESULT;

  // Called by stream threads when input data from the client has been
  // consumed.  If a session WINDOW_UPDATE (stream 0) should be sent, returns
  // the size of the update to send; otherwise, returns zero.  If the
  // SharedFlowControlWindow has already been aborted, returns 0 with no
  // effect.
  int32 OnInputDataConsumed(size_t length) WARN_UNUSED_RESULT;

  // Like OnInputDataConsumed, but automatically send a WINDOW_UPDATE for
  // stream 0 if needed.
  void OnInputDataConsumedSendUpdateIfNeeded(
      size_t length, SpdyFramePriorityQueue* output_queue);

  // This should be called by stream threads to consume quota from the shared
  // flow control window.  Consumes up to `amount_requested` bytes from the
  // window (less if the window is currently smaller than `amount_requested`)
  // and returns the number of bytes successfully consumed.  If the window is
  // currently empty, blocks until some value can be returned (or the
  // SharedFlowControlWindow is aborted); if the SharedFlowControlWindow is
  // aborted, returns zero.  The `amount_requested` must be strictly positive.
  int32 RequestOutputQuota(int32 amount_requested) WARN_UNUSED_RESULT;

  // This should be called by the connection thread to adjust the window size,
  // due to receiving a WINDOW_UPDATE frame from the client.  The delta
  // argument must be non-negative (WINDOW_UPDATE is never negative).  Return
  // false if the delta would cause the window size to overflow (in which case
  // the client has committed a flow control error and should be sent a
  // GOAWAY), true otherwise.  If the SharedFlowControlWindow has already been
  // aborted, returns true with no effect.
  bool IncreaseOutputWindowSize(int32 delta) WARN_UNUSED_RESULT;

 private:
  mutable base::Lock lock_;  // protects the below fields
  base::ConditionVariable condvar_;
  bool aborted_;
  const int32 init_input_window_size_;
  int32 input_window_size_;
  int32 input_bytes_consumed_;
  int32 output_window_size_;

  DISALLOW_COPY_AND_ASSIGN(SharedFlowControlWindow);
};

}  // namespace mod_spdy

#endif  // MOD_SPDY_COMMON_SHARED_FLOW_CONTROL_WINDOW_H_
