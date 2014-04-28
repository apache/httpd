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

#include <list>

#include "base/logging.h"
#include "base/stl_util.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "net/spdy/spdy_protocol.h"

namespace mod_spdy {

SpdyFrameQueue::SpdyFrameQueue()
    : condvar_(&lock_), is_aborted_(false) {}

SpdyFrameQueue::~SpdyFrameQueue() {
  STLDeleteContainerPointers(queue_.begin(), queue_.end());
}

bool SpdyFrameQueue::is_aborted() const {
  base::AutoLock autolock(lock_);
  return is_aborted_;
}

void SpdyFrameQueue::Abort() {
  base::AutoLock autolock(lock_);
  is_aborted_ = true;
  STLDeleteContainerPointers(queue_.begin(), queue_.end());
  queue_.clear();
  condvar_.Broadcast();
}

void SpdyFrameQueue::Insert(net::SpdyFrameIR* frame) {
  base::AutoLock autolock(lock_);
  DCHECK(frame);

  if (is_aborted_) {
    DCHECK(queue_.empty());
    delete frame;
  } else {
    if (queue_.empty()) {
      condvar_.Signal();
    }
    queue_.push_front(frame);
  }
}

bool SpdyFrameQueue::Pop(bool block, net::SpdyFrameIR** frame) {
  base::AutoLock autolock(lock_);
  DCHECK(frame);

  if (block) {
    // Block until the queue is nonempty or we abort.
    while (queue_.empty() && !is_aborted_) {
      condvar_.Wait();
    }
  }

  // If we've aborted, the queue should now be empty.
  DCHECK(!is_aborted_ || queue_.empty());
  if (queue_.empty()) {
    return false;
  }

  *frame = queue_.back();
  queue_.pop_back();
  return true;
}

}  // namespace mod_spdy
