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

#include "mod_spdy/common/spdy_frame_priority_queue.h"

#include <list>
#include <map>

#include "base/logging.h"
#include "base/stl_util.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/time/time.h"
#include "net/spdy/spdy_protocol.h"

namespace mod_spdy {

SpdyFramePriorityQueue::SpdyFramePriorityQueue()
    : condvar_(&lock_) {}

SpdyFramePriorityQueue::~SpdyFramePriorityQueue() {
  for (QueueMap::iterator iter = queue_map_.begin();
       iter != queue_map_.end(); ++iter) {
    FrameList* list = iter->second;
    STLDeleteContainerPointers(list->begin(), list->end());
    delete list;
  }
}

bool SpdyFramePriorityQueue::IsEmpty() const {
  base::AutoLock autolock(lock_);
  return queue_map_.empty();
}

const int SpdyFramePriorityQueue::kTopPriority = -1;

void SpdyFramePriorityQueue::Insert(int priority, net::SpdyFrameIR* frame) {
  base::AutoLock autolock(lock_);
  DCHECK(frame);

  // Get the frame list for the given priority; if it doesn't currently exist,
  // create it in the map.
  FrameList* list = NULL;
  QueueMap::iterator iter = queue_map_.find(priority);
  if (iter == queue_map_.end()) {
    list = new FrameList;
    queue_map_[priority] = list;
  } else {
    list = iter->second;
  }
  DCHECK(list);

  // Add the frame to the end of the list, and wake up at most one thread
  // sleeping on a BlockingPop.
  list->push_back(frame);
  condvar_.Signal();
}

bool SpdyFramePriorityQueue::Pop(net::SpdyFrameIR** frame) {
  base::AutoLock autolock(lock_);
  return InternalPop(frame);
}

bool SpdyFramePriorityQueue::BlockingPop(const base::TimeDelta& max_time,
                                         net::SpdyFrameIR** frame) {
  base::AutoLock autolock(lock_);
  DCHECK(frame);

  const base::TimeDelta zero = base::TimeDelta();
  base::TimeDelta time_remaining = max_time;
  while (time_remaining > zero && queue_map_.empty()) {
    // TODO(mdsteele): It appears from looking at the Chromium source code that
    // HighResNow() is "expensive" on Windows (how expensive, I am not sure);
    // however, the other options for getting a "now" time either don't
    // guarantee monotonicity (so time might go backwards) or might be too
    // low-resolution for our purposes, so I think we'd better stick with this
    // for now.  But is there a better way to do what we're doing here?
    const base::TimeTicks start = base::TimeTicks::HighResNow();
    condvar_.TimedWait(time_remaining);
    time_remaining -= base::TimeTicks::HighResNow() - start;
  }

  return InternalPop(frame);
}

bool SpdyFramePriorityQueue::InternalPop(net::SpdyFrameIR** frame) {
  lock_.AssertAcquired();
  DCHECK(frame);
  if (queue_map_.empty()) {
    return false;
  }
  // As an invariant, the lists in the queue map are never empty.  So get the
  // list of highest priority (smallest priority number) and pop the first
  // frame from it.
  QueueMap::iterator iter = queue_map_.begin();
  FrameList* list = iter->second;
  DCHECK(!list->empty());
  *frame = list->front();
  list->pop_front();
  // If the list is now empty, we have to delete it from the map to maintain
  // the invariant.
  if (list->empty()) {
    queue_map_.erase(iter);
    delete list;
  }
  return true;
}

}  // namespace mod_spdy
