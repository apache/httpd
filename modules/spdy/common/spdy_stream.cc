// Copyright 2010 Google Inc.
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

#include "mod_spdy/common/spdy_stream.h"


#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "mod_spdy/common/protocol_util.h"
#include "mod_spdy/common/shared_flow_control_window.h"
#include "mod_spdy/common/spdy_frame_priority_queue.h"
#include "mod_spdy/common/spdy_frame_queue.h"
#include "net/spdy/spdy_protocol.h"

namespace {

// The smallest WINDOW_UPDATE delta we're willing to send.  If the client sends
// us less than this much data, we wait for more data before sending a
// WINDOW_UPDATE frame (so that we don't end up sending lots of little ones).
const size_t kMinWindowUpdateSize =
    static_cast<size_t>(net::kSpdyStreamInitialWindowSize) / 8;

class DataLengthVisitor : public net::SpdyFrameVisitor {
 public:
  DataLengthVisitor() : length_(0) {}
  virtual ~DataLengthVisitor() {}

  size_t length() const { return length_; }

  virtual void VisitSynStream(const net::SpdySynStreamIR& frame) {}
  virtual void VisitSynReply(const net::SpdySynReplyIR& frame) {}
  virtual void VisitRstStream(const net::SpdyRstStreamIR& frame) {}
  virtual void VisitSettings(const net::SpdySettingsIR& frame) {}
  virtual void VisitPing(const net::SpdyPingIR& frame) {}
  virtual void VisitGoAway(const net::SpdyGoAwayIR& frame) {}
  virtual void VisitHeaders(const net::SpdyHeadersIR& frame) {}
  virtual void VisitWindowUpdate(const net::SpdyWindowUpdateIR& frame) {}
  virtual void VisitCredential(const net::SpdyCredentialIR& frame) {}
  virtual void VisitBlocked(const net::SpdyBlockedIR& frame) {}
  virtual void VisitPushPromise(const net::SpdyPushPromiseIR& frame) {}
  virtual void VisitData(const net::SpdyDataIR& frame) {
    length_ = frame.data().size();
  }

 private:
  size_t length_;

  DISALLOW_COPY_AND_ASSIGN(DataLengthVisitor);
};

// For data frames, return the size of the data payload; for control frames,
// return zero.
size_t DataFrameLength(const net::SpdyFrameIR& frame) {
  DataLengthVisitor visitor;
  frame.Visit(&visitor);
  return visitor.length();
}

}  // namespace

namespace mod_spdy {

SpdyStream::SpdyStream(spdy::SpdyVersion spdy_version,
                       net::SpdyStreamId stream_id,
                       net::SpdyStreamId associated_stream_id,
                       int32 server_push_depth,
                       net::SpdyPriority priority,
                       int32 initial_output_window_size,
                       SpdyFramePriorityQueue* output_queue,
                       SharedFlowControlWindow* shared_window,
                       SpdyServerPushInterface* pusher)
    : spdy_version_(spdy_version),
      stream_id_(stream_id),
      associated_stream_id_(associated_stream_id),
      server_push_depth_(server_push_depth),
      priority_(priority),
      output_queue_(output_queue),
      shared_window_(shared_window),
      pusher_(pusher),
      condvar_(&lock_),
      aborted_(false),
      output_window_size_(initial_output_window_size),
      // TODO(mdsteele): Make our initial input window size configurable (we
      //   would send the chosen value to the client with a SETTINGS frame).
      input_window_size_(net::kSpdyStreamInitialWindowSize),
      input_bytes_consumed_(0) {
  DCHECK_NE(spdy::SPDY_VERSION_NONE, spdy_version);
  DCHECK(output_queue_);
  DCHECK(shared_window_ || spdy_version < spdy::SPDY_VERSION_3_1);
  DCHECK(pusher_);
  DCHECK_GT(output_window_size_, 0);
  // In SPDY v2, priorities are in the range 0-3; in SPDY v3, they are 0-7.
  DCHECK_GE(priority, 0u);
  DCHECK_LE(priority, LowestSpdyPriorityForVersion(spdy_version));
}

SpdyStream::~SpdyStream() {}

bool SpdyStream::is_server_push() const {
  // By the SPDY spec, a stream has an even stream ID if and only if it was
  // initiated by the server.
  return stream_id_ % 2 == 0;
}

bool SpdyStream::is_aborted() const {
  base::AutoLock autolock(lock_);
  return aborted_;
}

void SpdyStream::AbortSilently() {
  base::AutoLock autolock(lock_);
  InternalAbortSilently();
}

void SpdyStream::AbortWithRstStream(net::SpdyRstStreamStatus status) {
  base::AutoLock autolock(lock_);
  InternalAbortWithRstStream(status);
}

int32 SpdyStream::current_input_window_size() const {
  base::AutoLock autolock(lock_);
  DCHECK_GE(spdy_version(), spdy::SPDY_VERSION_3);
  return input_window_size_;
}

int32 SpdyStream::current_output_window_size() const {
  base::AutoLock autolock(lock_);
  DCHECK_GE(spdy_version(), spdy::SPDY_VERSION_3);
  return output_window_size_;
}

void SpdyStream::OnInputDataConsumed(size_t size) {
  // Sanity check: there is no input data to absorb for a server push stream,
  // so we should only be getting called for client-initiated streams.
  DCHECK(!is_server_push());

  // Flow control only exists for SPDY v3 and up, so for SPDY v2 we don't need
  // to bother tracking this.
  if (spdy_version() < spdy::SPDY_VERSION_3) {
    return;
  }

  // If the size arg is zero, this method should be a no-op, so just quit now.
  if (size == 0) {
    return;
  }

  base::AutoLock autolock(lock_);

  // Don't bother with any of this if the stream has been aborted.
  if (aborted_) {
    return;
  }

  // First, if we're using SPDY/3.1 or later, we need to deal with the shared
  // session window.  If after consuming this input data the shared window
  // thinks it's time to send a WINDOW_UPDATE for the session input window
  // (stream 0), send one, at top priority.
  if (spdy_version_ >= spdy::SPDY_VERSION_3_1) {
    const int32 shared_window_update =
        shared_window_->OnInputDataConsumed(size);
    if (shared_window_update > 0) {
      output_queue_->Insert(
          SpdyFramePriorityQueue::kTopPriority,
          new net::SpdyWindowUpdateIR(0, shared_window_update));
    }
  }

  // Make sure the current input window size is sane.  Although there are
  // provisions in the SPDY spec that allow the window size to be temporarily
  // negative, or to go above its default initial size, with our current
  // implementation that should never happen.  Once we make the initial input
  // window size configurable, we may need to adjust or remove these checks.
  DCHECK_GE(input_window_size_, 0);
  DCHECK_LE(input_window_size_, net::kSpdyStreamInitialWindowSize);

  // Add the newly consumed data to the total.  Assuming our caller is behaving
  // well (even if the client isn't) -- that is, they are only consuming as
  // much data as we have put into the input queue -- there should be no
  // overflow here, and the new value should be at most the amount of
  // un-WINDOW_UPDATE-ed data we've received.  The reason we can be sure of
  // this is that PostInputFrame() refuses to put more data into the queue than
  // the window size allows, and aborts the stream if the client tries.
  input_bytes_consumed_ += size;
  DCHECK_GE(input_bytes_consumed_, size);
  DCHECK_LE(input_bytes_consumed_,
            static_cast<size_t>(net::kSpdyStreamInitialWindowSize -
                                input_window_size_));

  // We don't want to send lots of little WINDOW_UPDATE frames (as that would
  // waste bandwidth), so only bother sending one once it would have a
  // reasonably large value.
  // TODO(mdsteele): Consider also tracking whether we have received a FLAG_FIN
  //   on this stream; once we've gotten FLAG_FIN, there will be no more data,
  //   so we don't need to send any more WINDOW_UPDATE frames.
  if (input_bytes_consumed_ < kMinWindowUpdateSize) {
    return;
  }

  // The SPDY spec forbids sending WINDOW_UPDATE frames with a non-positive
  // delta-window-size (SPDY draft 3 section 2.6.8).  But since we already
  // checked above that size was positive, input_bytes_consumed_ should now be
  // positive as well.
  DCHECK_GT(input_bytes_consumed_, 0u);
  // Make sure there won't be any overflow shenanigans.
  COMPILE_ASSERT(sizeof(size_t) >= sizeof(net::kSpdyMaximumWindowSize),
                 size_t_is_at_least_32_bits);
  DCHECK_LE(input_bytes_consumed_,
            static_cast<size_t>(net::kSpdyMaximumWindowSize));

  // Send a WINDOW_UPDATE frame to the client and update our window size.
  SendOutputFrame(new net::SpdyWindowUpdateIR(
      stream_id_, input_bytes_consumed_));
  input_window_size_ += input_bytes_consumed_;
  DCHECK_LE(input_window_size_, net::kSpdyStreamInitialWindowSize);
  input_bytes_consumed_ = 0;
}

void SpdyStream::AdjustOutputWindowSize(int32 delta) {
  base::AutoLock autolock(lock_);

  // Flow control only exists for SPDY v3 and up.
  DCHECK_GE(spdy_version(), spdy::SPDY_VERSION_3);

  if (aborted_) {
    return;
  }

  // Check for overflow; if it happens, abort the stream (which will wake up
  // any blocked threads).  Note that although delta is usually positive, it
  // can also be negative, so we check for both overflow and underflow.
  const int64 new_size =
      static_cast<int64>(output_window_size_) + static_cast<int64>(delta);
  if (new_size > static_cast<int64>(net::kSpdyMaximumWindowSize) ||
      new_size < -static_cast<int64>(net::kSpdyMaximumWindowSize)) {
    LOG(WARNING) << "Flow control overflow/underflow on stream "
                 << stream_id_ << ".  Aborting stream.";
    InternalAbortWithRstStream(net::RST_STREAM_FLOW_CONTROL_ERROR);
    return;
  }

  // Update the window size.
  const int32 old_size = output_window_size_;
  output_window_size_ = static_cast<int32>(new_size);

  // If the window size is newly positive, wake up any blocked threads.
  if (old_size <= 0 && output_window_size_ > 0) {
    condvar_.Broadcast();
  }
}

void SpdyStream::PostInputFrame(net::SpdyFrameIR* frame_ptr) {
  base::AutoLock autolock(lock_);

  // Take ownership of the frame, so it will get deleted if we return early.
  scoped_ptr<net::SpdyFrameIR> frame(frame_ptr);

  // Once a stream has been aborted, nothing more goes into the queue.
  if (aborted_) {
    return;
  }

  // If this is a nonempty data frame (and we're using SPDY v3 or above) we
  // need to track flow control.
  if (spdy_version() >= spdy::SPDY_VERSION_3) {
    DCHECK_GE(input_window_size_, 0);
    const int size = DataFrameLength(*frame);  // returns zero for ctrl frames
    if (size > 0) {
      // If receiving this much data would overflow the window size, then abort
      // the stream with a flow control error.
      if (size > input_window_size_) {
        LOG(WARNING) << "Client violated flow control by sending too much data "
                     << "to stream " << stream_id_ << ".  Aborting stream.";
        InternalAbortWithRstStream(net::RST_STREAM_FLOW_CONTROL_ERROR);
        return;  // Quit without posting the frame to the queue.
      }
      // Otherwise, decrease the window size.  It will be increased again once
      // the data has been comsumed (by OnInputDataConsumed()).
      else {
        input_window_size_ -= size;
      }
    }
  }

  // Now that we've decreased the window size as necessary, we can make the
  // frame available for consumption by the stream thread.
  input_queue_.Insert(frame.release());
}

bool SpdyStream::GetInputFrame(bool block, net::SpdyFrameIR** frame) {
  return input_queue_.Pop(block, frame);
}

void SpdyStream::SendOutputSynStream(const net::SpdyHeaderBlock& headers,
                                     bool flag_fin) {
  DCHECK(is_server_push());
  base::AutoLock autolock(lock_);
  if (aborted_) {
    return;
  }

  scoped_ptr<net::SpdySynStreamIR> frame(new net::SpdySynStreamIR(stream_id_));
  frame->set_associated_to_stream_id(associated_stream_id_);
  frame->set_priority(priority_);
  frame->set_fin(flag_fin);
  frame->set_unidirectional(true);
  frame->GetMutableNameValueBlock()->insert(headers.begin(), headers.end());
  output_queue_->Insert(SpdyFramePriorityQueue::kTopPriority, frame.release());
}

void SpdyStream::SendOutputSynReply(const net::SpdyHeaderBlock& headers,
                                    bool flag_fin) {
  DCHECK(!is_server_push());
  base::AutoLock autolock(lock_);
  if (aborted_) {
    return;
  }

  scoped_ptr<net::SpdySynReplyIR> frame(new net::SpdySynReplyIR(stream_id_));
  frame->set_fin(flag_fin);
  frame->GetMutableNameValueBlock()->insert(headers.begin(), headers.end());
  SendOutputFrame(frame.release());
}

void SpdyStream::SendOutputHeaders(const net::SpdyHeaderBlock& headers,
                                   bool flag_fin) {
  base::AutoLock autolock(lock_);
  if (aborted_) {
    return;
  }

  scoped_ptr<net::SpdyHeadersIR> frame(new net::SpdyHeadersIR(stream_id_));
  frame->set_fin(flag_fin);
  frame->GetMutableNameValueBlock()->insert(headers.begin(), headers.end());
  SendOutputFrame(frame.release());
}

void SpdyStream::SendOutputDataFrame(base::StringPiece data, bool flag_fin) {
  base::AutoLock autolock(lock_);
  if (aborted_) {
    return;
  }

  // Flow control only exists for SPDY v3 and up; for SPDY v2, we can just send
  // the data without regard to the window size.  Even with flow control, we
  // can of course send empty DATA frames at will.
  if (spdy_version() < spdy::SPDY_VERSION_3 || data.empty()) {
    // Suppress empty DATA frames (unless we're setting FLAG_FIN).
    if (!data.empty() || flag_fin) {
      scoped_ptr<net::SpdyDataIR> frame(new net::SpdyDataIR(stream_id_, data));
      frame->set_fin(flag_fin);
      SendOutputFrame(frame.release());
    }
    return;
  }

  while (!data.empty()) {
    // If the current window size is non-positive, we must wait to send data
    // until the client increases it (or we abort).  Note that the window size
    // can be negative if the client decreased the maximum window size (with a
    // SETTINGS frame) after we already sent data (SPDY draft 3 section 2.6.8).
    while (!aborted_ && output_window_size_ <= 0) {
      condvar_.Wait();
    }
    if (aborted_) {
      return;
    }
    // If the current window size is less than the amount of data we'd like to
    // send, send a smaller data frame with the first part of the data, and
    // then we'll sleep until the window size is increased before sending the
    // rest.
    DCHECK_LE(data.size(), static_cast<size_t>(kint32max));
    const int32 full_length = data.size();
    DCHECK_GT(output_window_size_, 0);
    const int32 length_desired = std::min(full_length, output_window_size_);
    output_window_size_ -= length_desired;
    DCHECK_GE(output_window_size_, 0);
    // Now we need to request quota from the session-shared flow control
    // window.  Since the call to RequestQuota may block, we need to unlock
    // first.
    int32 length_acquired;
    if (spdy_version() >= spdy::SPDY_VERSION_3_1) {
      base::AutoUnlock autounlock(lock_);
      DCHECK(shared_window_);
      length_acquired = shared_window_->RequestOutputQuota(length_desired);
    } else {
      // For SPDY versions that don't have a session window, just act like we
      // got the quota we wanted.
      length_acquired = length_desired;
    }
    // RequestQuota will return zero if the shared window has been aborted
    // (i.e. if the session has been aborted).  So in that case let's just
    // abort too.
    if (length_acquired <= 0) {
      InternalAbortSilently();
      return;
    }
    // If we didn't acquire as much as we wanted from the shared window, put
    // the amount we're not actually using back into output_window_size_.
    else if (length_acquired < length_desired) {
      output_window_size_ += length_desired - length_acquired;
    }
    // Actually send the frame.
    scoped_ptr<net::SpdyDataIR> frame(
        new net::SpdyDataIR(stream_id_, data.substr(0, length_acquired)));
    frame->set_fin(flag_fin && length_acquired == full_length);
    SendOutputFrame(frame.release());
    data = data.substr(length_acquired);
  }
}

SpdyServerPushInterface::PushStatus SpdyStream::StartServerPush(
    net::SpdyPriority priority,
    const net::SpdyHeaderBlock& request_headers) {
  DCHECK_GE(spdy_version(), spdy::SPDY_VERSION_3);
  return pusher_->StartServerPush(stream_id_, server_push_depth_ + 1, priority,
                                  request_headers);
}

void SpdyStream::SendOutputFrame(net::SpdyFrameIR* frame) {
  lock_.AssertAcquired();
  DCHECK(!aborted_);
  output_queue_->Insert(static_cast<int>(priority_), frame);
}

void SpdyStream::InternalAbortSilently() {
  lock_.AssertAcquired();
  input_queue_.Abort();
  aborted_ = true;
  condvar_.Broadcast();
}

void SpdyStream::InternalAbortWithRstStream(net::SpdyRstStreamStatus status) {
  lock_.AssertAcquired();
  output_queue_->Insert(SpdyFramePriorityQueue::kTopPriority,
                        new net::SpdyRstStreamIR(stream_id_, status));
  // InternalAbortSilently will set aborted_ to true, which will prevent the
  // stream thread from sending any more frames on this stream after the
  // RST_STREAM.
  InternalAbortSilently();
}

}  // namespace mod_spdy
