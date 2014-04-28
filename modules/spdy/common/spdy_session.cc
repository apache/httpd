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

#include "mod_spdy/common/spdy_session.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/synchronization/lock.h"
#include "base/time/time.h"
#include "mod_spdy/common/protocol_util.h"
#include "mod_spdy/common/spdy_server_config.h"
#include "mod_spdy/common/spdy_session_io.h"
#include "mod_spdy/common/spdy_stream.h"
#include "mod_spdy/common/spdy_stream_task_factory.h"
#include "net/spdy/spdy_protocol.h"

namespace {

// Server push stream IDs must be even, and must fit in 31 bits (SPDY draft 3
// section 2.3.2).  Thus, this is the largest stream ID we can ever use for a
// pushed stream.
const net::SpdyStreamId kMaxServerPushStreamId = 0x7FFFFFFEu;

// Until the client informs us otherwise, we will assume a limit of 100 open
// push streams at a time.
const uint32 kInitMaxConcurrentPushes = 100u;

}  // namespace

namespace mod_spdy {

SpdySession::SpdySession(spdy::SpdyVersion spdy_version,
                         const SpdyServerConfig* config,
                         SpdySessionIO* session_io,
                         SpdyStreamTaskFactory* task_factory,
                         Executor* executor)
    : spdy_version_(spdy_version),
      config_(config),
      session_io_(session_io),
      task_factory_(task_factory),
      executor_(executor),
      framer_(SpdyVersionToFramerVersion(spdy_version), true),
      session_stopped_(false),
      already_sent_goaway_(false),
      last_client_stream_id_(0u),
      initial_window_size_(net::kSpdyStreamInitialWindowSize),
      max_concurrent_pushes_(kInitMaxConcurrentPushes),
      last_server_push_stream_id_(0u),
      received_goaway_(false),
      shared_window_(net::kSpdyStreamInitialWindowSize,
                     net::kSpdyStreamInitialWindowSize) {
  DCHECK_NE(spdy::SPDY_VERSION_NONE, spdy_version);
  framer_.set_visitor(this);
}

SpdySession::~SpdySession() {}

int32 SpdySession::current_shared_input_window_size() const {
  DCHECK_GE(spdy_version_, spdy::SPDY_VERSION_3_1);
  return shared_window_.current_input_window_size();
}

int32 SpdySession::current_shared_output_window_size() const {
  DCHECK_GE(spdy_version_, spdy::SPDY_VERSION_3_1);
  return shared_window_.current_output_window_size();
}

void SpdySession::Run() {
  // Send a SETTINGS frame when the connection first opens, to inform the
  // client of our MAX_CONCURRENT_STREAMS limit.
  SendSettingsFrame();

  // Initial amount time to block when waiting for output -- we start with
  // this, and as long as we fail to perform any input OR output, we increase
  // exponentially to the max, resetting when we succeed again.
  const base::TimeDelta kInitOutputBlockTime =
      base::TimeDelta::FromMilliseconds(1);
  // Maximum time to block when waiting for output.
  const base::TimeDelta kMaxOutputBlockTime =
      base::TimeDelta::FromMilliseconds(30);

  base::TimeDelta output_block_time = kInitOutputBlockTime;

  // Until we stop the session, or it is aborted by the client, alternate
  // between reading input from the client and (compressing and) sending output
  // frames that our stream threads have posted to the output queue.  This
  // basically amounts to a busy-loop, switching back and forth between input
  // and output, so we do our best to block when we can.  It would be far nicer
  // to have separate threads for input and output and have them always block;
  // unfortunately, we cannot do that, because in Apache the input and output
  // filter chains for a connection must be invoked by the same thread.
  while (!session_stopped_) {
    if (session_io_->IsConnectionAborted()) {
      LOG(WARNING) << "Master connection was aborted.";
      StopSession();
      break;
    }

    // Step 1: Read input from the client.
    {
      // Determine whether we should block until more input data is available.
      // For now, our policy is to block only if there is no pending output and
      // there are no currently-active streams (which might produce new
      // output).
      const bool should_block = StreamMapIsEmpty() && output_queue_.IsEmpty();

      // If there's no current output, and we can't create new streams (so
      // there will be no future output), then we should just shut down the
      // connection.
      if (should_block && already_sent_goaway_) {
        StopSession();
        break;
      }

      // Read available input data.  The SpdySessionIO will grab any
      // available data and push it into the SpdyFramer that we pass to it
      // here; the SpdyFramer, in turn, will call our OnControl and/or
      // OnStreamFrameData methods to report decoded frames.  If no input data
      // is currently available and should_block is true, this will block until
      // input becomes available (or the connection is closed).
      const SpdySessionIO::ReadStatus status =
          session_io_->ProcessAvailableInput(should_block, &framer_);
      if (status == SpdySessionIO::READ_SUCCESS) {
        // We successfully did some I/O, so reset the output block timeout.
        output_block_time = kInitOutputBlockTime;
      } else if (status == SpdySessionIO::READ_CONNECTION_CLOSED) {
        // The reading side of the connection has closed, so we won't be
        // reading anything more.  SPDY is transport-layer agnostic and not
        // TCP-specific; apparently, this means that there is no expectation
        // that we behave any differently for a half-closed connection than for
        // a fully-closed connection.  So if the reading side of the connection
        // closes, we're just going to shut down completely.
        //
        // But just in case the writing side is still open, let's try to send a
        // GOAWAY to let the client know we're shutting down gracefully.
        SendGoAwayFrame(net::GOAWAY_OK);
        // Now, shut everything down.
        StopSession();
      } else if (status == SpdySessionIO::READ_ERROR) {
        // There was an error during reading, so the session is corrupted and
        // we have no chance of reading anything more.
        //
        // We've probably already sent a GOAWAY with a PROTOCOL_ERROR by this
        // point, but if we haven't (perhaps the error was our fault?) then
        // send a GOAWAY now.  (If we've already sent a GOAWAY, then
        // SendGoAwayFrame is a no-op.)
        SendGoAwayFrame(net::GOAWAY_INTERNAL_ERROR);
        // Now, shut everything down.
        StopSession();
      } else {
        // Otherwise, there's simply no data available at the moment.
        DCHECK_EQ(SpdySessionIO::READ_NO_DATA, status);
      }
    }

    // Step 2: Send output to the client.
    if (!session_stopped_) {
      // If there are no active streams, then no new output can be getting
      // created right now, so we shouldn't block on output waiting for more.
      const bool no_active_streams = StreamMapIsEmpty();

      // Send any pending output, one frame at a time.  If there are any active
      // streams, we're willing to block briefly to wait for more frames to
      // send, if only to prevent this loop from busy-waiting too heavily --
      // not a great solution, but better than nothing for now.
      net::SpdyFrameIR* frame = NULL;
      if (no_active_streams ? output_queue_.Pop(&frame) :
          output_queue_.BlockingPop(output_block_time, &frame)) {
        do {
          SendFrame(frame);
        } while (!session_stopped_ && output_queue_.Pop(&frame));

        // We successfully did some I/O, so reset the output block timeout.
        output_block_time = kInitOutputBlockTime;
      } else {
        // The queue is currently empty; if no more streams can be created and
        // no more remain, we're done.
        if (already_sent_goaway_ && no_active_streams) {
          StopSession();
        } else {
          // There were no output frames within the timeout; so do an
          // exponential backoff by doubling output_block_time.
          output_block_time = std::min(kMaxOutputBlockTime,
                                       output_block_time * 2);
        }
      }
    }

    // TODO(mdsteele): What we really want to be able to do is to block until
    // *either* more input or more output is available.  Unfortunely, there's
    // no good way to query the input side (in Apache).  One possibility would
    // be to grab the input socket object (which we can do), and then arrange
    // to block until either the socket is ready to read OR our output queue is
    // nonempty (obviously we would abstract that away in SpdySessionIO),
    // but there's not even a nice way to do that (that I know of).
  }
}

SpdyServerPushInterface::PushStatus SpdySession::StartServerPush(
    net::SpdyStreamId associated_stream_id,
    int32 server_push_depth,
    net::SpdyPriority priority,
    const net::SpdyHeaderBlock& request_headers) {
  // Server push is pretty ill-defined in SPDY v2, so we require v3 or higher.
  DCHECK_GE(spdy_version(), spdy::SPDY_VERSION_3);

  // Grab the headers that we are required to send with the initial SYN_STREAM.
  const net::SpdyHeaderBlock::const_iterator host_iter =
      request_headers.find(spdy::kSpdy3Host);
  const net::SpdyHeaderBlock::const_iterator path_iter =
      request_headers.find(spdy::kSpdy3Path);
  const net::SpdyHeaderBlock::const_iterator scheme_iter =
      request_headers.find(spdy::kSpdy3Scheme);
  if (host_iter == request_headers.end() ||
      path_iter == request_headers.end() ||
      scheme_iter == request_headers.end()) {
    return SpdyServerPushInterface::INVALID_REQUEST_HEADERS;
  }
  const std::string& host_header = host_iter->second;
  const std::string& path_header = path_iter->second;
  const std::string& scheme_header = scheme_iter->second;

  StreamTaskWrapper* task_wrapper = NULL;
  {
    base::AutoLock autolock(stream_map_lock_);

    // If we've received a GOAWAY frame the client, we shouldn't create any new
    // streams on this session (SPDY draft 3 section 2.6.6).
    if (received_goaway_) {
      return SpdyServerPushInterface::CANNOT_PUSH_EVER_AGAIN;
    }

    // The associated stream must be active (SPDY draft 3 section 3.3.1).
    if (!stream_map_.IsStreamActive(associated_stream_id)) {
      return SpdyServerPushInterface::ASSOCIATED_STREAM_INACTIVE;
    }

    // Check if we're allowed to create new push streams right now (based on
    // the client SETTINGS_MAX_CONCURRENT_STREAMS).  Note that the number of
    // active push streams might be (temporarily) greater than the max, if the
    // client lowered the max after we already started a bunch of pushes.
    if (stream_map_.NumActivePushStreams() >= max_concurrent_pushes_) {
      return SpdyServerPushInterface::TOO_MANY_CONCURRENT_PUSHES;
    }

    // In the unlikely event that the session stays open so long that we run
    // out of server push stream IDs, we may not do any more pushes on this
    // session (SPDY draft 3 section 2.3.2).
    DCHECK_LE(last_server_push_stream_id_, kMaxServerPushStreamId);
    if (last_server_push_stream_id_ >= kMaxServerPushStreamId) {
      return SpdyServerPushInterface::CANNOT_PUSH_EVER_AGAIN;
    }
    // Server push stream IDs must be even (SPDY draft 3 section 2.3.2).  So
    // each time we do a push, we increment last_server_push_stream_id_ by two.
    DCHECK_EQ(last_server_push_stream_id_ % 2u, 0u);
    last_server_push_stream_id_ += 2u;
    const net::SpdyStreamId stream_id = last_server_push_stream_id_;
    // Only the server can create even stream IDs, and we never use the same
    // one twice, so our chosen stream_id should definitely not be in use.
    if (stream_map_.IsStreamActive(stream_id)) {
      LOG(DFATAL) << "Next server push stream ID already in use: "
                  << stream_id;
      return SpdyServerPushInterface::PUSH_INTERNAL_ERROR;
    }

    // Create task and add it to the stream map.
    task_wrapper = new StreamTaskWrapper(
        this, stream_id, associated_stream_id, server_push_depth, priority);
    stream_map_.AddStreamTask(task_wrapper);
    net::SpdySynStreamIR* frame = new net::SpdySynStreamIR(stream_id);
    frame->set_associated_to_stream_id(associated_stream_id);
    frame->set_priority(priority);
    frame->set_fin(true);
    frame->GetMutableNameValueBlock()->insert(
        request_headers.begin(), request_headers.end());
    task_wrapper->stream()->PostInputFrame(frame);

    // Send initial SYN_STREAM to the client.  It only needs to contain the
    // ":host", ":path", and ":scheme" headers; the rest can follow in a later
    // HEADERS frame (SPDY draft 3 section 3.3.1).
    net::SpdyHeaderBlock initial_response_headers;
    initial_response_headers[spdy::kSpdy3Host] = host_header;
    initial_response_headers[spdy::kSpdy3Path] = path_header;
    initial_response_headers[spdy::kSpdy3Scheme] = scheme_header;
    task_wrapper->stream()->SendOutputSynStream(
        initial_response_headers, false);

    VLOG(2) << "Starting server push; opening stream " << stream_id;
  }
  if (task_wrapper == NULL) {
    LOG(DFATAL) << "Can't happen: task_wrapper is NULL";
    return SpdyServerPushInterface::PUSH_INTERNAL_ERROR;
  }
  executor_->AddTask(task_wrapper, priority);
  return SpdyServerPushInterface::PUSH_STARTED;
}

void SpdySession::OnError(net::SpdyFramer::SpdyError error_code) {
  LOG(ERROR) << "Session error: "
             << net::SpdyFramer::ErrorCodeToString(error_code);
  SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
}

void SpdySession::OnStreamError(net::SpdyStreamId stream_id,
                                const std::string& description) {
  LOG(ERROR) << "Stream " << stream_id << " error: " << description;
  AbortStream(stream_id, net::RST_STREAM_PROTOCOL_ERROR);
}

void SpdySession::OnStreamFrameData(
    net::SpdyStreamId stream_id, const char* data, size_t length, bool fin) {
  // First check the shared input flow control window (for SPDY/3.1 and up).
  if (spdy_version_ >= spdy::SPDY_VERSION_3_1) {
    if (!shared_window_.OnReceiveInputData(length)) {
      LOG(ERROR) << "Client violated flow control by sending too much data "
                 << "to session.  Sending GOAWAY.";
      SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
      StopSession();
      return;
    }
  }

  // Look up the stream to post the data to.  We need to lock when reading the
  // stream map, because one of the stream threads could call
  // RemoveStreamTask() at any time.
  {
    base::AutoLock autolock(stream_map_lock_);
    SpdyStream* stream = stream_map_.GetStream(stream_id);
    if (stream != NULL) {
      VLOG(4) << "[stream " << stream_id << "] Received DATA (length="
              << length << ")";
      // Copy the data into an _uncompressed_ SPDY data frame and post it to
      // the stream's input queue.
      // Note that we must still be holding stream_map_lock_ when we call this
      // method -- otherwise the stream may be deleted out from under us by the
      // StreamTaskWrapper destructor.  That's okay -- PostInputFrame is a
      // quick operation and won't block (for any appreciable length of time).
      net::SpdyDataIR* frame =
          new net::SpdyDataIR(stream_id, base::StringPiece(data, length));
      frame->set_fin(fin);
      stream->PostInputFrame(frame);
      return;
    }
  }

  // If we reach this point, it means that the client has sent us DATA for a
  // stream that doesn't exist (possibly because it used to exist but has
  // already been closed by a FLAG_FIN); *unless* length=0, which is just the
  // BufferedSpdyFramer's way of telling us that there will be no more data on
  // this stream (i.e. because a FLAG_FIN has been received, possibly on a
  // previous control frame).

  // TODO(mdsteele): The BufferedSpdyFramer sends us OnStreamFrameData with
  // length=0 to indicate end-of-stream, but it will do this even if we already
  // got FLAG_FIN in a control frame (such as SYN_STREAM).  For now, we fix
  // this issue by simply ignoring length=0 data for streams that no longer
  // exist.  Once we transition to the new plain SpdyFramer, we'll be able to
  // handle this more precisely.
  if (length == 0) {
    return;
  }

  // If the client sends data for a nonexistant stream, we must send a
  // RST_STREAM frame with error code INVALID_STREAM (SPDY draft 2 section
  // 2.4).  Note that we release the mutex *before* sending the frame.
  LOG(WARNING) << "Client sent DATA (length=" << length
               << ") for nonexistant stream " << stream_id;
  SendRstStreamFrame(stream_id, net::RST_STREAM_INVALID_STREAM);
}

void SpdySession::OnSynStream(
    net::SpdyStreamId stream_id,
    net::SpdyStreamId associated_stream_id,
    net::SpdyPriority priority,
    uint8 credential_slot,
    bool fin,
    bool unidirectional,
    const net::SpdyHeaderBlock& headers) {
  // The SPDY spec requires us to ignore SYN_STREAM frames after sending a
  // GOAWAY frame (SPDY draft 3 section 2.6.6).
  if (already_sent_goaway_) {
    return;
  }

  // Client stream IDs must be odd-numbered.
  if (stream_id % 2 == 0) {
    LOG(WARNING) << "Client sent SYN_STREAM for even stream ID (" << stream_id
                 << ").  Sending GOAWAY.";
    SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
    return;
  }

  // Client stream IDs must be strictly increasing (SPDY draft 2 section
  // 2.5.1).
  if (stream_id <= last_client_stream_id_) {
    LOG(WARNING) << "Client sent SYN_STREAM for non-increasing stream ID ("
                 << stream_id << " after " << last_client_stream_id_
                 << ").";  //  Aborting stream.";
#if 0
    // TODO(mdsteele): re-enable this code block when
    // http://code.google.com/p/chromium/issues/detail?id=111708 is
    // fixed.
    AbortStream(stream_id, net::PROTOCOL_ERROR);
    return;
#endif
  }

  StreamTaskWrapper* task_wrapper = NULL;
  {
    // Lock the stream map before we start checking its size or adding a new
    // stream to it.  We need to lock when touching the stream map, because one
    // of the stream threads could call RemoveStreamTask() at any time.
    base::AutoLock autolock(stream_map_lock_);

#if 0
    // TODO(mdsteele): re-enable this code block when
    // http://code.google.com/p/chromium/issues/detail?id=111708 is
    // fixed.

    // We already checked that stream_id > last_client_stream_id_, so there
    // definitely shouldn't already be a stream with this ID in the map.
    DCHECK(!stream_map_.IsStreamActive(stream_id));
#else
    if (stream_map_.IsStreamActive(stream_id)) {
      SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
      return;
    }
#endif

    // Limit the number of simultaneous open streams the client can create;
    // refuse the stream if there are too many currently active (non-push)
    // streams.
    if (static_cast<int>(stream_map_.NumActiveClientStreams()) >=
        config_->max_streams_per_connection()) {
      SendRstStreamFrame(stream_id, net::RST_STREAM_REFUSED_STREAM);
      return;
    }

    // Initiate a new stream.
    last_client_stream_id_ = std::max(last_client_stream_id_, stream_id);
    task_wrapper = new StreamTaskWrapper(
        this, stream_id, associated_stream_id,
        0, // server_push_depth = 0
        priority);
    stream_map_.AddStreamTask(task_wrapper);
    net::SpdySynStreamIR* frame = new net::SpdySynStreamIR(stream_id);
    frame->set_associated_to_stream_id(associated_stream_id);
    frame->set_priority(priority);
    frame->set_slot(credential_slot);
    frame->set_fin(fin);
    frame->set_unidirectional(unidirectional);
    frame->GetMutableNameValueBlock()->insert(headers.begin(), headers.end());
    task_wrapper->stream()->PostInputFrame(frame);
  }
  DCHECK(task_wrapper);
  // Release the lock before adding the task to the executor.  This is mostly
  // for the benefit of unit tests, for which calling AddTask will execute the
  // task immediately (and we don't want to be holding the lock when that
  // happens).  Note that it's safe for us to pass task_wrapper here without
  // holding the lock, because the task won't get deleted before it's been
  // added to the executor.
  VLOG(2) << "Received SYN_STREAM; opening stream " << stream_id;
  executor_->AddTask(task_wrapper, priority);
}

void SpdySession::OnSynReply(net::SpdyStreamId stream_id,
                             bool fin,
                             const net::SpdyHeaderBlock& headers) {
  // TODO(mdsteele)
}

void SpdySession::OnRstStream(net::SpdyStreamId stream_id,
                              net::SpdyRstStreamStatus status) {
  switch (status) {
    // These are totally benign reasons to abort a stream, so just abort the
    // stream without a fuss.
    case net::RST_STREAM_REFUSED_STREAM:
    case net::RST_STREAM_CANCEL:
      VLOG(2) << "Client cancelled/refused stream " << stream_id;
      AbortStreamSilently(stream_id);
      break;
    // If there was an error, abort the stream, but log a warning first.
    // TODO(mdsteele): Should we have special behavior for different kinds of
    //   errors?
    default:
      LOG(WARNING) << "Client sent RST_STREAM with "
                   << RstStreamStatusCodeToString(status)
                   << " for stream " << stream_id << ".  Aborting stream.";
      AbortStreamSilently(stream_id);
      break;
  }
}

void SpdySession::OnSettings(bool clear_persisted) {
  // Do nothing; we never persist values, so we don't need to pay attention to
  // this flag.
}

void SpdySession::OnSetting(net::SpdySettingsIds id,
                            uint8 flags, uint32 value) {
  VLOG(4) << "Received SETTING (flags=" << flags << "): "
          << SettingsIdToString(id) << "=" << value;
  switch (id) {
    case net::SETTINGS_MAX_CONCURRENT_STREAMS:
      max_concurrent_pushes_ = value;
      break;
    case net::SETTINGS_INITIAL_WINDOW_SIZE:
      // Flow control only exists for SPDY v3 and up.
      if (spdy_version() < spdy::SPDY_VERSION_3) {
        LOG(ERROR) << "Client sent INITIAL_WINDOW_SIZE setting over "
                   << "SPDY/" << SpdyVersionNumberString(spdy_version())
                   << ".  Sending GOAWAY.";
        SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
      } else {
        SetInitialWindowSize(value);
      }
      break;
    case net::SETTINGS_UPLOAD_BANDWIDTH:
    case net::SETTINGS_DOWNLOAD_BANDWIDTH:
    case net::SETTINGS_ROUND_TRIP_TIME:
    case net::SETTINGS_CURRENT_CWND:
    case net::SETTINGS_DOWNLOAD_RETRANS_RATE:
      // Ignore other settings for now.
      break;
    default:
      LOG(ERROR) << "Client sent invalid SETTINGS id (" << id
                 << ").  Sending GOAWAY.";
      SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
      break;
  }
}

void SpdySession::OnPing(uint32 unique_id) {
  VLOG(4) << "Received PING frame (id=" << unique_id << ")";
  // The SPDY spec requires the server to ignore even-numbered PING frames that
  // it did not initiate (SPDY draft 3 section 2.6.5), and right now, we never
  // initiate pings.
  if (unique_id % 2 == 0) {
    return;
  }

  // Any odd-numbered PING frame we receive was initiated by the client, and
  // should be echoed back _immediately_ (SPDY draft 2 section 2.7.6).
  SendFrame(new net::SpdyPingIR(unique_id));
}

void SpdySession::OnGoAway(net::SpdyStreamId last_accepted_stream_id,
                           net::SpdyGoAwayStatus status) {
  VLOG(4) << "Received GOAWAY frame (status="
          << GoAwayStatusCodeToString(status) << ", last_accepted_stream_id="
          << last_accepted_stream_id << ")";

  // Take note that we have received a GOAWAY frame; we should not start any
  // new server push streams on this session.
  {
    base::AutoLock autolock(stream_map_lock_);
    received_goaway_ = true;
  }

  // If this was not a normal shutdown (GOAWAY_OK), we should probably log a
  // warning to let the user know something's up.
  switch (status) {
    case net::GOAWAY_OK:
      break;
    case net::GOAWAY_PROTOCOL_ERROR:
      LOG(WARNING) << "Client sent GOAWAY with PROTOCOL_ERROR.  Possibly we "
                   << "did something wrong?";
      break;
    case net::GOAWAY_INTERNAL_ERROR:
      LOG(WARNING) << "Client sent GOAWAY with INTERNAL_ERROR.  Apparently "
                   << "they're broken?";
      break;
    default:
      LOG(ERROR) << "Client sent GOAWAY with invalid status code ("
                 << status << ").  Sending GOAWAY.";
      SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
      break;
  }
}

void SpdySession::OnHeaders(net::SpdyStreamId stream_id,
                            bool fin,
                            const net::SpdyHeaderBlock& headers) {
  // Look up the stream to post the data to.  We need to lock when reading the
  // stream map, because one of the stream threads could call
  // RemoveStreamTask() at any time.
  {
    // TODO(mdsteele): This is pretty similar to the code in OnStreamFrameData.
    //   Maybe we can factor it out?
    base::AutoLock autolock(stream_map_lock_);
    SpdyStream* stream = stream_map_.GetStream(stream_id);
    if (stream != NULL) {
      VLOG(4) << "[stream " << stream_id << "] Received HEADERS frame";
      net::SpdySynStreamIR* frame = new net::SpdySynStreamIR(stream_id);
      frame->set_fin(true);
      frame->GetMutableNameValueBlock()->insert(
          headers.begin(), headers.end());
      stream->PostInputFrame(frame);
      return;
    }
  }

  // Note that we release the mutex *before* sending the frame.
  LOG(WARNING) << "Client sent HEADERS for nonexistant stream " << stream_id;
  SendRstStreamFrame(stream_id, net::RST_STREAM_INVALID_STREAM);
}

void SpdySession::OnPushPromise(net::SpdyStreamId stream_id,
                                net::SpdyStreamId promised_stream_id) {
  LOG(ERROR) << "Got a PUSH_PROMISE(" << stream_id << ", "
             << promised_stream_id << ") frame from the client.";
  SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
}

void SpdySession::OnWindowUpdate(net::SpdyStreamId stream_id,
                                 uint32 delta_window_size) {
  // Flow control only exists for SPDY/3 and up.
  if (spdy_version() < spdy::SPDY_VERSION_3) {
    LOG(ERROR) << "Got a WINDOW_UPDATE frame over SPDY/"
               << SpdyVersionNumberString(spdy_version());
    SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
    return;
  }

  // Stream zero is special; starting in SPDY/3.1, it represents the
  // session-wide flow control window.  For previous versions, it is invalid.
  if (stream_id == 0) {
    if (spdy_version() >= spdy::SPDY_VERSION_3_1) {
      if (!shared_window_.IncreaseOutputWindowSize(delta_window_size)) {
        LOG(ERROR) << "Got a WINDOW_UPDATE frame that overflows session "
                   << "window.  Sending GOAWAY.";
        SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
        StopSession();
      }
    } else {
      LOG(ERROR) << "Got a WINDOW_UPDATE frame for stream 0 over SPDY/"
                 << SpdyVersionNumberString(spdy_version());
      SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
      StopSession();
    }
    return;
  }

  base::AutoLock autolock(stream_map_lock_);
  SpdyStream* stream = stream_map_.GetStream(stream_id);
  if (stream == NULL) {
    // We must ignore WINDOW_UPDATE frames for closed streams (SPDY draft 3
    // section 2.6.8).
    return;
  }

  VLOG(4) << "[stream " << stream_id << "] Received WINDOW_UPDATE("
          << delta_window_size << ") frame";
  stream->AdjustOutputWindowSize(delta_window_size);
}

void SpdySession::SetInitialWindowSize(uint32 new_init_window_size) {
  // Flow control only exists for SPDY v3 and up.  We shouldn't be calling this
  // method for SPDY v2.
  if (spdy_version() < spdy::SPDY_VERSION_3) {
    LOG(DFATAL) << "SetInitialWindowSize called for SPDY/"
                << SpdyVersionNumberString(spdy_version());
    return;
  }

  // Validate the new window size; it must be positive, but at most int32max.
  if (new_init_window_size == 0 ||
      new_init_window_size >
      static_cast<uint32>(net::kSpdyMaximumWindowSize)) {
    LOG(WARNING) << "Client sent invalid init window size ("
                 << new_init_window_size << ").  Sending GOAWAY.";
    SendGoAwayFrame(net::GOAWAY_PROTOCOL_ERROR);
    return;
  }
  // Sanity check that our current init window size is positive.  It's a signed
  // int32, so we know it's no more than int32max.
  DCHECK_GT(initial_window_size_, 0);
  // We can now be sure that this subtraction won't overflow/underflow.
  const int32 delta =
      static_cast<int32>(new_init_window_size) - initial_window_size_;

  // Set the initial window size for new streams.
  initial_window_size_ = new_init_window_size;
  // We also have to adjust the window size of all currently active streams by
  // the delta (SPDY draft 3 section 2.6.8).
  base::AutoLock autolock(stream_map_lock_);
  stream_map_.AdjustAllOutputWindowSizes(delta);
}

// Compress (if necessary), send, and then delete the given frame object.
void SpdySession::SendFrame(const net::SpdyFrameIR* frame_ptr) {
  scoped_ptr<const net::SpdyFrameIR> frame(frame_ptr);
  scoped_ptr<const net::SpdySerializedFrame> serialized_frame(
      framer_.SerializeFrame(*frame));
  if (serialized_frame == NULL) {
    LOG(DFATAL) << "frame compression failed";
    StopSession();
    return;
  }
  SendFrameRaw(*serialized_frame);
}

void SpdySession::SendFrameRaw(const net::SpdySerializedFrame& frame) {
  const SpdySessionIO::WriteStatus status = session_io_->SendFrameRaw(frame);
  if (status == SpdySessionIO::WRITE_CONNECTION_CLOSED) {
    // If the connection was closed and we can't write anything to the client
    // anymore, then there's little point in continuing with the session.
    StopSession();
  } else {
    DCHECK_EQ(SpdySessionIO::WRITE_SUCCESS, status);
  }
}

void SpdySession::SendGoAwayFrame(net::SpdyGoAwayStatus status) {
  if (!already_sent_goaway_) {
    already_sent_goaway_ = true;
    SendFrame(new net::SpdyGoAwayIR(last_client_stream_id_, status));
  }
}

void SpdySession::SendRstStreamFrame(net::SpdyStreamId stream_id,
                                     net::SpdyRstStreamStatus status) {
  output_queue_.Insert(SpdyFramePriorityQueue::kTopPriority,
                       new net::SpdyRstStreamIR(stream_id, status));
}

void SpdySession::SendSettingsFrame() {
  scoped_ptr<net::SpdySettingsIR> settings(new net::SpdySettingsIR);
  settings->AddSetting(net::SETTINGS_MAX_CONCURRENT_STREAMS,
                       false, false, config_->max_streams_per_connection());
  SendFrame(settings.release());
}

void SpdySession::StopSession() {
  session_stopped_ = true;
  // Abort all remaining streams.  We need to lock when reading the stream
  // map, because one of the stream threads could call RemoveStreamTask() at
  // any time.
  {
    base::AutoLock autolock(stream_map_lock_);
    stream_map_.AbortAllSilently();
  }
  shared_window_.Abort();
  // Stop all stream threads and tasks for this SPDY session.  This will
  // block until all currently running stream tasks have exited, but since we
  // just aborted all streams, that should hopefully happen fairly soon.  Note
  // that we must release the lock before calling this, because each stream
  // will remove itself from the stream map as it shuts down.
  executor_->Stop();
}

// Abort the stream without sending anything to the client.
void SpdySession::AbortStreamSilently(net::SpdyStreamId stream_id) {
  // We need to lock when reading the stream map, because one of the stream
  // threads could call RemoveStreamTask() at any time.
  base::AutoLock autolock(stream_map_lock_);
  SpdyStream* stream = stream_map_.GetStream(stream_id);
  if (stream != NULL) {
    stream->AbortSilently();
  }
}

// Send a RST_STREAM frame and then abort the stream.
void SpdySession::AbortStream(net::SpdyStreamId stream_id,
                              net::SpdyRstStreamStatus status) {
  SendRstStreamFrame(stream_id, status);
  AbortStreamSilently(stream_id);
}

// Remove the StreamTaskWrapper from the stream map.  This is the only method
// of SpdySession that is ever called by another thread (specifically, it is
// called by the StreamTaskWrapper destructor, which is called by the executor,
// which presumably uses worker threads) -- it is because of this that we must
// lock the stream_map_lock_ whenever we touch the stream map or its contents.
void SpdySession::RemoveStreamTask(StreamTaskWrapper* task_wrapper) {
  // We need to lock when touching the stream map, in case the main connection
  // thread is currently in the middle of reading the stream map.
  base::AutoLock autolock(stream_map_lock_);
  VLOG(2) << "Closing stream " << task_wrapper->stream()->stream_id();
  stream_map_.RemoveStreamTask(task_wrapper);
}

bool SpdySession::StreamMapIsEmpty() {
  base::AutoLock autolock(stream_map_lock_);
  return stream_map_.IsEmpty();
}

// This constructor is always called by the main connection thread, so we're
// safe to call spdy_session_->task_factory_->NewStreamTask().  However,
// the other methods of this class (Run(), Cancel(), and the destructor) are
// liable to be called from other threads by the executor.
SpdySession::StreamTaskWrapper::StreamTaskWrapper(
    SpdySession* spdy_session,
    net::SpdyStreamId stream_id,
    net::SpdyStreamId associated_stream_id,
    int32 server_push_depth,
    net::SpdyPriority priority)
    : spdy_session_(spdy_session),
      stream_(spdy_session->spdy_version(), stream_id, associated_stream_id,
              server_push_depth, priority, spdy_session_->initial_window_size_,
              &spdy_session_->output_queue_, &spdy_session_->shared_window_,
              spdy_session_),
      subtask_(spdy_session_->task_factory_->NewStreamTask(&stream_)) {
  CHECK(subtask_);
}

SpdySession::StreamTaskWrapper::~StreamTaskWrapper() {
  // Remove this object from the SpdySession's stream map.
  spdy_session_->RemoveStreamTask(this);
}

void SpdySession::StreamTaskWrapper::Run() {
  subtask_->CallRun();
}

void SpdySession::StreamTaskWrapper::Cancel() {
  subtask_->CallCancel();
}

SpdySession::SpdyStreamMap::SpdyStreamMap()
    : num_active_push_streams_(0u) {}

SpdySession::SpdyStreamMap::~SpdyStreamMap() {}

bool SpdySession::SpdyStreamMap::IsEmpty() {
  DCHECK_LE(num_active_push_streams_, tasks_.size());
  return tasks_.empty();
}

size_t SpdySession::SpdyStreamMap::NumActiveClientStreams() {
  DCHECK_LE(num_active_push_streams_, tasks_.size());
  return tasks_.size() - num_active_push_streams_;
}

size_t SpdySession::SpdyStreamMap::NumActivePushStreams() {
  DCHECK_LE(num_active_push_streams_, tasks_.size());
  return num_active_push_streams_;
}

bool SpdySession::SpdyStreamMap::IsStreamActive(net::SpdyStreamId stream_id) {
  return tasks_.count(stream_id) > 0u;
}

void SpdySession::SpdyStreamMap::AddStreamTask(
    StreamTaskWrapper* task_wrapper) {
  DCHECK(task_wrapper);
  SpdyStream* stream = task_wrapper->stream();
  DCHECK(stream);
  net::SpdyStreamId stream_id = stream->stream_id();
  DCHECK_EQ(0u, tasks_.count(stream_id));
  tasks_[stream_id] = task_wrapper;
  if (stream->is_server_push()) {
    ++num_active_push_streams_;
  }
  DCHECK_LE(num_active_push_streams_, tasks_.size());
}

void SpdySession::SpdyStreamMap::RemoveStreamTask(
    StreamTaskWrapper* task_wrapper) {
  DCHECK(task_wrapper);
  SpdyStream* stream = task_wrapper->stream();
  DCHECK(stream);
  net::SpdyStreamId stream_id = stream->stream_id();
  DCHECK_EQ(1u, tasks_.count(stream_id));
  DCHECK_EQ(task_wrapper, tasks_[stream_id]);
  if (stream->is_server_push()) {
    DCHECK_GT(num_active_push_streams_, 0u);
    --num_active_push_streams_;
  }
  tasks_.erase(stream_id);
  DCHECK_LE(num_active_push_streams_, tasks_.size());
}

SpdyStream* SpdySession::SpdyStreamMap::GetStream(
    net::SpdyStreamId stream_id) {
  TaskMap::const_iterator iter = tasks_.find(stream_id);
  if (iter == tasks_.end()) {
    return NULL;
  }
  StreamTaskWrapper* task_wrapper = iter->second;
  DCHECK(task_wrapper);
  SpdyStream* stream = task_wrapper->stream();
  DCHECK(stream);
  DCHECK_EQ(stream_id, stream->stream_id());
  return stream;
}

void SpdySession::SpdyStreamMap::AdjustAllOutputWindowSizes(int32 delta) {
  for (TaskMap::const_iterator iter = tasks_.begin();
       iter != tasks_.end(); ++iter) {
    iter->second->stream()->AdjustOutputWindowSize(delta);
  }
}

void SpdySession::SpdyStreamMap::AbortAllSilently() {
  for (TaskMap::const_iterator iter = tasks_.begin();
       iter != tasks_.end(); ++iter) {
    iter->second->stream()->AbortSilently();
  }
}

}  // namespace mod_spdy
