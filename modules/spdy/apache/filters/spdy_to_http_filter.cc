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

#include "mod_spdy/apache/filters/spdy_to_http_filter.h"

#include <map>
#include <string>

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "mod_spdy/common/spdy_stream.h"
#include "mod_spdy/common/spdy_to_http_converter.h"
#include "net/spdy/spdy_frame_builder.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"

namespace {

// If, during an AP_MODE_GETLINE read, we pull in this much data (or more)
// without seeing a linebreak, just give up and return what we have.
const size_t kGetlineThreshold = 4096;

}  // namespace

namespace mod_spdy {

SpdyToHttpFilter::SpdyToHttpFilter(SpdyStream* stream)
    : stream_(stream),
      visitor_(&data_buffer_),
      converter_(stream_->spdy_version(), &visitor_),
      next_read_start_(0) {
  DCHECK(stream_ != NULL);
}

SpdyToHttpFilter::~SpdyToHttpFilter() {}

// Macro to check if the SPDY stream has been aborted; if so, mark the
// connection object as having been aborted and return APR_ECONNABORTED.
// Hopefully, this will convince Apache to shut down processing for this
// (slave) connection, thus allowing this stream's thread to complete and exit.
//
// As an extra measure, we also insert an EOS bucket into the brigade before
// returning.  This idea comes from ssl_io_filter_input() in ssl_engine_io.c in
// mod_ssl, which does so with the following comment: "Ok, if we aborted, we
// ARE at the EOS.  We also have aborted.  This 'double protection' is probably
// redundant, but also effective against just about anything."
#define RETURN_IF_STREAM_ABORT(filter, brigade)                         \
  do {                                                                  \
    if ((filter)->c->aborted || stream_->is_aborted()) {                \
      (filter)->c->aborted = true;                                      \
      APR_BRIGADE_INSERT_TAIL(                                          \
          (brigade), apr_bucket_eos_create((filter)->c->bucket_alloc)); \
      return APR_ECONNABORTED;                                          \
    }                                                                   \
  } while (false)

apr_status_t SpdyToHttpFilter::Read(ap_filter_t *filter,
                                    apr_bucket_brigade *brigade,
                                    ap_input_mode_t mode,
                                    apr_read_type_e block,
                                    apr_off_t readbytes) {
  // Turn readbytes into a size_t to avoid the need for static_casts below.  To
  // avoid any surprises (in cases where apr_off_t is signed), clamp it to a
  // non-negative value first.
  const size_t max_bytes = std::max(static_cast<apr_off_t>(0), readbytes);

  // This is a NETWORK-level filter, so there shouldn't be any filter after us.
  if (filter->next != NULL) {
    LOG(WARNING) << "SpdyToHttpFilter is not the last filter in the chain "
                 << "(it is followed by " << filter->next->frec->name << ")";
  }

  // Clear any buffer data that was already returned on a previous invocation
  // of this filter.
  if (next_read_start_ > 0) {
    data_buffer_.erase(0, next_read_start_);
    next_read_start_ = 0;
  }

  // We don't need to do anything for AP_MODE_INIT.  (We check this case before
  // checking for EOF, becuase that's what ap_core_input_filter() in
  // core_filters.c does.)
  if (mode == AP_MODE_INIT) {
    return APR_SUCCESS;
  }

  // If there will never be any more data on this stream, return EOF.  (That's
  // what ap_core_input_filter() in core_filters.c does.)
  if (end_of_stream_reached() && data_buffer_.empty()) {
    return APR_EOF;
  }

  // Check if this SPDY stream has been aborted, and if so, quit.  We will also
  // check for aborts just after each time we call GetNextFrame (that's a good
  // time to check, since a stream abort can interrupt a blocking call to
  // GetNextFrame).
  RETURN_IF_STREAM_ABORT(filter, brigade);

  // Keep track of how much data, if any, we should place into the brigade.
  size_t bytes_read = 0;

  // For AP_MODE_READBYTES and AP_MODE_SPECULATIVE, we try to read the quantity
  // of bytes we are asked for.  For AP_MODE_EXHAUSTIVE, we read as much as
  // possible.
  if (mode == AP_MODE_READBYTES || mode == AP_MODE_SPECULATIVE ||
      mode == AP_MODE_EXHAUSTIVE) {
    // Try to get as much data as we were asked for.
    while (max_bytes > data_buffer_.size() || mode == AP_MODE_EXHAUSTIVE) {
      const bool got_frame = GetNextFrame(block);
      RETURN_IF_STREAM_ABORT(filter, brigade);
      if (!got_frame) {
        break;
      }
    }

    // Return however much data we read, but no more than they asked for.
    bytes_read = data_buffer_.size();
    if (mode != AP_MODE_EXHAUSTIVE && max_bytes < bytes_read) {
      bytes_read = max_bytes;
    }
  }
  // For AP_MODE_GETLINE, try to return a full text line of data.
  else if (mode == AP_MODE_GETLINE) {
    // Try to find the first linebreak in the remaining data stream.
    size_t linebreak = std::string::npos;
    size_t start = 0;
    while (true) {
      linebreak = data_buffer_.find('\n', start);
      // Stop if we find a linebreak, or if we've pulled too much data already.
      if (linebreak != std::string::npos ||
          data_buffer_.size() >= kGetlineThreshold) {
        break;
      }
      // Remember where we left off so we don't have to re-scan the whole
      // buffer on the next iteration.
      start = data_buffer_.size();
      // We haven't seen a linebreak yet, so try to get more data.
      const bool got_frame = GetNextFrame(block);
      RETURN_IF_STREAM_ABORT(filter, brigade);
      if (!got_frame) {
        break;
      }
    }

    // If we found a linebreak, return data up to and including that linebreak.
    // Otherwise, just send whatever we were able to get.
    bytes_read = (linebreak == std::string::npos ?
                  data_buffer_.size() : linebreak + 1);
  }
  // We don't support AP_MODE_EATCRLF.  Doing so would be tricky, and probably
  // totally pointless.  But if we ever decide to implement it, see
  // http://mail-archives.apache.org/mod_mbox/httpd-dev/200504.mbox/%3C1e86e5df78f13fcc9af02b3f5d749b33@ricilake.net%3E
  // for more information on its subtle semantics.
  else {
    DCHECK(mode == AP_MODE_EATCRLF);
    VLOG(2) << "Unsupported read mode (" << mode << ") on stream "
            << stream_->stream_id();
    return APR_ENOTIMPL;
  }

  // Keep track of whether we were able to put any buckets into the brigade.
  bool success = false;

  // If we managed to read any data, put it into the brigade.  We use a
  // transient bucket (as opposed to a heap bucket) to avoid an extra string
  // copy.
  if (bytes_read > 0) {
    APR_BRIGADE_INSERT_TAIL(brigade, apr_bucket_transient_create(
        data_buffer_.data(), bytes_read, brigade->bucket_alloc));
    success = true;
  }

  // If this is the last bit of data from this stream, send an EOS bucket.
  if (end_of_stream_reached() && bytes_read == data_buffer_.size()) {
    APR_BRIGADE_INSERT_TAIL(brigade, apr_bucket_eos_create(
        brigade->bucket_alloc));
    success = true;
  }

  // If this read failed and this was a non-blocking read, invite the caller to
  // try again.
  if (!success && block == APR_NONBLOCK_READ) {
    return APR_EAGAIN;
  }

  // Unless this is a speculative read, we should skip past the bytes we read
  // next time this filter is invoked.  We don't want to erase those bytes
  // yet, though, so that we can return them to the previous filter in a
  // transient bucket.
  if (mode != AP_MODE_SPECULATIVE) {
    next_read_start_ = bytes_read;
  }

  return APR_SUCCESS;
}

SpdyToHttpFilter::DecodeFrameVisitor::DecodeFrameVisitor(
    SpdyToHttpFilter* filter)
    : filter_(filter), success_(false) {
  DCHECK(filter_);
}

void SpdyToHttpFilter::DecodeFrameVisitor::VisitSynStream(
    const net::SpdySynStreamIR& frame) {
  success_ = filter_->DecodeSynStreamFrame(frame);
}
void SpdyToHttpFilter::DecodeFrameVisitor::VisitSynReply(
    const net::SpdySynReplyIR& frame) { BadFrameType("SYN_REPLY"); }
void SpdyToHttpFilter::DecodeFrameVisitor::VisitRstStream(
    const net::SpdyRstStreamIR& frame) { BadFrameType("RST_STREAM"); }
void SpdyToHttpFilter::DecodeFrameVisitor::VisitSettings(
    const net::SpdySettingsIR& frame) { BadFrameType("SETTINGS"); }
void SpdyToHttpFilter::DecodeFrameVisitor::VisitPing(
    const net::SpdyPingIR& frame) { BadFrameType("PING"); }
void SpdyToHttpFilter::DecodeFrameVisitor::VisitGoAway(
    const net::SpdyGoAwayIR& frame) { BadFrameType("GOAWAY"); }
void SpdyToHttpFilter::DecodeFrameVisitor::VisitHeaders(
    const net::SpdyHeadersIR& frame) {
  success_ = filter_->DecodeHeadersFrame(frame);
}
void SpdyToHttpFilter::DecodeFrameVisitor::VisitWindowUpdate(
    const net::SpdyWindowUpdateIR& frame) { BadFrameType("WINDOW_UPDATE"); }
void SpdyToHttpFilter::DecodeFrameVisitor::VisitCredential(
    const net::SpdyCredentialIR& frame) { BadFrameType("CREDENTIAL"); }
void SpdyToHttpFilter::DecodeFrameVisitor::VisitBlocked(
    const net::SpdyBlockedIR& frame) { BadFrameType("BLOCKED"); }
void SpdyToHttpFilter::DecodeFrameVisitor::VisitPushPromise(
    const net::SpdyPushPromiseIR& frame) { BadFrameType("PUSH_PROMISE"); }
void SpdyToHttpFilter::DecodeFrameVisitor::VisitData(
    const net::SpdyDataIR& frame) {
  success_ = filter_->DecodeDataFrame(frame);
}

void SpdyToHttpFilter::DecodeFrameVisitor::BadFrameType(
    const char* frame_type) {
  LOG(DFATAL) << "Master connection sent a " << frame_type
              << " frame to stream " << filter_->stream_->stream_id();
  filter_->AbortStream(net::RST_STREAM_INTERNAL_ERROR);
  success_ = false;
}

bool SpdyToHttpFilter::GetNextFrame(apr_read_type_e block) {
  if (end_of_stream_reached()) {
    return false;
  }

  // Try to get the next SPDY frame from the stream.
  scoped_ptr<net::SpdyFrameIR> frame;
  {
    net::SpdyFrameIR* frame_ptr = NULL;
    if (!stream_->GetInputFrame(block == APR_BLOCK_READ, &frame_ptr)) {
      DCHECK(frame_ptr == NULL);
      return false;
    }
    frame.reset(frame_ptr);
  }
  DCHECK(frame.get() != NULL);

  // Decode the frame into HTTP and append to the data buffer.
  DecodeFrameVisitor visitor(this);
  frame->Visit(&visitor);
  return visitor.success();
}

bool SpdyToHttpFilter::DecodeSynStreamFrame(
    const net::SpdySynStreamIR& frame) {
  const SpdyToHttpConverter::Status status =
      converter_.ConvertSynStreamFrame(frame);
  switch (status) {
    case SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS:
      return true;
    case SpdyToHttpConverter::EXTRA_SYN_STREAM:
      // If we get multiple SYN_STREAM frames for a stream, we must abort
      // with PROTOCOL_ERROR (SPDY draft 2 section 2.7.1).
      LOG(ERROR) << "Client sent extra SYN_STREAM frame on stream "
                 << stream_->stream_id();
      AbortStream(net::RST_STREAM_PROTOCOL_ERROR);
      return false;
    case SpdyToHttpConverter::INVALID_HEADER_BLOCK:
      LOG(ERROR) << "Invalid SYN_STREAM header block on stream "
                 << stream_->stream_id();
      AbortStream(net::RST_STREAM_PROTOCOL_ERROR);
      return false;
    case SpdyToHttpConverter::BAD_REQUEST:
      // TODO(mdsteeele): According to the SPDY spec, we're supposed to return
      //   an HTTP 400 (Bad Request) reply in this case (SPDY draft 3 section
      //   3.2.1).  We need to do some refactoring to make that possible.
      LOG(ERROR) << "Could not generate request line from SYN_STREAM frame"
                  << " in stream " << stream_->stream_id();
      AbortStream(net::RST_STREAM_REFUSED_STREAM);
      return false;
    default:
      // No other outcome should be possible.
      LOG(DFATAL) << "Got " << SpdyToHttpConverter::StatusString(status)
                  << " from ConvertSynStreamFrame on stream "
                  << stream_->stream_id();
      AbortStream(net::RST_STREAM_INTERNAL_ERROR);
      return false;
  }
}

bool SpdyToHttpFilter::DecodeHeadersFrame(const net::SpdyHeadersIR& frame) {
  const SpdyToHttpConverter::Status status =
      converter_.ConvertHeadersFrame(frame);
  switch (status) {
    case SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS:
      return true;
    case SpdyToHttpConverter::FRAME_AFTER_FIN:
      AbortStream(net::RST_STREAM_INVALID_STREAM);
      return false;
    case SpdyToHttpConverter::INVALID_HEADER_BLOCK:
      LOG(ERROR) << "Invalid HEADERS header block on stream "
                 << stream_->stream_id();
      AbortStream(net::RST_STREAM_PROTOCOL_ERROR);
      return false;
    default:
      // No other outcome should be possible.
      LOG(DFATAL) << "Got " << SpdyToHttpConverter::StatusString(status)
                  << " from ConvertHeadersFrame on stream "
                  << stream_->stream_id();
      AbortStream(net::RST_STREAM_INTERNAL_ERROR);
      return false;
  }
}

bool SpdyToHttpFilter::DecodeDataFrame(const net::SpdyDataIR& frame) {
  const SpdyToHttpConverter::Status status =
      converter_.ConvertDataFrame(frame);
  switch (status) {
    case SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS:
      // TODO(mdsteele): This isn't really the ideal place for this -- we
      //   shouldn't send the WINDOW_UPDATE until we're about to return the
      //   data to the previous filter, so that we're aren't buffering an
      //   unbounded amount of data in this filter.  The trouble is that once
      //   we convert the frames, everything goes into data_buffer_ and we
      //   forget which of it is leading/trailing headers and which of it is
      //   request data, so it'll take a little work to know when to send the
      //   WINDOW_UPDATE frames.  For now, just doing it here is good enough.
      stream_->OnInputDataConsumed(frame.data().size());
      return true;
    case SpdyToHttpConverter::FRAME_AFTER_FIN:
      // If the stream is no longer open, we must send a RST_STREAM with
      // INVALID_STREAM (SPDY draft 3 section 2.2.2).
      AbortStream(net::RST_STREAM_INVALID_STREAM);
      return false;
    default:
      // No other outcome should be possible.
      LOG(DFATAL) << "Got " << SpdyToHttpConverter::StatusString(status)
                  << " from ConvertDataFrame on stream "
                  << stream_->stream_id();
      AbortStream(net::RST_STREAM_INTERNAL_ERROR);
      return false;
  }
}

void SpdyToHttpFilter::AbortStream(net::SpdyRstStreamStatus status) {
  stream_->AbortWithRstStream(status);
}

}  // namespace mod_spdy
