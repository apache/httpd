// Copyright 2010 Google Inc. All Rights Reserved.
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

#include "mod_spdy/common/spdy_to_http_converter.h"

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"  // for Int64ToString
#include "base/strings/string_piece.h"
#include "mod_spdy/common/http_request_visitor_interface.h"
#include "mod_spdy/common/protocol_util.h"
#include "net/spdy/spdy_frame_builder.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"

namespace mod_spdy {

namespace {

// Generate an HTTP request line from the given SPDY header block by calling
// the OnStatusLine() method of the given visitor, and return true.  If there's
// an error, this will return false without calling any methods on the visitor.
bool GenerateRequestLine(spdy::SpdyVersion spdy_version,
                         const net::SpdyHeaderBlock& block,
                         HttpRequestVisitorInterface* visitor) {
  const bool spdy2 = spdy_version < spdy::SPDY_VERSION_3;
  net::SpdyHeaderBlock::const_iterator method = block.find(
      spdy2 ? spdy::kSpdy2Method : spdy::kSpdy3Method);
  net::SpdyHeaderBlock::const_iterator scheme = block.find(
      spdy2 ? spdy::kSpdy2Scheme : spdy::kSpdy3Scheme);
  net::SpdyHeaderBlock::const_iterator host = block.find(
      spdy2 ? http::kHost : spdy::kSpdy3Host);
  net::SpdyHeaderBlock::const_iterator path = block.find(
      spdy2 ? spdy::kSpdy2Url : spdy::kSpdy3Path);
  net::SpdyHeaderBlock::const_iterator version = block.find(
      spdy2 ? spdy::kSpdy2Version : spdy::kSpdy3Version);

  if (method == block.end() ||
      scheme == block.end() ||
      host == block.end() ||
      path == block.end() ||
      version == block.end()) {
    return false;
  }

  visitor->OnRequestLine(method->second, path->second, version->second);
  return true;
}

// Convert the given SPDY header into HTTP header(s) by splitting on NUL bytes
// calling the specified method (either OnLeadingHeader or OnTrailingHeader) of
// the given visitor.
template <void(HttpRequestVisitorInterface::*OnHeader)(
    const base::StringPiece& key, const base::StringPiece& value)>
void InsertHeader(const base::StringPiece key,
                  const base::StringPiece value,
                  HttpRequestVisitorInterface* visitor) {
  // Split header values on null characters, emitting a separate
  // header key-value pair for each substring. Logic from
  // net/spdy/spdy_session.cc
  for (size_t start = 0, end = 0; end != value.npos; start = end) {
    start = value.find_first_not_of('\0', start);
    if (start == value.npos) {
      break;
    }
    end = value.find('\0', start);
    (visitor->*OnHeader)(key, (end != value.npos ?
                               value.substr(start, (end - start)) :
                               value.substr(start)));
  }
}

}  // namespace

SpdyToHttpConverter::SpdyToHttpConverter(spdy::SpdyVersion spdy_version,
                                         HttpRequestVisitorInterface* visitor)
    : spdy_version_(spdy_version),
      visitor_(visitor),
      state_(NO_FRAMES_YET),
      use_chunking_(true),
      seen_accept_encoding_(false) {
  DCHECK_NE(spdy::SPDY_VERSION_NONE, spdy_version);
  CHECK(visitor);
}

SpdyToHttpConverter::~SpdyToHttpConverter() {}

// static
const char* SpdyToHttpConverter::StatusString(Status status) {
  switch (status) {
    case SPDY_CONVERTER_SUCCESS:  return "SPDY_CONVERTER_SUCCESS";
    case FRAME_BEFORE_SYN_STREAM: return "FRAME_BEFORE_SYN_STREAM";
    case FRAME_AFTER_FIN:         return "FRAME_AFTER_FIN";
    case EXTRA_SYN_STREAM:        return "EXTRA_SYN_STREAM";
    case INVALID_HEADER_BLOCK:    return "INVALID_HEADER_BLOCK";
    case BAD_REQUEST:             return "BAD_REQUEST";
    default:
      LOG(DFATAL) << "Invalid status value: " << status;
      return "???";
  }
}

SpdyToHttpConverter::Status SpdyToHttpConverter::ConvertSynStreamFrame(
    const net::SpdySynStreamIR& frame) {
  if (state_ != NO_FRAMES_YET) {
    return EXTRA_SYN_STREAM;
  }
  state_ = RECEIVED_SYN_STREAM;

  const net::SpdyHeaderBlock& block = frame.name_value_block();

  if (!GenerateRequestLine(spdy_version(), block, visitor_)) {
    return BAD_REQUEST;
  }

  // Translate the headers to HTTP.
  GenerateLeadingHeaders(block);

  // If this is the last (i.e. only) frame on this stream, finish off the HTTP
  // request.
  if (frame.fin()) {
    FinishRequest();
  }

  return SPDY_CONVERTER_SUCCESS;
}

SpdyToHttpConverter::Status SpdyToHttpConverter::ConvertHeadersFrame(
    const net::SpdyHeadersIR& frame) {
  if (state_ == RECEIVED_FLAG_FIN) {
    return FRAME_AFTER_FIN;
  } else if (state_ == NO_FRAMES_YET) {
    return FRAME_BEFORE_SYN_STREAM;
  }

  // Parse the headers from the HEADERS frame.  If there have already been any
  // data frames, then we need to save these headers for later and send them as
  // trailing headers.  Otherwise, we can send them immediately.
  if (state_ == RECEIVED_DATA) {
    if (use_chunking_) {
      const net::SpdyHeaderBlock& block = frame.name_value_block();
      trailing_headers_.insert(block.begin(), block.end());
    } else {
      LOG(WARNING) << "Client sent trailing headers, "
                   << "but we had to ignore them.";
    }
  } else {
    DCHECK(state_ == RECEIVED_SYN_STREAM);
    DCHECK(trailing_headers_.empty());
    // Translate the headers to HTTP.
    GenerateLeadingHeaders(frame.name_value_block());
  }

  // If this is the last frame on this stream, finish off the HTTP request.
  if (frame.fin()) {
    FinishRequest();
  }

  return SPDY_CONVERTER_SUCCESS;
}

SpdyToHttpConverter::Status SpdyToHttpConverter::ConvertDataFrame(
    const net::SpdyDataIR& frame) {
  if (state_ == RECEIVED_FLAG_FIN) {
    return FRAME_AFTER_FIN;
  } else if (state_ == NO_FRAMES_YET) {
    return FRAME_BEFORE_SYN_STREAM;
  }

  // If this is the first data frame in the stream, we need to close the HTTP
  // headers section (for streams where there are never any data frames, we
  // close the headers section in FinishRequest instead).  Just before we do,
  // we may need to add some last-minute headers.
  if (state_ == RECEIVED_SYN_STREAM) {
    state_ = RECEIVED_DATA;

    // Unless we're not using chunked encoding (due to having received a
    // Content-Length headers), set Transfer-Encoding: chunked now.
    if (use_chunking_) {
      visitor_->OnLeadingHeader(http::kTransferEncoding, http::kChunked);
    }

    // Add any other last minute headers we need, and close the leading headers
    // section.
    EndOfLeadingHeaders();
  }
  DCHECK(state_ == RECEIVED_DATA);

  // Translate the SPDY data frame into an HTTP data chunk.  However, we must
  // not emit a zero-length chunk, as that would be interpreted as the
  // data-chunks-complete marker.
  if (frame.data().size() > 0) {
    if (use_chunking_) {
      visitor_->OnDataChunk(frame.data());
    } else {
      visitor_->OnRawData(frame.data());
    }
  }

  // If this is the last frame on this stream, finish off the HTTP request.
  if (frame.fin()) {
    FinishRequest();
  }

  return SPDY_CONVERTER_SUCCESS;
}

// Convert the given SPDY header block (e.g. from a SYN_STREAM or HEADERS
// frame) into HTTP headers by calling OnLeadingHeader on the given visitor.
void SpdyToHttpConverter::GenerateLeadingHeaders(
    const net::SpdyHeaderBlock& block) {
  for (net::SpdyHeaderBlock::const_iterator it = block.begin();
       it != block.end(); ++it) {
    base::StringPiece key = it->first;
    const base::StringPiece value = it->second;

    // Skip SPDY-specific (i.e. non-HTTP) headers.
    if (spdy_version() < spdy::SPDY_VERSION_3) {
      if (key == spdy::kSpdy2Method || key == spdy::kSpdy2Scheme ||
          key == spdy::kSpdy2Url || key == spdy::kSpdy2Version) {
        continue;
      }
    } else {
      if (key == spdy::kSpdy3Method || key == spdy::kSpdy3Scheme ||
          key == spdy::kSpdy3Path || key == spdy::kSpdy3Version) {
        continue;
      }
    }

    // Skip headers that are ignored by SPDY.
    if (key == http::kConnection || key == http::kKeepAlive) {
      continue;
    }

    // If the client sent a Content-Length header, take note, so that we'll
    // know not to used chunked encoding.
    if (key == http::kContentLength) {
      use_chunking_ = false;
    }

    // The client shouldn't be sending us a Transfer-Encoding header; it's
    // pretty pointless over SPDY.  If they do send one, just ignore it; we may
    // be overriding it later anyway.
    if (key == http::kTransferEncoding) {
      LOG(WARNING) << "Client sent \"transfer-encoding: " << value
                   << "\" header over SPDY.  Why would they do that?";
      continue;
    }

    // For SPDY v3 and later, we need to convert the SPDY ":host" header to an
    // HTTP "host" header.
    if (spdy_version() >= spdy::SPDY_VERSION_3 && key == spdy::kSpdy3Host) {
      key = http::kHost;
    }

    // Take note of whether the client has sent an explicit Accept-Encoding
    // header; if they never do, we'll insert on for them later on.
    if (key == http::kAcceptEncoding) {
      // TODO(mdsteele): Ideally, if the client sends something like
      //   "Accept-Encoding: lzma", we should change it to "Accept-Encoding:
      //   lzma, gzip".  However, that's more work (we might need to parse the
      //   syntax, to make sure we don't naively break it), and isn't
      //   (currently) likely to come up in practice.
      seen_accept_encoding_ = true;
    }

    InsertHeader<&HttpRequestVisitorInterface::OnLeadingHeader>(
        key, value, visitor_);
  }
}

void SpdyToHttpConverter::EndOfLeadingHeaders() {
  // All SPDY clients should be assumed to support both gzip and deflate, even
  // if they don't say so (SPDY draft 2 section 3; SPDY draft 3 section 3.2.1),
  // and indeed some SPDY clients omit the Accept-Encoding header.  So if we
  // didn't see that header yet, add one now so that Apache knows it can use
  // gzip/deflate.
  if (!seen_accept_encoding_) {
    visitor_->OnLeadingHeader(http::kAcceptEncoding, http::kGzipDeflate);
  }

  visitor_->OnLeadingHeadersComplete();
}

void SpdyToHttpConverter::FinishRequest() {
  if (state_ == RECEIVED_DATA) {
    if (use_chunking_) {
      // Indicate that there is no more data coming.
      visitor_->OnDataChunksComplete();

      // Append whatever trailing headers we've buffered, if any.
      if (!trailing_headers_.empty()) {
        for (net::SpdyHeaderBlock::const_iterator it =
                 trailing_headers_.begin();
             it != trailing_headers_.end(); ++it) {
          InsertHeader<&HttpRequestVisitorInterface::OnTrailingHeader>(
              it->first, it->second, visitor_);
        }
        trailing_headers_.clear();
        visitor_->OnTrailingHeadersComplete();
      }
    } else {
      // We don't add to trailing_headers_ if we're in no-chunk mode (we simply
      // ignore trailing HEADERS frames), so trailing_headers_ should still be
      // empty.
      DCHECK(trailing_headers_.empty());
    }
  } else {
    DCHECK(state_ == RECEIVED_SYN_STREAM);
    // We only ever add to trailing_headers_ after receiving at least one data
    // frame, so if we haven't received any data frames then trailing_headers_
    // should still be empty.
    DCHECK(trailing_headers_.empty());

    // There were no data frames in this stream, so we haven't closed the
    // normal (non-trailing) headers yet (if there had been any data frames, we
    // would have closed the normal headers in ConvertDataFrame instead).  Do
    // so now.
    EndOfLeadingHeaders();
  }

  // Indicate that this request is finished.
  visitor_->OnComplete();
  state_ = RECEIVED_FLAG_FIN;
}

}  // namespace mod_spdy
