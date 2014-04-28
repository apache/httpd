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

#include "mod_spdy/common/http_response_parser.h"

#include <string>

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "mod_spdy/common/http_response_visitor_interface.h"
#include "mod_spdy/common/protocol_util.h"

namespace {

// If the given position in the string is npos, then return the position of the
// end of the string; otherwise, return the given position unchanged.
size_t NposToEnd(const base::StringPiece& str, size_t pos) {
  return pos == base::StringPiece::npos ? str.size() : pos;
}

}  // namespace

namespace mod_spdy {

HttpResponseParser::HttpResponseParser(HttpResponseVisitorInterface* visitor)
    : visitor_(visitor),
      state_(STATUS_LINE),
      body_type_(NO_BODY),
      remaining_bytes_(0) {}

HttpResponseParser::~HttpResponseParser() {}

bool HttpResponseParser::ProcessInput(const base::StringPiece& input_data) {
  // Keep track of the slice of data we are currently looking at.  We will
  // modify this variable as we go.
  base::StringPiece data = input_data;

  size_t last_length = data.size() + 1;
  while (!data.empty()) {
    // Safety check to avoid infinite loops in case our code is buggy; the
    // slice of data we are looking at should get strictly smaller on every
    // iteration of this loop.
    if (data.size() >= last_length) {
      LOG(DFATAL) << "Potential infinite loop.";
      return false;
    }
    last_length = data.size();

    // Process the data based on our current parser state.  Most of these
    // methods receive a pointer to `data` and will mutate it as they consume
    // bytes.  We continue looping until the whole input_data is consumed.
    switch (state_) {
      case STATUS_LINE:
        if (!ProcessStatusLine(&data)) {
          return false;
        }
        break;
      case LEADING_HEADERS_CHECK_NEXT_LINE:
        if (!CheckStartOfHeaderLine(data)) {
          return false;
        }
        // fallthrough
      case LEADING_HEADERS:
        if (!ProcessLeadingHeaders(&data)) {
          return false;
        }
        break;
      case CHUNK_START:
        if (!ProcessChunkStart(&data)) {
          return false;
        }
        break;
      case BODY_DATA:
        if (!ProcessBodyData(&data)) {
          return false;
        }
        break;
      case CHUNK_ENDING:
        if (!ProcessChunkEnding(&data)) {
          return false;
        }
        break;
      case COMPLETE:
        DCHECK(buffer_.empty());
        return true;
      default:
        LOG(DFATAL) << "Invalid parser state: " << state_;
        return false;
    }
  }
  return true;
}

bool HttpResponseParser::ProcessStatusLine(base::StringPiece* data) {
  DCHECK(state_ == STATUS_LINE);
  const size_t linebreak = data->find("\r\n");

  // If we haven't reached the end of the line yet, buffer the data and quit.
  if (linebreak == base::StringPiece::npos) {
    data->AppendToString(&buffer_);
    *data = base::StringPiece();
    return true;
  }

  // Combine the data up to the linebreak with what we've buffered, and parse
  // the status line out of it.
  data->substr(0, linebreak).AppendToString(&buffer_);
  if (!ParseStatusLine(buffer_)) {
    return false;
  }
  buffer_.clear();

  // Chop off the linebreak and all data before it, and move on to parsing the
  // leading headers.
  *data = data->substr(linebreak + 2);
  state_ = LEADING_HEADERS;
  return true;
}

bool HttpResponseParser::CheckStartOfHeaderLine(const base::StringPiece& data){
  // This state is for when we have a complete header line buffered, and we
  // need to check the next line to see if it starts with leading whitespace.
  DCHECK(state_ == LEADING_HEADERS_CHECK_NEXT_LINE);
  DCHECK(!buffer_.empty());
  DCHECK(!data.empty());

  // If this line _doesn't_ start with whitespace, then the buffered line is a
  // complete header line, so we should parse it and clear the buffer.
  // Otherwise, this next line is a continuation of the header, so we need to
  // buffer more data.
  const char first = data[0];
  if (first != ' ' && first != '\t') {
    if (!ParseLeadingHeader(buffer_)) {
      return false;
    }
    buffer_.clear();
  }

  // Either way, we're ready to continuing parsing headers.
  state_ = LEADING_HEADERS;
  return true;
}

bool HttpResponseParser::ProcessLeadingHeaders(base::StringPiece* data) {
  DCHECK(state_ == LEADING_HEADERS);
  const size_t linebreak = data->find("\r\n");

  // If we haven't reached the end of the line yet, buffer the data and quit.
  if (linebreak == base::StringPiece::npos) {
    data->AppendToString(&buffer_);
    *data = base::StringPiece();
    return true;
  }

  // If we're not in the middle of a header line (buffer is empty) and the
  // linebreak comes at the very beginning, this must be the blank line that
  // signals the end of the leading headers.  Skip the linebreak, switch states
  // depending on what headers we saw (Is there body data?  Is it chunked?),
  // and return.
  if (linebreak == 0 && buffer_.empty()) {
    switch (body_type_) {
      case CHUNKED_BODY:
        state_ = CHUNK_START;
        break;
      case UNCHUNKED_BODY:
        state_ = BODY_DATA;
        break;
      case NO_BODY:
        state_ = COMPLETE;
        break;
      default:
        LOG(DFATAL) << "Invalid body type: " << body_type_;
        return false;
    }
    visitor_->OnLeadingHeadersComplete(state_ == COMPLETE);
    *data = data->substr(linebreak + 2);
    return true;
  }

  // We've reached the end of the line, but we need to check the next line to
  // see if it's a continuation of this header.  Buffer up to the linebreak,
  // skip the linebreak itself, and set our state to check the next line.
  data->substr(0, linebreak).AppendToString(&buffer_);
  *data = data->substr(linebreak + 2);
  state_ = LEADING_HEADERS_CHECK_NEXT_LINE;
  return true;
}

bool HttpResponseParser::ProcessChunkStart(base::StringPiece* data) {
  DCHECK(state_ == CHUNK_START);
  const size_t linebreak = data->find("\r\n");

  // If we haven't reached the end of the line yet, buffer the data and quit.
  if (linebreak == base::StringPiece::npos) {
    data->AppendToString(&buffer_);
    *data = base::StringPiece();
    return true;
  }

  // Combine the data up to the linebreak with what we've buffered, and parse
  // the chunk length out of it.
  data->substr(0, linebreak).AppendToString(&buffer_);
  if (!ParseChunkStart(buffer_)) {
    return false;
  }
  buffer_.clear();

  // Skip the linebreak.
  *data = data->substr(linebreak + 2);

  // ParseChunkStart will put the size of the chunk into remaining_bytes_.  If
  // the chunk size is zero, that means we've reached the end of the body data.
  // Otherwise, we now need to read the data in this chunk.
  if (remaining_bytes_ == 0) {
    state_ = COMPLETE;
    visitor_->OnData(base::StringPiece(), true);
  } else {
    state_ = BODY_DATA;
  }
  return true;
}

bool HttpResponseParser::ProcessBodyData(base::StringPiece* data) {
  DCHECK(state_ == BODY_DATA);

  // We never buffer anything when reading the body data.  This minimizes how
  // much string copying we need to do for most responses.
  DCHECK(buffer_.empty());

  // If the available data is less that what remains of this chunk (if the data
  // is chunked) or of the whole body (if there was instead an explicit
  // content-length), then read in all the data we have and subtract from
  // remaining_bytes_.
  if (data->size() < remaining_bytes_) {
    visitor_->OnData(*data, false);
    remaining_bytes_ -= data->size();
    *data = base::StringPiece();
  }
  // Otherwise, we have enough data here to fulfill remaining_bytes_, so read
  // in that much data, and then switch states depending on whether we're using
  // chunking or not.
  else {
    if (body_type_ == CHUNKED_BODY) {
      state_ = CHUNK_ENDING;
    } else {
      DCHECK(body_type_ == UNCHUNKED_BODY);
      state_ = COMPLETE;
    }
    visitor_->OnData(data->substr(0, remaining_bytes_), state_ == COMPLETE);
    *data = data->substr(remaining_bytes_);
    remaining_bytes_ = 0;
  }
  return true;
}

bool HttpResponseParser::ProcessChunkEnding(base::StringPiece* data) {
  DCHECK(state_ == CHUNK_ENDING);
  // For whatever reason, HTTP requires each chunk to end with a CRLF.  So,
  // make sure it's there, and then skip it, before moving on to read the next
  // chunk.
  if (!data->starts_with("\r\n")) {
    VLOG(1) << "Expected CRLF at end of chunk.";
    return false;
  }
  *data = data->substr(2);
  state_ = CHUNK_START;
  return true;
}

bool HttpResponseParser::ParseStatusLine(const base::StringPiece& text) {
  // An HTTP status line should look like:
  // <HTTP version> <single space> <status code> <single space> <status phrase>
  // For example, "HTTP/1.1 301 Moved permenantly".
  // We'll be a little more lenient just in case, and allow multiple spaces
  // between each part, and allow the phrase to be omitted.
  const size_t first_space = text.find(' ');
  if (first_space == base::StringPiece::npos) {
    VLOG(1) << "Bad status line: " << text;
    return false;
  }
  const size_t start_of_code = text.find_first_not_of(' ', first_space);
  if (start_of_code == base::StringPiece::npos) {
    VLOG(1) << "Bad status line: " << text;
    return false;
  }
  const size_t second_space = NposToEnd(text, text.find(' ', start_of_code));
  const size_t start_of_phrase =
      NposToEnd(text, text.find_first_not_of(' ', second_space));

  visitor_->OnStatusLine(
      text.substr(0, first_space),
      text.substr(start_of_code, second_space - start_of_code),
      text.substr(start_of_phrase));
  return true;
}

bool HttpResponseParser::ParseLeadingHeader(const base::StringPiece& text) {
  // Even for multiline headers, we strip out the CRLFs, so there shouldn't be
  // any left in the text that we're parsing.
  DCHECK(text.find("\r\n") == base::StringPiece::npos);

  // Find the colon separating the key from the value, and skip any leading
  // whitespace between the colon and the value.
  const size_t colon = text.find(':');
  if (colon == base::StringPiece::npos) {
    VLOG(1) << "Bad header line: " << text;
    return false;
  }
  const size_t value_start =
      NposToEnd(text, text.find_first_not_of(" \t", colon + 1));

  const base::StringPiece key = text.substr(0, colon);
  const base::StringPiece value = text.substr(value_start);

  // We need to check the Content-Length and Transfer-Encoding headers to know
  // if we're using chunking, and if not, how long the body is.
  if (LowerCaseEqualsASCII(key.begin(), key.end(), http::kTransferEncoding)) {
    if (value == http::kChunked) {
      body_type_ = CHUNKED_BODY;
    }
  } else if (body_type_ != CHUNKED_BODY &&
             LowerCaseEqualsASCII(key.begin(), key.end(),
                                  http::kContentLength)) {
    uint64 uint_value = 0u;
    if (base::StringToUint64(value, &uint_value) && uint_value > 0u) {
      remaining_bytes_ = uint_value;
      body_type_ = UNCHUNKED_BODY;
    } else {
      VLOG(1) << "Bad content-length: " << value;
    }
  }

  visitor_->OnLeadingHeader(key, value);
  return true;
}

bool HttpResponseParser::ParseChunkStart(const base::StringPiece& text) {
  // The line at the start of each chunk consists of the chunk length in
  // hexadecimal, potentially followed by chunk-extension metadata that we
  // don't care about anyway.  So just parse out the hex number and ignore the
  // rest.
  const size_t length =
      NposToEnd(text, text.find_first_not_of("0123456789abcdefABCDEF"));
  int int_value = 0;
  if (!base::HexStringToInt(text.substr(0, length), &int_value) ||
      int_value < 0) {
    VLOG(1) << "Bad chunk line: " << text;
    return false;
  }
  remaining_bytes_ = static_cast<size_t>(int_value);
  return true;
}

}  // namespace mod_spdy
