// Copyright 2012 Google Inc.
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

#include "mod_spdy/common/http_string_builder.h"

#include <string>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"

namespace {

void OnHeader(const base::StringPiece& key,
              const base::StringPiece& value,
              std::string* output) {
  key.AppendToString(output);
  output->append(": ");
  value.AppendToString(output);
  output->append("\r\n");
}

}  // namespace

namespace mod_spdy {

HttpStringBuilder::HttpStringBuilder(std::string* str)
    : string_(str), state_(REQUEST_LINE) {
  CHECK(string_);
}

HttpStringBuilder::~HttpStringBuilder() {}

void HttpStringBuilder::OnRequestLine(const base::StringPiece& method,
                                      const base::StringPiece& path,
                                      const base::StringPiece& version) {
  DCHECK(state_ == REQUEST_LINE);
  state_ = LEADING_HEADERS;
  method.AppendToString(string_);
  string_->push_back(' ');
  path.AppendToString(string_);
  string_->push_back(' ');
  version.AppendToString(string_);
  string_->append("\r\n");
}

void HttpStringBuilder::OnLeadingHeader(const base::StringPiece& key,
                                        const base::StringPiece& value) {
  DCHECK(state_ == LEADING_HEADERS);
  OnHeader(key, value, string_);
}

void HttpStringBuilder::OnLeadingHeadersComplete() {
  DCHECK(state_ == LEADING_HEADERS);
  state_ = LEADING_HEADERS_COMPLETE;
  string_->append("\r\n");
}

void HttpStringBuilder::OnRawData(const base::StringPiece& data) {
  DCHECK(state_ == LEADING_HEADERS_COMPLETE || state_ == RAW_DATA);
  state_ = RAW_DATA;
  data.AppendToString(string_);
}

void HttpStringBuilder::OnDataChunk(const base::StringPiece& data) {
  DCHECK(state_ == LEADING_HEADERS_COMPLETE || state_ == DATA_CHUNKS);
  state_ = DATA_CHUNKS;
  // Encode the data as an HTTP data chunk.  See RFC 2616 section 3.6.1 for
  // details.
  base::StringAppendF(string_, "%lX\r\n",
                      static_cast<unsigned long>(data.size()));
  data.AppendToString(string_);
  string_->append("\r\n");
}

void HttpStringBuilder::OnDataChunksComplete() {
  DCHECK(state_ == DATA_CHUNKS);
  state_ = DATA_CHUNKS_COMPLETE;
  // Indicate that there are no more HTTP data chunks coming.  See RFC 2616
  // section 3.6.1 for details.
  string_->append("0\r\n");
}

void HttpStringBuilder::OnTrailingHeader(const base::StringPiece& key,
                                         const base::StringPiece& value) {
  DCHECK(state_ == DATA_CHUNKS_COMPLETE || state_ == TRAILING_HEADERS);
  state_ = TRAILING_HEADERS;
  OnHeader(key, value, string_);
}

void HttpStringBuilder::OnTrailingHeadersComplete() {
  DCHECK(state_ == TRAILING_HEADERS);
  state_ = TRAILING_HEADERS_COMPLETE;
  string_->append("\r\n");
}

void HttpStringBuilder::OnComplete() {
  DCHECK(state_ == LEADING_HEADERS_COMPLETE ||
         state_ == RAW_DATA ||
         state_ == DATA_CHUNKS_COMPLETE ||
         state_ == TRAILING_HEADERS_COMPLETE);
  if (state_ == DATA_CHUNKS_COMPLETE) {
    // In this case, there have been data chunks, but we haven't called
    // OnTrailingHeadersComplete because there were no trailing headers.  We
    // still need an empty line to indicate the end of the request.
    string_->append("\r\n");
  }
  state_ = COMPLETE;
}

}  // namespace mod_spdy
