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

#include "mod_spdy/common/http_to_spdy_converter.h"

#include <string>

#include "base/basictypes.h"
#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "mod_spdy/common/http_response_visitor_interface.h"
#include "mod_spdy/common/protocol_util.h"
#include "net/spdy/spdy_protocol.h"

namespace {

// This is the number of bytes we want to send per data frame.  We never send
// data frames larger than this, but we might send smaller ones if we have to
// flush early.
// TODO The SPDY folks say that smallish (~4kB) data frames are good; however,
//      we should experiment later on to see what value here performs the best.
const size_t kTargetDataFrameBytes = 4096;

}  // namespace

namespace mod_spdy {

class HttpToSpdyConverter::ConverterImpl : public HttpResponseVisitorInterface{
 public:
  ConverterImpl(spdy::SpdyVersion spdy_version, SpdyReceiver* receiver);
  virtual ~ConverterImpl();

  void Flush();

  // HttpResponseVisitorInterface methods:
  virtual void OnStatusLine(const base::StringPiece& version,
                            const base::StringPiece& status_code,
                            const base::StringPiece& status_phrase);
  virtual void OnLeadingHeader(const base::StringPiece& key,
                               const base::StringPiece& value);
  virtual void OnLeadingHeadersComplete(bool fin);
  virtual void OnData(const base::StringPiece& data, bool fin);

 private:
  void SendDataIfNecessary(bool flush, bool fin);
  void SendDataFrame(const char* data, size_t size, bool flag_fin);

  const spdy::SpdyVersion spdy_version_;
  SpdyReceiver* const receiver_;
  net::SpdyHeaderBlock headers_;
  std::string data_buffer_;
  bool sent_flag_fin_;

  DISALLOW_COPY_AND_ASSIGN(ConverterImpl);
};

HttpToSpdyConverter::SpdyReceiver::SpdyReceiver() {}

HttpToSpdyConverter::SpdyReceiver::~SpdyReceiver() {}

HttpToSpdyConverter::HttpToSpdyConverter(spdy::SpdyVersion spdy_version,
                                         SpdyReceiver* receiver)
    : impl_(new ConverterImpl(spdy_version, receiver)),
      parser_(impl_.get()) {}

HttpToSpdyConverter::~HttpToSpdyConverter() {}

bool HttpToSpdyConverter::ProcessInput(base::StringPiece input_data) {
  return parser_.ProcessInput(input_data);
}

void HttpToSpdyConverter::Flush() {
  impl_->Flush();
}

HttpToSpdyConverter::ConverterImpl::ConverterImpl(
    spdy::SpdyVersion spdy_version, SpdyReceiver* receiver)
    : spdy_version_(spdy_version),
      receiver_(receiver),
      sent_flag_fin_(false) {
  DCHECK_NE(spdy::SPDY_VERSION_NONE, spdy_version);
  CHECK(receiver_);
}

HttpToSpdyConverter::ConverterImpl::~ConverterImpl() {}

void HttpToSpdyConverter::ConverterImpl::Flush() {
  SendDataIfNecessary(true,  // true = do flush
                      false);  // false = not fin yet
}

void HttpToSpdyConverter::ConverterImpl::OnStatusLine(
    const base::StringPiece& version,
    const base::StringPiece& status_code,
    const base::StringPiece& status_phrase) {
  DCHECK(headers_.empty());
  const bool spdy2 = spdy_version_ < spdy::SPDY_VERSION_3;
  headers_[spdy2 ? spdy::kSpdy2Version : spdy::kSpdy3Version] =
      version.as_string();
  headers_[spdy2 ? spdy::kSpdy2Status : spdy::kSpdy3Status] =
      status_code.as_string();
}

void HttpToSpdyConverter::ConverterImpl::OnLeadingHeader(
    const base::StringPiece& key,
    const base::StringPiece& value) {
  // Filter out headers that are invalid in SPDY.
  if (IsInvalidSpdyResponseHeader(key)) {
    return;
  }
  MergeInHeader(key, value, &headers_);
}

void HttpToSpdyConverter::ConverterImpl::OnLeadingHeadersComplete(bool fin) {
  if (sent_flag_fin_) {
    LOG(DFATAL) << "Trying to send headers after sending FLAG_FIN";
    return;
  }
  if (fin) {
    sent_flag_fin_ = true;
  }
  receiver_->ReceiveSynReply(&headers_, fin);
  headers_.clear();
}

void HttpToSpdyConverter::ConverterImpl::OnData(const base::StringPiece& data,
                                                bool fin) {
  data.AppendToString(&data_buffer_);
  SendDataIfNecessary(false, fin);  // false = don't flush
}

void HttpToSpdyConverter::ConverterImpl::SendDataIfNecessary(bool flush,
                                                             bool fin) {
  // If we have (strictly) more than one frame's worth of data waiting, send it
  // down the filter chain, kTargetDataFrameBytes bytes at a time.  If we are
  // left with _exactly_ kTargetDataFrameBytes bytes of data, we'll deal with
  // that in the next code block (see the comment there to explain why).
  if (data_buffer_.size() > kTargetDataFrameBytes) {
    const char* start = data_buffer_.data();
    size_t size = data_buffer_.size();
    while (size > kTargetDataFrameBytes) {
      SendDataFrame(start, kTargetDataFrameBytes, false);
      start += kTargetDataFrameBytes;
      size -= kTargetDataFrameBytes;
    }
    data_buffer_.erase(0, data_buffer_.size() - size);
  }
  DCHECK(data_buffer_.size() <= kTargetDataFrameBytes);

  // We may still have some leftover data.  We need to send another data frame
  // now (rather than waiting for a full kTargetDataFrameBytes) if:
  //   1) This is the end of the response,
  //   2) we're supposed to flush and the buffer is nonempty, or
  //   3) we still have a full data frame's worth in the buffer.
  //
  // Note that because of the previous code block, condition (3) will only be
  // true if we have exactly kTargetDataFrameBytes of data.  However, dealing
  // with that case here instead of in the above block makes it easier to make
  // sure we correctly set FLAG_FIN on the final data frame, which is why the
  // above block uses a strict, > comparison rather than a non-strict, >=
  // comparison.
  if (fin || (flush && !data_buffer_.empty()) ||
      data_buffer_.size() >= kTargetDataFrameBytes) {
    SendDataFrame(data_buffer_.data(), data_buffer_.size(), fin);
    data_buffer_.clear();
  }
}

void HttpToSpdyConverter::ConverterImpl::SendDataFrame(
    const char* data, size_t size, bool flag_fin) {
  if (sent_flag_fin_) {
    LOG(DFATAL) << "Trying to send data after sending FLAG_FIN";
    return;
  }
  if (flag_fin) {
    sent_flag_fin_ = true;
  }
  receiver_->ReceiveData(base::StringPiece(data, size), flag_fin);
}

}  // namespace mod_spdy
