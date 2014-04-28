// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "base/strings/string_piece.h"
#include "mod_spdy/common/protocol_util.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::_;
using testing::DeleteArg;
using testing::Eq;
using testing::InSequence;
using testing::Pointee;

namespace {

class MockSpdyReceiver : public mod_spdy::HttpToSpdyConverter::SpdyReceiver {
 public:
  MOCK_METHOD2(ReceiveSynReply, void(net::SpdyHeaderBlock* headers,
                                     bool flag_fin));
  MOCK_METHOD2(ReceiveData, void(base::StringPiece data, bool flag_fin));
};

class HttpToSpdyConverterTest :
      public testing::TestWithParam<mod_spdy::spdy::SpdyVersion> {
 public:
  HttpToSpdyConverterTest() : converter_(GetParam(), &receiver_) {}

 protected:
  const char* status_header_name() const {
    return (GetParam() < mod_spdy::spdy::SPDY_VERSION_3 ?
            mod_spdy::spdy::kSpdy2Status :
            mod_spdy::spdy::kSpdy3Status);
  }
  const char* version_header_name() const {
    return (GetParam() < mod_spdy::spdy::SPDY_VERSION_3 ?
            mod_spdy::spdy::kSpdy2Version :
            mod_spdy::spdy::kSpdy3Version);
  }

  MockSpdyReceiver receiver_;
  mod_spdy::HttpToSpdyConverter converter_;
  net::SpdyHeaderBlock expected_headers_;
};

// Simple response with a small payload.  We should get a SYN_REPLY and a DATA
// frame.
TEST_P(HttpToSpdyConverterTest, SimpleWithContentLength) {
  expected_headers_[status_header_name()] = "200";
  expected_headers_[version_header_name()] = "HTTP/1.1";
  expected_headers_[mod_spdy::http::kContentLength] = "14";
  expected_headers_[mod_spdy::http::kContentType] = "text/plain";
  expected_headers_["x-whatever"] = "foobar";

  InSequence seq;
  EXPECT_CALL(receiver_, ReceiveSynReply(Pointee(Eq(expected_headers_)),
                                         Eq(false)));
  EXPECT_CALL(receiver_, ReceiveData(Eq("Hello, world!\n"), Eq(true)));

  ASSERT_TRUE(converter_.ProcessInput(
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 14\r\n"
      "Content-Type:      text/plain\r\n"
      "X-Whatever:foobar\r\n"
      "\r\n"
      "Hello, world!\n"
      "\r\n"));
}

// The data arrives in two chunks, but they're small, so we should consolidate
// them into a single DATA frame.
TEST_P(HttpToSpdyConverterTest, SimpleWithChunking) {
  expected_headers_[status_header_name()] = "200";
  expected_headers_[version_header_name()] = "HTTP/1.1";
  expected_headers_[mod_spdy::http::kContentType] = "text/plain";

  InSequence seq;
  EXPECT_CALL(receiver_, ReceiveSynReply(Pointee(Eq(expected_headers_)),
                                         Eq(false)));
  EXPECT_CALL(receiver_, ReceiveData(Eq("Hello, world!\n"), Eq(true)));

  ASSERT_TRUE(converter_.ProcessInput(
      "HTTP/1.1 200 OK\r\n"
      "Connection: Keep-Alive\r\n"
      "Content-Type: text/plain\r\n"
      "Keep-Alive: timeout=10, max=5\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "6\r\n"
      "Hello,\r\n"
      "8\r\n"
      " world!\n\r\n"
      "0\r\n"
      "\r\n"));
}

// Test that we don't get tripped up if there is garbage after the end of
// a chunked message.
TEST_P(HttpToSpdyConverterTest, ChunkedEncodingWithTrailingGarbage) {
  expected_headers_[status_header_name()] = "200";
  expected_headers_[version_header_name()] = "HTTP/1.1";
  expected_headers_[mod_spdy::http::kContentType] = "text/plain";

  InSequence seq;
  EXPECT_CALL(receiver_, ReceiveSynReply(Pointee(Eq(expected_headers_)),
                                         Eq(false)));
  EXPECT_CALL(receiver_, ReceiveData(Eq("Hello, world!\n"), Eq(true)));

  ASSERT_TRUE(converter_.ProcessInput(
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "E\r\n"
      "Hello, world!\n\r\n"
      "0\r\n"
      "0\r\n" // multiple last-chunks
      "\r\n\x1bGaRbAgE"));  // and also some garbage bytes
}

// No response body, so we should get the FLAG_FIN on the SYN_REPLY, and no
// DATA frames.
TEST_P(HttpToSpdyConverterTest, NoResponseBody) {
  expected_headers_[status_header_name()] = "301";
  expected_headers_[version_header_name()] = "HTTP/1.1";
  expected_headers_["location"] = "https://www.example.com/";

  InSequence seq;
  EXPECT_CALL(receiver_, ReceiveSynReply(Pointee(Eq(expected_headers_)),
                                         Eq(true)));

  ASSERT_TRUE(converter_.ProcessInput(
      "HTTP/1.1 301 Moved permenantly\r\n"
      "Location: https://www.example.com/\r\n"
      "\r\n"));
}

// Simple response with a large payload.  We should get a SYN_REPLY and
// multiple DATA frames.
TEST_P(HttpToSpdyConverterTest, BreakUpLargeDataIntoMultipleFrames) {
  expected_headers_[status_header_name()] = "200";
  expected_headers_[version_header_name()] = "HTTP/1.1";
  expected_headers_[mod_spdy::http::kContentLength] = "10000";
  expected_headers_[mod_spdy::http::kContentType] = "text/plain";

  InSequence seq;
  EXPECT_CALL(receiver_, ReceiveSynReply(Pointee(Eq(expected_headers_)),
                                         Eq(false)));
  EXPECT_CALL(receiver_, ReceiveData(Eq(std::string(4096, 'x')), Eq(false)));
  EXPECT_CALL(receiver_, ReceiveData(Eq(std::string(4096, 'x')), Eq(false)));
  EXPECT_CALL(receiver_, ReceiveData(Eq(std::string(1808, 'x')), Eq(true)));

  ASSERT_TRUE(converter_.ProcessInput(
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10000\r\n"
      "Content-Type: text/plain\r\n"
      "\r\n" +
      std::string(10000, 'x') +
      "\r\n"));
}

// Test that we buffer data until we get the full frame.
TEST_P(HttpToSpdyConverterTest, BufferUntilWeHaveACompleteFrame) {
  expected_headers_[status_header_name()] = "200";
  expected_headers_[version_header_name()] = "HTTP/1.1";
  expected_headers_[mod_spdy::http::kContentLength] = "4096";
  expected_headers_[mod_spdy::http::kContentType] = "text/plain";

  InSequence seq;
  // Send some of the headers.  We shouldn't get anything out yet.
  ASSERT_TRUE(converter_.ProcessInput(
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 4096\r\n"));
  // Send the rest of the headers, and some of the data.  We should get the
  // SYN_REPLY now, but no data yet.
  EXPECT_CALL(receiver_, ReceiveSynReply(Pointee(Eq(expected_headers_)),
                                         Eq(false)));
  ASSERT_TRUE(converter_.ProcessInput(
      "Content-Type: text/plain\r\n"
      "\r\n" +
      std::string(2000, 'x')));
  // Send some more data, but still not enough for a full frame.
  ASSERT_TRUE(converter_.ProcessInput(std::string(2000, 'x')));
  // Send the last of the data.  We should finally get the one DATA frame.
  EXPECT_CALL(receiver_, ReceiveData(Eq(std::string(4096, 'x')), Eq(true)));
  ASSERT_TRUE(converter_.ProcessInput(std::string(96, 'x')));
}

// Test that we flush the buffer when told.
TEST_P(HttpToSpdyConverterTest, RespectFlushes) {
  expected_headers_[status_header_name()] = "200";
  expected_headers_[version_header_name()] = "HTTP/1.1";
  expected_headers_[mod_spdy::http::kContentLength] = "4096";
  expected_headers_[mod_spdy::http::kContentType] = "text/plain";

  InSequence seq;
  // Send the headers and some of the data (not enough for a full frame).  We
  // should get the headers out, but no data yet.
  EXPECT_CALL(receiver_, ReceiveSynReply(Pointee(Eq(expected_headers_)),
                                         Eq(false)));
  ASSERT_TRUE(converter_.ProcessInput(
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 4096\r\n"
      "Content-Type: text/plain\r\n"
      "\r\n" +
      std::string(2000, 'x')));
  // Perform a flush.  We should get the data sent so far.
  EXPECT_CALL(receiver_, ReceiveData(Eq(std::string(2000, 'x')), Eq(false)));
  converter_.Flush();
  // Send the rest of the data.  We should get out a second DATA frame, with
  // FLAG_FIN set.
  EXPECT_CALL(receiver_, ReceiveData(Eq(std::string(2096, 'y')), Eq(true)));
  ASSERT_TRUE(converter_.ProcessInput(std::string(2096, 'y')));
}

// Test that we flush the buffer when told.
TEST_P(HttpToSpdyConverterTest, FlushAfterEndDoesNothing) {
  expected_headers_[status_header_name()] = "200";
  expected_headers_[version_header_name()] = "HTTP/1.1";
  expected_headers_[mod_spdy::http::kContentLength] = "6";
  expected_headers_[mod_spdy::http::kContentType] = "text/plain";

  InSequence seq;
  EXPECT_CALL(receiver_, ReceiveSynReply(Pointee(Eq(expected_headers_)),
                                         Eq(false)));
  EXPECT_CALL(receiver_, ReceiveData(Eq("foobar"), Eq(true)));
  ASSERT_TRUE(converter_.ProcessInput(
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 6\r\n"
      "Content-Type: text/plain\r\n"
      "\r\n"
      "foobar"));
  // Flushing after we're done (even multiple times) should be permitted, but
  // should do nothing.
  converter_.Flush();
  converter_.Flush();
  converter_.Flush();
}

// Run each test over both SPDY v2 and SPDY v3.
INSTANTIATE_TEST_CASE_P(Spdy2And3, HttpToSpdyConverterTest, testing::Values(
    mod_spdy::spdy::SPDY_VERSION_2, mod_spdy::spdy::SPDY_VERSION_3,
    mod_spdy::spdy::SPDY_VERSION_3_1));

}  // namespace
