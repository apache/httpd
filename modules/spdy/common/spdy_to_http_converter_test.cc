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

#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "mod_spdy/common/http_request_visitor_interface.h"
#include "mod_spdy/common/protocol_util.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

using mod_spdy::SpdyToHttpConverter;
using testing::Eq;
using testing::InSequence;
using testing::Sequence;

const char* kMethod = "GET";
const char* kScheme = "http";
const char* kHost = "www.example.com";
const char* kPath = "/";
const char* kVersion = "HTTP/1.1";
const char kMultiValue[] = "this\0is\0\0\0four\0\0headers";

class MockHttpRequestVisitor: public mod_spdy::HttpRequestVisitorInterface {
 public:
  MOCK_METHOD3(OnRequestLine, void(const base::StringPiece&,
                                   const base::StringPiece&,
                                   const base::StringPiece&));
  MOCK_METHOD2(OnLeadingHeader, void(const base::StringPiece&,
                                     const base::StringPiece&));
  MOCK_METHOD0(OnLeadingHeadersComplete, void());
  MOCK_METHOD1(OnRawData, void(const base::StringPiece&));
  MOCK_METHOD1(OnDataChunk, void(const base::StringPiece&));
  MOCK_METHOD0(OnDataChunksComplete, void());
  MOCK_METHOD2(OnTrailingHeader, void(const base::StringPiece&,
                                      const base::StringPiece&));
  MOCK_METHOD0(OnTrailingHeadersComplete, void());
  MOCK_METHOD0(OnComplete, void());
};

class SpdyToHttpConverterTest :
      public testing::TestWithParam<mod_spdy::spdy::SpdyVersion> {
 public:
  SpdyToHttpConverterTest() : converter_(GetParam(), &visitor_) {}

 protected:
  void AddRequiredHeaders() {
    if (converter_.spdy_version() < mod_spdy::spdy::SPDY_VERSION_3) {
      headers_[mod_spdy::spdy::kSpdy2Method] = kMethod;
      headers_[mod_spdy::spdy::kSpdy2Scheme] = kScheme;
      headers_[mod_spdy::http::kHost] = kHost;
      headers_[mod_spdy::spdy::kSpdy2Url] = kPath;
      headers_[mod_spdy::spdy::kSpdy2Version] = kVersion;
    } else {
      headers_[mod_spdy::spdy::kSpdy3Method] = kMethod;
      headers_[mod_spdy::spdy::kSpdy3Scheme] = kScheme;
      headers_[mod_spdy::spdy::kSpdy3Host] = kHost;
      headers_[mod_spdy::spdy::kSpdy3Path] = kPath;
      headers_[mod_spdy::spdy::kSpdy3Version] = kVersion;
    }
  }

  MockHttpRequestVisitor visitor_;
  SpdyToHttpConverter converter_;
  net::SpdyHeaderBlock headers_;
};

TEST_P(SpdyToHttpConverterTest, MultiFrameStream) {
  // We expect all calls to happen in the specified order.
  InSequence seq;

  const net::SpdyStreamId stream_id = 1;
  AddRequiredHeaders();

  EXPECT_CALL(visitor_, OnRequestLine(Eq(kMethod), Eq(kPath), Eq(kVersion)));
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("host"), Eq(kHost)));
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("transfer-encoding"),
                                        Eq("chunked")));
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq(mod_spdy::http::kAcceptEncoding),
                                        Eq(mod_spdy::http::kGzipDeflate)));
  EXPECT_CALL(visitor_, OnLeadingHeadersComplete());
  scoped_ptr<net::SpdySynStreamIR> syn_stream_frame(
      new net::SpdySynStreamIR(stream_id));
  syn_stream_frame->set_priority(1);
  syn_stream_frame->GetMutableNameValueBlock()->insert(
      headers_.begin(), headers_.end());
  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertSynStreamFrame(*syn_stream_frame));

  EXPECT_CALL(visitor_, OnDataChunk(Eq(kHost)));
  scoped_ptr<net::SpdyDataIR> data_frame_1(
      new net::SpdyDataIR(stream_id, kHost));
  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertDataFrame(*data_frame_1));

  // Should be no call to OnDataChunk for an empty data frame.
  scoped_ptr<net::SpdyDataIR> data_frame_empty(
      new net::SpdyDataIR(stream_id, ""));
  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertDataFrame(*data_frame_empty));

  EXPECT_CALL(visitor_, OnDataChunk(Eq(kVersion)));
  EXPECT_CALL(visitor_, OnDataChunksComplete());
  EXPECT_CALL(visitor_, OnComplete());
  scoped_ptr<net::SpdyDataIR> data_frame_2(
      new net::SpdyDataIR(stream_id, kVersion));
  data_frame_2->set_fin(true);
  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertDataFrame(*data_frame_2));
}

TEST_P(SpdyToHttpConverterTest, SynFrameWithHeaders) {
  AddRequiredHeaders();
  headers_["foo"] = "bar";
  headers_[mod_spdy::http::kAcceptEncoding] = "deflate, gzip, lzma";

  // Create a multi-valued header to verify that it's processed
  // properly.
  std::string multi_values(kMultiValue, sizeof(kMultiValue));
  headers_["multi"] = multi_values;

  // Also make sure "junk" headers get skipped over.
  headers_["empty"] = std::string("\0\0\0", 3);

  scoped_ptr<net::SpdySynStreamIR> syn_frame(new net::SpdySynStreamIR(1));
  syn_frame->set_priority(1);
  syn_frame->set_fin(true);
  syn_frame->GetMutableNameValueBlock()->insert(
      headers_.begin(), headers_.end());

  // We expect a call to OnRequestLine(), followed by several calls to
  // OnLeadingHeader() (the order of the calls to OnLeadingHeader() is
  // non-deterministic so we put each in its own Sequence), followed by a final
  // call to OnLeadingHeadersComplete() and OnComplete().
  Sequence s1, s2, s3, s4;
  EXPECT_CALL(visitor_,
              OnRequestLine(Eq(kMethod), Eq(kPath), Eq(kVersion)))
      .InSequence(s1, s2, s3, s4);

  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("foo"), Eq("bar")))
      .InSequence(s1);

  EXPECT_CALL(visitor_, OnLeadingHeader(Eq(mod_spdy::http::kAcceptEncoding),
                                        Eq("deflate, gzip, lzma")))
      .InSequence(s2);

  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("multi"), Eq("this")))
      .InSequence(s3);
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("multi"), Eq("is")))
      .InSequence(s3);
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("multi"), Eq("four")))
      .InSequence(s3);
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("multi"), Eq("headers")))
      .InSequence(s3);

  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("host"), Eq(kHost)))
      .InSequence(s4);

  EXPECT_CALL(visitor_, OnLeadingHeadersComplete()).InSequence(s1, s2, s3, s4);

  EXPECT_CALL(visitor_, OnComplete()).InSequence(s1, s2, s3, s4);

  // Trigger the calls to the mock object by passing the frame to the
  // converter.
  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertSynStreamFrame(*syn_frame));
}

TEST_P(SpdyToHttpConverterTest, TrailingHeaders) {
  // First, send a SYN_STREAM frame without FLAG_FIN set.  We should get the
  // headers out that we sent, but no call yet to OnLeadingHeadersComplete,
  // because there might still be a HEADERS frame.
  AddRequiredHeaders();
  headers_["foo"] = "bar";
  scoped_ptr<net::SpdySynStreamIR> syn_frame(new net::SpdySynStreamIR(1));
  syn_frame->set_priority(1);
  syn_frame->GetMutableNameValueBlock()->insert(
      headers_.begin(), headers_.end());

  Sequence s1, s2;
  EXPECT_CALL(visitor_, OnRequestLine(Eq(kMethod), Eq(kPath), Eq(kVersion)))
      .InSequence(s1, s2);
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("foo"), Eq("bar")))
      .InSequence(s1);
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("host"), Eq(kHost)))
      .InSequence(s2);

  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertSynStreamFrame(*syn_frame));

  // Next, send a DATA frame.  This should trigger the accept-encoding and
  // transfer-encoding headers, and the end of the leading headers (along with
  // the data itself, of course).
  scoped_ptr<net::SpdyDataIR> data_frame(
      new net::SpdyDataIR(1, "Hello, world!\n"));

  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("transfer-encoding"),
                                        Eq("chunked"))).InSequence(s1, s2);
  EXPECT_CALL(visitor_, OnLeadingHeader(
      Eq(mod_spdy::http::kAcceptEncoding),
      Eq(mod_spdy::http::kGzipDeflate))).InSequence(s1, s2);
  EXPECT_CALL(visitor_, OnLeadingHeadersComplete()).InSequence(s1, s2);
  EXPECT_CALL(visitor_, OnDataChunk(Eq("Hello, world!\n"))).InSequence(s1, s2);

  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertDataFrame(*data_frame));

  // Finally, send a HEADERS frame with FLAG_FIN set.  Since this is the end of
  // the stream, we should get out a trailing header and the HTTP stream should
  // be closed.
  headers_.clear();
  headers_["quux"] = "baz";
  scoped_ptr<net::SpdyHeadersIR> headers_frame(new net::SpdyHeadersIR(1));
  headers_frame->set_fin(true);
  headers_frame->GetMutableNameValueBlock()->insert(
      headers_.begin(), headers_.end());

  EXPECT_CALL(visitor_, OnDataChunksComplete()).InSequence(s1, s2);
  EXPECT_CALL(visitor_, OnTrailingHeader(Eq("quux"), Eq("baz")))
      .InSequence(s1, s2);
  EXPECT_CALL(visitor_, OnTrailingHeadersComplete()).InSequence(s1, s2);
  EXPECT_CALL(visitor_, OnComplete()).InSequence(s1, s2);

  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertHeadersFrame(*headers_frame));
}

TEST_P(SpdyToHttpConverterTest, WithContentLength) {
  // First, send a SYN_STREAM frame without FLAG_FIN set.  We should get the
  // headers out that we sent, but no call yet to OnLeadingHeadersComplete,
  // because there might still be a HEADERS frame.
  AddRequiredHeaders();
  headers_["content-length"] = "11";
  scoped_ptr<net::SpdySynStreamIR> syn_frame(new net::SpdySynStreamIR(1));
  syn_frame->set_priority(1);
  syn_frame->GetMutableNameValueBlock()->insert(
      headers_.begin(), headers_.end());

  Sequence s1, s2;
  EXPECT_CALL(visitor_, OnRequestLine(Eq(kMethod), Eq(kPath), Eq(kVersion)))
      .InSequence(s1, s2);
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("content-length"), Eq("11")))
      .InSequence(s1);
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("host"), Eq(kHost)))
      .InSequence(s2);

  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertSynStreamFrame(*syn_frame));

  // Next, send a DATA frame.  This should trigger the end of the leading
  // headers (along with the data itself, of course), but because we sent a
  // content-length, the data should not be chunked.
  scoped_ptr<net::SpdyDataIR> data_frame(
      new net::SpdyDataIR(1, "foobar=quux"));

  EXPECT_CALL(visitor_, OnLeadingHeader(
      Eq(mod_spdy::http::kAcceptEncoding),
      Eq(mod_spdy::http::kGzipDeflate))).InSequence(s1, s2);
  EXPECT_CALL(visitor_, OnLeadingHeadersComplete()).InSequence(s1, s2);
  EXPECT_CALL(visitor_, OnRawData(Eq("foobar=quux"))).InSequence(s1, s2);

  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertDataFrame(*data_frame));

  // Finally, send a HEADERS frame with FLAG_FIN set.  Since we're not chunking
  // this stream, the trailing headers should be ignored.
  headers_.clear();
  headers_["x-metadata"] = "baz";
  scoped_ptr<net::SpdyHeadersIR> headers_frame(new net::SpdyHeadersIR(1));
  headers_frame->set_fin(true);
  headers_frame->GetMutableNameValueBlock()->insert(
      headers_.begin(), headers_.end());

  EXPECT_CALL(visitor_, OnComplete()).InSequence(s1, s2);

  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertHeadersFrame(*headers_frame));
}

TEST_P(SpdyToHttpConverterTest, DoubleSynStreamFrame) {
  AddRequiredHeaders();
  scoped_ptr<net::SpdySynStreamIR> syn_frame(
      new net::SpdySynStreamIR(1));
  syn_frame->set_priority(1);
  syn_frame->set_fin(true);
  syn_frame->GetMutableNameValueBlock()->insert(
      headers_.begin(), headers_.end());

  InSequence seq;
  EXPECT_CALL(visitor_, OnRequestLine(Eq(kMethod), Eq(kPath), Eq(kVersion)));
  EXPECT_CALL(visitor_, OnLeadingHeader(Eq("host"), Eq(kHost)));
  EXPECT_CALL(visitor_, OnLeadingHeader(
      Eq(mod_spdy::http::kAcceptEncoding),
      Eq(mod_spdy::http::kGzipDeflate)));
  EXPECT_CALL(visitor_, OnLeadingHeadersComplete());
  EXPECT_CALL(visitor_, OnComplete());

  EXPECT_EQ(SpdyToHttpConverter::SPDY_CONVERTER_SUCCESS,
            converter_.ConvertSynStreamFrame(*syn_frame));
  EXPECT_EQ(SpdyToHttpConverter::EXTRA_SYN_STREAM,
            converter_.ConvertSynStreamFrame(*syn_frame));
}

TEST_P(SpdyToHttpConverterTest, HeadersFrameBeforeSynStreamFrame) {
  headers_["x-foo"] = "bar";
  scoped_ptr<net::SpdyHeadersIR> headers_frame(new net::SpdyHeadersIR(1));
  headers_frame->GetMutableNameValueBlock()->insert(
      headers_.begin(), headers_.end());
  EXPECT_EQ(SpdyToHttpConverter::FRAME_BEFORE_SYN_STREAM,
            converter_.ConvertHeadersFrame(*headers_frame));
}

TEST_P(SpdyToHttpConverterTest, DataFrameBeforeSynStreamFrame) {
  scoped_ptr<net::SpdyDataIR> data_frame(
      new net::SpdyDataIR(1, kHost));
  EXPECT_EQ(SpdyToHttpConverter::FRAME_BEFORE_SYN_STREAM,
            converter_.ConvertDataFrame(*data_frame));
}

// Run each test over both SPDY v2 and SPDY v3.
INSTANTIATE_TEST_CASE_P(Spdy2And3, SpdyToHttpConverterTest, testing::Values(
    mod_spdy::spdy::SPDY_VERSION_2, mod_spdy::spdy::SPDY_VERSION_3,
    mod_spdy::spdy::SPDY_VERSION_3_1));

}  // namespace
