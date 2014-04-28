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

#include <string>

#include "httpd.h"
#include "apr_buckets.h"
#include "apr_tables.h"
#include "util_filter.h"

#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "mod_spdy/apache/pool_util.h"
#include "mod_spdy/common/protocol_util.h"
#include "mod_spdy/common/shared_flow_control_window.h"
#include "mod_spdy/common/spdy_frame_priority_queue.h"
#include "mod_spdy/common/spdy_stream.h"
#include "mod_spdy/common/testing/spdy_frame_matchers.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

class MockSpdyServerPushInterface : public mod_spdy::SpdyServerPushInterface {
 public:
    MOCK_METHOD4(StartServerPush,
                 mod_spdy::SpdyServerPushInterface::PushStatus(
                     net::SpdyStreamId associated_stream_id,
                     int32 server_push_depth,
                     net::SpdyPriority priority,
                     const net::SpdyNameValueBlock& request_headers));
};

class SpdyToHttpFilterTest :
      public testing::TestWithParam<mod_spdy::spdy::SpdyVersion> {
 public:
  SpdyToHttpFilterTest()
      : spdy_version_(GetParam()),
        stream_id_(1),
        priority_(0u),
        shared_window_(net::kSpdyStreamInitialWindowSize,
                       net::kSpdyStreamInitialWindowSize),
        stream_(spdy_version_, stream_id_, 0, 0, priority_,
                net::kSpdyStreamInitialWindowSize, &output_queue_,
                &shared_window_, &pusher_),
        spdy_to_http_filter_(&stream_) {
    bucket_alloc_ = apr_bucket_alloc_create(local_.pool());
    connection_ = static_cast<conn_rec*>(
        apr_pcalloc(local_.pool(), sizeof(conn_rec)));
    connection_->pool = local_.pool();
    connection_->bucket_alloc = bucket_alloc_;
    ap_filter_ = static_cast<ap_filter_t*>(
        apr_pcalloc(local_.pool(), sizeof(ap_filter_t)));
    ap_filter_->c = connection_;
    brigade_ = apr_brigade_create(local_.pool(), bucket_alloc_);
  }

 protected:
  void PostSynStreamFrame(bool fin, const net::SpdyNameValueBlock& headers) {
    scoped_ptr<net::SpdySynStreamIR> frame(
        new net::SpdySynStreamIR(stream_id_));
    frame->set_priority(priority_);
    frame->set_fin(fin);
    frame->GetMutableNameValueBlock()->insert(headers.begin(), headers.end());
    stream_.PostInputFrame(frame.release());
  }

  void PostHeadersFrame(bool fin, const net::SpdyNameValueBlock& headers) {
    scoped_ptr<net::SpdyHeadersIR> frame(new net::SpdyHeadersIR(stream_id_));
    frame->set_fin(fin);
    frame->GetMutableNameValueBlock()->insert(headers.begin(), headers.end());
    stream_.PostInputFrame(frame.release());
  }

  void PostDataFrame(bool fin, const base::StringPiece& payload) {
    scoped_ptr<net::SpdyDataIR> frame(
        new net::SpdyDataIR(stream_id_, payload));
    frame->set_fin(fin);
    EXPECT_TRUE(shared_window_.OnReceiveInputData(payload.size()));
    stream_.PostInputFrame(frame.release());
  }

  apr_status_t Read(ap_input_mode_t mode, apr_read_type_e block,
                    apr_off_t readbytes) {
    return spdy_to_http_filter_.Read(ap_filter_, brigade_,
                                     mode, block, readbytes);
  }

  void ExpectTransientBucket(const std::string& expected) {
    ASSERT_FALSE(APR_BRIGADE_EMPTY(brigade_))
        << "Expected TRANSIENT bucket, but brigade is empty.";
    apr_bucket* bucket = APR_BRIGADE_FIRST(brigade_);
    ASSERT_TRUE(APR_BUCKET_IS_TRANSIENT(bucket))
        << "Expected TRANSIENT bucket, but found " << bucket->type->name
        << " bucket.";
    const char* data = NULL;
    apr_size_t size = 0;
    ASSERT_EQ(APR_SUCCESS, apr_bucket_read(
        bucket, &data, &size, APR_NONBLOCK_READ));
    EXPECT_EQ(expected, std::string(data, size));
    apr_bucket_delete(bucket);
  }

  void ExpectEosBucket() {
    ASSERT_FALSE(APR_BRIGADE_EMPTY(brigade_))
        << "Expected EOS bucket, but brigade is empty.";
    apr_bucket* bucket = APR_BRIGADE_FIRST(brigade_);
    ASSERT_TRUE(APR_BUCKET_IS_EOS(bucket))
        << "Expected EOS bucket, but found " << bucket->type->name
        << " bucket.";
    apr_bucket_delete(bucket);
  }

  void ExpectEndOfBrigade() {
    ASSERT_TRUE(APR_BRIGADE_EMPTY(brigade_))
        << "Expected brigade to be empty, but found "
        << APR_BRIGADE_FIRST(brigade_)->type->name << " bucket.";
    ASSERT_EQ(APR_SUCCESS, apr_brigade_cleanup(brigade_));
  }

  void ExpectRstStream(net::SpdyRstStreamStatus status) {
    net::SpdyFrameIR* raw_frame;
    ASSERT_TRUE(output_queue_.Pop(&raw_frame))
        << "Expected RST_STREAM frame, but output queue is empty.";
    scoped_ptr<net::SpdyFrameIR> frame(raw_frame);
    EXPECT_THAT(*frame, mod_spdy::testing::IsRstStream(stream_id_, status));
  }

  void ExpectNoMoreOutputFrames() {
    EXPECT_TRUE(output_queue_.IsEmpty());
  }

  bool is_spdy2() const { return GetParam() < mod_spdy::spdy::SPDY_VERSION_3; }

  const char* host_header_name() const {
    return is_spdy2() ? mod_spdy::http::kHost : mod_spdy::spdy::kSpdy3Host;
  }
  const char* method_header_name() const {
    return (is_spdy2() ? mod_spdy::spdy::kSpdy2Method :
            mod_spdy::spdy::kSpdy3Method);
  }
  const char* path_header_name() const {
    return (is_spdy2() ? mod_spdy::spdy::kSpdy2Url :
            mod_spdy::spdy::kSpdy3Path);
  }
  const char* scheme_header_name() const {
    return (is_spdy2() ? mod_spdy::spdy::kSpdy2Scheme :
            mod_spdy::spdy::kSpdy3Scheme);
  }
  const char* version_header_name() const {
    return (is_spdy2() ? mod_spdy::spdy::kSpdy2Version :
            mod_spdy::spdy::kSpdy3Version);
  }

  const mod_spdy::spdy::SpdyVersion spdy_version_;
  const net::SpdyStreamId stream_id_;
  const net::SpdyPriority priority_;
  mod_spdy::SpdyFramePriorityQueue output_queue_;
  mod_spdy::SharedFlowControlWindow shared_window_;
  MockSpdyServerPushInterface pusher_;
  mod_spdy::SpdyStream stream_;
  mod_spdy::SpdyToHttpFilter spdy_to_http_filter_;

  mod_spdy::LocalPool local_;
  apr_bucket_alloc_t* bucket_alloc_;
  conn_rec* connection_;
  ap_filter_t* ap_filter_;
  apr_bucket_brigade* brigade_;
};

TEST_P(SpdyToHttpFilterTest, SimpleGetRequest) {
  // Perform an INIT.  It should succeed, with no effect.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_INIT, APR_BLOCK_READ, 1337));
  ExpectEndOfBrigade();

  // Invoke the fitler in non-blocking GETLINE mode.  We shouldn't get anything
  // yet, because we haven't sent any frames from the client yet.
  ASSERT_TRUE(APR_STATUS_IS_EAGAIN(
      Read(AP_MODE_GETLINE, APR_NONBLOCK_READ, 0)));
  ExpectEndOfBrigade();

  // Send a SYN_STREAM frame from the client, with FLAG_FIN set.
  net::SpdyNameValueBlock headers;
  headers[host_header_name()] = "www.example.com";
  headers[method_header_name()] = "GET";
  headers["referer"] = "https://www.example.com/index.html";
  headers[scheme_header_name()] = "https";
  headers[path_header_name()] = "/foo/bar/index.html";
  headers["user-agent"] = "ModSpdyUnitTest/1.0";
  headers[version_header_name()] = "HTTP/1.1";
  headers["x-do-not-track"] = "1";
  PostSynStreamFrame(true, headers);

  // Invoke the filter in blocking GETLINE mode.  We should get back just the
  // HTTP request line.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_GETLINE, APR_BLOCK_READ, 0));
  ExpectTransientBucket("GET /foo/bar/index.html HTTP/1.1\r\n");
  ExpectEndOfBrigade();

  // Now do a SPECULATIVE read.  We should get back a few bytes.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_SPECULATIVE, APR_NONBLOCK_READ, 8));
  ExpectTransientBucket("host: ww");
  ExpectEndOfBrigade();

  // Now do another GETLINE read.  We should get back the first header line,
  // including the data we just read speculatively.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_GETLINE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("host: www.example.com\r\n");
  ExpectEndOfBrigade();

  // Do a READBYTES read.  We should get back a few bytes.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_READBYTES, APR_NONBLOCK_READ, 12));
  ExpectTransientBucket("referer: htt");
  ExpectEndOfBrigade();

  // Do another GETLINE read.  We should get back the rest of the header line,
  // *not* including the data we just read.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_GETLINE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("ps://www.example.com/index.html\r\n");
  ExpectEndOfBrigade();

  // Finally, do an EXHAUSTIVE read.  We should get back everything that
  // remains, terminating with an EOS bucket.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("user-agent: ModSpdyUnitTest/1.0\r\n"
                        "x-do-not-track: 1\r\n"
                        "accept-encoding: gzip,deflate\r\n"
                        "\r\n");
  ExpectEosBucket();
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();

  // There's no more data left; attempting another read should result in EOF.
  ASSERT_TRUE(APR_STATUS_IS_EOF(
      Read(AP_MODE_READBYTES, APR_NONBLOCK_READ, 4)));
}

TEST_P(SpdyToHttpFilterTest, SimplePostRequest) {
  // Send a SYN_STREAM frame from the client.
  net::SpdyNameValueBlock headers;
  headers[host_header_name()] = "www.example.com";
  headers[method_header_name()] = "POST";
  headers["referer"] = "https://www.example.com/index.html";
  headers[scheme_header_name()] = "https";
  headers[path_header_name()] = "/erase/the/whole/database.cgi";
  headers["user-agent"] = "ModSpdyUnitTest/1.0";
  headers[version_header_name()] = "HTTP/1.1";
  PostSynStreamFrame(false, headers);

  // Do a nonblocking READBYTES read.  We ask for lots of bytes, but since it's
  // nonblocking we should immediately get back what's available so far.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_READBYTES, APR_NONBLOCK_READ, 4096));
  ExpectTransientBucket("POST /erase/the/whole/database.cgi HTTP/1.1\r\n"
                        "host: www.example.com\r\n"
                        "referer: https://www.example.com/index.html\r\n"
                        "user-agent: ModSpdyUnitTest/1.0\r\n");
  ExpectEndOfBrigade();

  // There's nothing more available yet, so a nonblocking read should fail.
  ASSERT_TRUE(APR_STATUS_IS_EAGAIN(
      Read(AP_MODE_READBYTES, APR_NONBLOCK_READ, 4)));
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();

  // Send some DATA frames.
  PostDataFrame(false, "Hello, world!\nPlease erase ");
  PostDataFrame(false, "the whole database ");
  PostDataFrame(true, "immediately.\nThanks!\n");

  // Now read in the data a bit at a time.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_GETLINE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("transfer-encoding: chunked\r\n");
  ExpectEndOfBrigade();
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_GETLINE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("accept-encoding: gzip,deflate\r\n");
  ExpectEndOfBrigade();
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_GETLINE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("\r\n");
  ExpectEndOfBrigade();
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_GETLINE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("1B\r\n");
  ExpectEndOfBrigade();
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_READBYTES, APR_NONBLOCK_READ, 24));
  ExpectTransientBucket("Hello, world!\nPlease era");
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_SPECULATIVE, APR_NONBLOCK_READ, 15));
  ExpectTransientBucket("se \r\n13\r\nthe wh");
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_READBYTES, APR_NONBLOCK_READ, 36));
  ExpectTransientBucket("se \r\n13\r\nthe whole database \r\n15\r\nim");
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_READBYTES, APR_NONBLOCK_READ, 21));
  ExpectTransientBucket("mediately.\nThanks!\n\r\n");
  ExpectEndOfBrigade();
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_GETLINE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("0\r\n");
  ExpectEndOfBrigade();
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_GETLINE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("\r\n");
  ExpectEosBucket();
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();

  // There's no more data left; attempting another read should result in EOF.
  ASSERT_TRUE(APR_STATUS_IS_EOF(Read(AP_MODE_GETLINE, APR_BLOCK_READ, 0)));
}

TEST_P(SpdyToHttpFilterTest, PostRequestWithHeadersFrames) {
  // Send a SYN_STREAM frame from the client.
  net::SpdyNameValueBlock headers;
  headers[host_header_name()] = "www.example.net";
  headers[method_header_name()] = "POST";
  headers["referer"] = "https://www.example.net/index.html";
  headers[scheme_header_name()] = "https";
  headers[path_header_name()] = "/erase/the/whole/database.cgi";
  headers["user-agent"] = "ModSpdyUnitTest/1.0";
  headers[version_header_name()] = "HTTP/1.1";
  PostSynStreamFrame(false, headers);

  // Send some DATA and HEADERS frames.  The HEADERS frames should get buffered
  // and placed at the end of the HTTP request body as trailing headers.
  PostDataFrame(false, "Please erase ");
  net::SpdyNameValueBlock headers2;
  headers2["x-super-cool"] = "foo";
  PostHeadersFrame(false, headers2);
  PostDataFrame(false, "everything ");
  net::SpdyNameValueBlock headers3;
  headers3["x-awesome"] = "quux";
  PostHeadersFrame(false, headers3);
  PostDataFrame(true, "immediately!!\n");

  // Read in all the data.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("POST /erase/the/whole/database.cgi HTTP/1.1\r\n"
                        "host: www.example.net\r\n"
                        "referer: https://www.example.net/index.html\r\n"
                        "user-agent: ModSpdyUnitTest/1.0\r\n"
                        "transfer-encoding: chunked\r\n"
                        "accept-encoding: gzip,deflate\r\n"
                        "\r\n"
                        "D\r\n"
                        "Please erase \r\n"
                        "B\r\n"
                        "everything \r\n"
                        "E\r\n"
                        "immediately!!\n\r\n"
                        "0\r\n"
                        "x-awesome: quux\r\n"
                        "x-super-cool: foo\r\n"
                        "\r\n");
  ExpectEosBucket();
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();
}

TEST_P(SpdyToHttpFilterTest, GetRequestWithHeadersRightAfterSynStream) {
  // Send a SYN_STREAM frame with some of the headers.
  net::SpdyNameValueBlock headers;
  headers[host_header_name()] = "www.example.org";
  headers[method_header_name()] = "GET";
  headers["referer"] = "https://www.example.org/foo/bar.html";
  headers[scheme_header_name()] = "https";
  headers[path_header_name()] = "/index.html";
  headers[version_header_name()] = "HTTP/1.1";
  PostSynStreamFrame(false, headers);

  // Read in everything that's available so far.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("GET /index.html HTTP/1.1\r\n"
                        "host: www.example.org\r\n"
                        "referer: https://www.example.org/foo/bar.html\r\n");
  ExpectEndOfBrigade();

  // Send a HEADERS frame with the rest of the headers.
  net::SpdyNameValueBlock headers2;
  headers2["accept-encoding"] = "deflate, gzip";
  headers2["user-agent"] = "ModSpdyUnitTest/1.0";
  PostHeadersFrame(true, headers2);

  // Read in the rest of the request.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("accept-encoding: deflate, gzip\r\n"
                        "user-agent: ModSpdyUnitTest/1.0\r\n"
                        "\r\n");
  ExpectEosBucket();
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();
}

TEST_P(SpdyToHttpFilterTest, PostRequestWithHeadersRightAfterSynStream) {
  // Send a SYN_STREAM frame from the client.
  net::SpdyNameValueBlock headers;
  headers[host_header_name()] = "www.example.org";
  headers[method_header_name()] = "POST";
  headers["referer"] = "https://www.example.org/index.html";
  headers[scheme_header_name()] = "https";
  headers[path_header_name()] = "/delete/everything.py";
  headers[version_header_name()] = "HTTP/1.1";
  headers["x-zzzz"] = "4Z";
  PostSynStreamFrame(false, headers);

  // Send a HEADERS frame before sending any data frames.
  net::SpdyNameValueBlock headers2;
  headers2["user-agent"] = "ModSpdyUnitTest/1.0";
  PostHeadersFrame(false, headers2);

  // Now send a couple DATA frames and a final HEADERS frame.
  PostDataFrame(false, "Please erase everything immediately");
  PostDataFrame(false, ", thanks!\n");
  net::SpdyNameValueBlock headers3;
  headers3["x-qqq"] = "3Q";
  PostHeadersFrame(true, headers3);

  // Read in all the data.  The first HEADERS frame should get put in before
  // the data, and the last HEADERS frame should get put in after the data.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("POST /delete/everything.py HTTP/1.1\r\n"
                        "host: www.example.org\r\n"
                        "referer: https://www.example.org/index.html\r\n"
                        "x-zzzz: 4Z\r\n"
                        "user-agent: ModSpdyUnitTest/1.0\r\n"
                        "transfer-encoding: chunked\r\n"
                        "accept-encoding: gzip,deflate\r\n"
                        "\r\n"
                        "23\r\n"
                        "Please erase everything immediately\r\n"
                        "A\r\n"
                        ", thanks!\n\r\n"
                        "0\r\n"
                        "x-qqq: 3Q\r\n"
                        "\r\n");
  ExpectEosBucket();
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();
}

TEST_P(SpdyToHttpFilterTest, PostRequestWithEmptyDataFrameInMiddle) {
  // Send a SYN_STREAM frame from the client.
  net::SpdyNameValueBlock headers;
  headers[host_header_name()] = "www.example.org";
  headers[method_header_name()] = "POST";
  headers["referer"] = "https://www.example.org/index.html";
  headers[scheme_header_name()] = "https";
  headers[path_header_name()] = "/do/some/stuff.py";
  headers[version_header_name()] = "HTTP/1.1";
  PostSynStreamFrame(false, headers);

  // Now send a few DATA frames, with a zero-length data frame in the middle.
  PostDataFrame(false, "Please do");
  PostDataFrame(false, " some ");
  PostDataFrame(false, "");
  PostDataFrame(true, "stuff.\n");

  // Read in all the data.  The empty data frame should be ignored.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("POST /do/some/stuff.py HTTP/1.1\r\n"
                        "host: www.example.org\r\n"
                        "referer: https://www.example.org/index.html\r\n"
                        "transfer-encoding: chunked\r\n"
                        "accept-encoding: gzip,deflate\r\n"
                        "\r\n"
                        "9\r\n"
                        "Please do\r\n"
                        "6\r\n"
                        " some \r\n"
                        "7\r\n"
                        "stuff.\n\r\n"
                        "0\r\n"
                        "\r\n");
  ExpectEosBucket();
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();
}

TEST_P(SpdyToHttpFilterTest, PostRequestWithEmptyDataFrameAtEnd) {
  // Send a SYN_STREAM frame from the client.
  net::SpdyNameValueBlock headers;
  headers[host_header_name()] = "www.example.org";
  headers[method_header_name()] = "POST";
  headers["referer"] = "https://www.example.org/index.html";
  headers[scheme_header_name()] = "https";
  headers[path_header_name()] = "/do/some/stuff.py";
  headers[version_header_name()] = "HTTP/1.1";
  PostSynStreamFrame(false, headers);

  // Now send a few DATA frames, with a zero-length data frame at the end.
  PostDataFrame(false, "Please do");
  PostDataFrame(false, " some ");
  PostDataFrame(false, "stuff.\n");
  PostDataFrame(true, "");

  // Read in all the data.  The empty data frame should be ignored (except for
  // its FLAG_FIN).
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("POST /do/some/stuff.py HTTP/1.1\r\n"
                        "host: www.example.org\r\n"
                        "referer: https://www.example.org/index.html\r\n"
                        "transfer-encoding: chunked\r\n"
                        "accept-encoding: gzip,deflate\r\n"
                        "\r\n"
                        "9\r\n"
                        "Please do\r\n"
                        "6\r\n"
                        " some \r\n"
                        "7\r\n"
                        "stuff.\n\r\n"
                        "0\r\n"
                        "\r\n");
  ExpectEosBucket();
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();
}

TEST_P(SpdyToHttpFilterTest, PostRequestWithContentLength) {
  // Send a SYN_STREAM frame from the client.
  net::SpdyNameValueBlock headers;
  headers[host_header_name()] = "www.example.org";
  headers[method_header_name()] = "POST";
  headers["referer"] = "https://www.example.org/index.html";
  headers[scheme_header_name()] = "https";
  headers[path_header_name()] = "/do/some/stuff.py";
  headers[version_header_name()] = "HTTP/1.1";
  PostSynStreamFrame(false, headers);

  // Send a few more headers before sending data, including a content-length.
  net::SpdyNameValueBlock headers2;
  headers2["content-length"] = "22";
  headers2["user-agent"] = "ModSpdyUnitTest/1.0";
  PostHeadersFrame(false, headers2);

  // Now send a few DATA frames.
  PostDataFrame(false, "Please do");
  PostDataFrame(false, " some ");
  PostDataFrame(true, "stuff.\n");

  // Read in all the data.  Because we supplied a content-length, chunked
  // encoding should not be used (to support modules that don't work with
  // chunked requests).
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("POST /do/some/stuff.py HTTP/1.1\r\n"
                        "host: www.example.org\r\n"
                        "referer: https://www.example.org/index.html\r\n"
                        "content-length: 22\r\n"
                        "user-agent: ModSpdyUnitTest/1.0\r\n"
                        "accept-encoding: gzip,deflate\r\n"
                        "\r\n"
                        "Please do some stuff.\n");
  ExpectEosBucket();
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();
}

TEST_P(SpdyToHttpFilterTest, PostRequestWithContentLengthAndTrailingHeaders) {
  // Send a SYN_STREAM frame from the client, including a content-length.
  net::SpdyNameValueBlock headers;
  headers["content-length"] = "22";
  headers[host_header_name()] = "www.example.org";
  headers[method_header_name()] = "POST";
  headers["referer"] = "https://www.example.org/index.html";
  headers[scheme_header_name()] = "https";
  headers[path_header_name()] = "/do/some/stuff.py";
  headers[version_header_name()] = "HTTP/1.1";
  PostSynStreamFrame(false, headers);

  // Now send a few DATA frames.
  PostDataFrame(false, "Please do");
  PostDataFrame(false, " some ");
  PostDataFrame(false, "stuff.\n");

  // Finish with a HEADERS frame.
  net::SpdyNameValueBlock headers2;
  headers2["x-metadata"] = "foobar";
  headers2["x-whatever"] = "quux";
  PostHeadersFrame(true, headers2);

  // Read in all the data.  Because we supplied a content-length, chunked
  // encoding should not be used, and as an unfortunate consequence, we must
  // therefore ignore the trailing headers (justified in that, at least in
  // HTTP, they're generally only used for ignorable metadata; in fact, they're
  // not generally used at all).
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0));
  // One (usually irrelevant) quirk of our implementation is that the host
  // header appears in a slightly different place for SPDY v2 and SPDY v3.
  // This is beacuse in SPDY v3 the host header is ":host", which sorts
  // earlier, and which we transform into the HTTP header "host".
  if (is_spdy2()) {
    ExpectTransientBucket("POST /do/some/stuff.py HTTP/1.1\r\n"
                          "content-length: 22\r\n"
                          "host: www.example.org\r\n"
                          "referer: https://www.example.org/index.html\r\n"
                          "accept-encoding: gzip,deflate\r\n"
                          "\r\n"
                          "Please do some stuff.\n");
  } else {
    ExpectTransientBucket("POST /do/some/stuff.py HTTP/1.1\r\n"
                          "host: www.example.org\r\n"
                          "content-length: 22\r\n"
                          "referer: https://www.example.org/index.html\r\n"
                          "accept-encoding: gzip,deflate\r\n"
                          "\r\n"
                          "Please do some stuff.\n");
  }
  ExpectEosBucket();
  ExpectEndOfBrigade();
  ExpectNoMoreOutputFrames();
}

TEST_P(SpdyToHttpFilterTest, ExtraSynStream) {
  // Send a SYN_STREAM frame from the client.
  net::SpdyNameValueBlock headers;
  headers[host_header_name()] = "www.example.com";
  headers[method_header_name()] = "POST";
  headers["referer"] = "https://www.example.com/index.html";
  headers[scheme_header_name()] = "https";
  headers[path_header_name()] = "/erase/the/whole/database.cgi";
  headers["user-agent"] = "ModSpdyUnitTest/1.0";
  headers[version_header_name()] = "HTTP/1.1";
  PostSynStreamFrame(false, headers);

  // Read in all available data.
  ASSERT_EQ(APR_SUCCESS, Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0));
  ExpectTransientBucket("POST /erase/the/whole/database.cgi HTTP/1.1\r\n"
                        "host: www.example.com\r\n"
                        "referer: https://www.example.com/index.html\r\n"
                        "user-agent: ModSpdyUnitTest/1.0\r\n");
  ExpectEndOfBrigade();

  // Now send another SYN_STREAM for the same stream_id, which is illegal.
  PostSynStreamFrame(false, headers);
  // If we try to read more data, we'll get nothing.
  ASSERT_TRUE(APR_STATUS_IS_ECONNABORTED(
      Read(AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ, 0)));
  ExpectEosBucket();
  ExpectEndOfBrigade();
  // The stream should have been aborted.
  ExpectRstStream(net::RST_STREAM_PROTOCOL_ERROR);
  ExpectNoMoreOutputFrames();
  EXPECT_TRUE(stream_.is_aborted());
}

// Run each test over both SPDY v2 and SPDY v3.
INSTANTIATE_TEST_CASE_P(Spdy2And3, SpdyToHttpFilterTest, testing::Values(
    mod_spdy::spdy::SPDY_VERSION_2, mod_spdy::spdy::SPDY_VERSION_3,
    mod_spdy::spdy::SPDY_VERSION_3_1));

}  // namespace
