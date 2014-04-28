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

#include "mod_spdy/common/spdy_session.h"

#include <list>
#include <string>

#include "base/basictypes.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "mod_spdy/common/protocol_util.h"
#include "mod_spdy/common/spdy_server_config.h"
#include "mod_spdy/common/spdy_session_io.h"
#include "mod_spdy/common/spdy_stream_task_factory.h"
#include "mod_spdy/common/testing/spdy_frame_matchers.h"
#include "mod_spdy/common/thread_pool.h"
#include "net/instaweb/util/public/function.h"
#include "net/spdy/buffered_spdy_framer.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using mod_spdy::testing::IsDataFrame;
using mod_spdy::testing::IsGoAway;
using mod_spdy::testing::IsHeaders;
using mod_spdy::testing::IsPing;
using mod_spdy::testing::IsRstStream;
using mod_spdy::testing::IsSettings;
using mod_spdy::testing::IsSynReply;
using mod_spdy::testing::IsSynStream;
using testing::_;
using testing::AllOf;
using testing::AtLeast;
using testing::DoAll;
using testing::Eq;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::NotNull;
using testing::Property;
using testing::Return;
using testing::StrictMock;
using testing::WithArg;

namespace {

void AddRequestHeaders(mod_spdy::spdy::SpdyVersion version,
                       net::SpdyNameValueBlock *headers) {
  const bool spdy2 = version < mod_spdy::spdy::SPDY_VERSION_3;
  (*headers)[spdy2 ? mod_spdy::http::kHost :
             mod_spdy::spdy::kSpdy3Host] = "www.example.com";
  (*headers)[spdy2 ? mod_spdy::spdy::kSpdy2Method :
             mod_spdy::spdy::kSpdy3Method] = "GET";
  (*headers)[spdy2 ? mod_spdy::spdy::kSpdy2Scheme :
             mod_spdy::spdy::kSpdy3Scheme] = "https";
  (*headers)[spdy2 ? mod_spdy::spdy::kSpdy2Url :
             mod_spdy::spdy::kSpdy3Path] = "/foo/index.html";
  (*headers)[spdy2 ? mod_spdy::spdy::kSpdy2Version :
             mod_spdy::spdy::kSpdy3Version] = "HTTP/1.1";
}

void AddResponseHeaders(mod_spdy::spdy::SpdyVersion version,
                        net::SpdyNameValueBlock *headers) {
  const bool spdy2 = version < mod_spdy::spdy::SPDY_VERSION_3;
  (*headers)[spdy2 ? mod_spdy::spdy::kSpdy2Status :
             mod_spdy::spdy::kSpdy3Status] = "200";
  (*headers)[spdy2 ? mod_spdy::spdy::kSpdy2Version :
             mod_spdy::spdy::kSpdy3Version] = "HTTP/1.1";
  (*headers)[mod_spdy::http::kContentType] = "text/html";
}

void AddInitialServerPushHeaders(const std::string& path,
                                 net::SpdyNameValueBlock *headers) {
  (*headers)[mod_spdy::spdy::kSpdy3Host] = "www.example.com";
  (*headers)[mod_spdy::spdy::kSpdy3Path] = path;
  (*headers)[mod_spdy::spdy::kSpdy3Scheme] = "https";
}

class MockSpdySessionIO : public mod_spdy::SpdySessionIO {
 public:
  MOCK_METHOD0(IsConnectionAborted, bool());
  MOCK_METHOD2(ProcessAvailableInput,
               ReadStatus(bool, net::BufferedSpdyFramer*));
  MOCK_METHOD1(SendFrameRaw, WriteStatus(const net::SpdySerializedFrame&));
};

class MockSpdyStreamTaskFactory : public mod_spdy::SpdyStreamTaskFactory {
 public:
  MOCK_METHOD1(NewStreamTask, net_instaweb::Function*(mod_spdy::SpdyStream*));
};

class MockStreamTask : public net_instaweb::Function {
 public:
  MockStreamTask() : stream(NULL) {}
  MOCK_METHOD0(Run, void());
  MOCK_METHOD0(Cancel, void());
  mod_spdy::SpdyStream* stream;
 private:
  DISALLOW_COPY_AND_ASSIGN(MockStreamTask);
};

// gMock action to be used with NewStreamTask.
ACTION_P(ReturnMockTask, task) {
  task->stream = arg0;
  return task;
}

// gMock action to be used with MockStreamTask::Run.
ACTION_P4(StartServerPush, task, priority, path, expected_status) {
  net::SpdyHeaderBlock push_headers;
  AddInitialServerPushHeaders(path, &push_headers);
  EXPECT_EQ(expected_status,
            task->stream->StartServerPush(priority, push_headers));
}

// gMock action to be used with MockStreamTask::Run.
ACTION_P(SendResponseHeaders, task) {
  net::SpdyHeaderBlock headers;
  AddResponseHeaders(task->stream->spdy_version(), &headers);
  if (task->stream->is_server_push()) {
    task->stream->SendOutputHeaders(headers, false);
  } else {
    task->stream->SendOutputSynReply(headers, false);
  }
}

// gMock action to be used with MockStreamTask::Run.
ACTION_P3(SendDataFrame, task, data, fin) {
  task->stream->SendOutputDataFrame(data, fin);
}

// gMock action to be used with MockStreamTask::Run.
ACTION_P(ConsumeInputUntilAborted, task) {
  while (!task->stream->is_aborted()) {
    net::SpdyFrameIR* raw_frame = NULL;
    if (task->stream->GetInputFrame(true, &raw_frame)) {
      delete raw_frame;
    }
  }
}

// An executor that runs all tasks in the same thread, either immediately when
// they are added or when it is told to run them.
class InlineExecutor : public mod_spdy::Executor {
 public:
  InlineExecutor() : run_on_add_(false), stopped_(false) {}
  virtual ~InlineExecutor() { Stop(); }

  virtual void AddTask(net_instaweb::Function* task,
                       net::SpdyPriority priority) {
    if (stopped_) {
      task->CallCancel();
    } else if (run_on_add_) {
      task->CallRun();
    } else {
      tasks_.push_back(task);
    }
  }
  virtual void Stop() {
    stopped_ = true;
    while (!tasks_.empty()) {
      tasks_.front()->CallCancel();
      tasks_.pop_front();
    }
  }
  void RunOne() {
    if (!tasks_.empty()) {
      tasks_.front()->CallRun();
      tasks_.pop_front();
    }
  }
  void RunAll() {
    while (!tasks_.empty()) {
      RunOne();
    }
  }
  void set_run_on_add(bool run) { run_on_add_ = run; }
  bool stopped() const { return stopped_; }

 private:
  std::list<net_instaweb::Function*> tasks_;
  bool run_on_add_;
  bool stopped_;

  DISALLOW_COPY_AND_ASSIGN(InlineExecutor);
};

// A BufferedSpdyFramer visitor that constructs IR objects for the frames it
// parses.
class ClientVisitor : public net::BufferedSpdyFramerVisitorInterface {
 public:
  ClientVisitor() : last_data_(NULL), last_settings_(NULL) {}
  virtual ~ClientVisitor() {}

  virtual void OnError(net::SpdyFramer::SpdyError error_code) {}
  virtual void OnStreamError(net::SpdyStreamId stream_id,
                             const std::string& description) {}
  virtual void OnSynStream(net::SpdyStreamId id, net::SpdyStreamId assoc_id,
                           net::SpdyPriority priority, uint8 slot,
                           bool fin, bool unidirectional,
                           const net::SpdyHeaderBlock& headers) {
    scoped_ptr<net::SpdySynStreamIR> frame(new net::SpdySynStreamIR(id));
    frame->set_associated_to_stream_id(assoc_id);
    frame->set_priority(priority);
    frame->set_slot(slot);
    frame->set_fin(fin);
    frame->set_unidirectional(unidirectional);
    frame->GetMutableNameValueBlock()->insert(
        headers.begin(), headers.end());
    last_frame_.reset(frame.release());
  }
  virtual void OnSynReply(net::SpdyStreamId id, bool fin,
                          const net::SpdyHeaderBlock& headers) {
    scoped_ptr<net::SpdySynReplyIR> frame(new net::SpdySynReplyIR(id));
    frame->set_fin(fin);
    frame->GetMutableNameValueBlock()->insert(
        headers.begin(), headers.end());
    last_frame_.reset(frame.release());
  }
  virtual void OnHeaders(net::SpdyStreamId id, bool fin,
                         const net::SpdyHeaderBlock& headers) {
    scoped_ptr<net::SpdyHeadersIR> frame(new net::SpdyHeadersIR(id));
    frame->set_fin(fin);
    frame->GetMutableNameValueBlock()->insert(
        headers.begin(), headers.end());
    last_frame_.reset(frame.release());
  }
  virtual void OnStreamFrameData(net::SpdyStreamId id, const char* data,
                                 size_t len, bool fin) {
    if (len == 0 && last_data_ != NULL && last_data_ == last_frame_.get()) {
      last_data_->set_fin(fin);
    } else {
      scoped_ptr<net::SpdyDataIR> frame(new net::SpdyDataIR(
          id, base::StringPiece(data, len)));
      frame->set_fin(fin);
      last_data_ = frame.get();
      last_frame_.reset(frame.release());
    }
  }
  virtual void OnSettings(bool clear_persisted) {
    scoped_ptr<net::SpdySettingsIR> frame(new net::SpdySettingsIR);
    frame->set_clear_settings(clear_persisted);
    last_settings_ = frame.get();
    last_frame_.reset(frame.release());
  }
  virtual void OnSetting(net::SpdySettingsIds id, uint8 flags, uint32 value) {
    CHECK(last_settings_ != NULL && last_settings_ == last_frame_.get());
    last_settings_->AddSetting(
        id, (flags & net::SETTINGS_FLAG_PLEASE_PERSIST),
        (flags & net::SETTINGS_FLAG_PERSISTED), value);
  }
  virtual void OnPing(uint32 id) {
    last_frame_.reset(new net::SpdyPingIR(id));
  }
  virtual void OnRstStream(net::SpdyStreamId id,
                           net::SpdyRstStreamStatus status) {
    last_frame_.reset(new net::SpdyRstStreamIR(id, status));
  }
  virtual void OnGoAway(net::SpdyStreamId id, net::SpdyGoAwayStatus status) {
    last_frame_.reset(new net::SpdyGoAwayIR(id, status));
  }
  virtual void OnWindowUpdate(net::SpdyStreamId id, uint32 delta) {
    last_frame_.reset(new net::SpdyWindowUpdateIR(id, delta));
  }
  virtual void OnPushPromise(net::SpdyStreamId id, net::SpdyStreamId promise) {
    last_frame_.reset(new net::SpdyPushPromiseIR(id, promise));
  }

  net::SpdyFrameIR* ReleaseLastFrame() {
    return last_frame_.release();
  }

 private:
  net::SpdyDataIR* last_data_;
  net::SpdySettingsIR* last_settings_;
  scoped_ptr<net::SpdyFrameIR> last_frame_;

  DISALLOW_COPY_AND_ASSIGN(ClientVisitor);
};

ACTION_P2(ClientDecodeFrame, test, matcher) {
  scoped_ptr<net::SpdyFrameIR> frame(test->DecodeFrameOnClient(arg0));
  ASSERT_TRUE(frame != NULL);
  EXPECT_THAT(*frame, matcher);
}

ACTION_P3(SendBackWindowUpdate, test, stream_id, delta) {
  test->ReceiveWindowUpdateFrameFromClient(stream_id, delta);
}

ACTION_P3(SendBackSettings, test, key, value) {
  test->ReceiveSettingsFrameFromClient(key, value);
}

// Base class for SpdySession tests.
class SpdySessionTestBase :
      public testing::TestWithParam<mod_spdy::spdy::SpdyVersion> {
 public:
  SpdySessionTestBase()
      : spdy_version_(GetParam()),
        client_framer_(mod_spdy::SpdyVersionToFramerVersion(spdy_version_),
                       true) {
    client_framer_.set_visitor(&client_visitor_);
    ON_CALL(session_io_, IsConnectionAborted()).WillByDefault(Return(false));
    ON_CALL(session_io_, ProcessAvailableInput(_, NotNull()))
        .WillByDefault(Invoke(this, &SpdySessionTestBase::ReadNextInputChunk));
    ON_CALL(session_io_, SendFrameRaw(_))
        .WillByDefault(Return(mod_spdy::SpdySessionIO::WRITE_SUCCESS));
  }

  // Use as gMock action for ProcessAvailableInput:
  //   Invoke(this, &SpdySessionTest::ReadNextInputChunk)
  mod_spdy::SpdySessionIO::ReadStatus ReadNextInputChunk(
      bool block, net::BufferedSpdyFramer* framer) {
    if (input_queue_.empty()) {
      return mod_spdy::SpdySessionIO::READ_NO_DATA;
    }
    const std::string chunk = input_queue_.front();
    input_queue_.pop_front();
    framer->ProcessInput(chunk.data(), chunk.size());
    return (framer->HasError() ? mod_spdy::SpdySessionIO::READ_ERROR :
            mod_spdy::SpdySessionIO::READ_SUCCESS);
  }

  // This is called by the ClientDecodeFrame gMock action defined above.
  net::SpdyFrameIR* DecodeFrameOnClient(
      const net::SpdySerializedFrame& frame) {
    client_framer_.ProcessInput(frame.data(), frame.size());
    return client_visitor_.ReleaseLastFrame();
  }

  // Push a frame into the input queue.
  void ReceiveFrameFromClient(const net::SpdySerializedFrame& frame) {
    input_queue_.push_back(std::string(frame.data(), frame.size()));
  }

  // Push a PING frame into the input queue.
  void ReceivePingFromClient(uint32 id) {
    scoped_ptr<net::SpdySerializedFrame> frame(
        client_framer_.CreatePingFrame(id));
    ReceiveFrameFromClient(*frame);
  }

  // Push a valid SYN_STREAM frame into the input queue.
  void ReceiveSynStreamFromClient(net::SpdyStreamId stream_id,
                                  net::SpdyPriority priority,
                                  net::SpdyControlFlags flags) {
    net::SpdyHeaderBlock headers;
    AddRequestHeaders(spdy_version_, &headers);
    scoped_ptr<net::SpdySerializedFrame> frame(client_framer_.CreateSynStream(
        stream_id, 0, priority, 0, flags,
        true,  // true = use compression
        &headers));
    ReceiveFrameFromClient(*frame);
  }

  // Push a valid DATA frame into the input queue.
  void ReceiveDataFromClient(net::SpdyStreamId stream_id,
                             base::StringPiece data,
                             net::SpdyDataFlags flags) {
    scoped_ptr<net::SpdySerializedFrame> frame(client_framer_.CreateDataFrame(
        stream_id, data.data(), data.size(), flags));
    ReceiveFrameFromClient(*frame);
  }

  // Push a SETTINGS frame into the input queue.
  void ReceiveSettingsFrameFromClient(
      net::SpdySettingsIds setting, uint32 value) {
    net::SettingsMap settings;
    settings[setting] = std::make_pair(net::SETTINGS_FLAG_NONE, value);
    scoped_ptr<net::SpdySerializedFrame> frame(
        client_framer_.CreateSettings(settings));
    ReceiveFrameFromClient(*frame);
  }

  // Push a WINDOW_UPDATE frame into the input queue.
  void ReceiveWindowUpdateFrameFromClient(
      net::SpdyStreamId stream_id, uint32 delta) {
    scoped_ptr<net::SpdySerializedFrame> frame(
        client_framer_.CreateWindowUpdate(stream_id, delta));
    ReceiveFrameFromClient(*frame);
  }

 protected:
  void ExpectSendFrame(::testing::Matcher<const net::SpdyFrameIR&> matcher) {
    EXPECT_CALL(session_io_, SendFrameRaw(_))
        .WillOnce(DoAll(ClientDecodeFrame(this, matcher),
                        Return(mod_spdy::SpdySessionIO::WRITE_SUCCESS)));
  }

  void ExpectBeginServerPush(
      net::SpdyStreamId stream_id, net::SpdyStreamId assoc_stream_id,
      net::SpdyPriority priority, const std::string& path) {
    net::SpdyNameValueBlock headers;
    AddInitialServerPushHeaders(path, &headers);
    ExpectSendFrame(IsSynStream(stream_id, assoc_stream_id, priority, false,
                                true, headers));
  }

  void ExpectSendSynReply(net::SpdyStreamId stream_id, bool fin) {
    net::SpdyNameValueBlock headers;
    AddResponseHeaders(spdy_version_, &headers);
    ExpectSendFrame(IsSynReply(stream_id, fin, headers));
  }

  void ExpectSendHeaders(net::SpdyStreamId stream_id, bool fin) {
    net::SpdyNameValueBlock headers;
    AddResponseHeaders(spdy_version_, &headers);
    ExpectSendFrame(IsHeaders(stream_id, fin, headers));
  }

  void ExpectSendGoAway(net::SpdyStreamId last_stream_id,
                        net::SpdyGoAwayStatus status) {
    // SPDY/2 doesn't have status codes on GOAWAY frames, so for SPDY/2 the
    // client framer decodes it as GOAWAY_OK regardless of what we sent.
    if (spdy_version_ == mod_spdy::spdy::SPDY_VERSION_2) {
      ExpectSendFrame(IsGoAway(last_stream_id, net::GOAWAY_OK));
    } else {
      ExpectSendFrame(IsGoAway(last_stream_id, status));
    }
  }

  const mod_spdy::spdy::SpdyVersion spdy_version_;
  ClientVisitor client_visitor_;
  net::BufferedSpdyFramer client_framer_;
  mod_spdy::SpdyServerConfig config_;
  StrictMock<MockSpdySessionIO> session_io_;
  StrictMock<MockSpdyStreamTaskFactory> task_factory_;
  std::list<std::string> input_queue_;
};

// Class for most SpdySession tests; this uses an InlineExecutor, so that test
// behavior is very predictable.
class SpdySessionTest : public SpdySessionTestBase {
 public:
  SpdySessionTest()
      : session_(spdy_version_, &config_, &session_io_, &task_factory_,
                 &executor_) {}

 protected:
  InlineExecutor executor_;
  mod_spdy::SpdySession session_;
};

// Test that if the connection is already closed, we stop immediately.
TEST_P(SpdySessionTest, ConnectionAlreadyClosed) {
  testing::InSequence seq;
  EXPECT_CALL(session_io_, SendFrameRaw(_))
      .WillOnce(Return(mod_spdy::SpdySessionIO::WRITE_CONNECTION_CLOSED));

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

// Test that when the connection is aborted, we stop.
TEST_P(SpdySessionTest, ImmediateConnectionAbort) {
  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted()).WillOnce(Return(true));

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

// Test responding to a PING frame from the client (followed by the connection
// closing, so that we can exit the Run loop).
TEST_P(SpdySessionTest, SinglePing) {
  ReceivePingFromClient(47);

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  ExpectSendFrame(IsPing(47));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()))
      .WillOnce(Return(mod_spdy::SpdySessionIO::READ_CONNECTION_CLOSED));
  ExpectSendGoAway(0, net::GOAWAY_OK);

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

// Test handling a single stream request.
TEST_P(SpdySessionTest, SingleStream) {
  MockStreamTask* task = new MockStreamTask;
  executor_.set_run_on_add(false);
  const net::SpdyStreamId stream_id = 1;
  const net::SpdyPriority priority = 2;
  ReceiveSynStreamFromClient(stream_id, priority, net::CONTROL_FLAG_FIN);

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  EXPECT_CALL(task_factory_, NewStreamTask(
      AllOf(Property(&mod_spdy::SpdyStream::stream_id, Eq(stream_id)),
            Property(&mod_spdy::SpdyStream::associated_stream_id, Eq(0u)),
            Property(&mod_spdy::SpdyStream::priority, Eq(priority)))))
      .WillOnce(ReturnMockTask(task));
  EXPECT_CALL(session_io_, IsConnectionAborted())
      .WillOnce(DoAll(InvokeWithoutArgs(&executor_, &InlineExecutor::RunAll),
                      Return(false)));
  EXPECT_CALL(*task, Run()).WillOnce(DoAll(
      SendResponseHeaders(task), SendDataFrame(task, "foobar", false),
      SendDataFrame(task, "quux", true)));
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(false), NotNull()));
  ExpectSendSynReply(stream_id, false);
  ExpectSendFrame(IsDataFrame(stream_id, false, "foobar"));
  ExpectSendFrame(IsDataFrame(stream_id, true, "quux"));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()))
      .WillOnce(Return(mod_spdy::SpdySessionIO::READ_CONNECTION_CLOSED));
  ExpectSendGoAway(1, net::GOAWAY_OK);

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

// Test that if SendFrameRaw fails, we immediately stop trying to send data and
// shut down the session.
TEST_P(SpdySessionTest, ShutDownSessionIfSendFrameRawFails) {
  MockStreamTask* task = new MockStreamTask;
  executor_.set_run_on_add(false);
  const net::SpdyStreamId stream_id = 1;
  const net::SpdyPriority priority = 2;
  ReceiveSynStreamFromClient(stream_id, priority, net::CONTROL_FLAG_FIN);

  testing::InSequence seq;
  // We start out the same way as in the SingleStream test above.
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, _));
  EXPECT_CALL(task_factory_, NewStreamTask(_))
      .WillOnce(ReturnMockTask(task));
  EXPECT_CALL(session_io_, IsConnectionAborted())
      .WillOnce(DoAll(InvokeWithoutArgs(&executor_, &InlineExecutor::RunAll),
                      Return(false)));
  EXPECT_CALL(*task, Run()).WillOnce(DoAll(
      SendResponseHeaders(task), SendDataFrame(task, "foobar", false),
      SendDataFrame(task, "quux", true)));
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, _));
  ExpectSendSynReply(stream_id, false);
  // At this point, the connection is closed by the client.
  EXPECT_CALL(session_io_, SendFrameRaw(_))
      .WillOnce(Return(mod_spdy::SpdySessionIO::WRITE_CONNECTION_CLOSED));
  // Even though we have another frame to send at this point (already in the
  // output queue), we immediately stop sending data and exit the session.

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

// Test that when the client sends us garbage data, we send a GOAWAY frame and
// then quit.
TEST_P(SpdySessionTest, SendGoawayInResponseToGarbage) {
  input_queue_.push_back("\x88\x5f\x92\x02\xf8\x92\x12\xd1"
                         "\x82\xdc\x1a\x40\xbb\xb2\x9d\x13");

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  ExpectSendGoAway(0, net::GOAWAY_PROTOCOL_ERROR);

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

// Test that when the client sends us a SYN_STREAM with a corrupted header
// block, we send a GOAWAY frame and then quit.
TEST_P(SpdySessionTest, SendGoawayForBadSynStreamCompression) {
  net::SpdyHeaderBlock headers;
  headers["foobar"] = "Foo is to bar as bar is to baz.";
  net::SpdyFramer framer(mod_spdy::SpdyVersionToFramerVersion(spdy_version_));
  framer.set_enable_compression(false);
  scoped_ptr<net::SpdySerializedFrame> frame(framer.CreateSynStream(
      1, 0, framer.GetHighestPriority(), 0, net::CONTROL_FLAG_FIN,
      false,  // false = no compression
      &headers));
  ReceiveFrameFromClient(*frame);

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  ExpectSendGoAway(0, net::GOAWAY_PROTOCOL_ERROR);

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

// TODO(mdsteele): At the moment, SpdyFramer DCHECKs that the stream ID is
// nonzero when decoding, so this test would crash in debug builds.  Once this
// has been corrected in the Chromium code, we can remove this #ifdef.
#ifdef NDEBUG
// Test that when the client sends us a SYN_STREAM with a stream ID of 0, we
// send a GOAWAY frame and then quit.
TEST_P(SpdySessionTest, SendGoawayForSynStreamIdZero) {
  net::SpdyHeaderBlock headers;
  AddRequestHeaders(spdy_version_, &headers);
  scoped_ptr<net::SpdySerializedFrame> frame(client_framer_.CreateSynStream(
      0, 0, client_framer_.GetHighestPriority(), 0, net::CONTROL_FLAG_FIN,
      true,  // true = use compression
      &headers));
  ReceiveFrameFromClient(*frame);

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  ExpectSendGoAway(0, net::GOAWAY_PROTOCOL_ERROR);

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}
#endif

// Test that when the client sends us two SYN_STREAMs with the same ID, we send
// a GOAWAY frame (but still finish out the good stream before quitting).
TEST_P(SpdySessionTest, SendGoawayForDuplicateStreamId) {
  MockStreamTask* task = new MockStreamTask;
  executor_.set_run_on_add(false);
  const net::SpdyStreamId stream_id = 1;
  const net::SpdyPriority priority = 2;
  ReceiveSynStreamFromClient(stream_id, priority, net::CONTROL_FLAG_FIN);
  ReceiveSynStreamFromClient(stream_id, priority, net::CONTROL_FLAG_FIN);

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  // Get the first SYN_STREAM; it looks good, so create a new task (but because
  // we set executor_.set_run_on_add(false) above, it doesn't execute yet).
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  EXPECT_CALL(task_factory_, NewStreamTask(
      AllOf(Property(&mod_spdy::SpdyStream::stream_id, Eq(stream_id)),
            Property(&mod_spdy::SpdyStream::associated_stream_id, Eq(0u)),
            Property(&mod_spdy::SpdyStream::priority, Eq(priority)))))
      .WillOnce(ReturnMockTask(task));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  // There's an active stream out, so ProcessAvailableInput should have false
  // for the first argument (false = nonblocking read).  Here we get the second
  // SYN_STREAM with the same stream ID, so we should send GOAWAY.
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(false), NotNull()));
  ExpectSendGoAway(1, net::GOAWAY_PROTOCOL_ERROR);
  // At this point, tell the executor to run the task.
  EXPECT_CALL(session_io_, IsConnectionAborted())
      .WillOnce(DoAll(InvokeWithoutArgs(&executor_, &InlineExecutor::RunAll),
                      Return(false)));
  EXPECT_CALL(*task, Run()).WillOnce(DoAll(
      SendResponseHeaders(task), SendDataFrame(task, "foobar", false),
      SendDataFrame(task, "quux", true)));
  // The stream is no longer active, but there are pending frames to send, so
  // we shouldn't block on input.
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(false), NotNull()));
  // Now we should send the output.
  ExpectSendSynReply(stream_id, false);
  ExpectSendFrame(IsDataFrame(stream_id, false, "foobar"));
  ExpectSendFrame(IsDataFrame(stream_id, true, "quux"));
  // Finally, there is no more output to send, and no chance of creating new
  // streams (since we GOAWAY'd), so we quit.
  EXPECT_CALL(session_io_, IsConnectionAborted());

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

// Run each test over both SPDY v2 and SPDY v3.
INSTANTIATE_TEST_CASE_P(Spdy2And3, SpdySessionTest, testing::Values(
    mod_spdy::spdy::SPDY_VERSION_2, mod_spdy::spdy::SPDY_VERSION_3,
    mod_spdy::spdy::SPDY_VERSION_3_1));

// Create a type alias so that we can instantiate some of our
// SpdySessionTest-based tests using a different set of parameters.
typedef SpdySessionTest SpdySessionNoFlowControlTest;

// Test that we send GOAWAY if the client tries to send
// SETTINGS_INITIAL_WINDOW_SIZE over SPDY v2.
TEST_P(SpdySessionNoFlowControlTest, SendGoawayForInitialWindowSize) {
  net::SettingsMap settings;
  settings[net::SETTINGS_INITIAL_WINDOW_SIZE] =
      std::make_pair(net::SETTINGS_FLAG_NONE, 4000);
  scoped_ptr<net::SpdySerializedFrame> frame(
      client_framer_.CreateSettings(settings));
  ReceiveFrameFromClient(*frame);

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  ExpectSendGoAway(0, net::GOAWAY_PROTOCOL_ERROR);

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

// Only run no-flow-control tests for SPDY v2.
INSTANTIATE_TEST_CASE_P(Spdy2, SpdySessionNoFlowControlTest, testing::Values(
    mod_spdy::spdy::SPDY_VERSION_2));

// Test class for flow-control tests.  This uses a ThreadPool Executor, so that
// we can test concurrency behavior.
class SpdySessionFlowControlTest : public SpdySessionTestBase {
 public:
  SpdySessionFlowControlTest() : thread_pool_(1, 1) {}

  void SetUp() {
    ASSERT_TRUE(thread_pool_.Start());
    executor_.reset(thread_pool_.NewExecutor());
    session_.reset(new mod_spdy::SpdySession(
        spdy_version_, &config_, &session_io_, &task_factory_,
        executor_.get()));
  }

  void ExpectSendDataGetWindowUpdateBack(
      net::SpdyStreamId stream_id, bool fin, base::StringPiece payload) {
    EXPECT_CALL(session_io_, SendFrameRaw(_)).WillOnce(DoAll(
        ClientDecodeFrame(this, IsDataFrame(stream_id, fin, payload)),
        SendBackWindowUpdate(this, stream_id, payload.size()),
        Return(mod_spdy::SpdySessionIO::WRITE_SUCCESS)));
  }

 protected:
  mod_spdy::ThreadPool thread_pool_;
  scoped_ptr<mod_spdy::Executor> executor_;
  scoped_ptr<mod_spdy::SpdySession> session_;
};

TEST_P(SpdySessionFlowControlTest, SingleStreamWithFlowControl) {
  MockStreamTask* task = new MockStreamTask;
  // Start by setting the initial window size to very small (three bytes).
  ReceiveSettingsFrameFromClient(net::SETTINGS_INITIAL_WINDOW_SIZE, 3);
  // Then send a SYN_STREAM.
  const net::SpdyStreamId stream_id = 1;
  const net::SpdyPriority priority = 2;
  ReceiveSynStreamFromClient(stream_id, priority, net::CONTROL_FLAG_FIN);

  // We'll have to go through the loop at least five times -- once for each of
  // five frames that we _must_ receive (SETTINGS, SYN_STREAM, and three
  // WINDOW_UDPATEs.
  EXPECT_CALL(session_io_, IsConnectionAborted()).Times(AtLeast(5));
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, NotNull()))
      .Times(AtLeast(5));

  // The rest of these will have to happen in a fixed order.
  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(task_factory_, NewStreamTask(
      AllOf(Property(&mod_spdy::SpdyStream::stream_id, Eq(stream_id)),
            Property(&mod_spdy::SpdyStream::associated_stream_id, Eq(0u)),
            Property(&mod_spdy::SpdyStream::priority, Eq(priority)))))
      .WillOnce(ReturnMockTask(task));
  EXPECT_CALL(*task, Run()).WillOnce(DoAll(
      SendResponseHeaders(task), SendDataFrame(task, "foobar", false),
      SendDataFrame(task, "quux", true)));
  // Since the window size is just three bytes, we can only send three bytes at
  // a time.
  ExpectSendSynReply(stream_id, false);
  ExpectSendDataGetWindowUpdateBack(stream_id, false, "foo");
  ExpectSendDataGetWindowUpdateBack(stream_id, false, "bar");
  ExpectSendDataGetWindowUpdateBack(stream_id, false, "quu");
  ExpectSendDataGetWindowUpdateBack(stream_id, true, "x");
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()))
      .WillOnce(Return(mod_spdy::SpdySessionIO::READ_CONNECTION_CLOSED));
  ExpectSendGoAway(stream_id, net::GOAWAY_OK);

  session_->Run();
}

// Suppose the input side of the connection closes while we're blocked on flow
// control; we should abort the blocked streams.
TEST_P(SpdySessionFlowControlTest, CeaseInputWithFlowControl) {
  MockStreamTask* task = new MockStreamTask;
  // Start by setting the initial window size to very small (three bytes).
  ReceiveSettingsFrameFromClient(net::SETTINGS_INITIAL_WINDOW_SIZE, 3);
  // Then send a SYN_STREAM.
  const net::SpdyStreamId stream_id = 1;
  const net::SpdyPriority priority = 2;
  ReceiveSynStreamFromClient(stream_id, priority, net::CONTROL_FLAG_FIN);

  EXPECT_CALL(session_io_, IsConnectionAborted()).Times(AtLeast(1));
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, NotNull()))
      .Times(AtLeast(1));

  // The rest of these will have to happen in a fixed order.
  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(task_factory_, NewStreamTask(
      AllOf(Property(&mod_spdy::SpdyStream::stream_id, Eq(stream_id)),
            Property(&mod_spdy::SpdyStream::associated_stream_id, Eq(0u)),
            Property(&mod_spdy::SpdyStream::priority, Eq(priority)))))
      .WillOnce(ReturnMockTask(task));
  EXPECT_CALL(*task, Run()).WillOnce(DoAll(
      SendResponseHeaders(task), SendDataFrame(task, "foobar", false),
      SendDataFrame(task, "quux", true)));
  ExpectSendSynReply(stream_id, false);
  // Since the window size is just three bytes, we can only send three bytes at
  // a time.  The stream thread will then be blocked.
  ExpectSendFrame(IsDataFrame(stream_id, false, "foo"));
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, _))
      .WillOnce(Return(mod_spdy::SpdySessionIO::READ_CONNECTION_CLOSED));
  // At this point, we're blocked on flow control, and the test will close the
  // input side of the connection.  Since the stream can never complete, the
  // session should abort the stream and shut down, rather than staying blocked
  // forever.
  ExpectSendGoAway(stream_id, net::GOAWAY_OK);

  session_->Run();
}

// Test that we send GOAWAY if the client tries to send
// SETTINGS_INITIAL_WINDOW_SIZE with a value of 0.
TEST_P(SpdySessionFlowControlTest, SendGoawayForTooSmallInitialWindowSize) {
  ReceiveSettingsFrameFromClient(net::SETTINGS_INITIAL_WINDOW_SIZE, 0);

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  ExpectSendGoAway(0, net::GOAWAY_PROTOCOL_ERROR);

  session_->Run();
}

// Test that we send GOAWAY if the client tries to send
// SETTINGS_INITIAL_WINDOW_SIZE with a value of 0x80000000.
TEST_P(SpdySessionFlowControlTest, SendGoawayForTooLargeInitialWindowSize) {
  ReceiveSettingsFrameFromClient(net::SETTINGS_INITIAL_WINDOW_SIZE,
                                 0x80000000);

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  ExpectSendGoAway(0, net::GOAWAY_PROTOCOL_ERROR);

  session_->Run();
}

TEST_P(SpdySessionFlowControlTest, SharedOutputFlowControlWindow) {
  ReceiveWindowUpdateFrameFromClient(0, 10000);

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  if (session_->spdy_version() >= mod_spdy::spdy::SPDY_VERSION_3_1) {
    EXPECT_CALL(session_io_, IsConnectionAborted()).WillOnce(Return(true));
  } else {
    ExpectSendGoAway(0, net::GOAWAY_PROTOCOL_ERROR);
  }

  if (session_->spdy_version() >= mod_spdy::spdy::SPDY_VERSION_3_1) {
    EXPECT_EQ(65536, session_->current_shared_output_window_size());
  }
  session_->Run();
  if (session_->spdy_version() >= mod_spdy::spdy::SPDY_VERSION_3_1) {
    EXPECT_EQ(75536, session_->current_shared_output_window_size());
  }
}

TEST_P(SpdySessionFlowControlTest, SharedInputFlowControlWindow) {
  MockStreamTask* task = new MockStreamTask;
  const net::SpdyStreamId stream_id = 1;
  const net::SpdyPriority priority = 2;
  ReceiveSynStreamFromClient(stream_id, priority, net::CONTROL_FLAG_NONE);
  const std::string data1(32000, 'x');
  const std::string data2(2000, 'y');
  ReceiveDataFromClient(stream_id, data1, net::DATA_FLAG_NONE);
  ReceiveDataFromClient(stream_id, data1, net::DATA_FLAG_NONE);
  ReceiveDataFromClient(stream_id, data2, net::DATA_FLAG_FIN);

  EXPECT_CALL(session_io_, IsConnectionAborted()).Times(AtLeast(4));

  // The rest of these will have to happen in a fixed order.
  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  // Receive the SYN_STREAM from the client.
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, NotNull()));
  EXPECT_CALL(task_factory_, NewStreamTask(
      AllOf(Property(&mod_spdy::SpdyStream::stream_id, Eq(stream_id)),
            Property(&mod_spdy::SpdyStream::associated_stream_id, Eq(0u)),
            Property(&mod_spdy::SpdyStream::priority, Eq(priority)))))
      .WillOnce(ReturnMockTask(task));
  EXPECT_CALL(*task, Run()).WillOnce(ConsumeInputUntilAborted(task));
  // Receive the first two blocks of data from the client with no problems.
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, NotNull()));
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, NotNull()));
  // The third block of data is too much; it's a flow control error.  For
  // SPDY/3.1 and up it's a session flow control error; for SPDY/3 it's a
  // stream flow control error.
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, NotNull()));
  if (session_->spdy_version() >= mod_spdy::spdy::SPDY_VERSION_3_1) {
    ExpectSendGoAway(stream_id, net::GOAWAY_PROTOCOL_ERROR);
  } else {
    ExpectSendFrame(IsRstStream(1, net::RST_STREAM_FLOW_CONTROL_ERROR));
    EXPECT_CALL(session_io_, IsConnectionAborted()).WillOnce(Return(true));
  }

  session_->Run();
}

// Only run flow control tests for SPDY v3 and up.
INSTANTIATE_TEST_CASE_P(Spdy3, SpdySessionFlowControlTest, testing::Values(
    mod_spdy::spdy::SPDY_VERSION_3, mod_spdy::spdy::SPDY_VERSION_3_1));

// Create a type alias so that we can instantiate some of our
// SpdySessionTest-based tests using a different set of parameters.
typedef SpdySessionTest SpdySessionServerPushTest;

TEST_P(SpdySessionServerPushTest, SimpleServerPush) {
  MockStreamTask* task1 = new MockStreamTask;
  MockStreamTask* task2 = new MockStreamTask;
  executor_.set_run_on_add(true);
  const net::SpdyStreamId stream_id = 3;
  const net::SpdyPriority priority = 2;
  const net::SpdyPriority push_priority = 3;
  const std::string push_path = "/script.js";
  ReceiveSynStreamFromClient(stream_id, priority, net::CONTROL_FLAG_FIN);

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()));
  EXPECT_CALL(task_factory_, NewStreamTask(
      AllOf(Property(&mod_spdy::SpdyStream::stream_id, Eq(stream_id)),
            Property(&mod_spdy::SpdyStream::associated_stream_id, Eq(0u)),
            Property(&mod_spdy::SpdyStream::priority, Eq(priority)))))
      .WillOnce(ReturnMockTask(task1));
  EXPECT_CALL(*task1, Run()).WillOnce(DoAll(
      SendResponseHeaders(task1),
      StartServerPush(task1, push_priority, push_path,
                      mod_spdy::SpdyServerPushInterface::PUSH_STARTED),
      SendDataFrame(task1, "foobar", false),
      SendDataFrame(task1, "quux", true)));
  // We should right away create the server push task, and get the SYN_STREAM
  // before any other frames from the original stream.
  EXPECT_CALL(task_factory_, NewStreamTask(
      AllOf(Property(&mod_spdy::SpdyStream::stream_id, Eq(2u)),
            Property(&mod_spdy::SpdyStream::associated_stream_id,
                     Eq(stream_id)),
            Property(&mod_spdy::SpdyStream::priority, Eq(push_priority)))))
      .WillOnce(ReturnMockTask(task2));
  EXPECT_CALL(*task2, Run()).WillOnce(DoAll(
      SendResponseHeaders(task2),
      SendDataFrame(task2, "hello", false),
      SendDataFrame(task2, "world", true)));
  ExpectBeginServerPush(2u, stream_id, push_priority, push_path);
  // The pushed stream has a low priority, so the rest of the first stream
  // should get sent before the rest of the pushed stream.
  ExpectSendSynReply(stream_id, false);
  ExpectSendFrame(IsDataFrame(stream_id, false, "foobar"));
  ExpectSendFrame(IsDataFrame(stream_id, true, "quux"));
  // Now we should get the rest of the pushed stream.
  ExpectSendHeaders(2u, false);
  ExpectSendFrame(IsDataFrame(2u, false, "hello"));
  ExpectSendFrame(IsDataFrame(2u, true, "world"));
  // And, we're done.
  EXPECT_CALL(session_io_, IsConnectionAborted());
  EXPECT_CALL(session_io_, ProcessAvailableInput(Eq(true), NotNull()))
      .WillOnce(Return(mod_spdy::SpdySessionIO::READ_CONNECTION_CLOSED));
  ExpectSendGoAway(stream_id, net::GOAWAY_OK);

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

TEST_P(SpdySessionServerPushTest, TooManyConcurrentPushes) {
  MockStreamTask* task1 = new MockStreamTask;
  MockStreamTask* task2 = new MockStreamTask;
  MockStreamTask* task3 = new MockStreamTask;
  executor_.set_run_on_add(false);
  const net::SpdyStreamId stream_id = 9;
  const net::SpdyPriority priority = 0;
  ReceiveSettingsFrameFromClient(net::SETTINGS_MAX_CONCURRENT_STREAMS, 2);
  ReceiveSynStreamFromClient(stream_id, priority, net::CONTROL_FLAG_FIN);

  EXPECT_CALL(session_io_, IsConnectionAborted()).Times(AtLeast(3));
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, NotNull()))
      .Times(AtLeast(3));

  testing::InSequence seq;
  ExpectSendFrame(IsSettings(net::SETTINGS_MAX_CONCURRENT_STREAMS, 100));
  EXPECT_CALL(task_factory_, NewStreamTask(
      AllOf(Property(&mod_spdy::SpdyStream::stream_id, Eq(stream_id)),
            Property(&mod_spdy::SpdyStream::associated_stream_id, Eq(0u)),
            Property(&mod_spdy::SpdyStream::priority, Eq(priority)))))
      .WillOnce(ReturnMockTask(task1));
  EXPECT_CALL(session_io_, IsConnectionAborted())
      .WillOnce(DoAll(InvokeWithoutArgs(&executor_, &InlineExecutor::RunOne),
                      Return(false)));
  EXPECT_CALL(*task1, Run()).WillOnce(DoAll(
      StartServerPush(task1, 3u, "/foo.css",
          mod_spdy::SpdyServerPushInterface::PUSH_STARTED),
      StartServerPush(task1, 2u, "/bar.css",
          mod_spdy::SpdyServerPushInterface::PUSH_STARTED),
      StartServerPush(task1, 1u, "/baz.css",
          mod_spdy::SpdyServerPushInterface::TOO_MANY_CONCURRENT_PUSHES),
      SendResponseHeaders(task1), SendDataFrame(task1, "html", true)));
  // Start the first two pushes.  The third push should fail due to too many
  // concurrent pushes.
  EXPECT_CALL(task_factory_, NewStreamTask(
      AllOf(Property(&mod_spdy::SpdyStream::stream_id, Eq(2u)),
            Property(&mod_spdy::SpdyStream::associated_stream_id,
                     Eq(stream_id)),
            Property(&mod_spdy::SpdyStream::priority, Eq(3u)))))
      .WillOnce(ReturnMockTask(task2));
  EXPECT_CALL(task_factory_, NewStreamTask(
      AllOf(Property(&mod_spdy::SpdyStream::stream_id, Eq(4u)),
            Property(&mod_spdy::SpdyStream::associated_stream_id,
                     Eq(stream_id)),
            Property(&mod_spdy::SpdyStream::priority, Eq(2u)))))
      .WillOnce(ReturnMockTask(task3));
  // Now we get the SYN_STREAMs for the pushed streams before anything else.
  ExpectBeginServerPush(2u, stream_id, 3u, "/foo.css");
  ExpectBeginServerPush(4u, stream_id, 2u, "/bar.css");
  // We now send the frames from the original stream.
  ExpectSendSynReply(stream_id, false);
  ExpectSendFrame(IsDataFrame(stream_id, true, "html"));
  // At this point, the client will change MAX_CONCURRENT_STREAMS to zero.  We
  // shouldn't barf, even though we have more active push streams than the new
  // maximum.
  EXPECT_CALL(session_io_, IsConnectionAborted())
      .WillOnce(DoAll(
          SendBackSettings(this, net::SETTINGS_MAX_CONCURRENT_STREAMS, 0u),
          Return(false)));
  // Now let's run the rest of the tasks.  One of them will try to start yet
  // another server push, but that should fail because MAX_CONCURRENT_STREAMS
  // is now zero.
  EXPECT_CALL(session_io_, IsConnectionAborted())
      .WillOnce(DoAll(InvokeWithoutArgs(&executor_, &InlineExecutor::RunAll),
                      Return(false)));
  EXPECT_CALL(*task2, Run()).WillOnce(DoAll(
      SendResponseHeaders(task2), SendDataFrame(task2, "foo", true)));
  EXPECT_CALL(*task3, Run()).WillOnce(DoAll(
      StartServerPush(task3, 3u, "/stuff.png",
          mod_spdy::SpdyServerPushInterface::TOO_MANY_CONCURRENT_PUSHES),
      SendResponseHeaders(task3), SendDataFrame(task3, "bar", true)));
  // And now we get all those frames.  The "bar" stream's frames should come
  // first, because that's a higher-priority stream.
  ExpectSendHeaders(4u, false);
  ExpectSendFrame(IsDataFrame(4u, true, "bar"));
  ExpectSendHeaders(2u, false);
  ExpectSendFrame(IsDataFrame(2u, true, "foo"));
  // And, we're done.
  EXPECT_CALL(session_io_, ProcessAvailableInput(_, NotNull()))
      .WillOnce(Return(mod_spdy::SpdySessionIO::READ_CONNECTION_CLOSED));
  ExpectSendGoAway(stream_id, net::GOAWAY_OK);

  session_.Run();
  EXPECT_TRUE(executor_.stopped());
}

// Only run server push tests for SPDY v3 and up.
INSTANTIATE_TEST_CASE_P(Spdy3, SpdySessionServerPushTest, testing::Values(
    mod_spdy::spdy::SPDY_VERSION_3, mod_spdy::spdy::SPDY_VERSION_3_1));

}  // namespace
