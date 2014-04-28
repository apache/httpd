// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "mod_spdy/common/testing/spdy_frame_matchers.h"

#include <iostream>
#include <string>

#include "base/basictypes.h"
#include "base/strings/stringprintf.h"
#include "mod_spdy/common/protocol_util.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"

namespace {

void AppendHeadersString(const net::SpdyNameValueBlock& headers,
                         std::string* out) {
  out->append("{ ");
  bool comma = false;
  for (net::SpdyNameValueBlock::const_iterator iter = headers.begin();
       iter != headers.end(); ++iter) {
    if (comma) {
      out->append(", ");
    }
    base::StringAppendF(out, "'%s': '%s'", iter->first.c_str(),
                        iter->second.c_str());
    comma = true;
  }
  out->append(" }");
}

class FrameToStringVisitor : public net::SpdyFrameVisitor {
 public:
  explicit FrameToStringVisitor(std::string* out)
      : out_(out) {
    CHECK(out_);
  }
  virtual ~FrameToStringVisitor() {}

  virtual void VisitSynStream(const net::SpdySynStreamIR& syn_stream) {
    // TODO(mdsteele): include other fields
    base::StringAppendF(
        out_, "SYN_STREAM(%u p%u%s%s)",
        static_cast<unsigned>(syn_stream.stream_id()),
        static_cast<unsigned>(syn_stream.priority()),
        (syn_stream.fin() ? " fin" : ""),
        (syn_stream.unidirectional() ? " unidirectional" : ""));
    AppendHeadersString(syn_stream.name_value_block(), out_);
  }
  virtual void VisitSynReply(const net::SpdySynReplyIR& syn_reply) {
    base::StringAppendF(
        out_, "SYN_REPLY(%u%s)",
        static_cast<unsigned>(syn_reply.stream_id()),
        (syn_reply.fin() ? " fin" : ""));
    AppendHeadersString(syn_reply.name_value_block(), out_);
  }
  virtual void VisitRstStream(const net::SpdyRstStreamIR& rst_stream) {
    base::StringAppendF(
        out_, "RST_STREAM(%u %s)",
        static_cast<unsigned>(rst_stream.stream_id()),
        mod_spdy::RstStreamStatusCodeToString(rst_stream.status()));
  }
  virtual void VisitSettings(const net::SpdySettingsIR& settings) {
    base::StringAppendF(
        out_, "SETTINGS(%s",
        (settings.clear_settings() ? "clear " : ""));
    bool comma = false;
    for (net::SpdySettingsIR::ValueMap::const_iterator iter =
             settings.values().begin(), end = settings.values().end();
         iter != end; ++iter) {
      if (comma) {
        out_->append(", ");
      }
      base::StringAppendF(
          out_, "%s%s%s: %d",
          (iter->second.persist_value ? "persist " : ""),
          (iter->second.persisted ? "persisted " : ""),
          mod_spdy::SettingsIdToString(iter->first),
          static_cast<int>(iter->second.value));
    }
    out_->append(")");
  }
  virtual void VisitPing(const net::SpdyPingIR& ping) {
    base::StringAppendF(
        out_, "PING(%u)", static_cast<unsigned>(ping.id()));
  }
  virtual void VisitGoAway(const net::SpdyGoAwayIR& goaway) {
    base::StringAppendF(
        out_, "GOAWAY(%u %s)",
        static_cast<unsigned>(goaway.last_good_stream_id()),
        mod_spdy::GoAwayStatusCodeToString(goaway.status()));
  }
  virtual void VisitHeaders(const net::SpdyHeadersIR& headers) {
    base::StringAppendF(
        out_, "HEADERS(%u%s)", static_cast<unsigned>(headers.stream_id()),
        (headers.fin() ? " fin" : ""));
    AppendHeadersString(headers.name_value_block(), out_);
  }
  virtual void VisitWindowUpdate(const net::SpdyWindowUpdateIR& window) {
    base::StringAppendF(
        out_, "WINDOW_UPDATE(%u %+d)",
        static_cast<unsigned>(window.stream_id()),
        static_cast<int>(window.delta()));
  }
  virtual void VisitCredential(const net::SpdyCredentialIR& credential) {
    // TODO(mdsteele): include other fields
    base::StringAppendF(
        out_, "CREDENTIAL(%d)", static_cast<int>(credential.slot()));
  }
  virtual void VisitBlocked(const net::SpdyBlockedIR& blocked) {
    base::StringAppendF(
        out_, "BLOCKED(%u)", static_cast<unsigned>(blocked.stream_id()));
  }
  virtual void VisitPushPromise(const net::SpdyPushPromiseIR& push_promise) {
    base::StringAppendF(
        out_, "PUSH_PROMISE(%u, %u)",
        static_cast<unsigned>(push_promise.stream_id()),
        static_cast<unsigned>(push_promise.promised_stream_id()));
  }
  virtual void VisitData(const net::SpdyDataIR& data) {
    base::StringAppendF(
        out_, "DATA(%u%s \"", static_cast<unsigned>(data.stream_id()),
        (data.fin() ? " fin" : ""));
    out_->append(data.data().data(), data.data().size());
    out_->append("\")");
  }

 private:
  std::string* out_;

  DISALLOW_COPY_AND_ASSIGN(FrameToStringVisitor);
};

void AppendSpdyFrameToString(const net::SpdyFrameIR& frame, std::string* out) {
  FrameToStringVisitor visitor(out);
  frame.Visit(&visitor);
}

class IsEquivalentFrameMatcher :
      public ::testing::MatcherInterface<const net::SpdyFrameIR&> {
 public:
  explicit IsEquivalentFrameMatcher(const net::SpdyFrameIR& frame);
  virtual ~IsEquivalentFrameMatcher();
  virtual bool MatchAndExplain(const net::SpdyFrameIR& frame,
                               ::testing::MatchResultListener* listener) const;
  virtual void DescribeTo(std::ostream* out) const;
  virtual void DescribeNegationTo(std::ostream* out) const;

 private:
  std::string expected_;

  DISALLOW_COPY_AND_ASSIGN(IsEquivalentFrameMatcher);
};

IsEquivalentFrameMatcher::IsEquivalentFrameMatcher(
    const net::SpdyFrameIR& frame) {
  AppendSpdyFrameToString(frame, &expected_);
}

IsEquivalentFrameMatcher::~IsEquivalentFrameMatcher() {}

bool IsEquivalentFrameMatcher::MatchAndExplain(
    const net::SpdyFrameIR& frame,
    ::testing::MatchResultListener* listener) const {
  std::string actual;
  AppendSpdyFrameToString(frame, &actual);
  if (actual != expected_) {
    *listener << "is a " << actual << " frame";
    return false;
  }
  return true;
}

void IsEquivalentFrameMatcher::DescribeTo(std::ostream* out) const {
  *out << "is a " << expected_ << " frame";
}

void IsEquivalentFrameMatcher::DescribeNegationTo(std::ostream* out) const {
  *out << "isn't a " << expected_ << " frame";
}

}  // namespace

namespace mod_spdy {

namespace testing {

::testing::Matcher<const net::SpdyFrameIR&> IsSynStream(
     net::SpdyStreamId stream_id, net::SpdyStreamId assoc_stream_id,
     net::SpdyPriority priority, bool fin, bool unidirectional,
     const net::SpdyNameValueBlock& headers) {
  net::SpdySynStreamIR frame(stream_id);
  frame.set_associated_to_stream_id(assoc_stream_id);
  frame.set_priority(priority);
  frame.set_fin(fin);
  frame.set_unidirectional(unidirectional);
  frame.GetMutableNameValueBlock()->insert(headers.begin(), headers.end());
  return ::testing::MakeMatcher(new IsEquivalentFrameMatcher(frame));
}

::testing::Matcher<const net::SpdyFrameIR&> IsSynReply(
     net::SpdyStreamId stream_id, bool fin,
     const net::SpdyNameValueBlock& headers) {
  net::SpdySynReplyIR frame(stream_id);
  frame.set_fin(fin);
  frame.GetMutableNameValueBlock()->insert(headers.begin(), headers.end());
  return ::testing::MakeMatcher(new IsEquivalentFrameMatcher(frame));
}

::testing::Matcher<const net::SpdyFrameIR&> IsRstStream(
     net::SpdyStreamId stream_id, net::SpdyRstStreamStatus status) {
  net::SpdyRstStreamIR frame(stream_id, status);
  return ::testing::MakeMatcher(new IsEquivalentFrameMatcher(frame));
}

::testing::Matcher<const net::SpdyFrameIR&> IsSettings(
     net::SpdySettingsIds id, int32 value) {
  net::SpdySettingsIR frame;
  frame.AddSetting(id, false, false, value);
  return ::testing::MakeMatcher(new IsEquivalentFrameMatcher(frame));
}

::testing::Matcher<const net::SpdyFrameIR&> IsPing(net::SpdyPingId ping_id) {
  net::SpdyPingIR frame(ping_id);
  return ::testing::MakeMatcher(new IsEquivalentFrameMatcher(frame));
}

::testing::Matcher<const net::SpdyFrameIR&> IsGoAway(
     net::SpdyStreamId last_good_stream_id, net::SpdyGoAwayStatus status) {
  net::SpdyGoAwayIR frame(last_good_stream_id, status);
  return ::testing::MakeMatcher(new IsEquivalentFrameMatcher(frame));
}

::testing::Matcher<const net::SpdyFrameIR&> IsHeaders(
     net::SpdyStreamId stream_id, bool fin,
     const net::SpdyNameValueBlock& headers) {
  net::SpdyHeadersIR frame(stream_id);
  frame.set_fin(fin);
  frame.GetMutableNameValueBlock()->insert(headers.begin(), headers.end());
  return ::testing::MakeMatcher(new IsEquivalentFrameMatcher(frame));
}

::testing::Matcher<const net::SpdyFrameIR&> IsWindowUpdate(
     net::SpdyStreamId stream_id, uint32 delta) {
  net::SpdyWindowUpdateIR frame(stream_id, delta);
  return ::testing::MakeMatcher(new IsEquivalentFrameMatcher(frame));
}

::testing::Matcher<const net::SpdyFrameIR&> IsDataFrame(
    net::SpdyStreamId stream_id, bool fin, base::StringPiece payload) {
  net::SpdyDataIR frame(stream_id, payload);
  frame.set_fin(fin);
  return ::testing::MakeMatcher(new IsEquivalentFrameMatcher(frame));
}

}  // namespace testing

}  // namespace mod_spdy
