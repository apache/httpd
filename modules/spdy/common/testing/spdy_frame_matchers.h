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

#ifndef MOD_SPDY_TESTING_SPDY_FRAME_MATCHERS_H_
#define MOD_SPDY_TESTING_SPDY_FRAME_MATCHERS_H_

#include "base/basictypes.h"
#include "base/strings/string_piece.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/gmock/include/gmock/gmock.h"

namespace mod_spdy {

namespace testing {

// Make a matcher that requires the argument to be a SYN_STREAM frame with the
// given stream ID, associated stream ID, priority, flag_fin,
// flag_unidirectional, and headers.
::testing::Matcher<const net::SpdyFrameIR&> IsSynStream(
     net::SpdyStreamId stream_id, net::SpdyStreamId assoc_stream_id,
     net::SpdyPriority priority, bool fin, bool unidirectional,
     const net::SpdyNameValueBlock& headers);

// Make a matcher that requires the argument to be a SYN_REPLY frame with the
// given stream ID, flag_fin, and headers.
::testing::Matcher<const net::SpdyFrameIR&> IsSynReply(
     net::SpdyStreamId stream_id, bool fin,
     const net::SpdyNameValueBlock& headers);

// Make a matcher that requires the argument to be a RST_STREAM frame with the
// given stream ID and status code.
::testing::Matcher<const net::SpdyFrameIR&> IsRstStream(
     net::SpdyStreamId stream_id, net::SpdyRstStreamStatus status);

// Make a matcher that requires the argument to be a SETTINGS frame with the
// given setting.
::testing::Matcher<const net::SpdyFrameIR&> IsSettings(
     net::SpdySettingsIds id, int32 value);

// Make a matcher that requires the argument to be a PING frame with the
// given ID.
::testing::Matcher<const net::SpdyFrameIR&> IsPing(net::SpdyPingId ping_id);

// Make a matcher that requires the argument to be a GOAWAY frame with the
// given last-good-stream-ID and status code.
::testing::Matcher<const net::SpdyFrameIR&> IsGoAway(
     net::SpdyStreamId last_good_stream_id, net::SpdyGoAwayStatus status);

// Make a matcher that requires the argument to be a HEADERS frame with the
// given stream ID, flag_fin, and headers.
::testing::Matcher<const net::SpdyFrameIR&> IsHeaders(
     net::SpdyStreamId stream_id, bool fin,
     const net::SpdyNameValueBlock& headers);

// Make a matcher that requires the argument to be a WINDOW_UPDATE frame with
// the given window-size-delta.
::testing::Matcher<const net::SpdyFrameIR&> IsWindowUpdate(
     net::SpdyStreamId stream_id, uint32 delta);

// Make a matcher that requires the argument to be a DATA frame.
::testing::Matcher<const net::SpdyFrameIR&> IsDataFrame(
     net::SpdyStreamId stream_id, bool fin, base::StringPiece payload);

}  // namespace testing

}  // namespace mod_spdy

#endif  // MOD_SPDY_TESTING_SPDY_FRAME_MATCHERS_H_
