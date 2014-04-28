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

#include "mod_spdy/common/protocol_util.h"

#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "net/spdy/spdy_frame_builder.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"

namespace mod_spdy {

namespace http {

extern const char* const kAcceptEncoding = "accept-encoding";
extern const char* const kConnection = "connection";
extern const char* const kContentLength = "content-length";
extern const char* const kContentType = "content-type";
extern const char* const kHost = "host";
extern const char* const kKeepAlive = "keep-alive";
extern const char* const kProxyConnection = "proxy-connection";
extern const char* const kReferer = "referer";
extern const char* const kTransferEncoding = "transfer-encoding";
extern const char* const kXAssociatedContent = "x-associated-content";
extern const char* const kXModSpdy = "x-mod-spdy";

extern const char* const kChunked = "chunked";
extern const char* const kGzipDeflate = "gzip,deflate";

}  // namespace http

namespace spdy {

extern const char* const kSpdy2Method = "method";
extern const char* const kSpdy2Scheme = "scheme";
extern const char* const kSpdy2Status = "status";
extern const char* const kSpdy2Url = "url";
extern const char* const kSpdy2Version = "version";

extern const char* const kSpdy3Host = ":host";
extern const char* const kSpdy3Method = ":method";
extern const char* const kSpdy3Path = ":path";
extern const char* const kSpdy3Scheme = ":scheme";
extern const char* const kSpdy3Status = ":status";
extern const char* const kSpdy3Version = ":version";

}  // namespace spdy

net::SpdyMajorVersion SpdyVersionToFramerVersion(spdy::SpdyVersion version) {
  switch (version) {
    case spdy::SPDY_VERSION_2:
      return net::SPDY2;
    case spdy::SPDY_VERSION_3:
    case spdy::SPDY_VERSION_3_1:
      return net::SPDY3;
    default:
      LOG(DFATAL) << "Invalid SpdyVersion value: " << version;
      return static_cast<net::SpdyMajorVersion>(0);
  }
}

const char* SpdyVersionNumberString(spdy::SpdyVersion version) {
  switch (version) {
    case spdy::SPDY_VERSION_2:   return "2";
    case spdy::SPDY_VERSION_3:   return "3";
    case spdy::SPDY_VERSION_3_1: return "3.1";
    default:
      LOG(DFATAL) << "Invalid SpdyVersion value: " << version;
      return "?";
  }
}

const char* GoAwayStatusCodeToString(net::SpdyGoAwayStatus status) {
  switch (status) {
    case net::GOAWAY_OK:             return "OK";
    case net::GOAWAY_PROTOCOL_ERROR: return "PROTOCOL_ERROR";
    case net::GOAWAY_INTERNAL_ERROR: return "INTERNAL_ERROR";
    default:                         return "<unknown>";
  }
}

const char* SettingsIdToString(net::SpdySettingsIds id) {
  switch (id) {
    case net::SETTINGS_UPLOAD_BANDWIDTH:       return "UPLOAD_BANDWIDTH";
    case net::SETTINGS_DOWNLOAD_BANDWIDTH:     return "DOWNLOAD_BANDWIDTH";
    case net::SETTINGS_ROUND_TRIP_TIME:        return "ROUND_TRIP_TIME";
    case net::SETTINGS_MAX_CONCURRENT_STREAMS: return "MAX_CONCURRENT_STREAMS";
    case net::SETTINGS_CURRENT_CWND:           return "CURRENT_CWND";
    case net::SETTINGS_DOWNLOAD_RETRANS_RATE:  return "DOWNLOAD_RETRANS_RATE";
    case net::SETTINGS_INITIAL_WINDOW_SIZE:    return "INITIAL_WINDOW_SIZE";
    default:                                   return "<unknown>";
  }
}

bool IsInvalidSpdyResponseHeader(base::StringPiece key) {
  // The following headers are forbidden in SPDY responses (SPDY draft 3
  // section 3.2.2).
  return (LowerCaseEqualsASCII(key.begin(), key.end(), http::kConnection) ||
          LowerCaseEqualsASCII(key.begin(), key.end(), http::kKeepAlive) ||
          LowerCaseEqualsASCII(key.begin(), key.end(),
                               http::kProxyConnection) ||
          LowerCaseEqualsASCII(key.begin(), key.end(),
                               http::kTransferEncoding));
}

net::SpdyPriority LowestSpdyPriorityForVersion(
    spdy::SpdyVersion spdy_version) {
  return (spdy_version < spdy::SPDY_VERSION_3 ? 3u : 7u);
}

void MergeInHeader(base::StringPiece key, base::StringPiece value,
                   net::SpdyHeaderBlock* headers) {
  // The SPDY spec requires that header names be lowercase, so forcibly
  // lowercase the key here.
  std::string lower_key(key.as_string());
  StringToLowerASCII(&lower_key);

  net::SpdyHeaderBlock::iterator iter = headers->find(lower_key);
  if (iter == headers->end()) {
    (*headers)[lower_key] = value.as_string();
  } else {
    iter->second.push_back('\0');
    value.AppendToString(&iter->second);
  }
}

}  // namespace mod_spdy
