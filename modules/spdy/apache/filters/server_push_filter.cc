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

#include "mod_spdy/apache/filters/server_push_filter.h"

#include <string>

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"  // for StringToUint
#include "base/strings/string_piece.h"
#include "mod_spdy/common/protocol_util.h"
#include "mod_spdy/common/spdy_server_config.h"
#include "mod_spdy/common/spdy_stream.h"

namespace mod_spdy {

namespace {

// Utility function passed to apr_table_do:
int AddOneHeader(void* headers, const char* key, const char* value) {
  mod_spdy::MergeInHeader(
      key, value, static_cast<net::SpdyHeaderBlock*>(headers));
  return 1;  // return zero to stop, or non-zero to continue iterating
}

// Modify *source to remove whitespace characters from the front.
void AbsorbWhiteSpace(base::StringPiece* source) {
  *source = source->substr(source->find_first_not_of(" \n\r\t"));
}

// If the first thing in *source is '"foobar"', set out to 'foobar', modify
// *source to skip past both quotes and any whitespace thereafter, and return
// true.  Otherwise return false.
bool ParseQuotedString(base::StringPiece* source, std::string* out) {
  if (source->empty() || (*source)[0] != '"') {
    return false;  // failure: no open quote
  }
  const size_t close = source->find('"', 1);
  if (close == base::StringPiece::npos) {
    return false;  // failure: no close quote
  }
  source->substr(1, close - 1).CopyToString(out);
  *source = source->substr(close + 1);
  AbsorbWhiteSpace(source);
  return true;
}

// If the next character in *source is c, modify *source to skip past the
// character and any whitespace thereafter, and return true.  Otherwise return
// false.
bool ParseSeparator(char c, base::StringPiece* source) {
  if (source->empty() || (*source)[0] != c) {
    return false;
  }
  *source = source->substr(1);
  AbsorbWhiteSpace(source);
  return true;
}

// If the next part of *source looks like ':2' (for some value of 2), parse the
// number, store it in *out, and modify *source to skip past it.  Otherwise,
// just leave *source unchanged.  See ParseAssociatedContent for the full
// expected format of *source.
net::SpdyPriority ParseOptionalPriority(SpdyStream* spdy_stream,
                                        base::StringPiece* source) {
  const net::SpdyPriority lowest_priority =
      LowestSpdyPriorityForVersion(spdy_stream->spdy_version());
  if (!ParseSeparator(':', source)) {
    // It's okay for the ":priority" to not be there.  In that case, we default
    // to minimal priority.
    return lowest_priority;
  }
  const size_t end = source->find_first_not_of("0123456789");
  const base::StringPiece number = source->substr(0, end);
  unsigned priority;
  if (!StringToUint(number, &priority)) {
    LOG(INFO) << "Invalid priority value in X-Associated-Content: '"
              << number << "'";
    return lowest_priority;
  }
  *source = source->substr(end);
  AbsorbWhiteSpace(source);
  // Clamp the priority to a legal value (larger numbers represent lower
  // priorities, so we must not return a number greater than lowest_priority).
  return (priority > lowest_priority ? lowest_priority : priority);
}

}  // namespace

ServerPushFilter::ServerPushFilter(SpdyStream* stream, request_rec* request,
                                   const SpdyServerConfig* server_cfg)
    : stream_(stream), request_(request), server_cfg_(server_cfg) {
  DCHECK(stream_);
  DCHECK(request_);
}

ServerPushFilter::~ServerPushFilter() {}

apr_status_t ServerPushFilter::Write(ap_filter_t* filter,
                                     apr_bucket_brigade* input_brigade) {
  DCHECK_EQ(request_, filter->r);
  // We only do server pushes for SPDY v3 and later.  Also, to avoid infinite
  // push loops, we don't allow push streams to invoke further push streams
  // beyond a specified depth.
  if (stream_->spdy_version() >= spdy::SPDY_VERSION_3 &&
      stream_->server_push_depth() < server_cfg_->max_server_push_depth()) {
    // Parse and start pushes for each X-Associated-Content header, if any.
    // (Note that APR tables allow multiple entries with the same key, just
    // like HTTP headers.)
    apr_table_do(
        OnXAssociatedContent,   // function to call on each key/value pair
        this,                   // void* to be passed as first arg to function
        request_->headers_out,  // the apr_table_t to iterate over
        // Varargs: zero or more char* keys to iterate over, followed by NULL
        http::kXAssociatedContent, NULL);
    // We need to give the same treatment to err_headers_out as we just gave to
    // headers_out.  Depending on how the X-Associated-Content header was set,
    // it might end up in either one.  For example, using a mod_headers Header
    // directive will put the header in headers_out, but using a PHP header()
    // function call will put the header in err_headers_out.
    apr_table_do(OnXAssociatedContent, this, request_->err_headers_out,
                 http::kXAssociatedContent, NULL);
  }
  // Even in cases where we forbid pushes from this stream, we still purge the
  // X-Associated-Content header (from both headers_out and err_headers_out).
  apr_table_unset(request_->headers_out, http::kXAssociatedContent);
  apr_table_unset(request_->err_headers_out, http::kXAssociatedContent);

  // Remove ourselves from the filter chain.
  ap_remove_output_filter(filter);
  // Pass the data through unchanged.
  return ap_pass_brigade(filter->next, input_brigade);
}

void ServerPushFilter::ParseXAssociatedContentHeader(base::StringPiece value) {
  AbsorbWhiteSpace(&value);
  bool first_url = true;

  while (!value.empty()) {
    // The URLs should be separated by commas, so a comma should proceed each
    // URL except the first.
    if (first_url) {
      first_url = false;
    } else if (!ParseSeparator(',', &value)) {
      LOG(INFO) << "Parse error in X-Associated-Content: missing comma";
      return;
    }

    // Get a quoted URL string.
    std::string url;
    if (!ParseQuotedString(&value, &url)) {
      LOG(INFO) << "Parse error in X-Associated-Content: expected quoted URL";
      return;
    }

    // The URL may optionally be followed by a priority.  If the priority is
    // not there, use the lowest-importance priority by default.
    net::SpdyPriority priority = ParseOptionalPriority(stream_, &value);

    // Try to parse the URL string.  If it does not form a valid URL, log an
    // error and skip past this entry.
    apr_uri_t parsed_url;
    {
      const apr_status_t status =
          apr_uri_parse(request_->pool, url.c_str(), &parsed_url);
      if (status != APR_SUCCESS) {
        LOG(ERROR) << "Invalid URL in X-Associated-Content: '" << url << "'";
        continue;
      }
    }

    // Populate the fake request headers for the pushed stream.
    net::SpdyHeaderBlock request_headers;
    // Start off by pulling in certain headers from the associated stream's
    // request headers.
    apr_table_do(
        AddOneHeader,          // function to call on each key/value pair
        &request_headers,      // void* to be passed as first arg to function
        request_->headers_in,  // the apr_table_t to iterate over
        // Varargs: zero or more char* keys to iterate over, followed by NULL
        "accept", "accept-charset", "accept-datetime",
        mod_spdy::http::kAcceptEncoding, "accept-language", "authorization",
        "user-agent", NULL);
    // Next, we populate special SPDY headers, using a combination of pushed
    // URL and details from the associated request.
    if (parsed_url.hostinfo != NULL) {
      request_headers[spdy::kSpdy3Host] = parsed_url.hostinfo;
    } else {
      const char* host_header =
          apr_table_get(request_->headers_in, http::kHost);
      request_headers[spdy::kSpdy3Host] =
          (host_header != NULL ? host_header :
           request_->hostname != NULL ? request_->hostname : "");
    }
    request_headers[spdy::kSpdy3Method] = "GET";
    request_headers[spdy::kSpdy3Scheme] =
        (parsed_url.scheme != NULL ? parsed_url.scheme : "https");
    request_headers[spdy::kSpdy3Version] = request_->protocol;
    // Construct the path that we are pushing from the parsed URL.
    // TODO(mdsteele): It'd be nice to support relative URLs.
    {
      std::string* path = &request_headers[spdy::kSpdy3Path];
      path->assign(parsed_url.path == NULL ? "/" : parsed_url.path);
      if (parsed_url.query != NULL) {
        path->push_back('?');
        path->append(parsed_url.query);
      }
      if (parsed_url.fragment != NULL) {
        // It's a little weird to try to push a URL with a fragment in it, but
        // if someone does so anyway, we may as well honor it.
        path->push_back('#');
        path->append(parsed_url.fragment);
      }
    }
    // Finally, we set the HTTP referrer to be the associated stream's URL.
    request_headers[http::kReferer] = request_->unparsed_uri;

    // Try to perform the push.  If it succeeds, we'll continue with parsing.
    const SpdyServerPushInterface::PushStatus status =
        stream_->StartServerPush(priority, request_headers);
    switch (status) {
      case SpdyServerPushInterface::PUSH_STARTED:
        break;  // success
      case SpdyServerPushInterface::INVALID_REQUEST_HEADERS:
        // This shouldn't happen unless there's a bug in the above code.
        LOG(DFATAL) << "ParseAssociatedContent: invalid request headers";
        return;
      case SpdyServerPushInterface::ASSOCIATED_STREAM_INACTIVE:
      case SpdyServerPushInterface::CANNOT_PUSH_EVER_AGAIN:
      case SpdyServerPushInterface::TOO_MANY_CONCURRENT_PUSHES:
      case SpdyServerPushInterface::PUSH_INTERNAL_ERROR:
        // In any of these cases, any remaining pushes specified by the header
        // are unlikely to succeed, so just stop parsing and quit.
        LOG(INFO) << "Push failed while processing X-Associated-Content "
                  << "header (status=" << status << ").  Skipping remainder.";
        return;
      default:
        LOG(DFATAL) << "Invalid push status value: " << status;
        return;
    }
  }
}

// static
int ServerPushFilter::OnXAssociatedContent(
    void* server_push_filter, const char* key, const char* value) {
  static_cast<ServerPushFilter*>(server_push_filter)->
      ParseXAssociatedContentHeader(value);
  return 1;  // return zero to stop, or non-zero to continue iterating
}

}  // namespace mod_spdy
