// Copyright 2010 Google Inc.
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

// There are a number of things that every output filter should do, according
// to <http://httpd.apache.org/docs/2.3/developer/output-filters.html>.  In
// short, these things are:
//
//   - Respect FLUSH and EOS metadata buckets, and pass other metadata buckets
//     down the chain.  Ignore all buckets after an EOS.
//
//   - Don't allocate long-lived memory on every invocation.  In particular, if
//     you need a temp brigade, allocate it once and then reuse it each time.
//
//   - Never pass an empty brigade down the chain, but be ready to accept one
//     and do nothing.
//
//   - Calling apr_brigade_destroy can be dangerous; prefer using
//     apr_brigade_cleanup instead.
//
//   - Don't read the entire brigade into memory at once; the brigade may, for
//     example, contain a FILE bucket representing a 42 GB file.  Instead, use
//     apr_bucket_read to read a reasonable portion of the bucket, put the
//     resulting (small) bucket into a temp brigade, pass it down the chain,
//     and then clean up the temp brigade before continuing.
//
//   - If a bucket is to be saved beyond the scope of the filter invocation
//     that first received it, it must be "set aside" using the
//     apr_bucket_setaside macro.
//
//   - When reading a bucket, first use a non-blocking read; if it fails with
//     APR_EAGAIN, send a FLUSH bucket down the chain, and then read the bucket
//     with a blocking read.
//
// This code attempts to follow these rules.

#include "mod_spdy/apache/filters/http_to_spdy_filter.h"

#include "apr_strings.h"

#include "base/logging.h"
#include "mod_spdy/apache/pool_util.h"  // for AprStatusString
#include "mod_spdy/common/protocol_util.h"
#include "mod_spdy/common/spdy_server_config.h"
#include "mod_spdy/common/spdy_stream.h"
#include "mod_spdy/common/version.h"
#include "net/spdy/spdy_protocol.h"

namespace {

const char* kModSpdyVersion = MOD_SPDY_VERSION_STRING "-" LASTCHANGE_STRING;

}  // namespace

namespace mod_spdy {

HttpToSpdyFilter::HttpToSpdyFilter(const SpdyServerConfig* config,
                                   SpdyStream* stream)
    : receiver_(config, stream),
      converter_(stream->spdy_version(), &receiver_),
      eos_bucket_received_(false) {}

HttpToSpdyFilter::~HttpToSpdyFilter() {}

// Check if the SPDY stream has been aborted; if so, mark the connection object
// as having been aborted and return APR_ECONNABORTED.  Hopefully, this will
// convince Apache to shut down processing for this (slave) connection, thus
// allowing this stream's thread to complete and exit.
#define RETURN_IF_STREAM_ABORT(filter)                                 \
  do {                                                                 \
    if ((filter)->c->aborted || receiver_.stream_->is_aborted()) {     \
      (filter)->c->aborted = true;                                     \
      return APR_ECONNABORTED;                                         \
    }                                                                  \
  } while (false)

apr_status_t HttpToSpdyFilter::Write(ap_filter_t* filter,
                                     apr_bucket_brigade* input_brigade) {
  // This is a NETWORK-level filter, so there shouldn't be any filter after us.
  if (filter->next != NULL) {
    LOG(WARNING) << "HttpToSpdyFilter is not the last filter in the chain "
                 << "(it is followed by " << filter->next->frec->name << ")";
  }

  // According to the page at
  //   http://httpd.apache.org/docs/2.3/developer/output-filters.html
  // we should never pass an empty brigade down the chain, but to be safe, we
  // should be prepared to accept one and do nothing.
  if (APR_BRIGADE_EMPTY(input_brigade)) {
    LOG(INFO) << "HttpToSpdyFilter received an empty brigade.";
    return APR_SUCCESS;
  }

  // Loop through the brigade, reading and sending data.  We delete each bucket
  // once we have successfully consumed it, before moving on to the next
  // bucket.  There are two reasons to delete buckets as we go:
  //
  //   1) Some output filters (such as mod_deflate) that come before us will
  //      expect us to empty out the brigade that they give us before we
  //      return.  If we don't do so, the second time they call us we'll see
  //      all those same buckets again (along with the new buckets).
  //
  //   2) Some bucket types such as FILE don't store their data in memory, and
  //      when read, split into two buckets: one containing some data, and the
  //      other representing the rest of the file.  If we read in all buckets
  //      in the brigade without deleting ones we're done with, we will
  //      eventually read the whole file into memory; by deleting buckets as we
  //      go, only a portion of the file is in memory at a time.
  while (!APR_BRIGADE_EMPTY(input_brigade)) {
    apr_bucket* bucket = APR_BRIGADE_FIRST(input_brigade);

    if (APR_BUCKET_IS_METADATA(bucket)) {
      if (APR_BUCKET_IS_EOS(bucket)) {
        // EOS bucket -- there should be no more data buckets in this stream.
        eos_bucket_received_ = true;
        RETURN_IF_STREAM_ABORT(filter);
        converter_.Flush();
      } else if (APR_BUCKET_IS_FLUSH(bucket)) {
        // FLUSH bucket -- call Send() immediately and flush the data buffer.
        RETURN_IF_STREAM_ABORT(filter);
        converter_.Flush();
      } else {
        // Unknown metadata bucket.  This bucket has no meaning to us, and
        // there's no further filter to pass it to, so we just ignore it.
      }
    } else if (eos_bucket_received_) {
      // We shouldn't be getting any data buckets after an EOS (since this is a
      // connection-level filter, we do sometimes see other metadata buckets
      // after the EOS).  If we do get them, ignore them.
      LOG(INFO) << "HttpToSpdyFilter received " << bucket->type->name
                << " bucket after an EOS (and ignored it).";
    } else {
      // Data bucket -- get ready to read.
      const char* data = NULL;
      apr_size_t data_length = 0;

      // First, try a non-blocking read.
      apr_status_t status = apr_bucket_read(bucket, &data, &data_length,
                                            APR_NONBLOCK_READ);
      if (status == APR_SUCCESS) {
        RETURN_IF_STREAM_ABORT(filter);
        if (!converter_.ProcessInput(data, static_cast<size_t>(data_length))) {
          // Parse failure.  The parser will have already logged an error.
          return APR_EGENERAL;
        }
      } else if (APR_STATUS_IS_EAGAIN(status)) {
        // Non-blocking read failed with EAGAIN, so try again with a blocking
        // read (but flush first, in case we block for a long time).
        RETURN_IF_STREAM_ABORT(filter);
        converter_.Flush();
        status = apr_bucket_read(bucket, &data, &data_length, APR_BLOCK_READ);
        if (status != APR_SUCCESS) {
          LOG(ERROR) << "Blocking read failed with status " << status << ": "
                     << AprStatusString(status);
          // Since we didn't successfully consume this bucket, don't delete it;
          // rather, leave it (and any remaining buckets) in the brigade.
          return status;  // failure
        }
        RETURN_IF_STREAM_ABORT(filter);
        if (!converter_.ProcessInput(data, static_cast<size_t>(data_length))) {
          // Parse failure.  The parser will have already logged an error.
          return APR_EGENERAL;
        }
      } else {
        // Since we didn't successfully consume this bucket, don't delete it;
        // rather, leave it (and any remaining buckets) in the brigade.
        return status;  // failure
      }
    }

    // We consumed this bucket successfully, so delete it and move on to the
    // next.
    apr_bucket_delete(bucket);
  }

  // We went through the whole brigade successfully, so it must be empty when
  // we return (see http://code.google.com/p/mod-spdy/issues/detail?id=17).
  DCHECK(APR_BRIGADE_EMPTY(input_brigade));
  return APR_SUCCESS;
}

HttpToSpdyFilter::ReceiverImpl::ReceiverImpl(const SpdyServerConfig* config,
                                             SpdyStream* stream)
    : config_(config), stream_(stream) {
  DCHECK(config_);
  DCHECK(stream_);
}

HttpToSpdyFilter::ReceiverImpl::~ReceiverImpl() {}

void HttpToSpdyFilter::ReceiverImpl::ReceiveSynReply(
    net::SpdyHeaderBlock* headers, bool flag_fin) {
  DCHECK(headers);
  if (config_->send_version_header()) {
    (*headers)[http::kXModSpdy] = kModSpdyVersion;
  }
  // For client-requested streams, we should send a SYN_REPLY.  For
  // server-pushed streams, the SpdySession has already sent an initial
  // SYN_STREAM with FLAG_UNIDIRECTIONAL and minimal server push headers, so we
  // now follow up with a HEADERS frame with the response headers.
  if (stream_->is_server_push()) {
    stream_->SendOutputHeaders(*headers, flag_fin);
  } else {
    stream_->SendOutputSynReply(*headers, flag_fin);
  }
}

void HttpToSpdyFilter::ReceiverImpl::ReceiveData(
    base::StringPiece data, bool flag_fin) {
  stream_->SendOutputDataFrame(data, flag_fin);
}

}  // namespace mod_spdy
