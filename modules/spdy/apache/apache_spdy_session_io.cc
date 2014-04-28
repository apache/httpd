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

#include "mod_spdy/apache/apache_spdy_session_io.h"

#include "apr_buckets.h"
#include "http_log.h"
#include "util_filter.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "mod_spdy/apache/pool_util.h"  // for AprStatusString
#include "mod_spdy/common/protocol_util.h"  // for FrameData
#include "net/spdy/buffered_spdy_framer.h"
#include "net/spdy/spdy_protocol.h"

namespace mod_spdy {

namespace {

// How many bytes to ask for at a time when pulling data from the connection
// input filters.  We use non-blocking reads, so we'll sometimes get less than
// this.
const apr_off_t kReadBytes = 4096;

}  // namespace

ApacheSpdySessionIO::ApacheSpdySessionIO(conn_rec* connection)
    : connection_(connection),
      input_brigade_(apr_brigade_create(connection_->pool,
                                        connection_->bucket_alloc)),
      output_brigade_(apr_brigade_create(connection_->pool,
                                         connection_->bucket_alloc)) {}

ApacheSpdySessionIO::~ApacheSpdySessionIO() {}

bool ApacheSpdySessionIO::IsConnectionAborted() {
  return static_cast<bool>(connection_->aborted);
}

SpdySessionIO::ReadStatus ApacheSpdySessionIO::ProcessAvailableInput(
    bool block, net::BufferedSpdyFramer* framer) {
  const apr_read_type_e read_type = block ? APR_BLOCK_READ : APR_NONBLOCK_READ;

  // Make sure the input brigade we're using is empty.
  if (!APR_BRIGADE_EMPTY(input_brigade_)) {
    LOG(DFATAL) << "input_brigade_ should be empty";
    apr_brigade_cleanup(input_brigade_);
  }

  // Try to read some data into the brigade.
  {
    const apr_status_t status = ap_get_brigade(
        connection_->input_filters, input_brigade_, AP_MODE_READBYTES,
        read_type, kReadBytes);
    if (status == APR_SUCCESS) {
      // Success; we'll process the brigade below.
    } else if (APR_STATUS_IS_EAGAIN(status)) {
      // EAGAIN probably indicates that we did a non-blocking read and no data
      // was available.  So, just press on and process the brigade (it should
      // be empty, but maybe there'll be metadata buckets or something).  Most
      // likely we'll end up returning READ_NO_DATA at the end of this method.
    } else if (APR_STATUS_IS_TIMEUP(status)) {
      // TIMEUP tends to occur for blocking reads, if some upstream filter set
      // a timeout.  Just like with EAGAIN, we'll press on and process the
      // probably-empty brigade, but since these seem to be rare, let's VLOG
      // here so that we can see when they happen.
      VLOG(3) << "ap_get_brigade returned TIMEUP";
    } else {
      // Otherwise, something has gone wrong and we should consider the
      // connection closed.  If the client merely closed the connection on us,
      // we'll get an EOF error, which is fine; otherwise, something may be
      // wrong, so we should log an error.
      if (APR_STATUS_IS_EOF(status)) {
        VLOG(2) << "ap_get_brigade returned EOF";
      } else {
        LOG(ERROR) << "ap_get_brigade failed with status " << status << ": "
                   << AprStatusString(status);
      }
      apr_brigade_cleanup(input_brigade_);
      return READ_CONNECTION_CLOSED;
    }
  }

  bool pushed_any_data = false;
  while (!APR_BRIGADE_EMPTY(input_brigade_)) {
    apr_bucket* bucket = APR_BRIGADE_FIRST(input_brigade_);

    if (APR_BUCKET_IS_METADATA(bucket)) {
      // Metadata bucket.  We don't care about EOS or FLUSH buckets here (or
      // other, unknown metadata buckets), and there's no further filter to
      // pass it to, so we just ignore it.
    } else {
      // Data bucket -- get ready to read.
      const char* data = NULL;
      apr_size_t data_length = 0;
      const apr_status_t status = apr_bucket_read(bucket, &data, &data_length,
                                                  read_type);
      if (status != APR_SUCCESS) {
        // TODO(mdsteele): In what situations might apr_bucket_read fail here?
        //   These buckets are almost certainly coming from mod_ssl, which
        //   seems to only use transient buckets, for which apr_bucket_read
        //   will always succeed.  However, in theory there could be another
        //   filter between us and mod_ssl, and in theory it could be sending
        //   us bucket types for which non-blocking reads can fail.
        LOG(ERROR) << "apr_bucket_read failed with status " << status << ": "
                   << AprStatusString(status);
      }

      const size_t consumed = framer->ProcessInput(data, data_length);
      // If the SpdyFramer encountered an error (i.e. the client sent us
      // malformed data), then we can't recover.
      if (framer->HasError()) {
        apr_brigade_cleanup(input_brigade_);
        return READ_ERROR;
      }
      // If there was no error, the framer will have consumed all the data.
      // TODO(mdsteele): Is that true?  I think it's true.
      DCHECK(consumed == data_length);
      pushed_any_data |= consumed > 0;
    }

    // Delete this bucket and move on to the next one.
    apr_bucket_delete(bucket);
  }

  // We deleted buckets as we went, so the brigade should be empty now.
  DCHECK(APR_BRIGADE_EMPTY(input_brigade_));

  return pushed_any_data ? READ_SUCCESS : READ_NO_DATA;
}

SpdySessionIO::WriteStatus ApacheSpdySessionIO::SendFrameRaw(
    const net::SpdySerializedFrame& frame) {
  // Make sure the output brigade we're using is empty.
  if (!APR_BRIGADE_EMPTY(output_brigade_)) {
    LOG(DFATAL) << "output_brigade_ should be empty";
    apr_brigade_cleanup(output_brigade_);
  }

  // Put the frame data into the output brigade.
  APR_BRIGADE_INSERT_TAIL(output_brigade_, apr_bucket_transient_create(
      frame.data(), frame.size(), output_brigade_->bucket_alloc));

  // Append a flush bucket to the end of the brigade, to make sure that this
  // frame makes it all the way out to the client.
  APR_BRIGADE_INSERT_TAIL(output_brigade_, apr_bucket_flush_create(
      output_brigade_->bucket_alloc));

  // Send the brigade through the connection's output filter chain.
  const apr_status_t status =
      ap_pass_brigade(connection_->output_filters, output_brigade_);
  apr_brigade_cleanup(output_brigade_);
  DCHECK(APR_BRIGADE_EMPTY(output_brigade_));

  // If we sent the data successfully, great; otherwise, consider the
  // connection closed.
  if (status == APR_SUCCESS) {
    return WRITE_SUCCESS;
  } else {
    // ECONNABORTED and EPIPE (broken pipe) are two common symptoms of the
    // connection having been closed; those are no cause for concern.  For any
    // other non-success status, log an error (for now).
    if (APR_STATUS_IS_ECONNABORTED(status)) {
      VLOG(2) << "ap_pass_brigade returned ECONNABORTED";
    } else if (APR_STATUS_IS_EPIPE(status)) {
      VLOG(2) << "ap_pass_brigade returned EPIPE";
    } else {
      LOG(ERROR) << "ap_pass_brigade failed with status " << status << ": "
                 << AprStatusString(status);
    }
    return WRITE_CONNECTION_CLOSED;
  }
}

}  // namespace mod_spdy
