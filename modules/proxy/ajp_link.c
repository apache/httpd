/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ajp.h"


apr_status_t ajp_ilink_send(apr_socket_t *sock, ajp_msg_t *msg)
{
    char         *buf;
    apr_status_t status;
    apr_size_t   length;

    if (sock == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                      "ajp_ilink_send(): NULL socket provided");
        return AJP_EINVAL;
    }

    ajp_msg_end(msg);

    length = msg->len;
    buf    = (char *)msg->buf;

    do {
        apr_size_t written = length;

        status = apr_socket_send(sock, buf, &written);
        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, status, NULL,
                          "ajp_ilink_send(): send failed");
            return status;
        }
        length -= written;
        buf    += written;
    } while (length);

    return APR_SUCCESS;
}


static apr_status_t ilink_read(apr_socket_t *sock, apr_byte_t *buf,
                               apr_size_t len)
{
    apr_size_t   length = len;
    apr_size_t   rdlen  = 0;
    apr_status_t status;

    while (rdlen < len) {

        status = apr_socket_recv(sock, (char *)(buf + rdlen), &length);

        if (status == APR_EOF)
            return status;          /* socket closed. */
        else if (APR_STATUS_IS_EAGAIN(status))
            continue;
        else if (status != APR_SUCCESS)
            return status;          /* any error. */

        rdlen += length;
        length = len - rdlen;
    }
    return APR_SUCCESS;
}


apr_status_t ajp_ilink_receive(apr_socket_t *sock, ajp_msg_t *msg)
{
    apr_status_t status;
    apr_size_t   hlen;
    apr_size_t   blen;

    if (sock == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                      "ajp_ilink_receive(): NULL socket provided");
        return AJP_EINVAL;
    }

    hlen = msg->header_len;

    status = ilink_read(sock, msg->buf, hlen);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, NULL,
                     "ajp_ilink_receive() can't receive header");
        return (APR_STATUS_IS_TIMEUP(status) ? APR_TIMEUP : AJP_ENO_HEADER);
    }

    status = ajp_msg_check_header(msg, &blen);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "ajp_ilink_receive() received bad header");
        return AJP_EBAD_HEADER;
    }

    status = ilink_read(sock, msg->buf + hlen, blen);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, NULL,
                     "ajp_ilink_receive() error while receiving message body "
                     "of length %" APR_SIZE_T_FMT,
                     hlen);
        return AJP_EBAD_MESSAGE;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "ajp_ilink_receive() received packet len=%" APR_SIZE_T_FMT
                 "type=%d",
                  blen, (int)msg->buf[hlen]);

    return APR_SUCCESS;
}

