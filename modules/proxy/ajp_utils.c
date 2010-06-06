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

APLOG_USE_MODULE(proxy_ajp);

/*
 * Handle the CPING/CPONG
 */
apr_status_t ajp_handle_cping_cpong(apr_socket_t *sock,
                                    request_rec *r,
                                    apr_interval_time_t timeout)
{
    ajp_msg_t *msg;
    apr_status_t rc, rv;
    apr_interval_time_t org;
    apr_byte_t result;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Into ajp_handle_cping_cpong");

    rc = ajp_msg_create(r->pool, AJP_PING_PONG_SZ, &msg);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_handle_cping_cpong: ajp_msg_create failed");
        return rc;
    }

    rc = ajp_msg_serialize_cping(msg);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_handle_cping_cpong: ajp_marshal_into_msgb failed");
        return rc;
    }

    rc = ajp_ilink_send(sock, msg);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_handle_cping_cpong: ajp_ilink_send failed");
        return rc;
    }

    rc = apr_socket_timeout_get(sock, &org);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_handle_cping_cpong: apr_socket_timeout_get failed");
        return rc;
    }

    /* Set CPING/CPONG response timeout */
    rc = apr_socket_timeout_set(sock, timeout);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_handle_cping_cpong: apr_socket_timeout_set failed");
        return rc;
    }
    ajp_msg_reuse(msg);

    /* Read CPONG reply */
    rv = ajp_ilink_receive(sock, msg);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_handle_cping_cpong: ajp_ilink_receive failed");
        goto cleanup;
    }

    rv = ajp_msg_get_uint8(msg, &result);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_handle_cping_cpong: invalid CPONG message");
        goto cleanup;
    }
    if (result != CMD_AJP13_CPONG) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_handle_cping_cpong: awaited CPONG, received %d ",
               result);
        rv = APR_EGENERAL;
        goto cleanup;
    }

cleanup:
    /* Restore original socket timeout */
    rc = apr_socket_timeout_set(sock, org);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
               "ajp_handle_cping_cpong: apr_socket_timeout_set failed");
        return rc;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "ajp_handle_cping_cpong: Done");
    return rv;
}
