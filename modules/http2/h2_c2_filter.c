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
 
#include <assert.h>
#include <stdio.h>

#include <apr_date.h>
#include <apr_lib.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <util_time.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_conn_ctx.h"
#include "h2_config.h"
#include "h2_c1.h"
#include "h2_c2_filter.h"
#include "h2_c2.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_util.h"


apr_status_t h2_c2_filter_notes_out(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    request_rec *r_prev;
    ap_bucket_response *resp;
    const char *err;

    if (!f->r) {
        goto pass;
    }

    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        if (AP_BUCKET_IS_RESPONSE(b)) {
            resp = b->data;
            if (resp->status >= 400 && f->r->prev) {
                /* Error responses are commonly handled via internal
                 * redirects to error documents. That creates a new
                 * request_rec with 'prev' set to the original.
                 * Each of these has its onw 'notes'.
                 * We'd like to copy interesting ones into the current 'r->notes'
                 * as we reset HTTP/2 stream with H2 specific error codes then.
                 */
                for (r_prev = f->r; r_prev != NULL; r_prev = r_prev->prev) {
                    if ((err = apr_table_get(r_prev->notes, "ssl-renegotiate-forbidden"))) {
                        if (r_prev != f->r) {
                            apr_table_setn(resp->notes, "ssl-renegotiate-forbidden", err);
                        }
                        break;
                    }
                }
            }
            else if (h2_config_rgeti(f->r, H2_CONF_PUSH) == 0
                     && h2_config_sgeti(f->r->server, H2_CONF_PUSH) != 0) {
                /* location configuration turns off H2 PUSH handling */
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, f->c,
                              "h2_c2_filter_notes_out, turning PUSH off");
                apr_table_setn(resp->notes, H2_PUSH_MODE_NOTE, "0");
            }
        }
    }
pass:
    return ap_pass_brigade(f->next, bb);
}

