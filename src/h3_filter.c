/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <httpd.h>

#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include <apr_buckets.h>
#include <apr_strings.h>

#include "h3_conn.h"
#include "h3_filter.h"
#include "h3_private.h"

apr_status_t h3_filter_out(ap_filter_t* f, apr_bucket_brigade* bb)
{
    apr_bucket* b;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out");
    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
    {
        if (APR_BUCKET_IS_METADATA(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_METADATA");
        }
        if (APR_BUCKET_IS_FLUSH(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_FLUSH");
        }
        if (APR_BUCKET_IS_EOS(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_EOS");
        }
        if (AP_BUCKET_IS_ERROR(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out AP_BUCKET_IS_ERROR");
        }
        if (AP_BUCKET_IS_EOC(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out AP_BUCKET_IS_EOC");
        }
        if (APR_BUCKET_IS_FILE(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_FILE");
        }
        if (AP_BUCKET_IS_HEADERS(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out AP_BUCKET_IS_HEADERS");
        }
        if (APR_BUCKET_IS_FLUSH(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_FLUSH");
        }
        if (APR_BUCKET_IS_IMMORTAL(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_IMMORTAL");
        }
        if (APR_BUCKET_IS_HEAP(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_HEAP");
        }
        if (APR_BUCKET_IS_MMAP(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_MMAP");
        }
        if (AP_BUCKET_IS_EOR(b))
        {
            /* the response/request done */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out AP_BUCKET_IS_EOR");
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out DONE");
            return DONE;
        }
        if (AP_BUCKET_IS_RESPONSE(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out AP_BUCKET_IS_RESPONSE");
        }
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out DONE");
    return APR_SUCCESS;
}

static int print_table_entry(void* rec, const char* key, const char* value)
{
    const conn_rec* c = (conn_rec*)rec;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, c, "h3_filter_out_proto print_table_entry %s %s", key, value);
    return 1;
}

apr_status_t h3_filter_out_proto(ap_filter_t* f, apr_bucket_brigade* bb)
{
    apr_bucket* b = NULL;
    apr_status_t rv = 0;
    h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto %p START", (void*)ctx);
    if (ctx == NULL)
        return ap_pass_brigade(f->next, bb);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto %d", f->r->status);

    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
    {
        if (APR_BUCKET_IS_METADATA(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_METADATA");
        }
        if (APR_BUCKET_IS_FLUSH(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FLUSH");
        }
        else if (APR_BUCKET_IS_EOS(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_EOS");
        }
        else if (AP_BUCKET_IS_ERROR(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_ERROR");
        }
        else if (AP_BUCKET_IS_EOC(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_EOC");
        }
        else if (APR_BUCKET_IS_FILE(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FILE");
        }
        else if (AP_BUCKET_IS_HEADERS(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_HEADERS");
        }
        else if (APR_BUCKET_IS_HEAP(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_HEAP");
        }
        else if (AP_BUCKET_IS_EOR(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_EOR");
        }
        else if (AP_BUCKET_IS_RESPONSE(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE");
        }
        else
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_SOMETHING %s", b->type->name);
        }

        if (AP_BUCKET_IS_ERROR(b))
        {
            /* Should we generate the error page here */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_ERROR");
            ap_send_error_response(f->r, 0);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_ERROR after ap_send_error_response()");
            return OK;
        }
        if (APR_BUCKET_IS_FILE(b) || APR_BUCKET_IS_MMAP(b))
        {
            h3_conn_ctx_t* inner_ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto add to otherpart %s", b->type->name);
            if (inner_ctx != NULL)
            {
                /* we will need to read the file and send it */
                APR_BUCKET_REMOVE(b);
                apr_bucket_setaside(b, inner_ctx->c3reqpool);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto add to otherpart otherpart %p b: %p", (void*)inner_ctx->otherpart, (void*)b);
                inner_ctx->otherpart = b;
                if (inner_ctx->dataheap != NULL)
                    abort();
            }
            else
            {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FILE NO CTX");
            }
        }
        if (AP_BUCKET_IS_RESPONSE(b))
        {
            ap_bucket_response* resp = b->data;
            h3_conn_ctx_t* inner_ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
            /* we will process the response information */
            APR_BUCKET_REMOVE(b);
            apr_bucket_setaside(b, inner_ctx->c3reqpool);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE");
            if (inner_ctx != NULL)
            {
                inner_ctx->resp = resp;
                if (inner_ctx->otherpart != NULL)
                {
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE otherpart %s", inner_ctx->otherpart->type->name);
                }
            }
            else
            {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE NO CTX!!!!");
            }
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto status: %d", resp->status);
            /* XXX: just debug information */
            if (resp->reason != NULL)
            {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto reason: %s", resp->reason);
            }
            if (resp->headers != NULL)
            {
                apr_table_do(print_table_entry, (void*)f->c, resp->headers, NULL);
            }
            if (resp->notes != NULL)
            {
                apr_table_do(print_table_entry, (void*)f->c, resp->notes, NULL);
            }
        }
        if (APR_BUCKET_IS_HEAP(b))
        {
            h3_conn_ctx_t* inner_ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_HEAP");
            if (inner_ctx != NULL && b->data != NULL)
            {
                const char* data;
                apr_size_t len;
                /* We will process it. */
                APR_BUCKET_REMOVE(b);
                apr_bucket_setaside(b, inner_ctx->c3reqpool);
                apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
                inner_ctx->dataheap = (char*)data;
                inner_ctx->dataheaplen = len;
            }
            else
            {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_HEAP NO CTX or NO DATA!!!!");
            }
        }
        if (AP_BUCKET_IS_EOR(b))
        {
            /* EOR belongs to network filters! */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_EOR");
        }
    }
    if (ctx != NULL && ctx->otherpart != NULL && ctx->resp != NULL)
    {
        /* we are done, just return */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto %d %d %p DONE", rv, f->r->status, (void*)f->r->connection);
        return OK;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto CALLING ap_pass_brigade() on next");
    rv = ap_pass_brigade(f->next, bb);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto %d %d %p DONE", rv, f->r->status, (void*)f->r->connection);

    return rv;
}

apr_status_t h3_filter_in_proto(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_status_t rv;
    h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto %p", (void*)ctx);
    if (ctx == NULL)
        return ap_get_brigade(f->next, bb, mode, block, readbytes);

    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto let's do nothing!");
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }
    ap_remove_input_filter(f);
    if (mode == AP_MODE_READBYTES)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto AP_MODE_READBYTES status %d %ld", f->r->status, (long)f->r->clength);
        if (APR_BRIGADE_EMPTY(bb))
        {
            const char* postdata = apr_table_get(f->r->notes, "H3POSTDATA");
            const char* postdatalen = apr_table_get(f->r->notes, "H3POSTDATALEN");
            if (postdatalen && postdata)
            {
                apr_int64_t data_len64 = apr_atoi64(postdatalen);
                if (data_len64 < 0 || (uint64_t)data_len64 > (uint64_t)APR_SIZE_MAX)
                {
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_in_proto: invalid data length");
                    return APR_EGENERAL;
                }
                apr_size_t data_len = (apr_size_t)data_len64;
                apr_status_t write_rv = apr_brigade_write(bb, NULL, NULL, postdata, data_len);
                if (write_rv != APR_SUCCESS)
                {
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, write_rv, f->c, "h3_filter_in_proto: brigade write failed");
                    return write_rv;
                }
                f->r->clength = (apr_off_t)data_len;
            }
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto AP_MODE_READBYTES add EOS");
            apr_bucket* eos;
            eos = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, eos);
        }
        return APR_SUCCESS;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto OTHER status %d", f->r->status);
    rv = ap_pass_brigade(f->next, bb);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto %d %d %d", rv, mode, AP_MODE_READBYTES);
    return APR_SUCCESS;
}

apr_status_t h3_filter_in(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e /*block*/, apr_off_t /*readbytes*/)
{
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in mode %d", mode);
    if (mode == AP_MODE_READBYTES)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in AP_MODE_READBYTES");
        if (f->ctx == NULL)
        {
            apr_bucket* e = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            f->ctx = (void*)1;
            return APR_EOF;
        }
        ap_remove_input_filter(f);
    }
    return APR_EOF;
}
