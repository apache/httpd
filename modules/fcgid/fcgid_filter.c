/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "fcgid_filter.h"
#include "fcgid_bucket.h"
#include "fcgid_conf.h"

apr_status_t fcgid_filter(ap_filter_t * f, apr_bucket_brigade * bb)
{
    apr_status_t rv;
    apr_bucket_brigade *tmp_brigade;
    apr_size_t save_size = 0;
    conn_rec *c = f->c;
    server_rec *s = f->r->server;
    fcgid_server_conf *sconf = ap_get_module_config(s->module_config,
                                                    &fcgid_module);

    tmp_brigade =
        apr_brigade_create(f->r->pool, f->r->connection->bucket_alloc);
    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_size_t readlen;
        const char *buffer;

        apr_bucket *e = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_EOS(e))
            break;

        if (APR_BUCKET_IS_METADATA(e)) {
            apr_bucket_delete(e);
            continue;
        }

        /* Read the bucket now */
        if ((rv = apr_bucket_read(e, &buffer, &readlen,
                                  APR_BLOCK_READ)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, f->r,
                          "mod_fcgid: can't read data from fcgid handler");
            return rv;
        }

        /* Move on to next bucket if it's fastcgi header bucket */
        if (e->type == &ap_bucket_type_fcgid_header
            || (e->type == &apr_bucket_type_immortal && readlen == 0)) {
            apr_bucket_delete(e);
            continue;
        }
        save_size += readlen;

        /* Cache it to tmp_brigade */
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(tmp_brigade, e);

        /* I will pass tmp_brigade to next filter if I have got too much buckets */
        if (save_size > sconf->output_buffersize) {
            APR_BRIGADE_INSERT_TAIL(tmp_brigade,
                                    apr_bucket_flush_create(f->r->
                                                            connection->
                                                            bucket_alloc));

            if ((rv =
                 ap_pass_brigade(f->next, tmp_brigade)) != APR_SUCCESS)
                return rv;

            /* Is the client aborted? */
            if (c && c->aborted)
                return APR_SUCCESS;

            save_size = 0;
        }
    }

    /* Any thing left? */
    if (!APR_BRIGADE_EMPTY(tmp_brigade)) {
        if ((rv = ap_pass_brigade(f->next, tmp_brigade)) != APR_SUCCESS)
            return rv;
    }

    /* This filter is done once it has served up its content */
    ap_remove_output_filter(f);
    return APR_SUCCESS;
}
