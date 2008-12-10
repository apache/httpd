/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

#include "apr_strings.h"
#include "apreq_module.h"
#include "apreq_error.h"
#include "apreq_util.h"

#define READ_BYTES (64 * 1024)

struct custom_handle {
    struct apreq_handle_t        handle;

    apr_table_t                 *jar, *args, *body;
    apr_status_t                 jar_status,
                                 args_status,
                                 body_status;

    apreq_parser_t              *parser;

    apr_uint64_t                 read_limit;
    apr_uint64_t                 bytes_read;
    apr_bucket_brigade          *in;
    apr_bucket_brigade          *tmpbb;
};


static apr_status_t custom_parse_brigade(apreq_handle_t *handle, apr_uint64_t bytes)
{
    struct custom_handle *req = (struct custom_handle *)handle;
    apr_status_t s;
    apr_bucket *e;

    if (req->body_status != APR_INCOMPLETE)
        return req->body_status;

    switch (s = apr_brigade_partition(req->in, bytes, &e)) {
        apr_off_t len;

    case APR_SUCCESS:
        apreq_brigade_move(req->tmpbb, req->in, e);
        req->bytes_read += bytes;

        if (req->bytes_read > req->read_limit) {
            req->body_status = APREQ_ERROR_OVERLIMIT;
            break;
        }

        req->body_status =
            apreq_parser_run(req->parser, req->body, req->tmpbb);

        apr_brigade_cleanup(req->tmpbb);
        break;

    case APR_INCOMPLETE:
        apreq_brigade_move(req->tmpbb, req->in, e);
        s = apr_brigade_length(req->tmpbb, 1, &len);
        if (s != APR_SUCCESS) {
            req->body_status = s;
            break;
        }
        req->bytes_read += len;

        if (req->bytes_read > req->read_limit) {
            req->body_status = APREQ_ERROR_OVERLIMIT;
            break;
        }
        req->body_status =
            apreq_parser_run(req->parser, req->body, req->tmpbb);

        apr_brigade_cleanup(req->tmpbb);
        break;

    default:
        req->body_status = s;
    }

    return req->body_status;
}



static apr_status_t custom_jar(apreq_handle_t *handle, const apr_table_t **t)
{
    struct custom_handle *req = (struct custom_handle *)handle;
    *t = req->jar;
    return req->jar_status;
}

static apr_status_t custom_args(apreq_handle_t *handle, const apr_table_t **t)
{
    struct custom_handle *req = (struct custom_handle*)handle;
    *t = req->args;
    return req->args_status;
}

static apr_status_t custom_body(apreq_handle_t *handle, const apr_table_t **t)
{
    struct custom_handle *req = (struct custom_handle*)handle;
    while (req->body_status == APR_INCOMPLETE)
        custom_parse_brigade(handle, READ_BYTES);
    *t = req->body;
    return req->body_status;
}



static apreq_cookie_t *custom_jar_get(apreq_handle_t *handle, const char *name)
{
    struct custom_handle *req = (struct custom_handle*)handle;
    const char *val;

    if (req->jar == NULL || name == NULL)
        return NULL;

    val = apr_table_get(req->jar, name);

    if (val == NULL)
        return NULL;

    return apreq_value_to_cookie(val);
}

static apreq_param_t *custom_args_get(apreq_handle_t *handle, const char *name)
{
    struct custom_handle *req = (struct custom_handle*)handle;
    const char *val;

    if (req->args == NULL || name == NULL)
        return NULL;

    val = apr_table_get(req->args, name);

    if (val == NULL)
        return NULL;

    return apreq_value_to_param(val);
}

static apreq_param_t *custom_body_get(apreq_handle_t *handle, const char *name)
{
    struct custom_handle *req = (struct custom_handle*)handle;
    const char *val;

    if (req->body == NULL || name == NULL)
        return NULL;

    while (1) {
        *(const char **)&val = apr_table_get(req->body, name);
        if (val != NULL)
            break;

        if (req->body_status == APR_INCOMPLETE)
            custom_parse_brigade(handle, READ_BYTES);
        else
            return NULL;
    }

    return apreq_value_to_param(val);
}



static apr_status_t custom_parser_get(apreq_handle_t *handle,
                                      const apreq_parser_t **parser)
{
    struct custom_handle *req = (struct custom_handle*)handle;
    *parser = req->parser;

    return APR_SUCCESS;
}

static apr_status_t custom_parser_set(apreq_handle_t *handle,
                                      apreq_parser_t *parser)
{
    (void)handle;
    (void)parser;
    return APR_ENOTIMPL;
}

static apr_status_t custom_hook_add(apreq_handle_t *handle,
                                    apreq_hook_t *hook)
{
    struct custom_handle *req = (struct custom_handle*)handle;
    apreq_parser_add_hook(req->parser, hook);
    return APR_SUCCESS;
}

static apr_status_t custom_brigade_limit_get(apreq_handle_t *handle,
                                             apr_size_t *bytes)
{
    struct custom_handle *req = (struct custom_handle*)handle;
    *bytes = req->parser->brigade_limit;
    return APR_SUCCESS;
}

static apr_status_t custom_brigade_limit_set(apreq_handle_t *handle,
                                             apr_size_t bytes)
{
    (void)handle;
    (void)bytes;
    return APR_ENOTIMPL;
}

static apr_status_t custom_read_limit_get(apreq_handle_t *handle,
                                          apr_uint64_t *bytes)
{
    struct custom_handle *req = (struct custom_handle*)handle;
    *bytes = req->read_limit;
    return APR_SUCCESS;
}

static apr_status_t custom_read_limit_set(apreq_handle_t *handle,
                                          apr_uint64_t bytes)
{
    (void)handle;
    (void)bytes;
    return APR_ENOTIMPL;
}

static apr_status_t custom_temp_dir_get(apreq_handle_t *handle,
                                        const char **path)
{
    struct custom_handle *req = (struct custom_handle*)handle;

    *path = req->parser->temp_dir;
    return APR_SUCCESS;
}

static apr_status_t custom_temp_dir_set(apreq_handle_t *handle,
                                        const char *path)
{
    (void)handle;
    (void)path;
    return APR_ENOTIMPL;
}


static APREQ_MODULE(custom, 20070428);

APREQ_DECLARE(apreq_handle_t *)apreq_handle_custom(apr_pool_t *pool,
                                                   const char *query_string,
                                                   const char *cookie,
                                                   apreq_parser_t *parser,
                                                   apr_uint64_t read_limit,
                                                   apr_bucket_brigade *in)
{
    struct custom_handle *req;
    req = apr_palloc(pool, sizeof(*req));
    req->handle.module = &custom_module;
    req->handle.pool = pool;
    req->handle.bucket_alloc = in->bucket_alloc;
    req->read_limit = read_limit;
    req->bytes_read = 0;
    req->parser = parser;
    req->in = apr_brigade_create(pool, in->bucket_alloc);
    req->tmpbb = apr_brigade_create(pool, in->bucket_alloc);
    req->body = apr_table_make(pool, APREQ_DEFAULT_NELTS);
    req->body_status = APR_INCOMPLETE;
    APR_BRIGADE_CONCAT(req->in, in);

    if (cookie != NULL) {
        req->jar = apr_table_make(pool, APREQ_DEFAULT_NELTS);
        req->jar_status =
            apreq_parse_cookie_header(pool, req->jar, cookie);
    }
    else {
        req->jar = NULL;
        req->jar_status = APREQ_ERROR_NODATA;
    }


    if (query_string != NULL) {
        req->args = apr_table_make(pool, APREQ_DEFAULT_NELTS);
        req->args_status =
            apreq_parse_query_string(pool, req->args, query_string);
    }
    else {
        req->args = NULL;
        req->args_status = APREQ_ERROR_NODATA;
    }

    if (!APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(req->in))) {
        apr_bucket *eos = apr_bucket_eos_create(in->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(req->in, eos);
    }

    return &req->handle;
}

