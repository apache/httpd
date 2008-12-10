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
#include <assert.h>

#include "apreq_module.h"
#include "apreq_error.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_env.h"
#include "apreq_util.h"

#define USER_DATA_KEY "apreq"

/* Parroting APLOG_* ... */

#define	CGILOG_EMERG	0	/* system is unusable */
#define	CGILOG_ALERT	1	/* action must be taken immediately */
#define	CGILOG_CRIT	2	/* critical conditions */
#define	CGILOG_ERR	3	/* error conditions */
#define	CGILOG_WARNING	4	/* warning conditions */
#define	CGILOG_NOTICE	5	/* normal but significant condition */
#define	CGILOG_INFO	6	/* informational */
#define	CGILOG_DEBUG	7	/* debug-level messages */

#define CGILOG_LEVELMASK 7
#define CGILOG_MARK     __FILE__, __LINE__




struct cgi_handle {
    struct apreq_handle_t       handle;

    apr_table_t                 *jar, *args, *body;
    apr_status_t                 jar_status,
                                 args_status,
                                 body_status;

    apreq_parser_t              *parser;
    apreq_hook_t                *hook_queue;
    apreq_hook_t                *find_param;

    const char                  *temp_dir;
    apr_size_t                   brigade_limit;
    apr_uint64_t                 read_limit;
    apr_uint64_t                 bytes_read;

    apr_bucket_brigade          *in;
    apr_bucket_brigade          *tmpbb;

};

#define CRLF "\015\012"

typedef struct {
    const char *t_name;
    int      t_val;
} TRANS;

static const TRANS priorities[] = {
    {"emerg",   CGILOG_EMERG},
    {"alert",   CGILOG_ALERT},
    {"crit",    CGILOG_CRIT},
    {"error",   CGILOG_ERR},
    {"warn",    CGILOG_WARNING},
    {"notice",  CGILOG_NOTICE},
    {"info",    CGILOG_INFO},
    {"debug",   CGILOG_DEBUG},
    {NULL,      -1},
};

static const char *cgi_header_in(apreq_handle_t *handle,
                                 const char *name)
{
    apr_pool_t *p = handle->pool;
    char *key = apr_pstrcat(p, "HTTP_", name, NULL);
    char *k, *value = NULL;
    for (k = key; *k; ++k) {
        if (*k == '-')
            *k = '_';
        else
            *k = apr_toupper(*k);
    }

    if (!strcmp(key, "HTTP_CONTENT_TYPE")
        || !strcmp(key, "HTTP_CONTENT_LENGTH"))
        {
            key += 5; /* strlen("HTTP_") */
        }

    apr_env_get(&value, key, p);

    return value;
}




static void cgi_log_error(const char *file, int line, int level,
                          apr_status_t status, apreq_handle_t *handle,
                          const char *fmt, ...)
{
    apr_pool_t *p = handle->pool;
    char buf[256];
    char *log_level_string, *ra;
    const char *remote_addr;
    unsigned log_level = CGILOG_WARNING;
    char date[APR_CTIME_LEN];
    va_list vp;
#ifndef WIN32
    apr_file_t *err;
#endif

    va_start(vp, fmt);

    if (apr_env_get(&log_level_string, "LOG_LEVEL", p) == APR_SUCCESS)
        log_level = (log_level_string[0] - '0');

    level &= CGILOG_LEVELMASK;

    if (level < (int)log_level) {

        if (apr_env_get(&ra, "REMOTE_ADDR", p) == APR_SUCCESS)
            remote_addr = ra;
        else
            remote_addr = "address unavailable";

        apr_ctime(date, apr_time_now());

#ifndef WIN32

        apr_file_open_stderr(&err, p);
        apr_file_printf(err, "[%s] [%s] [%s] %s(%d): %s: %s\n",
                        date, priorities[level].t_name, remote_addr, file, line,
                        apr_strerror(status,buf,255),apr_pvsprintf(p,fmt,vp));
        apr_file_flush(err);

#else
        fprintf(stderr, "[%s] [%s] [%s] %s(%d): %s: %s\n",
                date, priorities[level].t_name, remote_addr, file, line,
                apr_strerror(status,buf,255),apr_pvsprintf(p,fmt,vp));
#endif
    }

    va_end(vp);

}


APR_INLINE
static const char *cgi_query_string(apreq_handle_t *handle)
{
    char *value = NULL, qs[] = "QUERY_STRING";
    apr_env_get(&value, qs, handle->pool);
    return value;
}


static void init_body(apreq_handle_t *handle)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;
    const char *cl_header = cgi_header_in(handle, "Content-Length");
    apr_bucket_alloc_t *ba = handle->bucket_alloc;
    apr_pool_t *pool = handle->pool;
    apr_file_t *file;
    apr_bucket *eos, *pipe;

    req->body  = apr_table_make(pool, APREQ_DEFAULT_NELTS);

    if (cl_header != NULL) {
        char *dummy;
        apr_int64_t content_length = apr_strtoi64(cl_header, &dummy, 0);

        if (dummy == NULL || *dummy != 0) {
            req->body_status = APREQ_ERROR_BADHEADER;
            cgi_log_error(CGILOG_MARK, CGILOG_ERR, req->body_status, handle,
                          "Invalid Content-Length header (%s)", cl_header);
            return;
        }
        else if ((apr_uint64_t)content_length > req->read_limit) {
            req->body_status = APREQ_ERROR_OVERLIMIT;
            cgi_log_error(CGILOG_MARK, CGILOG_ERR, req->body_status, handle,
                          "Content-Length header (%s) exceeds configured "
                          "max_body limit (%" APR_UINT64_T_FMT ")",
                          cl_header, req->read_limit);
            return;
        }
    }

    if (req->parser == NULL) {
        const char *ct_header = cgi_header_in(handle, "Content-Type");

        if (ct_header != NULL) {
            apreq_parser_function_t pf = apreq_parser(ct_header);

            if (pf != NULL) {
                req->parser = apreq_parser_make(pool,
                                                ba,
                                                ct_header,
                                                pf,
                                                req->brigade_limit,
                                                req->temp_dir,
                                                req->hook_queue,
                                                NULL);
            }
            else {
                req->body_status = APREQ_ERROR_NOPARSER;
                return;
            }
        }
        else {
            req->body_status = APREQ_ERROR_NOHEADER;
            return;
        }
    }
    else {
        if (req->parser->brigade_limit > req->brigade_limit)
            req->parser->brigade_limit = req->brigade_limit;
        if (req->temp_dir != NULL)
            req->parser->temp_dir = req->temp_dir;
        if (req->hook_queue != NULL)
            apreq_parser_add_hook(req->parser, req->hook_queue);
    }

    req->hook_queue = NULL;
    req->in         = apr_brigade_create(pool, ba);
    req->tmpbb      = apr_brigade_create(pool, ba);

    apr_file_open_stdin(&file, pool); // error status?
    pipe = apr_bucket_pipe_create(file, ba);
    eos = apr_bucket_eos_create(ba);
    APR_BRIGADE_INSERT_HEAD(req->in, pipe);
    APR_BRIGADE_INSERT_TAIL(req->in, eos);

    req->body_status = APR_INCOMPLETE;

}

static apr_status_t cgi_read(apreq_handle_t *handle,
                             apr_off_t bytes)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;
    apr_bucket *e;
    apr_status_t s;

    if (req->body_status == APR_EINIT)
        init_body(handle);

    if (req->body_status != APR_INCOMPLETE)
        return req->body_status;


    switch (s = apr_brigade_partition(req->in, bytes, &e)) {
        apr_off_t len;

    case APR_SUCCESS:

        apreq_brigade_move(req->tmpbb, req->in, e);
        req->bytes_read += bytes;

        if (req->bytes_read > req->read_limit) {
            req->body_status = APREQ_ERROR_OVERLIMIT;
            cgi_log_error(CGILOG_MARK, CGILOG_ERR, req->body_status,
                          handle, "Bytes read (%" APR_UINT64_T_FMT
                          ") exceeds configured limit (%" APR_UINT64_T_FMT ")",
                          req->bytes_read, req->read_limit);
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
            cgi_log_error(CGILOG_MARK, CGILOG_ERR, req->body_status, handle,
                          "Bytes read (%" APR_UINT64_T_FMT
                          ") exceeds configured limit (%" APR_UINT64_T_FMT ")",
                          req->bytes_read, req->read_limit);

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



static apr_status_t cgi_jar(apreq_handle_t *handle,
                            const apr_table_t **t)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;

    if (req->jar_status == APR_EINIT) {
        const char *cookies = cgi_header_in(handle, "Cookie");
        if (cookies != NULL) {
            req->jar = apr_table_make(handle->pool, APREQ_DEFAULT_NELTS);
            req->jar_status =
                apreq_parse_cookie_header(handle->pool, req->jar, cookies);
        }
        else
            req->jar_status = APREQ_ERROR_NODATA;
    }

    *t = req->jar;
    return req->jar_status;
}

static apr_status_t cgi_args(apreq_handle_t *handle,
                             const apr_table_t **t)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;

    if (req->args_status == APR_EINIT) {
        const char *qs = cgi_query_string(handle);
        if (qs != NULL) {
            req->args = apr_table_make(handle->pool, APREQ_DEFAULT_NELTS);
            req->args_status =
                apreq_parse_query_string(handle->pool, req->args, qs);
        }
        else
            req->args_status = APREQ_ERROR_NODATA;
    }

    *t = req->args;
    return req->args_status;
}




static apreq_cookie_t *cgi_jar_get(apreq_handle_t *handle,
                                   const char *name)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;
    const apr_table_t *t;
    const char *val;

    if (req->jar_status == APR_EINIT)
        cgi_jar(handle, &t);
    else
        t = req->jar;

    if (t == NULL)
        return NULL;

    val = apr_table_get(t, name);
    if (val == NULL)
        return NULL;

    return apreq_value_to_cookie(val);
}

static apreq_param_t *cgi_args_get(apreq_handle_t *handle,
                                   const char *name)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;
    const apr_table_t *t;
    const char *val;

    if (req->args_status == APR_EINIT)
        cgi_args(handle, &t);
    else
        t = req->args;

    if (t == NULL)
        return NULL;

    val = apr_table_get(t, name);
    if (val == NULL)
        return NULL;

    return apreq_value_to_param(val);
}



static apr_status_t cgi_body(apreq_handle_t *handle,
                             const apr_table_t **t)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;

    switch (req->body_status) {

    case APR_EINIT:
        init_body(handle);
        if (req->body_status != APR_INCOMPLETE)
            break;

    case APR_INCOMPLETE:
        while (cgi_read(handle, APREQ_DEFAULT_READ_BLOCK_SIZE)
               == APR_INCOMPLETE)
            ;   /*loop*/
    }

    *t = req->body;
    return req->body_status;
}

static apreq_param_t *cgi_body_get(apreq_handle_t *handle,
                                   const char *name)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;
    const char *val;
    apreq_hook_t *h;

    switch (req->body_status) {

    case APR_SUCCESS:

        val = apr_table_get(req->body, name);
        if (val != NULL)
            return apreq_value_to_param(val);
        return NULL;


    case APR_EINIT:

        init_body(handle);
        if (req->body_status != APR_INCOMPLETE)
            return NULL;
        cgi_read(handle, APREQ_DEFAULT_READ_BLOCK_SIZE);


    case APR_INCOMPLETE:

        val = apr_table_get(req->body, name);
        if (val != NULL)
            return apreq_value_to_param(val);

        /* Not seen yet, so we need to scan for
           param while prefetching the body */

        if (req->find_param == NULL)
            req->find_param = apreq_hook_make(handle->pool,
                                              apreq_hook_find_param,
                                              NULL, NULL);
        h = req->find_param;
        h->next = req->parser->hook;
        req->parser->hook = h;
        h->ctx = (void *)name;

        do {
            cgi_read(handle, APREQ_DEFAULT_READ_BLOCK_SIZE);
            if (h->ctx != name) {
                req->parser->hook = h->next;
                return h->ctx;
            }
        } while (req->body_status == APR_INCOMPLETE);

        req->parser->hook = h->next;
        return NULL;


    default:

        if (req->body == NULL)
            return NULL;

        val = apr_table_get(req->body, name);
        if (val != NULL)
            return apreq_value_to_param(val);
        return NULL;
    }

    /* not reached */
    return NULL;
}

static apr_status_t cgi_parser_get(apreq_handle_t *handle,
                                   const apreq_parser_t **parser)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;

    *parser = req->parser;
    return APR_SUCCESS;
}

static apr_status_t cgi_parser_set(apreq_handle_t *handle,
                                   apreq_parser_t *parser)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;

    if (req->parser == NULL) {

        if (req->hook_queue != NULL) {
            apr_status_t s = apreq_parser_add_hook(parser, req->hook_queue);
            if (s != APR_SUCCESS)
                return s;
        }
        if (req->temp_dir != NULL) {
            parser->temp_dir = req->temp_dir;
        }
        if (req->brigade_limit < parser->brigade_limit) {
            parser->brigade_limit = req->brigade_limit;
        }

        req->hook_queue = NULL;
        req->parser = parser;
        return APR_SUCCESS;
    }
    else
        return APREQ_ERROR_MISMATCH;
}


static apr_status_t cgi_hook_add(apreq_handle_t *handle,
                                     apreq_hook_t *hook)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;

    if (req->parser != NULL) {
        return apreq_parser_add_hook(req->parser, hook);
    }
    else if (req->hook_queue != NULL) {
        apreq_hook_t *h = req->hook_queue;
        while (h->next != NULL)
            h = h->next;
        h->next = hook;
    }
    else {
        req->hook_queue = hook;
    }
    return APR_SUCCESS;

}

static apr_status_t cgi_brigade_limit_set(apreq_handle_t *handle,
                                          apr_size_t bytes)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;
    apr_size_t *limit = (req->parser == NULL)
                      ? &req->brigade_limit
                      : &req->parser->brigade_limit;

    if (*limit > bytes) {
        *limit = bytes;
        return APR_SUCCESS;
    }

    return APREQ_ERROR_MISMATCH;
}

static apr_status_t cgi_brigade_limit_get(apreq_handle_t *handle,
                                          apr_size_t *bytes)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;
    *bytes = (req->parser == NULL)
           ?  req->brigade_limit
           :  req->parser->brigade_limit;

    return APR_SUCCESS;
}

static apr_status_t cgi_read_limit_set(apreq_handle_t *handle,
                                       apr_uint64_t bytes)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;

    if (req->read_limit > bytes && req->bytes_read < bytes) {
        req->read_limit = bytes;
        return APR_SUCCESS;
    }

    return APREQ_ERROR_MISMATCH;
}


static apr_status_t cgi_read_limit_get(apreq_handle_t *handle,
                                       apr_uint64_t *bytes)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;
    *bytes = req->read_limit;
    return APR_SUCCESS;
}


static apr_status_t cgi_temp_dir_set(apreq_handle_t *handle,
                                     const char *path)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;
    const char **temp_dir = (req->parser == NULL)
                          ? &req->temp_dir
                          : &req->parser->temp_dir;


    if (*temp_dir == NULL && req->bytes_read == 0) {
        if (path != NULL)
            *temp_dir = apr_pstrdup(handle->pool, path);
        return APR_SUCCESS;
    }

    return APREQ_ERROR_MISMATCH;
}


static apr_status_t cgi_temp_dir_get(apreq_handle_t *handle,
                                     const char **path)
{
    struct cgi_handle *req = (struct cgi_handle *)handle;
    *path = (req->parser == NULL)
           ? req->temp_dir
           : req->parser->temp_dir;
    return APR_SUCCESS;
}



#ifdef APR_POOL_DEBUG
static apr_status_t ba_cleanup(void *data)
{
    apr_bucket_alloc_t *ba = data;
    apr_bucket_alloc_destroy(ba);
    return APR_SUCCESS;
}
#endif

static APREQ_MODULE(cgi, 20050425);

APREQ_DECLARE(apreq_handle_t *)apreq_handle_cgi(apr_pool_t *pool)
{
    apr_bucket_alloc_t *ba;
    struct cgi_handle *req;
    void *data;

    apr_pool_userdata_get(&data, USER_DATA_KEY, pool);

    if (data != NULL)
        return data;

    req = apr_pcalloc(pool, sizeof *req);
    ba = apr_bucket_alloc_create(pool);

    /* check pool's userdata first. */

    req->handle.module        = &cgi_module;
    req->handle.pool          = pool;
    req->handle.bucket_alloc  = ba;
    req->read_limit           = (apr_uint64_t) -1;
    req->brigade_limit        = APREQ_DEFAULT_BRIGADE_LIMIT;

    req->args_status =
        req->jar_status =
            req->body_status = APR_EINIT;

    apr_pool_userdata_setn(&req->handle, USER_DATA_KEY, NULL, pool);

#ifdef APR_POOL_DEBUG
    apr_pool_cleanup_register(pool, ba, ba_cleanup, ba_cleanup);
#endif

    return &req->handle;
}
