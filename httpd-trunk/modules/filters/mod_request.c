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

/*
 * mod_request.c --- HTTP routines to set aside or process request bodies.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "http_request.h"

#include "mod_request.h"

/* Handles for core filters */
static ap_filter_rec_t *keep_body_input_filter_handle;
static ap_filter_rec_t *kept_body_input_filter_handle;

static apr_status_t bail_out_on_error(apr_bucket_brigade *bb,
                                      ap_filter_t *f,
                                      int http_error)
{
    apr_bucket *e;

    apr_brigade_cleanup(bb);
    e = ap_bucket_error_create(http_error,
                               NULL, f->r->pool,
                               f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    e = apr_bucket_eos_create(f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    return ap_pass_brigade(f->r->output_filters, bb);
}

typedef struct keep_body_filter_ctx {
    apr_off_t remaining;
    apr_off_t keep_body;
} keep_body_ctx_t;

/**
 * This is the KEEP_BODY_INPUT filter for HTTP requests, for times when the
 * body should be set aside for future use by other modules.
 */
static apr_status_t keep_body_filter(ap_filter_t *f, apr_bucket_brigade *b,
                                     ap_input_mode_t mode,
                                     apr_read_type_e block,
                                     apr_off_t readbytes)
{
    apr_bucket *e;
    keep_body_ctx_t *ctx = f->ctx;
    apr_status_t rv;
    apr_bucket *bucket;
    apr_off_t len = 0;


    if (!ctx) {
        const char *lenp;
        char *endstr = NULL;
        request_dir_conf *dconf = ap_get_module_config(f->r->per_dir_config,
                                                       &request_module);

        /* must we step out of the way? */
        if (!dconf->keep_body || f->r->kept_body) {
            ap_remove_input_filter(f);
            return ap_get_brigade(f->next, b, mode, block, readbytes);
        }

        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));

        /* fail fast if the content length exceeds keep body */
        lenp = apr_table_get(f->r->headers_in, "Content-Length");
        if (lenp) {

            /* Protects against over/underflow, non-digit chars in the
             * string (excluding leading space) (the endstr checks)
             * and a negative number. */
            if (apr_strtoff(&ctx->remaining, lenp, &endstr, 10)
                || endstr == lenp || *endstr || ctx->remaining < 0) {

                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(01411)
                              "Invalid Content-Length");

                ap_remove_input_filter(f);
                return bail_out_on_error(b, f, HTTP_REQUEST_ENTITY_TOO_LARGE);
            }

            /* If we have a limit in effect and we know the C-L ahead of
             * time, stop it here if it is invalid.
             */
            if (dconf->keep_body < ctx->remaining) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(01412)
                          "Requested content-length of %" APR_OFF_T_FMT
                          " is larger than the configured limit"
                          " of %" APR_OFF_T_FMT, ctx->remaining, dconf->keep_body);
                ap_remove_input_filter(f);
                return bail_out_on_error(b, f, HTTP_REQUEST_ENTITY_TOO_LARGE);
            }

        }

        f->r->kept_body = apr_brigade_create(f->r->pool, f->r->connection->bucket_alloc);
        ctx->remaining = dconf->keep_body;

    }

    /* get the brigade from upstream, and read it in to get its length */
    rv = ap_get_brigade(f->next, b, mode, block, readbytes);
    if (rv == APR_SUCCESS) {
        rv = apr_brigade_length(b, 1, &len);
    }

    /* does the length take us over the limit? */
    if (APR_SUCCESS == rv && len > ctx->remaining) {
        if (f->r->kept_body) {
            apr_brigade_cleanup(f->r->kept_body);
            f->r->kept_body = NULL;
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(01413)
                      "Requested content-length of %" APR_OFF_T_FMT
                      " is larger than the configured limit"
                      " of %" APR_OFF_T_FMT, len, ctx->keep_body);
        return bail_out_on_error(b, f, HTTP_REQUEST_ENTITY_TOO_LARGE);
    }
    ctx->remaining -= len;

    /* pass any errors downstream */
    if (rv != APR_SUCCESS) {
        if (f->r->kept_body) {
            apr_brigade_cleanup(f->r->kept_body);
            f->r->kept_body = NULL;
        }
        return rv;
    }

    /* all is well, set aside the buckets */
    for (bucket = APR_BRIGADE_FIRST(b);
         bucket != APR_BRIGADE_SENTINEL(b);
         bucket = APR_BUCKET_NEXT(bucket))
    {
        apr_bucket_copy(bucket, &e);
        APR_BRIGADE_INSERT_TAIL(f->r->kept_body, e);
    }

    return APR_SUCCESS;
}


typedef struct kept_body_filter_ctx {
    apr_off_t offset;
    apr_off_t remaining;
} kept_body_ctx_t;

/**
 * Initialisation of filter to handle a kept body on subrequests.
 *
 * If a body is to be reinserted into a subrequest, any chunking will have
 * been removed from the body during storage. We need to change the request
 * from Transfer-Encoding: chunked to an explicit Content-Length.
 */
static int kept_body_filter_init(ap_filter_t *f) {
    apr_off_t length = 0;
    request_rec *r = f->r;
    apr_bucket_brigade *kept_body = r->kept_body;

    if (kept_body) {
        apr_table_unset(r->headers_in, "Transfer-Encoding");
        apr_brigade_length(kept_body, 1, &length);
        apr_table_setn(r->headers_in, "Content-Length", apr_off_t_toa(r->pool, length));
    }

    return OK;
}

/**
 * Filter to handle a kept body on subrequests.
 *
 * If a body has been previously kept by the request, and if a subrequest wants
 * to re-insert the body into the request, this input filter makes it happen.
 */
static apr_status_t kept_body_filter(ap_filter_t *f, apr_bucket_brigade *b,
                                     ap_input_mode_t mode,
                                     apr_read_type_e block,
                                     apr_off_t readbytes)
{
    request_rec *r = f->r;
    apr_bucket_brigade *kept_body = r->kept_body;
    kept_body_ctx_t *ctx = f->ctx;
    apr_bucket *ec, *e2;
    apr_status_t rv;

    /* just get out of the way of things we don't want. */
    if (!kept_body || (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE)) {
        return ap_get_brigade(f->next, b, mode, block, readbytes);
    }

    /* set up the context if it does not already exist */
    if (!ctx) {
        f->ctx = ctx = apr_palloc(f->r->pool, sizeof(*ctx));
        ctx->offset = 0;
        apr_brigade_length(kept_body, 1, &ctx->remaining);
    }

    /* kept_body is finished, send next filter */
    if (ctx->remaining <= 0) {
        return ap_get_brigade(f->next, b, mode, block, readbytes);
    }

    /* send all of the kept_body, but no more */
    if (readbytes > ctx->remaining) {
        readbytes = ctx->remaining;
    }

    /* send part of the kept_body */
    if ((rv = apr_brigade_partition(kept_body, ctx->offset, &ec)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01414)
                      "apr_brigade_partition() failed on kept_body at %" APR_OFF_T_FMT, ctx->offset);
        return rv;
    }
    if ((rv = apr_brigade_partition(kept_body, ctx->offset + readbytes, &e2)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01415)
                      "apr_brigade_partition() failed on kept_body at %" APR_OFF_T_FMT, ctx->offset + readbytes);
        return rv;
    }

    do {
        apr_bucket *foo;
        const char *str;
        apr_size_t len;

        if (apr_bucket_copy(ec, &foo) != APR_SUCCESS) {
            /* As above; this should not fail since the bucket has
             * a known length, but just to be sure, this takes
             * care of uncopyable buckets that do somehow manage
             * to slip through.  */
            /* XXX: check for failure? */
            apr_bucket_read(ec, &str, &len, APR_BLOCK_READ);
            apr_bucket_copy(ec, &foo);
        }
        APR_BRIGADE_INSERT_TAIL(b, foo);
        ec = APR_BUCKET_NEXT(ec);
    } while (ec != e2);

    ctx->remaining -= readbytes;
    ctx->offset += readbytes;
    return APR_SUCCESS;

}

/**
 * Check whether this filter is not already present.
 */
static int request_is_filter_present(request_rec * r, ap_filter_rec_t *fn)
{
    ap_filter_t * f = r->input_filters;
    while (f) {
        if (f->frec == fn) {
            return 1;
        }
        f = f->next;
    }
    return 0;
}

/**
 * Insert filter hook.
 *
 * Add the KEEP_BODY filter to the request, if the admin wants to keep
 * the body using the KeptBodySize directive.
 *
 * As a precaution, any pre-existing instances of either the kept_body or
 * keep_body filters will be removed before the filter is added.
 *
 * @param r The request
 */
static void ap_request_insert_filter(request_rec * r)
{
    request_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                  &request_module);

    if (r->kept_body) {
        if (!request_is_filter_present(r, kept_body_input_filter_handle)) {
            ap_add_input_filter_handle(kept_body_input_filter_handle,
                                       NULL, r, r->connection);
        }
    }
    else if (conf->keep_body) {
        if (!request_is_filter_present(r, kept_body_input_filter_handle)) {
            ap_add_input_filter_handle(keep_body_input_filter_handle,
                                       NULL, r, r->connection);
        }
    }

}

/**
 * Remove the kept_body and keep body filters from this specific request.
 */
static void ap_request_remove_filter(request_rec * r)
{
    ap_filter_t * f = r->input_filters;
    while (f) {
        if (f->frec->filter_func.in_func == kept_body_filter ||
                f->frec->filter_func.in_func == keep_body_filter) {
            ap_remove_input_filter(f);
        }
        f = f->next;
    }
}

static void *create_request_dir_config(apr_pool_t *p, char *dummy)
{
    request_dir_conf *new =
        (request_dir_conf *) apr_pcalloc(p, sizeof(request_dir_conf));

    new->keep_body_set = 0; /* unset */
    new->keep_body = 0; /* don't by default */

    return (void *) new;
}

static void *merge_request_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    request_dir_conf *new = (request_dir_conf *) apr_pcalloc(p, sizeof(request_dir_conf));
    request_dir_conf *add = (request_dir_conf *) addv;
    request_dir_conf *base = (request_dir_conf *) basev;

    new->keep_body = (add->keep_body_set == 0) ? base->keep_body : add->keep_body;
    new->keep_body_set = add->keep_body_set || base->keep_body_set;

    return new;
}

static const char *set_kept_body_size(cmd_parms *cmd, void *dconf,
                                      const char *arg)
{
    request_dir_conf *conf = dconf;
    char *end = NULL;

    if (APR_SUCCESS != apr_strtoff(&(conf->keep_body), arg, &end, 10)
            || conf->keep_body < 0 || *end) {
        return "KeptBodySize must be a valid size in bytes, or zero.";
    }
    conf->keep_body_set = 1;

    return NULL;
}

static const command_rec request_cmds[] = {
    AP_INIT_TAKE1("KeptBodySize", set_kept_body_size, NULL, ACCESS_CONF,
                  "Maximum size of request bodies kept aside for use by filters"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    keep_body_input_filter_handle =
        ap_register_input_filter(KEEP_BODY_FILTER, keep_body_filter,
                                 NULL, AP_FTYPE_RESOURCE);
    kept_body_input_filter_handle =
        ap_register_input_filter(KEPT_BODY_FILTER, kept_body_filter,
                                 kept_body_filter_init, AP_FTYPE_RESOURCE);
    ap_hook_insert_filter(ap_request_insert_filter, NULL, NULL, APR_HOOK_LAST);
    APR_REGISTER_OPTIONAL_FN(ap_request_insert_filter);
    APR_REGISTER_OPTIONAL_FN(ap_request_remove_filter);
}

AP_DECLARE_MODULE(request) = {
    STANDARD20_MODULE_STUFF,
    create_request_dir_config, /* create per-directory config structure */
    merge_request_dir_config,  /* merge per-directory config structures */
    NULL,                      /* create per-server config structure */
    NULL,                      /* merge per-server config structures */
    request_cmds,              /* command apr_table_t */
    register_hooks             /* register hooks */
};
