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
 * Originally written @ BBC by Graham Leggett
 * (C) 2011 British Broadcasting Corporation
 */

/*
 * mod_policy.c --- Enforce specific policies on outgoing requests, logging
 *                  or rejecting requests as appropriate.
 *
 * To enable, add the corresponding filters like so:
 *
 * SetOutputFilter POLICY_TYPE,POLICY_LENGTH
 *
 */

#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#include <apr_tables.h>
#include <apr_strings.h>
#include <apr_date.h>

module AP_MODULE_DECLARE_DATA policy_module;

#define DEFAULT_TYPE "*/*"

typedef enum policy_result
{
    policy_ignore = 0, /* ignore this policy */
    policy_log, /* log the violation as a warning, but let it through */
    policy_enforce /* log the violation as an error, and decline */
} policy_result;

typedef struct policy_conf
{
    int policy; /* whether the filters should do anything at all */
    int policy_set;
    const char *environment; /* optional name of the subprocess environment variable that
     * controls whether the policies are enforced.
     */
    const char *environment_log; /* value to trigger logging only */
    const char *environment_ignore; /* value to suspend policy enforcement */
    int environment_set;
    policy_result type_action;
    apr_array_header_t *type_matches; /* content type default patterns to match */
    int type_set;
    const char *type_url;
    int type_url_set;
    policy_result length_action;
    int length_set;
    const char *length_url;
    int length_url_set;
    policy_result keepalive_action;
    int keepalive_set;
    const char *keepalive_url;
    int keepalive_url_set;
    policy_result vary_action;
    apr_array_header_t *vary_matches; /* Vary default patterns to match */
    int vary_set;
    const char *vary_url;
    int vary_url_set;
    policy_result validation_action;
    int validation_set;
    const char *validation_url;
    int validation_url_set;
    policy_result conditional_action;
    int conditional_set;
    const char *conditional_url;
    int conditional_url_set;
    policy_result nocache_action;
    int nocache_set;
    const char *nocache_url;
    int nocache_url_set;
    policy_result maxage_action;
    apr_int64_t maxage;
    int maxage_set;
    const char *maxage_url;
    int maxage_url_set;
    policy_result version_action;
    const char *version;
    int version_num;
    int version_set;
    const char *version_url;
    int version_url_set;
} policy_conf;

/**
 * Does the value of a flagpole override the original value?
 */
static int check_enabled(request_rec *r, policy_conf *conf,
        policy_result result)
{
    if (conf && !conf->policy) {
        return policy_ignore;
    }
    if (conf && result != policy_ignore && conf->environment) {
        const char *value = apr_table_get(r->subprocess_env, conf->environment);
        if (value) {
            /* downgrade enforce to log? */
            if (conf->environment_log && !strcmp(value, conf->environment_log)) {
                if (result == policy_enforce) {
                    return policy_log;
                }
            }
            /* downgrade enforce and log to ignore? */
            else if (conf->environment_ignore && !strcmp(value,
                    conf->environment_ignore)) {
                return policy_ignore;
            }
        }
    }
    return result;
}

static void handle_policy(request_rec *r, policy_result result,
        const char *message, const char *url, apr_bucket_brigade *bb,
        int status)
{
    apr_bucket *e;

    switch (result) {
    case policy_log: {
        ap_log_rerror(
                APLOG_MARK,
                APLOG_WARNING,
                0,
                r,
                "mod_policy: violation: %s, uri: %s",
                message, r->uri);
        apr_table_addn(r->headers_out, "Warning", apr_psprintf(r->pool,
                "299 %s \"%s\"", ap_get_server_name(r), message));
        break;
    }
    case policy_enforce: {

        ap_log_rerror(
                APLOG_MARK,
                APLOG_ERR,
                0,
                r,
                "mod_policy: violation, rejecting request: %s, uri: %s",
                message, r->uri);
        apr_table_addn(r->err_headers_out, "Warning", apr_psprintf(r->pool,
                "299 %s \"Rejected: %s\"", ap_get_server_name(r), message));
        apr_table_setn(
                r->notes, "error-notes",
                    apr_pstrcat(r->pool, url ? apr_pstrcat(r->pool, "<a href=\"",
                            url, "\">", NULL) : "", message, url ? "</a>" : "",
                                    NULL));

        apr_brigade_cleanup(bb);
        e = ap_bucket_error_create(status, NULL, r->pool,
                r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
        e = apr_bucket_eos_create(r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);

    }
    case policy_ignore: {
    }
    }

}

/**
 * Policy for Content-Type.
 *
 * - It must be present.
 * - It must match the optional regex (default .* / .*)
 */
static apr_status_t policy_type_out_filter(ap_filter_t *f,
        apr_bucket_brigade *bb)
{

    policy_conf *conf = ap_get_module_config(f->r->per_dir_config,
            &policy_module);
    policy_result result = check_enabled(f->r, conf, conf->type_action);

    if (result != policy_ignore) {
        int fail = 1;

        /* content type present and valid? */
        if (f->r->content_type) {
            const char *type = f->r->content_type;
            const char *end = strchr(type, ';');
            if (end) {
                type = apr_pstrmemdup(f->r->pool, type, end - type);
            }
            if (!conf->type_matches) {
                if (!ap_strcmp_match(type, DEFAULT_TYPE)) {
                    fail = 0;
                }
            }
            else {
                int i;
                for (i = 0; i < conf->type_matches->nelts; i++) {
                    if (!ap_strcmp_match(type,
                            ((char **) conf->type_matches->elts)[i])) {
                        fail = 0;
                        break;
                    }
                }
            }
        }

        if (fail) {
            const char *types = NULL;
            if (conf->type_matches) {
                int i;
                for (i = 0; i < conf->type_matches->nelts; i++) {
                    types = apr_pstrcat(f->r->pool, types ? ", " : "",
                            ((char **) conf->type_matches->elts)[i], NULL);
                }
            }
            else {
                types = DEFAULT_TYPE;
            }

            handle_policy(
                    f->r,
                    result,
                    apr_psprintf(
                            f->r->pool,
                            "Content-Type of '%s' should be RFC compliant and match one of: %s",
                            f->r->content_type, types), conf->type_url, bb, HTTP_BAD_GATEWAY);

        }

    }

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

/**
 * Policy for Content-Length.
 *
 * - It must be present (missing, or Transfer-Encoding: chunked would be rejected)
 * - Only applies to 2xx result codes
 */
static apr_status_t policy_length_out_filter(ap_filter_t *f,
        apr_bucket_brigade *bb)
{
    request_rec *r = f->r;

    policy_conf *conf = ap_get_module_config(r->per_dir_config,
            &policy_module);
    policy_result result = check_enabled(r, conf, conf->length_action);

    if (result != policy_ignore && r->status >= 200 && r->status < 300
            && r->status != HTTP_NO_CONTENT) {

        if (!apr_table_get(r->headers_out, "Content-Length")) {

            handle_policy(r, result, "Content-Length should be present",
                    conf->length_url, bb, HTTP_BAD_GATEWAY);

        }

    }

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

/**
 * Policy for Content-Length / Chunked Encoding.
 *
 * We follow a subset of the algorithm httpd uses, which is:
 *
 *   IF  we have not marked this connection as errored;
 *   and the client isn't expecting 100-continue (PR47087 - more
 *       input here could be the client continuing when we're
 *       closing the request).
 *   and the response status does not require a close;
 *   and the response body has a defined length due to the status code
 *       being 304 or 204, the request method being HEAD, already
 *       having defined Content-Length or Transfer-Encoding: chunked, or
 *       the request version being HTTP/1.1 and thus capable of being set
 *       as chunked
 *   THEN  we support keepalive.
 *
 * Note: The server may choose to turn off keepalive for various reasons,
 * such as an imminent shutdown, or a Connection: close from the client,
 * but for our purposes we only care that keepalive was possible from
 * the application, not that keepalive actually took place.
 */
static apr_status_t policy_keepalive_out_filter(ap_filter_t *f,
        apr_bucket_brigade *bb)
{
    request_rec *r = f->r;

    policy_conf *conf = ap_get_module_config(r->per_dir_config,
            &policy_module);
    policy_result result = check_enabled(r, conf, conf->keepalive_action);

    if (result != policy_ignore && r->connection->keepalive != AP_CONN_CLOSE
            && !r->expecting_100 && !ap_status_drops_connection(r->status)) {

        if (!((r->status == HTTP_NOT_MODIFIED)
                || (r->status == HTTP_NO_CONTENT)
                || r->header_only
                || apr_table_get(r->headers_out, "Content-Length")
                || ap_find_last_token(r->pool, apr_table_get(r->headers_out,
                        "Transfer-Encoding"), "chunked")
                || r->proto_num >= HTTP_VERSION(1, 1))) {

            handle_policy(r, result, "Keepalive should be possible (supply Content-Length or HTTP/1.1 Transfer-Encoding)",
                    conf->keepalive_url, bb, HTTP_BAD_GATEWAY);

        }

    }

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static int vary_test(void *rec, const char *key, const char *value) {
    request_rec *r = (request_rec *)rec;
    char *token = apr_pstrdup(r->pool, value);
    char *last;

    policy_conf *conf = ap_get_module_config(r->per_dir_config,
            &policy_module);

    token = apr_strtok(token, ", \t", &last);
    while (token) {
        int i;
        for (i = 0; i < conf->vary_matches->nelts; i++) {
            if (!ap_strcasecmp_match(token,
                    ((char **) conf->vary_matches->elts)[i])) {
                return 0;
            }
        }

        token = apr_strtok(NULL, ", \t", &last);
    }
    return 1;
}

/**
 * Policy for Vary.
 *
 * - If an element matches the optional regex (no default), the request is rejected.
 * Typically used to reject Varying on User-Agent.
 */
static apr_status_t policy_vary_out_filter(ap_filter_t *f,
        apr_bucket_brigade *bb)
{

    policy_conf *conf = ap_get_module_config(f->r->per_dir_config,
            &policy_module);
    policy_result result = check_enabled(f->r, conf, conf->vary_action);

    if (result != policy_ignore) {

        /* Vary present and valid? */
        if (!apr_table_do(vary_test, f->r, f->r->headers_out, "Vary", NULL)) {
            const char *varys = NULL;
            if (conf->vary_matches) {
                int i;
                for (i = 0; i < conf->vary_matches->nelts; i++) {
                    varys = apr_pstrcat(f->r->pool, varys ? ", " : "",
                            ((char **) conf->vary_matches->elts)[i], NULL);
                }
            }

            handle_policy(f->r, result, apr_psprintf(f->r->pool,
                    "Vary header(s) should NOT match any of: %s", varys),
                    conf->vary_url, bb, HTTP_BAD_GATEWAY);

        }

    }

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

/**
 * Policy for Validation.
 *
 * Validation is possible through either the ETag or Last-Modified header, as described
 * in http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.3.
 *
 * - Either must be present
 * - Last-Modified, if present, must parse to a valid date
 * - ETag, if present, must parse to a valid ETag.
 */
static apr_status_t policy_validation_out_filter(ap_filter_t *f,
        apr_bucket_brigade *bb)
{

    policy_conf *conf = ap_get_module_config(f->r->per_dir_config,
            &policy_module);
    policy_result result = check_enabled(f->r, conf, conf->validation_action);

    if (result != policy_ignore) {
        int fail = 1, etagfail = 0, lmfail = 0;
        const char *etag = apr_table_get(f->r->headers_out, "ETag");
        const char *lastmodified = apr_table_get(f->r->headers_out,
                "Last-Modified");

        if (etag) {
            int len = strlen(etag);
            if (len > 1) {
                if (etag[0] == '\"' && etag[len - 1] == '\"') {
                    fail = 0;
                }
                else if (etag[0] == 'W' && etag[1] == '/' && etag[2] == '\"'
                        && etag[len - 1] == '\"') {
                    fail = 0;
                }
            }
            if (fail) {
                etagfail = 1;
            }
        }

        if (lastmodified) {
            apr_time_t lastmod = apr_date_parse_http(lastmodified);
            if (lastmod != APR_DATE_BAD) {
                fail = 0;
            }
            if (fail) {
                lmfail = 1;
            }
        }

        if (fail) {
            const char *error = NULL;
            if (!etag && !lastmodified) {
                error = apr_psprintf(f->r->pool,
                        "Etag and Last Modified missing");
            }
            else {
                error = apr_pstrcat(f->r->pool,
                        (etagfail ? "ETag syntax error (check quotes)" : ""),
                        (etagfail && lmfail ? " / " : ""),
                        (lmfail ? "Last-Modified could not be parsed" : ""),
                        NULL);
            }

            handle_policy(f->r, result, error, conf->validation_url, bb,
                    HTTP_BAD_GATEWAY);

        }

    }

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

/**
 * Policy for Revalidation through Conditional Requests.
 *
 * The If-None-Match header is described in
 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.26. Over and above the
 * checks done in the validation filter, the conditional filter detects when an
 * If-None-Match header is present in the request, an ETag is present in the response,
 * and the response code is unexpected given the match. A result code is unexpected
 * where a 304 Not Modified or 412 Precondition Failed was expected, but a 200 response
 * was seen instead.
 */
static apr_status_t policy_conditional_out_filter(ap_filter_t *f,
        apr_bucket_brigade *bb)
{

    policy_conf *conf = ap_get_module_config(f->r->per_dir_config,
            &policy_module);
    policy_result result = check_enabled(f->r, conf, conf->conditional_action);

    if (result != policy_ignore) {
        int code = ap_meets_conditions(f->r);

        if (OK != code && code != f->r->status) {

            handle_policy(
                    f->r,
                    result,
                    apr_psprintf(
                            f->r->pool,
                            "Conditional request should have returned %d, instead returned %d",
                            code, f->r->status), conf->conditional_url, bb,
                    HTTP_BAD_GATEWAY);

        }

    }

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

/**
 * Policy for No-Cache Requests.
 *
 * If the Cache-Control and/or Pragma header specifies that the content is not
 * cacheable, the request will be rejected.
 *
 * - If Cache-Control: no-cache
 * - If Pragma: no-cache
 * - If Cache-Control: no-store
 * - If Cache-Control: private
 */
static apr_status_t policy_nocache_out_filter(ap_filter_t *f,
        apr_bucket_brigade *bb)
{

    policy_conf *conf = ap_get_module_config(f->r->per_dir_config,
            &policy_module);
    policy_result result = check_enabled(f->r, conf, conf->nocache_action);

    if (result != policy_ignore) {
        request_rec *r = f->r;
        const char *cc_header = apr_table_get(r->headers_out, "Cache-Control");
        const char *pragma_header = apr_table_get(r->headers_out, "Pragma");
        int fail = 0;
        char *last;

        if (pragma_header) {
            char *header = apr_pstrdup(r->pool, pragma_header);
            const char *token = apr_strtok(header, ", ", &last);
            while (token) {
                /* handle most common quickest case... */
                if (!strcmp(token, "no-cache")) {
                    fail = 1;
                }
                /* ...then try slowest case */
                else if (!strcasecmp(token, "no-cache")) {
                    fail = 1;
                }
                token = apr_strtok(NULL, ", ", &last);
            }
        }

        if (cc_header) {
            char *header = apr_pstrdup(r->pool, cc_header);
            const char *token = apr_strtok(header, ", ", &last);
            while (token) {
                switch (token[0]) {
                case 'n':
                case 'N': {
                    /* handle most common quickest cases... */
                    if (!strcmp(token, "no-cache")) {
                        fail = 1;
                    }
                    else if (!strcmp(token, "no-store")) {
                        fail = 1;
                    }
                    /* ...then try slowest cases */
                    else if (!strncasecmp(token, "no-cache", 8)) {
                        if (token[8] == '=') {
                        }
                        else if (!token[8]) {
                            fail = 1;
                        }
                        break;
                    }
                    else if (!strcasecmp(token, "no-store")) {
                        fail = 1;
                    }
                    break;
                }
                case 'p':
                case 'P': {
                    /* handle most common quickest cases... */
                    if (!strcmp(token, "private")) {
                        fail = 1;
                    }
                    /* ...then try slowest cases */
                    else if (!strncasecmp(token, "private", 7)) {
                        if (token[7] == '=') {
                        }
                        else if (!token[7]) {
                            fail = 1;
                        }
                        break;
                    }
                    break;
                }
                }
                token = apr_strtok(NULL, ", ", &last);
            }
        }

        if (fail) {

            handle_policy(r, result, "Response is marked uncacheable",
                    conf->nocache_url, bb, HTTP_BAD_GATEWAY);

        }

    }

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

/**
 * Policy for Maxage.
 *
 * If the effective maxage of the request is less than the parameter provided,
 * the request will be rejected.
 *
 * - If Cache-Control: s-maxage is less than the limit
 * - If Cache-Control: maxage is less than the limit
 * - If Expires - Date is less than the limit
 * - If none of the above, reject the request, as maxage is heuristic
 *
 * As soon as a test passes, we stop, as HTTP maxage handling follows a given
 * set of priorities (s-maxage beats maxage, maxage beats Expires).
 */
static apr_status_t policy_maxage_out_filter(ap_filter_t *f,
        apr_bucket_brigade *bb)
{

    policy_conf *conf = ap_get_module_config(f->r->per_dir_config,
            &policy_module);
    policy_result result = check_enabled(f->r, conf, conf->maxage_action);

    if (result != policy_ignore) {
        request_rec *r = f->r;
        const char *cc_header;
        const char *expires_header;
        const char *date_header;
        char *last;

        int max_age = 0;
        apr_int64_t max_age_value = 0;
        int s_maxage = 0;
        apr_int64_t s_maxage_value = 0;

        /* parse Cache-Control */
        cc_header = apr_table_get(r->headers_out, "Cache-Control");
        if (cc_header) {
            char *header = apr_pstrdup(r->pool, cc_header);
            const char *token = apr_strtok(header, ", ", &last);
            while (token) {
                switch (token[0]) {
                case 'm':
                case 'M': {
                    /* handle most common quickest cases... */
                    if (!strncmp(token, "max-age", 7)) {
                        max_age = 1;
                        max_age_value = apr_atoi64(token + 8);
                    }
                    /* ...then try slowest cases */
                    else if (!strncasecmp(token, "max-age", 7)) {
                        if (token[7] == '=') {
                            max_age = 1;
                            max_age_value = apr_atoi64(token + 8);
                        }
                        break;
                    }
                    break;
                }
                case 's':
                case 'S': {
                    if (!strncmp(token, "s-maxage", 8)) {
                        if (token[8] == '=') {
                            s_maxage = 1;
                            s_maxage_value = apr_atoi64(token + 9);
                        }
                        break;
                    }
                    else if (!strncasecmp(token, "s-maxage", 8)) {
                        if (token[8] == '=') {
                            s_maxage = 1;
                            s_maxage_value = apr_atoi64(token + 9);
                        }
                        break;
                    }
                    break;
                }
                }
                token = apr_strtok(NULL, ", ", &last);
            }
        }

        /* test s-maxage, if present */
        if (s_maxage) {
            if (s_maxage_value < conf->maxage) {

                handle_policy(
                        f->r,
                        result,
                        apr_psprintf(
                                f->r->pool,
                                "Response s-maxage of %" APR_INT64_T_FMT " must be at least %" APR_INT64_T_FMT,
                                s_maxage_value, conf->maxage), conf->maxage_url,
                        bb, HTTP_BAD_GATEWAY);

            }

            /* decision is made, leave */
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* test max-age, if present */
        if (max_age) {
            if (max_age_value < conf->maxage) {

                handle_policy(
                        f->r,
                        result,
                        apr_psprintf(
                                f->r->pool,
                                "Response max-age of %" APR_INT64_T_FMT " must be at least %" APR_INT64_T_FMT,
                                max_age_value, conf->maxage), conf->maxage_url,
                        bb, HTTP_BAD_GATEWAY);

            }

            /* decision is made, leave */
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* test expires, if present */
        expires_header = apr_table_get(r->headers_out, "Expires");
        date_header = apr_table_get(r->headers_out, "Date");
        if (expires_header && date_header) {
            apr_time_t expires = apr_date_parse_http(expires_header);
            apr_time_t date = apr_date_parse_http(date_header);
            apr_int64_t fresh = apr_time_sec(expires - date);

            if (expires == APR_DATE_BAD) {

                handle_policy(
                        f->r,
                        result,
                        apr_psprintf(
                                f->r->pool,
                                "Response Expires of '%s' is invalid, maxage %" APR_INT64_T_FMT " required",
                                expires_header, conf->maxage),
                        conf->maxage_url, bb, HTTP_BAD_GATEWAY);

            }

            else if (date == APR_DATE_BAD) {

                handle_policy(
                        f->r,
                        result,
                        apr_psprintf(
                                f->r->pool,
                                "Response Date of '%s' is invalid, maxage %" APR_INT64_T_FMT " required",
                                date_header, conf->maxage),
                        conf->maxage_url, bb, HTTP_BAD_GATEWAY);

            }

            else if (conf->maxage > 0 && fresh < conf->maxage) {

                handle_policy(
                        f->r,
                        result,
                        apr_psprintf(
                                f->r->pool,
                                "Response expires in %" APR_INT64_T_FMT " seconds, must be at least %" APR_INT64_T_FMT,
                                fresh, conf->maxage),
                        conf->maxage_url, bb, HTTP_BAD_GATEWAY);

            }

            /* decision is made, leave */
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* no explicit maxage defined, so fail */
        handle_policy(r, result, "Response has no explicit freshness lifetime (s-maxage, max-age or Expires/Date)",
                conf->maxage_url, bb, HTTP_BAD_GATEWAY);

    }

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static const char *version_string(int proto_num)
{
    switch (proto_num) {
    case HTTP_VERSION(0, 9): {
        return "HTTP/0.9";
    }
    case HTTP_VERSION(1, 0): {
        return "HTTP/1.0";
    }
    case HTTP_VERSION(1, 1): {
        return "HTTP/1.1";
    }
    default: {
        return "(unknown)";
    }
    }
}

/**
 * Policy for HTTP Version.
 *
 * - The HTTP version of the response must be at least the level specified.
 */
static apr_status_t policy_version_out_filter(ap_filter_t *f,
        apr_bucket_brigade *bb)
{
    request_rec *r = f->r;

    policy_conf *conf = ap_get_module_config(r->per_dir_config,
            &policy_module);
    policy_result result = check_enabled(r, conf, conf->version_action);

    if (result != policy_ignore) {

        if (r->proto_num > 0 && r->proto_num < conf->version_num) {

            handle_policy(f->r, result, apr_psprintf(f->r->pool,
                    "Request HTTP version '%s' should be at least '%s'",
                    version_string(r->proto_num), conf->version),
                    conf->version_url, bb, HTTP_VERSION_NOT_SUPPORTED);

        }

    }

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static void *create_policy_config(apr_pool_t *p, char *dummy)
{
    policy_conf *new = (policy_conf *) apr_pcalloc(p, sizeof(policy_conf));

    new->policy = 1;
    new->type_action = policy_log;
    new->length_action = policy_log;
    new->vary_action = policy_log;
    new->validation_action = policy_log;
    new->conditional_action = policy_log;
    new->nocache_action = policy_log;
    new->maxage_action = policy_log;
    new->version_action = policy_log;
    new->version_num = HTTP_VERSION(0, 9);
    new->version = "HTTP/0.9";

    return (void *) new;
}

static void *merge_policy_config(apr_pool_t *p, void *basev, void *addv)
{
    policy_conf *new = (policy_conf *) apr_pcalloc(p, sizeof(policy_conf));
    policy_conf *add = (policy_conf *) addv;
    policy_conf *base = (policy_conf *) basev;

    new->policy = (add->policy_set == 0) ? base->policy : add->policy;
    new->policy_set = add->policy_set || base->policy_set;
    new->environment = (add->environment_set == 0) ? base->environment : add->environment;
    new->environment_log = (add->environment_set == 0) ? base->environment_log
            : add->environment_log;
    new->environment_ignore = (add->environment_set == 0) ? base->environment_ignore
            : add->environment_ignore;
    new->environment_set = add->environment_set || base->environment_set;
    new->type_action = (add->type_set == 0) ? base->type_action
            : add->type_action;
    new->type_matches = (add->type_set == 0) ? base->type_matches
            : add->type_matches;
    new->type_set = add->type_set || base->type_set;
    new->type_url = (add->type_url_set == 0) ? base->type_url : add->type_url;
    new->type_url_set = add->type_url_set || base->type_url_set;
    new->length_action = (add->length_set == 0) ? base->length_action
            : add->length_action;
    new->length_set = add->length_set || base->length_set;
    new->length_url = (add->length_url_set == 0) ? base->length_url
            : add->length_url;
    new->length_url_set = add->length_url_set || base->length_url_set;
    new->vary_action = (add->vary_set == 0) ? base->vary_action
            : add->vary_action;
    new->vary_matches = (add->vary_set == 0) ? base->vary_matches
            : add->vary_matches;
    new->vary_set = add->vary_set || base->vary_set;
    new->vary_url = (add->vary_url_set == 0) ? base->vary_url : add->vary_url;
    new->vary_url_set = add->vary_url_set || base->vary_url_set;
    new->validation_action
            = (add->validation_set == 0) ? base->validation_action
                    : add->validation_action;
    new->validation_set = add->validation_set || base->validation_set;
    new->validation_url = (add->validation_url_set == 0) ? base->validation_url
            : add->validation_url;
    new->validation_url_set = add->validation_url_set
            || base->validation_url_set;
    new->conditional_action
            = (add->conditional_set == 0) ? base->conditional_action
                    : add->conditional_action;
    new->conditional_set = add->conditional_set || base->conditional_set;
    new->conditional_url
            = (add->conditional_url_set == 0) ? base->conditional_url
                    : add->conditional_url;
    new->conditional_url_set = add->conditional_url_set
            || base->conditional_url_set;
    new->nocache_action = (add->nocache_set == 0) ? base->nocache_action
            : add->nocache_action;
    new->nocache_set = add->nocache_set || base->nocache_set;
    new->nocache_url = (add->nocache_url_set == 0) ? base->nocache_url
            : add->nocache_url;
    new->nocache_url_set = add->nocache_url_set || base->nocache_url_set;
    new->maxage_action = (add->maxage_set == 0) ? base->maxage_action
            : add->maxage_action;
    new->maxage = (add->maxage_set == 0) ? base->maxage : add->maxage;
    new->maxage_set = add->maxage_set || base->maxage_set;
    new->maxage_url = (add->maxage_url_set == 0) ? base->maxage_url
            : add->maxage_url;
    new->maxage_url_set = add->maxage_url_set || base->maxage_url_set;
    new->version_action = (add->version_set == 0) ? base->version_action
            : add->version_action;
    new->version = (add->version_set == 0) ? base->version : add->version;
    new->version_num = (add->version_set == 0) ? base->version_num : add->version_num;
    new->version_set = add->version_set || base->version_set;
    new->version_url = (add->version_url_set == 0) ? base->version_url
            : add->version_url;
    new->version_url_set = add->version_url_set || base->version_url_set;


    return new;
}

static const char *parse_action(apr_pool_t *pool, const char *action,
        policy_result *result)
{
    if (!strcmp(action, "enforce")) {
        *result = policy_enforce;
    }
    else if (!strcmp(action, "log")) {
        *result = policy_log;
    }
    else if (!strcmp(action, "ignore")) {
        *result = policy_ignore;
    }
    else {
        return apr_psprintf(pool,
                "'%s' must be one of 'enforce, 'log' or 'ignore'.", action);
    }
    return NULL;
}

static const char *set_policy(cmd_parms *cmd, void *dconf, int flag)
{
    policy_conf *conf = dconf;

    conf->policy = flag;
    conf->policy_set = 1;

    return NULL;
}

static const char *set_environment(cmd_parms *cmd, void *dconf,
        const char *environment, const char *log, const char *ignore)
{
    policy_conf *conf = dconf;

    conf->environment = environment;
    conf->environment_log = log;
    conf->environment_ignore = ignore;
    conf->environment_set = 1;

    return NULL;
}

static const char *set_type(cmd_parms *cmd, void *dconf, const char *action,
        const char *type)
{
    policy_conf *conf = dconf;

    if (type) {
        const char **match_ptr;
        if (!conf->type_matches) {
            conf->type_matches = apr_array_make(cmd->pool, 2,
                    sizeof(const char *));
        }
        match_ptr = apr_array_push(conf->type_matches);
        *match_ptr = type;
    }
    conf->type_set = 1;

    return parse_action(cmd->pool, action, &conf->type_action);
}

static const char *set_type_url(cmd_parms *cmd, void *dconf, const char *url)
{
    policy_conf *conf = dconf;

    conf->type_url = url;
    conf->type_url_set = 1;

    return NULL;
}

static const char *set_length(cmd_parms *cmd, void *dconf, const char *action)
{
    policy_conf *conf = dconf;

    conf->length_set = 1;

    return parse_action(cmd->pool, action, &conf->length_action);
}

static const char *set_length_url(cmd_parms *cmd, void *dconf, const char *url)
{
    policy_conf *conf = dconf;

    conf->length_url = url;
    conf->length_url_set = 1;

    return NULL;
}

static const char *set_keepalive(cmd_parms *cmd, void *dconf, const char *action)
{
    policy_conf *conf = dconf;

    conf->keepalive_set = 1;

    return parse_action(cmd->pool, action, &conf->keepalive_action);
}

static const char *set_keepalive_url(cmd_parms *cmd, void *dconf, const char *url)
{
    policy_conf *conf = dconf;

    conf->keepalive_url = url;
    conf->keepalive_url_set = 1;

    return NULL;
}

static const char *set_vary(cmd_parms *cmd, void *dconf, const char *action,
        const char *vary)
{
    policy_conf *conf = dconf;

    if (vary) {
        const char **match_ptr;
        if (!conf->vary_matches) {
            conf->vary_matches = apr_array_make(cmd->pool, 2,
                    sizeof(const char *));
        }
        match_ptr = apr_array_push(conf->vary_matches);
        *match_ptr = vary;
    }
    conf->vary_set = 1;

    return parse_action(cmd->pool, action, &conf->vary_action);
}

static const char *set_vary_url(cmd_parms *cmd, void *dconf, const char *url)
{
    policy_conf *conf = dconf;

    conf->vary_url = url;
    conf->vary_url_set = 1;

    return NULL;
}

static const char *set_validation(cmd_parms *cmd, void *dconf,
        const char *action)
{
    policy_conf *conf = dconf;

    conf->validation_set = 1;

    return parse_action(cmd->pool, action, &conf->validation_action);
}

static const char *set_validation_url(cmd_parms *cmd, void *dconf,
        const char *url)
{
    policy_conf *conf = dconf;

    conf->validation_url = url;
    conf->validation_url_set = 1;

    return NULL;
}

static const char *set_conditional(cmd_parms *cmd, void *dconf,
        const char *action)
{
    policy_conf *conf = dconf;

    conf->conditional_set = 1;

    return parse_action(cmd->pool, action, &conf->conditional_action);
}

static const char *set_conditional_url(cmd_parms *cmd, void *dconf,
        const char *url)
{
    policy_conf *conf = dconf;

    conf->conditional_url = url;
    conf->conditional_url_set = 1;

    return NULL;
}

static const char *set_nocache(cmd_parms *cmd, void *dconf, const char *action)
{
    policy_conf *conf = dconf;

    conf->nocache_set = 1;

    return parse_action(cmd->pool, action, &conf->nocache_action);
}

static const char *set_nocache_url(cmd_parms *cmd, void *dconf, const char *url)
{
    policy_conf *conf = dconf;

    conf->nocache_url = url;
    conf->nocache_url_set = 1;

    return NULL;
}

static const char *set_maxage(cmd_parms *cmd, void *dconf, const char *action, const char *maxage)
{
    policy_conf *conf = dconf;

    conf->maxage_set = 1;
    conf->maxage = apr_atoi64(maxage);
    if (conf->maxage < 0) {
        return apr_psprintf(cmd->pool,
                "'%s' must be a positive integer.", maxage);
    }

    return parse_action(cmd->pool, action, &conf->maxage_action);
}

static const char *set_maxage_url(cmd_parms *cmd, void *dconf, const char *url)
{
    policy_conf *conf = dconf;

    conf->maxage_url = url;
    conf->maxage_url_set = 1;

    return NULL;
}

static const char *set_version(cmd_parms *cmd, void *dconf, const char *action, const char *version)
{
    policy_conf *conf = dconf;

    conf->version_set = 1;

    if (!strcmp(version, "HTTP/1.1")) {
        conf->version = "HTTP/1.1";
        conf->version_num = HTTP_VERSION(1, 1);
    }
    else if (!strcmp(version, "HTTP/1.0")) {
        conf->version = "HTTP/1.0";
        conf->version_num = HTTP_VERSION(1, 0);
    }
    else if (!strcmp(version, "HTTP/0.9")) {
        conf->version = "HTTP/0.9";
        conf->version_num = HTTP_VERSION(0, 9);
    }
    else {
        return apr_psprintf(cmd->pool,
                "'%s' must be one of 'HTTP/1.1', 'HTTP/1.0' or 'HTTP/0.9'.", version);
    }

    return parse_action(cmd->pool, action, &conf->version_action);
}

static const char *set_version_url(cmd_parms *cmd, void *dconf, const char *url)
{
    policy_conf *conf = dconf;

    conf->version_url = url;
    conf->version_url_set = 1;

    return NULL;
}

static const command_rec
        policy_cmds[] =
        {
                AP_INIT_FLAG("PolicyFilter", set_policy, NULL, RSRC_CONF
                        | ACCESS_CONF,
                        "Whether policies should be applied. Defaults to 'on'."),
                AP_INIT_TAKE1(
                        "PolicyConditional",
                        set_conditional,
                        NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "Action to take (enforce, ignore, log) if a conditional request was not honoured. Defaults to 'log'."),
                AP_INIT_TAKE1("PolicyConditionalURL", set_conditional_url,
                        NULL, RSRC_CONF | ACCESS_CONF,
                        "URL describing the conditional request policy."),
                AP_INIT_TAKE3(
                        "PolicyEnvironment",
                        set_environment,
                        NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "Environment variable to control policy enforcement, followed by the variable value for logging only, and the value for policy suspension."),
                AP_INIT_TAKE1(
                        "PolicyLength",
                        set_length,
                        NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "Action to take (enforce, ignore, log) if Content-Length missing. Defaults to 'log'."),
                AP_INIT_TAKE1("PolicyLengthURL", set_length_url, NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "URL describing the content length policy."),
                AP_INIT_TAKE1(
                        "PolicyKeepalive",
                        set_keepalive,
                        NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "Action to take (enforce, ignore, log) if keepalive is not possible. Defaults to 'log'."),
                AP_INIT_TAKE1("PolicyKeepaliveURL", set_keepalive_url, NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "URL describing the keepalive policy."),
                AP_INIT_ITERATE2(
                        "PolicyType",
                        set_type,
                        NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "Action to take (enforce, ignore, log), followed by one or more valid content types containing optional wildcards ? and *"),
                AP_INIT_TAKE1("PolicyTypeURL", set_type_url, NULL, RSRC_CONF
                        | ACCESS_CONF,
                        "URL describing the content type policy."),
                AP_INIT_ITERATE2(
                        "PolicyVary",
                        set_vary,
                        NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "Action to take (enforce, ignore, log), followed by one or more headers containing optional wildcards ? and * that are NOT to appear in a Vary header"),
                AP_INIT_TAKE1("PolicyVaryURL", set_vary_url, NULL, RSRC_CONF
                        | ACCESS_CONF,
                        "URL describing the vary header policy."),
                AP_INIT_TAKE1(
                        "PolicyValidation",
                        set_validation,
                        NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "Action to take (enforce, ignore, log) if Last-Modified or Etag is missing or invalid. Defaults to 'log'."),
                AP_INIT_TAKE1("PolicyValidationURL", set_validation_url, NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "URL describing the content validation policy."),
                AP_INIT_TAKE1(
                        "PolicyNocache",
                        set_nocache,
                        NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "Action to take (enforce, ignore, log) if a response is not cacheable. Defaults to 'log'."),
                AP_INIT_TAKE1("PolicyNocacheURL", set_nocache_url, NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "URL describing the no cache policy."),
                AP_INIT_TAKE2(
                        "PolicyMaxage",
                        set_maxage,
                        NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "Action to take (enforce, ignore, log) if a response has an effective maxage less than the age provided. Defaults to 'log'."),
                AP_INIT_TAKE1("PolicyMaxageURL", set_maxage_url, NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "URL describing the maxage policy."),
                AP_INIT_TAKE2(
                        "PolicyVersion",
                        set_version,
                        NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "Action to take (enforce, ignore, log) if a response has an HTTP version less than the version provided. Defaults to 'log HTTP/0.9'."),
                AP_INIT_TAKE1("PolicyVersionURL", set_version_url, NULL,
                        RSRC_CONF | ACCESS_CONF,
                        "URL describing the version policy."),
                { NULL } };

static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter("POLICY_TYPE", policy_type_out_filter, NULL,
            AP_FTYPE_CONTENT_SET + 5);
    ap_register_output_filter("POLICY_LENGTH", policy_length_out_filter, NULL,
            AP_FTYPE_CONTENT_SET + 5);
    ap_register_output_filter("POLICY_KEEPALIVE", policy_keepalive_out_filter, NULL,
            AP_FTYPE_CONTENT_SET + 5);
    ap_register_output_filter("POLICY_VARY", policy_vary_out_filter, NULL,
            AP_FTYPE_CONTENT_SET + 5);
    ap_register_output_filter("POLICY_VALIDATION",
            policy_validation_out_filter, NULL, AP_FTYPE_CONTENT_SET + 5);
    ap_register_output_filter("POLICY_CONDITIONAL",
            policy_conditional_out_filter, NULL, AP_FTYPE_CONTENT_SET + 5);
    ap_register_output_filter("POLICY_NOCACHE", policy_nocache_out_filter,
            NULL, AP_FTYPE_CONTENT_SET + 5);
    ap_register_output_filter("POLICY_MAXAGE", policy_maxage_out_filter,
            NULL, AP_FTYPE_CONTENT_SET + 5);
    ap_register_output_filter("POLICY_VERSION", policy_version_out_filter,
            NULL, AP_FTYPE_CONTENT_SET + 5);
}

AP_DECLARE_MODULE(policy) =
{
    STANDARD20_MODULE_STUFF, create_policy_config, /* create per-directory config structure */
    merge_policy_config, /* merge per-directory config structures */
    NULL, /* create per-server config structure */
    NULL, /* merge per-server config structures */
    policy_cmds, /* command apr_table_t */
    register_hooks /* register hooks */
};
