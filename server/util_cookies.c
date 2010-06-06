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

#include "util_cookies.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "http_log.h"

#define LOG_PREFIX "ap_cookie: "

APLOG_USE_MODULE(core);

/**
 * Write an RFC2109 compliant cookie.
 *
 * @param r The request
 * @param name The name of the cookie.
 * @param val The value to place in the cookie.
 * @param attrs The string containing additional cookie attributes. If NULL, the
 *              DEFAULT_ATTRS will be used.
 * @param maxage If non zero, a Max-Age header will be added to the cookie.
 */
AP_DECLARE(apr_status_t) ap_cookie_write(request_rec * r, const char *name, const char *val,
                                         const char *attrs, long maxage, ...)
{

    const char *buffer;
    const char *rfc2109;
    apr_table_t *t;
    va_list vp;

    /* handle expiry */
    buffer = "";
    if (maxage) {
        buffer = apr_pstrcat(r->pool, "Max-Age=", apr_ltoa(r->pool, maxage), ";", NULL);
    }

    /* create RFC2109 compliant cookie */
    rfc2109 = apr_pstrcat(r->pool, name, "=", val, ";",
                          buffer,
                          attrs && strlen(attrs) > 0 ?
                          attrs : DEFAULT_ATTRS, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, LOG_PREFIX
                  "user '%s' set cookie: '%s'", r->user, rfc2109);

    /* write the cookie to the header table(s) provided */
    va_start(vp, maxage);
    while ((t = va_arg(vp, apr_table_t *))) {
        apr_table_addn(t, SET_COOKIE, rfc2109);
    }
    va_end(vp);

    return APR_SUCCESS;

}

/**
 * Write an RFC2965 compliant cookie.
 *
 * @param r The request
 * @param name2 The name of the cookie.
 * @param val The value to place in the cookie.
 * @param attrs2 The string containing additional cookie attributes. If NULL, the
 *               DEFAULT_ATTRS will be used.
 * @param maxage If non zero, a Max-Age header will be added to the cookie.
 */
AP_DECLARE(apr_status_t) ap_cookie_write2(request_rec * r, const char *name2, const char *val,
                                          const char *attrs2, long maxage, ...)
{

    const char *buffer;
    const char *rfc2965;
    apr_table_t *t;
    va_list vp;

    /* handle expiry */
    buffer = "";
    if (maxage) {
        buffer = apr_pstrcat(r->pool, "Max-Age=", apr_ltoa(r->pool, maxage), ";", NULL);
    }

    /* create RFC2965 compliant cookie */
    rfc2965 = apr_pstrcat(r->pool, name2, "=", val, ";",
                          buffer,
                          attrs2 && strlen(attrs2) > 0 ?
                          attrs2 : DEFAULT_ATTRS, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, LOG_PREFIX
                  "user '%s' set cookie2: '%s'", r->user, rfc2965);

    /* write the cookie to the header table(s) provided */
    va_start(vp, maxage);
    while ((t = va_arg(vp, apr_table_t *))) {
        apr_table_addn(t, SET_COOKIE2, rfc2965);
    }
    va_end(vp);

    return APR_SUCCESS;

}

/**
 * Remove an RFC2109 compliant cookie.
 *
 * @param r The request
 * @param name The name of the cookie.
 */
AP_DECLARE(apr_status_t) ap_cookie_remove(request_rec * r, const char *name, const char *attrs, ...)
{
    apr_table_t *t;
    va_list vp;

    /* create RFC2109 compliant cookie */
    const char *rfc2109 = apr_pstrcat(r->pool, name, "=;Max-Age=0;",
                                attrs ? attrs : CLEAR_ATTRS, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, LOG_PREFIX
                  "user '%s' removed cookie: '%s'", r->user, rfc2109);

    /* write the cookie to the header table(s) provided */
    va_start(vp, attrs);
    while ((t = va_arg(vp, apr_table_t *))) {
        apr_table_addn(t, SET_COOKIE, rfc2109);
    }
    va_end(vp);

    return APR_SUCCESS;

}

/**
 * Remove an RFC2965 compliant cookie.
 *
 * @param r The request
 * @param name2 The name of the cookie.
 */
AP_DECLARE(apr_status_t) ap_cookie_remove2(request_rec * r, const char *name2, const char *attrs2, ...)
{
    apr_table_t *t;
    va_list vp;

    /* create RFC2965 compliant cookie */
    const char *rfc2965 = apr_pstrcat(r->pool, name2, "=;Max-Age=0;",
                                attrs2 ? attrs2 : CLEAR_ATTRS, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, LOG_PREFIX
                  "user '%s' removed cookie2: '%s'", r->user, rfc2965);

    /* write the cookie to the header table(s) provided */
    va_start(vp, attrs2);
    while ((t = va_arg(vp, apr_table_t *))) {
        apr_table_addn(t, SET_COOKIE2, rfc2965);
    }
    va_end(vp);

    return APR_SUCCESS;

}

/* Iterate through the cookies, isolate our cookie and then remove it.
 *
 * If our cookie appears two or more times, but with different values,
 * remove it twice and set the duplicated flag to true. Remove any
 * $path or other attributes following our cookie if present. If we end
 * up with an empty cookie, remove the whole header.
 */
static int extract_cookie_line(ap_cookie_do * v, const char *key, const char *val)
{
    char *last1, *last2;
    char *cookie = apr_pstrdup(v->r->pool, val);
    const char *name = apr_pstrcat(v->r->pool, v->name ? v->name : "", "=", NULL);
    size_t len = strlen(name);
    const char *new_cookie = "";
    const char *comma = ",";
    char *next1;
    const char *semi = ";";
    char *next2;
    const char *sep = "";
    int cookies = 0;

    /* find the cookie called name */
    int eat = 0;
    next1 = apr_strtok(cookie, comma, &last1);
    while (next1) {
        next2 = apr_strtok(next1, semi, &last2);
        while (next2) {
            char *trim = next2;
            while (apr_isspace(*trim)) {
                trim++;
            }
            if (!strncmp(trim, name, len)) {
                if (v->encoded) {
                    if (strcmp(v->encoded, trim + len)) {
                        v->duplicated = 1;
                    }
                }
                v->encoded = apr_pstrdup(v->r->pool, trim + len);
                eat = 1;
            }
            else {
                if (*trim != '$') {
                    cookies++;
                    eat = 0;
                }
                if (!eat) {
                    new_cookie = apr_pstrcat(v->r->pool, new_cookie, sep, next2, NULL);
                }
            }
            next2 = apr_strtok(NULL, semi, &last2);
            sep = semi;
        }

        next1 = apr_strtok(NULL, comma, &last1);
        sep = comma;
    }

    /* any cookies left over? */
    if (cookies) {
        apr_table_addn(v->new_cookies, key, new_cookie);
    }

    return 1;
}

/**
 * Read a cookie called name, placing its value in val.
 *
 * Both the Cookie and Cookie2 headers are scanned for the cookie.
 *
 * If the cookie is duplicated, this function returns APR_EGENERAL. If found,
 * and if remove is non zero, the cookie will be removed from the headers, and
 * thus kept private from the backend.
 */
AP_DECLARE(apr_status_t) ap_cookie_read(request_rec * r, const char *name, const char **val,
                                        int remove)
{

    ap_cookie_do v;
    v.r = r;
    v.encoded = NULL;
    v.new_cookies = apr_table_make(r->pool, 10);
    v.duplicated = 0;
    v.name = name;

    apr_table_do((int (*) (void *, const char *, const char *))
                 extract_cookie_line, (void *) &v, r->headers_in,
                 "Cookie", "Cookie2", NULL);
    if (v.duplicated) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOG_PREFIX
         "client submitted cookie '%s' more than once: %s", v.name, r->uri);
        return APR_EGENERAL;
    }

    /* remove our cookie(s), and replace them */
    if (remove) {
        apr_table_unset(r->headers_in, "Cookie");
        apr_table_unset(r->headers_in, "Cookie2");
        r->headers_in = apr_table_overlay(r->pool, r->headers_in, v.new_cookies);
    }

    *val = v.encoded;

    return APR_SUCCESS;

}

/**
 * Sanity check a given string that it exists, is not empty,
 * and does not contain the special characters '=', ';' and '&'.
 *
 * It is used to sanity check the cookie names.
 */
AP_DECLARE(apr_status_t) ap_cookie_check_string(const char *string)
{
    if (!string || !*string || ap_strchr_c(string, '=') || ap_strchr_c(string, '&') ||
        ap_strchr_c(string, ';')) {
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}
