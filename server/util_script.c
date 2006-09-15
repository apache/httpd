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

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_main.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"       /* for sub_req_lookup_uri() */
#include "util_script.h"
#include "apr_date.h"           /* For apr_date_parse_http() */
#include "util_ebcdic.h"

#ifdef OS2
#define INCL_DOS
#include <os2.h>
#endif

/*
 * Various utility functions which are common to a whole lot of
 * script-type extensions mechanisms, and might as well be gathered
 * in one place (if only to avoid creating inter-module dependancies
 * where there don't have to be).
 */

#define MALFORMED_MESSAGE "malformed header from script. Bad header="
#define MALFORMED_HEADER_LENGTH_TO_SHOW 30

static char *http2env(apr_pool_t *a, const char *w)
{
    char *res = (char *)apr_palloc(a, sizeof("HTTP_") + strlen(w));
    char *cp = res;
    char c;

    *cp++ = 'H';
    *cp++ = 'T';
    *cp++ = 'T';
    *cp++ = 'P';
    *cp++ = '_';

    while ((c = *w++) != 0) {
        if (!apr_isalnum(c)) {
            *cp++ = '_';
        }
        else {
            *cp++ = apr_toupper(c);
        }
    }
    *cp = 0;

    return res;
}

AP_DECLARE(char **) ap_create_environment(apr_pool_t *p, apr_table_t *t)
{
    const apr_array_header_t *env_arr = apr_table_elts(t);
    const apr_table_entry_t *elts = (const apr_table_entry_t *) env_arr->elts;
    char **env = (char **) apr_palloc(p, (env_arr->nelts + 2) * sizeof(char *));
    int i, j;
    char *tz;
    char *whack;

    j = 0;
    if (!apr_table_get(t, "TZ")) {
        tz = getenv("TZ");
        if (tz != NULL) {
            env[j++] = apr_pstrcat(p, "TZ=", tz, NULL);
        }
    }
    for (i = 0; i < env_arr->nelts; ++i) {
        if (!elts[i].key) {
            continue;
        }
        env[j] = apr_pstrcat(p, elts[i].key, "=", elts[i].val, NULL);
        whack = env[j];
        if (apr_isdigit(*whack)) {
            *whack++ = '_';
        }
        while (*whack != '=') {
            if (!apr_isalnum(*whack) && *whack != '_') {
                *whack = '_';
            }
            ++whack;
        }
        ++j;
    }

    env[j] = NULL;
    return env;
}

AP_DECLARE(void) ap_add_common_vars(request_rec *r)
{
    apr_table_t *e;
    server_rec *s = r->server;
    conn_rec *c = r->connection;
    const char *rem_logname;
    char *env_path;
#if defined(WIN32) || defined(OS2) || defined(BEOS)
    char *env_temp;
#endif
    const char *host;
    const apr_array_header_t *hdrs_arr = apr_table_elts(r->headers_in);
    const apr_table_entry_t *hdrs = (const apr_table_entry_t *) hdrs_arr->elts;
    int i;
    apr_port_t rport;

    /* use a temporary apr_table_t which we'll overlap onto
     * r->subprocess_env later
     * (exception: if r->subprocess_env is empty at the start,
     * write directly into it)
     */
    if (apr_is_empty_table(r->subprocess_env)) {
        e = r->subprocess_env;
    }
    else {
        e = apr_table_make(r->pool, 25 + hdrs_arr->nelts);
    }

    /* First, add environment vars from headers... this is as per
     * CGI specs, though other sorts of scripting interfaces see
     * the same vars...
     */

    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key) {
            continue;
        }

        /* A few headers are special cased --- Authorization to prevent
         * rogue scripts from capturing passwords; content-type and -length
         * for no particular reason.
         */

        if (!strcasecmp(hdrs[i].key, "Content-type")) {
            apr_table_addn(e, "CONTENT_TYPE", hdrs[i].val);
        }
        else if (!strcasecmp(hdrs[i].key, "Content-length")) {
            apr_table_addn(e, "CONTENT_LENGTH", hdrs[i].val);
        }
        /*
         * You really don't want to disable this check, since it leaves you
         * wide open to CGIs stealing passwords and people viewing them
         * in the environment with "ps -e".  But, if you must...
         */
#ifndef SECURITY_HOLE_PASS_AUTHORIZATION
        else if (!strcasecmp(hdrs[i].key, "Authorization")
                 || !strcasecmp(hdrs[i].key, "Proxy-Authorization")) {
            continue;
        }
#endif
        else {
            apr_table_addn(e, http2env(r->pool, hdrs[i].key), hdrs[i].val);
        }
    }

    if (!(env_path = getenv("PATH"))) {
        env_path = DEFAULT_PATH;
    }
    apr_table_addn(e, "PATH", apr_pstrdup(r->pool, env_path));

#ifdef WIN32
    if (env_temp = getenv("SystemRoot")) {
        apr_table_addn(e, "SystemRoot", env_temp);
    }
    if (env_temp = getenv("COMSPEC")) {
        apr_table_addn(e, "COMSPEC", env_temp);
    }
    if (env_temp = getenv("PATHEXT")) {
        apr_table_addn(e, "PATHEXT", env_temp);
    }
    if (env_temp = getenv("WINDIR")) {
        apr_table_addn(e, "WINDIR", env_temp);
    }
#endif

#ifdef OS2
    if ((env_temp = getenv("COMSPEC")) != NULL) {
        apr_table_addn(e, "COMSPEC", env_temp);
    }
    if ((env_temp = getenv("ETC")) != NULL) {
        apr_table_addn(e, "ETC", env_temp);
    }
    if ((env_temp = getenv("DPATH")) != NULL) {
        apr_table_addn(e, "DPATH", env_temp);
    }
    if ((env_temp = getenv("PERLLIB_PREFIX")) != NULL) {
        apr_table_addn(e, "PERLLIB_PREFIX", env_temp);
    }
#endif

#ifdef BEOS
    if ((env_temp = getenv("LIBRARY_PATH")) != NULL) {
        apr_table_addn(e, "LIBRARY_PATH", env_temp);
    }
#endif

    apr_table_addn(e, "SERVER_SIGNATURE", ap_psignature("", r));
    apr_table_addn(e, "SERVER_SOFTWARE", ap_get_server_banner());
    apr_table_addn(e, "SERVER_NAME",
                   ap_escape_html(r->pool, ap_get_server_name(r)));
    apr_table_addn(e, "SERVER_ADDR", r->connection->local_ip);  /* Apache */
    apr_table_addn(e, "SERVER_PORT",
                  apr_psprintf(r->pool, "%u", ap_get_server_port(r)));
    host = ap_get_remote_host(c, r->per_dir_config, REMOTE_HOST, NULL);
    if (host) {
        apr_table_addn(e, "REMOTE_HOST", host);
    }
    apr_table_addn(e, "REMOTE_ADDR", c->remote_ip);
    apr_table_addn(e, "DOCUMENT_ROOT", ap_document_root(r));    /* Apache */
    apr_table_addn(e, "SERVER_ADMIN", s->server_admin); /* Apache */
    apr_table_addn(e, "SCRIPT_FILENAME", r->filename);  /* Apache */

    rport = c->remote_addr->port;
    apr_table_addn(e, "REMOTE_PORT", apr_itoa(r->pool, rport));

    if (r->user) {
        apr_table_addn(e, "REMOTE_USER", r->user);
    }
    else if (r->prev) {
        request_rec *back = r->prev;

        while (back) {
            if (back->user) {
                apr_table_addn(e, "REDIRECT_REMOTE_USER", back->user);
                break;
            }
            back = back->prev;
        }
    }
    if (r->ap_auth_type) {
        apr_table_addn(e, "AUTH_TYPE", r->ap_auth_type);
    }
    rem_logname = ap_get_remote_logname(r);
    if (rem_logname) {
        apr_table_addn(e, "REMOTE_IDENT", apr_pstrdup(r->pool, rem_logname));
    }

    /* Apache custom error responses. If we have redirected set two new vars */

    if (r->prev) {
        if (r->prev->args) {
            apr_table_addn(e, "REDIRECT_QUERY_STRING", r->prev->args);
        }
        if (r->prev->uri) {
            apr_table_addn(e, "REDIRECT_URL", r->prev->uri);
        }
    }

    if (e != r->subprocess_env) {
      apr_table_overlap(r->subprocess_env, e, APR_OVERLAP_TABLES_SET);
    }
}

/* This "cute" little function comes about because the path info on
 * filenames and URLs aren't always the same. So we take the two,
 * and find as much of the two that match as possible.
 */

AP_DECLARE(int) ap_find_path_info(const char *uri, const char *path_info)
{
    int lu = strlen(uri);
    int lp = strlen(path_info);

    while (lu-- && lp-- && uri[lu] == path_info[lp]) {
        if (path_info[lp] == '/') {
            while (lu && uri[lu-1] == '/') lu--;
        }
    }

    if (lu == -1) {
        lu = 0;
    }

    while (uri[lu] != '\0' && uri[lu] != '/') {
        lu++;
    }
    return lu;
}

/* Obtain the Request-URI from the original request-line, returning
 * a new string from the request pool containing the URI or "".
 */
static char *original_uri(request_rec *r)
{
    char *first, *last;

    if (r->the_request == NULL) {
        return (char *) apr_pcalloc(r->pool, 1);
    }

    first = r->the_request;     /* use the request-line */

    while (*first && !apr_isspace(*first)) {
        ++first;                /* skip over the method */
    }
    while (apr_isspace(*first)) {
        ++first;                /*   and the space(s)   */
    }

    last = first;
    while (*last && !apr_isspace(*last)) {
        ++last;                 /* end at next whitespace */
    }

    return apr_pstrmemdup(r->pool, first, last - first);
}

AP_DECLARE(void) ap_add_cgi_vars(request_rec *r)
{
    apr_table_t *e = r->subprocess_env;

    apr_table_setn(e, "GATEWAY_INTERFACE", "CGI/1.1");
    apr_table_setn(e, "SERVER_PROTOCOL", r->protocol);
    apr_table_setn(e, "REQUEST_METHOD", r->method);
    apr_table_setn(e, "QUERY_STRING", r->args ? r->args : "");
    apr_table_setn(e, "REQUEST_URI", original_uri(r));

    /* Note that the code below special-cases scripts run from includes,
     * because it "knows" that the sub_request has been hacked to have the
     * args and path_info of the original request, and not any that may have
     * come with the script URI in the include command.  Ugh.
     */

    if (!strcmp(r->protocol, "INCLUDED")) {
        apr_table_setn(e, "SCRIPT_NAME", r->uri);
        if (r->path_info && *r->path_info) {
            apr_table_setn(e, "PATH_INFO", r->path_info);
        }
    }
    else if (!r->path_info || !*r->path_info) {
        apr_table_setn(e, "SCRIPT_NAME", r->uri);
    }
    else {
        int path_info_start = ap_find_path_info(r->uri, r->path_info);

        apr_table_setn(e, "SCRIPT_NAME",
                      apr_pstrndup(r->pool, r->uri, path_info_start));

        apr_table_setn(e, "PATH_INFO", r->path_info);
    }

    if (r->path_info && r->path_info[0]) {
        /*
         * To get PATH_TRANSLATED, treat PATH_INFO as a URI path.
         * Need to re-escape it for this, since the entire URI was
         * un-escaped before we determined where the PATH_INFO began.
         */
        request_rec *pa_req;

        pa_req = ap_sub_req_lookup_uri(ap_escape_uri(r->pool, r->path_info), r,
                                       NULL);

        if (pa_req->filename) {
            char *pt = apr_pstrcat(r->pool, pa_req->filename, pa_req->path_info,
                                  NULL);
#ifdef WIN32
            /* We need to make this a real Windows path name */
            apr_filepath_merge(&pt, "", pt, APR_FILEPATH_NATIVE, r->pool);
#endif
            apr_table_setn(e, "PATH_TRANSLATED", pt);
        }
        ap_destroy_sub_req(pa_req);
    }
}


static int set_cookie_doo_doo(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

#define HTTP_UNSET (-HTTP_OK)

AP_DECLARE(int) ap_scan_script_header_err_core(request_rec *r, char *buffer,
                                       int (*getsfunc) (char *, int, void *),
                                       void *getsfunc_data)
{
    char x[MAX_STRING_LEN];
    char *w, *l;
    int p;
    int cgi_status = HTTP_UNSET;
    apr_table_t *merge;
    apr_table_t *cookie_table;

    if (buffer) {
        *buffer = '\0';
    }
    w = buffer ? buffer : x;

    /* temporary place to hold headers to merge in later */
    merge = apr_table_make(r->pool, 10);

    /* The HTTP specification says that it is legal to merge duplicate
     * headers into one.  Some browsers that support Cookies don't like
     * merged headers and prefer that each Set-Cookie header is sent
     * separately.  Lets humour those browsers by not merging.
     * Oh what a pain it is.
     */
    cookie_table = apr_table_make(r->pool, 2);
    apr_table_do(set_cookie_doo_doo, cookie_table, r->err_headers_out, "Set-Cookie", NULL);

    while (1) {

        if ((*getsfunc) (w, MAX_STRING_LEN - 1, getsfunc_data) == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_TOCLIENT, 0, r,
                          "Premature end of script headers: %s",
                          apr_filepath_name_get(r->filename));
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Delete terminal (CR?)LF */

        p = strlen(w);
             /* Indeed, the host's '\n':
                '\012' for UNIX; '\015' for MacOS; '\025' for OS/390
                 -- whatever the script generates.
             */
        if (p > 0 && w[p - 1] == '\n') {
            if (p > 1 && w[p - 2] == CR) {
                w[p - 2] = '\0';
            }
            else {
                w[p - 1] = '\0';
            }
        }

        /*
         * If we've finished reading the headers, check to make sure any
         * HTTP/1.1 conditions are met.  If so, we're done; normal processing
         * will handle the script's output.  If not, just return the error.
         * The appropriate thing to do would be to send the script process a
         * SIGPIPE to let it know we're ignoring it, close the channel to the
         * script process, and *then* return the failed-to-meet-condition
         * error.  Otherwise we'd be waiting for the script to finish
         * blithering before telling the client the output was no good.
         * However, we don't have the information to do that, so we have to
         * leave it to an upper layer.
         */
        if (w[0] == '\0') {
            int cond_status = OK;

           /* PR#38070: This fails because it gets confused when a
            * CGI Status header overrides ap_meets_conditions.
            * 
            * We can fix that by dropping ap_meets_conditions when
            * Status has been set.  Since this is the only place
            * cgi_status gets used, let's test it explicitly.
            *
            * The alternative would be to ignore CGI Status when
            * ap_meets_conditions returns anything interesting.
            * That would be safer wrt HTTP, but would break CGI.
            */
            if ((cgi_status == HTTP_UNSET) && (r->method_number == M_GET)) {
                cond_status = ap_meets_conditions(r);
            }
            apr_table_overlap(r->err_headers_out, merge,
                APR_OVERLAP_TABLES_MERGE);
            if (!apr_is_empty_table(cookie_table)) {
                /* the cookies have already been copied to the cookie_table */
                apr_table_unset(r->err_headers_out, "Set-Cookie");
                r->err_headers_out = apr_table_overlay(r->pool,
                    r->err_headers_out, cookie_table);
            }
            return cond_status;
        }

        /* if we see a bogus header don't ignore it. Shout and scream */

#if APR_CHARSET_EBCDIC
            /* Chances are that we received an ASCII header text instead of
             * the expected EBCDIC header lines. Try to auto-detect:
             */
        if (!(l = strchr(w, ':'))) {
            int maybeASCII = 0, maybeEBCDIC = 0;
            unsigned char *cp, native;
            apr_size_t inbytes_left, outbytes_left;

            for (cp = w; *cp != '\0'; ++cp) {
                native = apr_xlate_conv_byte(ap_hdrs_from_ascii, *cp);
                if (apr_isprint(*cp) && !apr_isprint(native))
                    ++maybeEBCDIC;
                if (!apr_isprint(*cp) && apr_isprint(native))
                    ++maybeASCII;
            }
            if (maybeASCII > maybeEBCDIC) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "CGI Interface Error: Script headers apparently ASCII: (CGI = %s)",
                             r->filename);
                inbytes_left = outbytes_left = cp - w;
                apr_xlate_conv_buffer(ap_hdrs_from_ascii,
                                      w, &inbytes_left, w, &outbytes_left);
            }
        }
#endif /*APR_CHARSET_EBCDIC*/
        if (!(l = strchr(w, ':'))) {
            char malformed[(sizeof MALFORMED_MESSAGE) + 1
                           + MALFORMED_HEADER_LENGTH_TO_SHOW];

            strcpy(malformed, MALFORMED_MESSAGE);
            strncat(malformed, w, MALFORMED_HEADER_LENGTH_TO_SHOW);

            if (!buffer) {
                /* Soak up all the script output - may save an outright kill */
                while ((*getsfunc) (w, MAX_STRING_LEN - 1, getsfunc_data)) {
                    continue;
                }
            }

            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_TOCLIENT, 0, r,
                          "%s: %s", malformed,
                          apr_filepath_name_get(r->filename));
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        *l++ = '\0';
        while (*l && apr_isspace(*l)) {
            ++l;
        }

        if (!strcasecmp(w, "Content-type")) {
            char *tmp;

            /* Nuke trailing whitespace */

            char *endp = l + strlen(l) - 1;
            while (endp > l && apr_isspace(*endp)) {
                *endp-- = '\0';
            }

            tmp = apr_pstrdup(r->pool, l);
            ap_content_type_tolower(tmp);
            ap_set_content_type(r, tmp);
        }
        /*
         * If the script returned a specific status, that's what
         * we'll use - otherwise we assume 200 OK.
         */
        else if (!strcasecmp(w, "Status")) {
            r->status = cgi_status = atoi(l);
            r->status_line = apr_pstrdup(r->pool, l);
        }
        else if (!strcasecmp(w, "Location")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Content-Length")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Content-Range")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Transfer-Encoding")) {
            apr_table_set(r->headers_out, w, l);
        }
        /*
         * If the script gave us a Last-Modified header, we can't just
         * pass it on blindly because of restrictions on future values.
         */
        else if (!strcasecmp(w, "Last-Modified")) {
            ap_update_mtime(r, apr_date_parse_http(l));
            ap_set_last_modified(r);
        }
        else if (!strcasecmp(w, "Set-Cookie")) {
            apr_table_add(cookie_table, w, l);
        }
        else {
            apr_table_add(merge, w, l);
        }
    }

    return OK;
}

static int getsfunc_FILE(char *buf, int len, void *f)
{
    return apr_file_gets(buf, len, (apr_file_t *) f) == APR_SUCCESS;
}

AP_DECLARE(int) ap_scan_script_header_err(request_rec *r, apr_file_t *f,
                                          char *buffer)
{
    return ap_scan_script_header_err_core(r, buffer, getsfunc_FILE, f);
}

static int getsfunc_BRIGADE(char *buf, int len, void *arg)
{
    apr_bucket_brigade *bb = (apr_bucket_brigade *)arg;
    const char *dst_end = buf + len - 1; /* leave room for terminating null */
    char *dst = buf;
    apr_bucket *e = APR_BRIGADE_FIRST(bb);
    apr_status_t rv;
    int done = 0;

    while ((dst < dst_end) && !done && !APR_BUCKET_IS_EOS(e)) {
        const char *bucket_data;
        apr_size_t bucket_data_len;
        const char *src;
        const char *src_end;
        apr_bucket * next;

        rv = apr_bucket_read(e, &bucket_data, &bucket_data_len,
                             APR_BLOCK_READ);
        if (rv != APR_SUCCESS || (bucket_data_len == 0)) {
            return 0;
        }
        src = bucket_data;
        src_end = bucket_data + bucket_data_len;
        while ((src < src_end) && (dst < dst_end) && !done) {
            if (*src == '\n') {
                done = 1;
            }
            else if (*src != '\r') {
                *dst++ = *src;
            }
            src++;
        }

        if (src < src_end) {
            apr_bucket_split(e, src - bucket_data);
        }
        next = APR_BUCKET_NEXT(e);
        APR_BUCKET_REMOVE(e);
        apr_bucket_destroy(e);
        e = next;
    }
    *dst = 0;
    return 1;
}

AP_DECLARE(int) ap_scan_script_header_err_brigade(request_rec *r,
                                                  apr_bucket_brigade *bb,
                                                  char *buffer)
{
    return ap_scan_script_header_err_core(r, buffer, getsfunc_BRIGADE, bb);
}

struct vastrs {
    va_list args;
    int arg;
    const char *curpos;
};

static int getsfunc_STRING(char *w, int len, void *pvastrs)
{
    struct vastrs *strs = (struct vastrs*) pvastrs;
    const char *p;
    int t;

    if (!strs->curpos || !*strs->curpos)
        return 0;
    p = ap_strchr_c(strs->curpos, '\n');
    if (p)
        ++p;
    else
        p = ap_strchr_c(strs->curpos, '\0');
    t = p - strs->curpos;
    if (t > len)
        t = len;
    strncpy (w, strs->curpos, t);
    w[t] = '\0';
    if (!strs->curpos[t]) {
        ++strs->arg;
        strs->curpos = va_arg(strs->args, const char *);
    }
    else
        strs->curpos += t;
    return t;
}

/* ap_scan_script_header_err_strs() accepts additional const char* args...
 * each is treated as one or more header lines, and the first non-header
 * character is returned to **arg, **data.  (The first optional arg is
 * counted as 0.)
 */
AP_DECLARE_NONSTD(int) ap_scan_script_header_err_strs(request_rec *r,
                                                      char *buffer,
                                                      const char **termch,
                                                      int *termarg, ...)
{
    struct vastrs strs;
    int res;

    va_start(strs.args, termarg);
    strs.arg = 0;
    strs.curpos = va_arg(strs.args, char*);
    res = ap_scan_script_header_err_core(r, buffer, getsfunc_STRING, (void *) &strs);
    if (termch)
        *termch = strs.curpos;
    if (termarg)
        *termarg = strs.arg;
    va_end(strs.args);
    return res;
}
