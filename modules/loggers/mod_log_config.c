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
 * Modified by djm@va.pubnix.com:
 * If no TransferLog is given explicitly, decline to log.
 *
 * This is module implements the TransferLog directive (same as the
 * common log module), and additional directives, LogFormat and CustomLog.
 *
 *
 * Syntax:
 *
 *    TransferLog fn      Logs transfers to fn in standard log format, unless
 *                        a custom format is set with LogFormat
 *    LogFormat format    Set a log format from TransferLog files
 *    CustomLog fn format
 *                        Log to file fn with format given by the format
 *                        argument
 *
 * There can be any number of TransferLog and CustomLog
 * commands. Each request will be logged to _ALL_ the
 * named files, in the appropriate format.
 *
 * If no TransferLog or CustomLog directive appears in a VirtualHost,
 * the request will be logged to the log file(s) defined outside
 * the virtual host section. If a TransferLog or CustomLog directive
 * appears in the VirtualHost section, the log files defined outside
 * the VirtualHost will _not_ be used. This makes this module compatible
 * with the CLF and config log modules, where the use of TransferLog
 * inside the VirtualHost section overrides its use outside.
 *
 * Examples:
 *
 *    TransferLog    logs/access_log
 *    <VirtualHost>
 *    LogFormat      "... custom format ..."
 *    TransferLog    log/virtual_only
 *    CustomLog      log/virtual_useragents "%t %{user-agent}i"
 *    </VirtualHost>
 *
 * This will log using CLF to access_log any requests handled by the
 * main server, while any requests to the virtual host will be logged
 * with the "... custom format..." to virtual_only _AND_ using
 * the custom user-agent log to virtual_useragents.
 *
 * Note that the NCSA referer and user-agent logs are easily added with
 * CustomLog:
 *   CustomLog   logs/referer  "%{referer}i -> %U"
 *   CustomLog   logs/agent    "%{user-agent}i"
 *
 * RefererIgnore functionality can be obtained with conditional
 * logging (SetEnvIf and CustomLog ... env=!VAR).
 *
 * But using this method allows much easier modification of the
 * log format, e.g. to log hosts along with UA:
 *   CustomLog   logs/referer "%{referer}i %U %h"
 *
 * The argument to LogFormat and CustomLog is a string, which can include
 * literal characters copied into the log files, and '%' directives as
 * follows:
 *
 * %...B:  bytes sent, excluding HTTP headers.
 * %...b:  bytes sent, excluding HTTP headers in CLF format, i.e. a '-'
 *         when no bytes where sent (rather than a '0'.
 * %...{FOOBAR}C:  The contents of the HTTP cookie FOOBAR
 * %...{FOOBAR}e:  The contents of the environment variable FOOBAR
 * %...f:  filename
 * %...h:  remote host
 * %...a:  remote IP-address
 * %...A:  local IP-address
 * %...{Foobar}i:  The contents of Foobar: header line(s) in the request
 *                 sent to the client.
 * %...k:  number of keepalive requests served over this connection
 * %...l:  remote logname (from identd, if supplied)
 * %...{Foobar}n:  The contents of note "Foobar" from another module.
 * %...{Foobar}o:  The contents of Foobar: header line(s) in the reply.
 * %...p:  the canonical port for the server
 * %...{format}p: the canonical port for the server, or the actual local
 *                or remote port
 * %...P:  the process ID of the child that serviced the request.
 * %...{format}P: the process ID or thread ID of the child/thread that
 *                serviced the request
 * %...r:  first line of request
 * %...s:  status.  For requests that got internally redirected, this
 *         is status of the *original* request --- %...>s for the last.
 * %...t:  time, in common log format time format
 * %...{format}t:  The time, in the form given by format, which should
 *                 be in strftime(3) format.
 * %...T:  the time taken to serve the request, in seconds.
 * %...{s}T:  the time taken to serve the request, in seconds, same as %T.
 * %...{us}T:  the time taken to serve the request, in micro seconds, same as %D.
 * %...{ms}T:  the time taken to serve the request, in milliseconds.
 * %...D:  the time taken to serve the request, in micro seconds.
 * %...u:  remote user (from auth; may be bogus if return status (%s) is 401)
 * %...U:  the URL path requested.
 * %...v:  the configured name of the server (i.e. which virtual host?)
 * %...V:  the server name according to the UseCanonicalName setting
 * %...m:  the request method
 * %...H:  the request protocol
 * %...q:  the query string prepended by "?", or empty if no query string
 * %...X:  Status of the connection.
 *         'X' = connection aborted before the response completed.
 *         '+' = connection may be kept alive after the response is sent.
 *         '-' = connection will be closed after the response is sent.
 *         (This directive was %...c in late versions of Apache 1.3, but
 *          this conflicted with the historical ssl %...{var}c syntax.)
 * %...L:  Log-Id of the Request (or '-' if none)
 * %...{c}L:  Log-Id of the Connection (or '-' if none)
 *
 * The '...' can be nothing at all (e.g. "%h %u %r %s %b"), or it can
 * indicate conditions for inclusion of the item (which will cause it
 * to be replaced with '-' if the condition is not met).  Note that
 * there is no escaping performed on the strings from %r, %...i and
 * %...o; some with long memories may remember that I thought this was
 * a bad idea, once upon a time, and I'm still not comfortable with
 * it, but it is difficult to see how to "do the right thing" with all
 * of '%..i', unless we URL-escape everything and break with CLF.
 *
 * The forms of condition are a list of HTTP status codes, which may
 * or may not be preceded by '!'.  Thus, '%400,501{User-agent}i' logs
 * User-agent: on 400 errors and 501 errors (Bad Request, Not
 * Implemented) only; '%!200,304,302{Referer}i' logs Referer: on all
 * requests which did *not* return some sort of normal status.
 *
 * The default LogFormat reproduces CLF; see below.
 *
 * The way this is supposed to work with virtual hosts is as follows:
 * a virtual host can have its own LogFormat, or its own TransferLog.
 * If it doesn't have its own LogFormat, it inherits from the main
 * server.  If it doesn't have its own TransferLog, it writes to the
 * same descriptor (meaning the same process for "| ...").
 *
 * --- rst */

#include "apr_escape.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_optional.h"
#include "apr_anylock.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "mod_log_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"          /* For REMOTE_NAME */
#include "http_log.h"
#include "http_protocol.h"
#include "http_ssl.h"
#include "util_time.h"
#include "ap_mpm.h"
#include "ap_provider.h"
#include "apu_version.h"

#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 7)
#include "apr_json.h"
#endif

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#define DEFAULT_LOG_FORMAT "%h %l %u %t \"%r\" %>s %b"

module AP_MODULE_DECLARE_DATA log_config_module;


static int xfer_flags = (APR_WRITE | APR_APPEND | APR_CREATE | APR_LARGEFILE);
static apr_fileperms_t xfer_perms = APR_OS_DEFAULT;

static apr_hash_t *log_hash;  /* tag to log_struct */
static apr_hash_t *llog_hash; /* tag to long name */

static apr_status_t ap_default_log_writer(request_rec *r,
                           void *handle,
                           const char **strs,
                           int *strl,
                           int nelts,
                           apr_size_t len);
static apr_status_t ap_buffered_log_writer(request_rec *r,
                           void *handle,
                           const char **strs,
                           int *strl,
                           int nelts,
                           apr_size_t len);

static ap_log_formatted_data * ap_json_log_formatter(request_rec *r,
                           const void *handle,
                           ap_log_formatted_data *lfd,
                           const void *items);
typedef struct {
    int use_short_attribute_names;
    int omit_null_values;
} json_log_formatter_options;

static void *ap_default_log_writer_init(apr_pool_t *p, server_rec *s,
                                        const char* name);
static void *ap_buffered_log_writer_init(apr_pool_t *p, server_rec *s,
                                        const char* name);

static ap_log_writer_init *ap_log_set_writer_init(ap_log_writer_init *handle);
static ap_log_writer *ap_log_set_writer(ap_log_writer *handle);

static ap_log_writer *log_writer = ap_default_log_writer;
static ap_log_writer_init *log_writer_init = ap_default_log_writer_init;

static int buffered_logs = 0; /* default unbuffered */
static apr_array_header_t *all_buffered_logs = NULL;

/* POSIX.1 defines PIPE_BUF as the maximum number of bytes that is
 * guaranteed to be atomic when writing a pipe.  And PIPE_BUF >= 512
 * is guaranteed.  So we'll just guess 512 in the event the system
 * doesn't have this.  Now, for file writes there is actually no limit,
 * the entire write is atomic.  Whether all systems implement this
 * correctly is another question entirely ... so we'll just use PIPE_BUF
 * because it's probably a good guess as to what is implemented correctly
 * everywhere.
 */
#ifdef PIPE_BUF
#define LOG_BUFSIZE     PIPE_BUF
#else
#define LOG_BUFSIZE     (512)
#endif

/*
 * multi_log_state is our per-(virtual)-server configuration. We store
 * an array of the logs we are going to use, each of type config_log_state.
 * If a default log format is given by LogFormat, store in default_format
 * (backward compat. with mod_log_config).  We also store for each virtual
 * server a pointer to the logs specified for the main server, so that if this
 * vhost has no logs defined, we can use the main server's logs instead.
 *
 * So, for the main server, config_logs contains a list of the log files
 * and server_config_logs is empty. For a vhost, server_config_logs
 * points to the same array as config_logs in the main server, and
 * config_logs points to the array of logs defined inside this vhost,
 * which might be empty.
 */

typedef struct {
    const char *default_format_string;
    apr_array_header_t *default_format;
    apr_array_header_t *config_logs;
    apr_array_header_t *server_config_logs;
    apr_table_t *formats;
} multi_log_state;

/*
 * config_log_state holds the status of a single log file. fname might
 * be NULL, which means this module does no logging for this
 * request. format might be NULL, in which case the default_format
 * from the multi_log_state should be used, or if that is NULL as
 * well, use the CLF.
 * log_writer is NULL before the log file is opened and is
 * set to a opaque structure (usually a fd) after it is opened.

 */
typedef struct {
    apr_file_t *handle;
    apr_size_t outcnt;
    char outbuf[LOG_BUFSIZE];
    apr_anylock_t mutex;
} buffered_log;

typedef struct {
    const char *fname;
    const char *format_string;
    apr_array_header_t *format;
    void *log_writer_data;
    ap_log_formatter *log_formatter;
    void *log_formatter_data;
    char *condition_var;
    int inherit;
    ap_expr_info_t *condition_expr;
    /** place of definition or NULL if already checked */
    const ap_directive_t *directive;
} config_log_state;

/*
 * log_request_state holds request specific log data that is not
 * part of the request_rec.
 */
typedef struct {
    apr_time_t request_end_time;
} log_request_state;

/*
 * Format items...
 * Note that many of these could have ap_sprintfs replaced with static buffers.
 */

typedef struct {
    const char *tag; /* tag that did create this lfi */
    ap_log_handler *log_handler;
    const char *arg;
    int condition_sense;
    int want_orig;
    apr_array_header_t *conditions;
} log_format_item;

/*
 * errorlog_provider_data holds pointer to provider and its handle
 * generated by provider initialization. It is used when logging using
 * ap_errorlog_provider.
 */
typedef struct {
    struct ap_errorlog_provider *provider;
    void *handle;
} errorlog_provider_data;

/*
 * Type of the log_writer created by ap_default_log_writer_init.
 * It is used by ap_default_log_writer to determine the type of
 * the log_writer.
 */
enum default_log_writer_type {
    LOG_WRITER_FD,
    LOG_WRITER_PROVIDER
};

/*
 * Abstract struct to allow multiple types of log writers to be created
 * by ap_default_log_writer_init function.
 */
typedef struct {
    enum default_log_writer_type type;
    void *log_writer;
} default_log_writer;

static char *pfmt(apr_pool_t *p, int i)
{
    if (i <= 0) {
        return NULL;
    }
    else {
        return apr_itoa(p, i);
    }
}

static const char *constant_item(request_rec *dummy, char *stuff)
{
    return stuff;
}

static const char *log_remote_host(request_rec *r, char *a)
{
    const char *remote_host;
    if (a && !strcmp(a, "c")) {
        remote_host = ap_get_remote_host(r->connection, r->per_dir_config,
                                         REMOTE_NAME, NULL);
    }
    else {
        remote_host = ap_get_useragent_host(r, REMOTE_NAME, NULL);
    }
    return remote_host;
}

static const char *log_remote_address(request_rec *r, char *a)
{
    if (a && !strcmp(a, "c")) {
        return r->connection->client_ip;
    }
    else {
        return r->useragent_ip;
    }
}

static const char *log_local_address(request_rec *r, char *a)
{
    return r->connection->local_ip;
}

static const char *log_remote_logname(request_rec *r, char *a)
{
    return ap_get_remote_logname(r);
}

static const char *log_remote_user(request_rec *r, char *a)
{
    char *rvalue = r->user;
    return rvalue;
}

static const char *log_request_line(request_rec *r, char *a)
{
    /* NOTE: If the original request contained a password, we
     * re-write the request line here to contain XXXXXX instead:
     * (note the truncation before the protocol string for HTTP/0.9 requests)
     * (note also that r->the_request contains the unmodified request)
     */
    return (r->parsed_uri.password) ? apr_pstrcat(r->pool, r->method, " ",
                                                  apr_uri_unparse(r->pool, &r->parsed_uri, 0),
                                                  r->assbackwards ? NULL : " ",
                                                  r->protocol, NULL)
                                    : r->the_request;
}

static const char *log_request_file(request_rec *r, char *a)
{
    return r->filename;
}
static const char *log_request_uri(request_rec *r, char *a)
{
    return r->uri;
}
static const char *log_request_method(request_rec *r, char *a)
{
    return r->method;
}
static const char *log_request_flushed(request_rec *r, char *a)
{
    return (r->flushed) ? "F" : NULL;
}
static const char *log_log_id(request_rec *r, char *a)
{
    if (a && !strcmp(a, "c")) {
        return r->connection->log_id;
    }
    else {
        return r->log_id;
    }
}
static const char *log_request_protocol(request_rec *r, char *a)
{
    return r->protocol;
}
static const char *log_request_query(request_rec *r, char *a)
{
    return (r->args) ? apr_pstrcat(r->pool, "?", r->args, NULL)
                     : "";
}
static const char *log_status(request_rec *r, char *a)
{
    return pfmt(r->pool, r->status);
}

static const char *log_handler(request_rec *r, char *a)
{
    return r->handler;
}

static const char *clf_log_bytes_sent(request_rec *r, char *a)
{
    if (!r->sent_bodyct || !r->bytes_sent) {
        return NULL;
    }
    else {
        return apr_off_t_toa(r->pool, r->bytes_sent);
    }
}

static const char *log_bytes_sent(request_rec *r, char *a)
{
    if (!r->sent_bodyct || !r->bytes_sent) {
        return "0";
    }
    else {
        return apr_off_t_toa(r->pool, r->bytes_sent);
    }
}


static const char *log_header_in(request_rec *r, char *a)
{
    return apr_table_get(r->headers_in, a);
}

static const char *log_trailer_in(request_rec *r, char *a)
{
    return apr_table_get(r->trailers_in, a);
}


static APR_INLINE char *find_multiple_headers(apr_pool_t *pool,
                                              const apr_table_t *table,
                                              const char *key)
{
    const apr_array_header_t *elts;
    const apr_table_entry_t *t_elt;
    const apr_table_entry_t *t_end;
    apr_size_t len;
    struct sle {
        struct sle *next;
        const char *value;
        apr_size_t len;
    } *result_list, *rp;

    elts = apr_table_elts(table);

    if (!elts->nelts) {
        return NULL;
    }

    t_elt = (const apr_table_entry_t *)elts->elts;
    t_end = t_elt + elts->nelts;
    len = 1; /* \0 */
    result_list = rp = NULL;

    do {
        if (!ap_cstr_casecmp(t_elt->key, key)) {
            if (!result_list) {
                result_list = rp = apr_palloc(pool, sizeof(*rp));
            }
            else {
                rp = rp->next = apr_palloc(pool, sizeof(*rp));
                len += 2; /* ", " */
            }

            rp->next = NULL;
            rp->value = t_elt->val;
            rp->len = strlen(rp->value);

            len += rp->len;
        }
        ++t_elt;
    } while (t_elt < t_end);

    if (result_list) {
        char *result = apr_palloc(pool, len);
        char *cp = result;

        rp = result_list;
        while (rp) {
            if (rp != result_list) {
                *cp++ = ',';
                *cp++ = ' ';
            }
            memcpy(cp, rp->value, rp->len);
            cp += rp->len;
            rp = rp->next;
        }
        *cp = '\0';

        return result;
    }

    return NULL;
}

static const char *log_header_out(request_rec *r, char *a)
{
    const char *cp = NULL;

    if (!ap_cstr_casecmp(a, "Content-type") && r->content_type) {
        cp = ap_field_noparam(r->pool, r->content_type);
    }
    else if (!ap_cstr_casecmp(a, "Set-Cookie")) {
        cp = find_multiple_headers(r->pool, r->headers_out, a);
    }
    else {
        cp = apr_table_get(r->headers_out, a);
    }

    return cp;
}

static const char *log_trailer_out(request_rec *r, char *a)
{
    return apr_table_get(r->trailers_out, a);
}

static const char *log_note(request_rec *r, char *a)
{
    return apr_table_get(r->notes, a);
}
static const char *log_env_var(request_rec *r, char *a)
{
    return apr_table_get(r->subprocess_env, a);
}

static const char *log_cookie(request_rec *r, char *a)
{
    const char *cookies_entry;

    /*
     * This supports Netscape version 0 cookies while being tolerant to
     * some properties of RFC2109/2965 version 1 cookies:
     * - case-insensitive match of cookie names
     * - white space between the tokens
     * It does not support the following version 1 features:
     * - quoted strings as cookie values
     * - commas to separate cookies
     */

    if ((cookies_entry = apr_table_get(r->headers_in, "Cookie"))) {
        char *cookie, *last1, *last2;
        char *cookies = apr_pstrdup(r->pool, cookies_entry);

        while ((cookie = apr_strtok(cookies, ";", &last1))) {
            char *name = apr_strtok(cookie, "=", &last2);
            /* last2 points to the next char following an '=' delim,
               or the trailing NUL char of the string */
            char *value = last2;
            if (name && *name &&  value && *value) {
                char *last = value - 2;
                /* Move past leading WS */
                name += strspn(name, " \t");
                while (last >= name && apr_isspace(*last)) {
                    *last = '\0';
                    --last;
                }

                if (!ap_cstr_casecmp(name, a)) {
                    /* last1 points to the next char following the ';' delim,
                       or the trailing NUL char of the string */
                    last = last1 - (*last1 ? 2 : 1);
                    /* Move past leading WS */
                    value += strspn(value, " \t");
                    while (last >= value && apr_isspace(*last)) {
                       *last = '\0';
                       --last;
                    }

                    return value;
                }
            }
            /* Iterate the remaining tokens using apr_strtok(NULL, ...) */
            cookies = NULL;
        }
    }
    return NULL;
}

static const char *log_request_time_custom(request_rec *r, char *a,
                                           apr_time_exp_t *xt)
{
    apr_size_t retcode;
    char tstr[MAX_STRING_LEN];
    apr_strftime(tstr, &retcode, sizeof(tstr), a, xt);
    return apr_pstrdup(r->pool, tstr);
}

#define DEFAULT_REQUEST_TIME_SIZE 32
typedef struct {
    unsigned t;
    char timestr[DEFAULT_REQUEST_TIME_SIZE];
    unsigned t_validate;
} cached_request_time;

#define TIME_FMT_CUSTOM          0
#define TIME_FMT_CLF             1
#define TIME_FMT_ABS_SEC         2
#define TIME_FMT_ABS_MSEC        3
#define TIME_FMT_ABS_USEC        4
#define TIME_FMT_ABS_MSEC_FRAC   5
#define TIME_FMT_ABS_USEC_FRAC   6

#define TIME_CACHE_SIZE 4
#define TIME_CACHE_MASK 3
static cached_request_time request_time_cache[TIME_CACHE_SIZE];

static apr_time_t get_request_end_time(request_rec *r)
{
    log_request_state *state = (log_request_state *)ap_get_module_config(r->request_config,
                                                                         &log_config_module);
    if (!state) {
        state = apr_pcalloc(r->pool, sizeof(log_request_state));
        ap_set_module_config(r->request_config, &log_config_module, state);
    }
    if (state->request_end_time == 0) {
        state->request_end_time = apr_time_now();
    }
    return state->request_end_time;
}


static const char *log_request_time(request_rec *r, char *a)
{
    apr_time_exp_t xt;
    apr_time_t request_time = r->request_time;
    int fmt_type = TIME_FMT_CUSTOM;
    char *fmt = a;

    if (fmt && *fmt) {
        if (!strncmp(fmt, "begin", 5)) {
            fmt += 5;
            if (!*fmt) {
                fmt_type = TIME_FMT_CLF;
            }
            else if (*fmt == ':') {
                fmt++;
                a = fmt;
            }
        }
        else if (!strncmp(fmt, "end", 3)) {
            fmt += 3;
            if (!*fmt) {
                request_time = get_request_end_time(r);
                fmt_type = TIME_FMT_CLF;
            }
            else if (*fmt == ':') {
                fmt++;
                a = fmt;
                request_time = get_request_end_time(r);
            }
        }
        if (!strncmp(fmt, "msec", 4)) {
            fmt += 4;
            if (!*fmt) {
                fmt_type = TIME_FMT_ABS_MSEC;
            }
            else if (!strcmp(fmt, "_frac")) {
                fmt_type = TIME_FMT_ABS_MSEC_FRAC;
            }
        }
        else if (!strncmp(fmt, "usec", 4)) {
            fmt += 4;
            if (!*fmt) {
                fmt_type = TIME_FMT_ABS_USEC;
            }
            else if (!strcmp(fmt, "_frac")) {
                fmt_type = TIME_FMT_ABS_USEC_FRAC;
            }
        }
        else if (!strcmp(fmt, "sec")) {
            fmt_type = TIME_FMT_ABS_SEC;
        }
        else if (!*fmt) {
            fmt_type = TIME_FMT_CLF;
        }
    }
    else {
        fmt_type = TIME_FMT_CLF;
    }

    if (fmt_type >= TIME_FMT_ABS_SEC) {      /* Absolute (micro-/milli-)second time
                                              * or msec/usec fraction
                                              */
        char* buf = apr_palloc(r->pool, 20);
        switch (fmt_type) {
        case TIME_FMT_ABS_SEC:
            apr_snprintf(buf, 20, "%" APR_TIME_T_FMT, apr_time_sec(request_time));
            break;
        case TIME_FMT_ABS_MSEC:
            apr_snprintf(buf, 20, "%" APR_TIME_T_FMT, apr_time_as_msec(request_time));
            break;
        case TIME_FMT_ABS_USEC:
            apr_snprintf(buf, 20, "%" APR_TIME_T_FMT, request_time);
            break;
        case TIME_FMT_ABS_MSEC_FRAC:
            apr_snprintf(buf, 20, "%03" APR_TIME_T_FMT, apr_time_msec(request_time));
            break;
        case TIME_FMT_ABS_USEC_FRAC:
            apr_snprintf(buf, 20, "%06" APR_TIME_T_FMT, apr_time_usec(request_time));
            break;
        default:
            return NULL;
        }
        return buf;
    }
    else if (fmt_type == TIME_FMT_CUSTOM) {  /* Custom format */
        /* The custom time formatting uses a very large temp buffer
         * on the stack.  To avoid using so much stack space in the
         * common case where we're not using a custom format, the code
         * for the custom format in a separate function.  (That's why
         * log_request_time_custom is not inlined right here.)
         */
        ap_explode_recent_localtime(&xt, request_time);
        return log_request_time_custom(r, a, &xt);
    }
    else {                                   /* CLF format */
        /* This code uses the same technique as ap_explode_recent_localtime():
         * optimistic caching with logic to detect and correct race conditions.
         * See the comments in server/util_time.c for more information.
         */
        cached_request_time* cached_time = apr_palloc(r->pool,
                                                      sizeof(*cached_time));
        unsigned t_seconds = (unsigned)apr_time_sec(request_time);
        unsigned i = t_seconds & TIME_CACHE_MASK;
        *cached_time = request_time_cache[i];
        if ((t_seconds != cached_time->t) ||
            (t_seconds != cached_time->t_validate)) {

            /* Invalid or old snapshot, so compute the proper time string
             * and store it in the cache
             */
            char sign;
            int timz;

            ap_explode_recent_localtime(&xt, request_time);
            timz = xt.tm_gmtoff;
            if (timz < 0) {
                timz = -timz;
                sign = '-';
            }
            else {
                sign = '+';
            }
            cached_time->t = t_seconds;
            apr_snprintf(cached_time->timestr, DEFAULT_REQUEST_TIME_SIZE,
                         "[%02d/%s/%d:%02d:%02d:%02d %c%.2d%.2d]",
                         xt.tm_mday, apr_month_snames[xt.tm_mon],
                         xt.tm_year+1900, xt.tm_hour, xt.tm_min, xt.tm_sec,
                         sign, timz / (60*60), (timz % (60*60)) / 60);
            cached_time->t_validate = t_seconds;
            request_time_cache[i] = *cached_time;
        }
        return cached_time->timestr;
    }
}

static const char *log_request_duration_microseconds(request_rec *r, char *a)
{
    return apr_psprintf(r->pool, "%" APR_TIME_T_FMT,
                        (get_request_end_time(r) - r->request_time));
}

static const char *log_request_duration_scaled(request_rec *r, char *a)
{
    apr_time_t duration = get_request_end_time(r) - r->request_time;
    if (*a == '\0' || !strcasecmp(a, "s")) {
        duration = apr_time_sec(duration);
    }
    else if (!strcasecmp(a, "ms")) {
        duration = apr_time_as_msec(duration);
    }
    else if (!strcasecmp(a, "us")) {
    }
    else {
        /* bogus format */
        return a;
    }
    return apr_psprintf(r->pool, "%" APR_TIME_T_FMT, duration);
}

/* These next two routines use the canonical name:port so that log
 * parsers don't need to duplicate all the vhost parsing crud.
 */
static const char *log_virtual_host(request_rec *r, char *a)
{
    return r->server->server_hostname;
}

static const char *log_server_port(request_rec *r, char *a)
{
    apr_port_t port;

    if (*a == '\0' || !strcasecmp(a, "canonical")) {
        port = r->server->port ? r->server->port : ap_default_port(r);
    }
    else if (!strcasecmp(a, "remote")) {
        port = r->useragent_addr->port;
    }
    else if (!strcasecmp(a, "local")) {
        port = r->connection->local_addr->port;
    }
    else {
        /* bogus format */
        return a;
    }
    return apr_itoa(r->pool, (int)port);
}

/* This respects the setting of UseCanonicalName so that
 * the dynamic mass virtual hosting trick works better.
 */
static const char *log_server_name(request_rec *r, char *a)
{
    return ap_get_server_name(r);
}

static const char *log_pid_tid(request_rec *r, char *a)
{
    if (*a == '\0' || !strcasecmp(a, "pid")) {
        return ap_append_pid(r->pool, "", "");
    }
    else if (!strcasecmp(a, "tid") || !strcasecmp(a, "hextid")) {
#if APR_HAS_THREADS
        apr_os_thread_t tid = apr_os_thread_current();
#else
        int tid = 0; /* APR will format "0" anyway but an arg is needed */
#endif
        return apr_psprintf(r->pool,
                            /* APR can format a thread id in hex */
                            *a == 'h' ? "%pt" : "%pT", &tid);
    }
    /* bogus format */
    return a;
}

static const char *log_connection_status(request_rec *r, char *a)
{
    if (r->connection->aborted)
        return "X";

    if (r->connection->keepalive == AP_CONN_KEEPALIVE &&
        (!r->server->keep_alive_max ||
         (r->server->keep_alive_max - r->connection->keepalives) > 0)) {
        return "+";
    }
    return NULL;
}

static const char *log_requests_on_connection(request_rec *r, char *a)
{
    int num = r->connection->keepalives ? r->connection->keepalives - 1 : 0;
    return apr_itoa(r->pool, num);
}

static const char *log_ssl_var(request_rec *r, char *a)
{
    const char *result;

    /* Any SSL module responsible for the connection/request will provide the value */
    result = ap_ssl_var_lookup(r->pool, r->server, r->connection, r, a);
    return (result && result[0])? result : NULL;
}

static const char *log_ssl_var_short(request_rec *r, char *a)
{
    /* Several shortcut names, previously defined and installed in mod_ssl
     * that lookup SSL variables. */
    if (!strcasecmp(a, "version"))
        return log_ssl_var(r, "SSL_PROTOCOL");
    else if (!strcasecmp(a, "cipher"))
        return log_ssl_var(r, "SSL_CIPHER");
    else if (!strcasecmp(a, "subjectdn") || !strcasecmp(a, "clientcert"))
        return log_ssl_var(r, "SSL_CLIENT_S_DN");
    else if (!strcasecmp(a, "issuerdn") || !strcasecmp(a, "cacert"))
        return log_ssl_var(r, "SSL_CLIENT_I_DN");
    else if (!strcasecmp(a, "errcode"))
        /* Copied from mod_ssl for backward compatibility. */
        return NULL;
    else if (!strcasecmp(a, "errstr"))
        return log_ssl_var(r, "SSL_CLIENT_VERIFY_ERRSTR");
    return NULL;
}

/*****************************************************************
 *
 * Parsing the log format string
 */

static char *parse_log_misc_string(apr_pool_t *p, log_format_item *it,
                                   const char **sa)
{
    const char *s;
    char *d;

    it->tag = NULL;
    it->log_handler = apr_palloc(p, sizeof(*it->log_handler));
    it->log_handler->func = constant_item;
    it->conditions = NULL;

    s = *sa;
    while (*s && *s != '%') {
        s++;
    }
    /*
     * This might allocate a few chars extra if there's a backslash
     * escape in the format string.
     */
    it->arg = d = apr_palloc(p, s - *sa + 1);

    s = *sa;
    while (*s && *s != '%') {
        if (*s != '\\') {
            *d++ = *s++;
        }
        else {
            s++;
            switch (*s) {
            case '\\':
                *d++ = '\\';
                s++;
                break;
            case 'r':
                *d++ = '\r';
                s++;
                break;
            case 'n':
                *d++ = '\n';
                s++;
                break;
            case 't':
                *d++ = '\t';
                s++;
                break;
            default:
                /* copy verbatim */
                *d++ = '\\';
                /*
                 * Allow the loop to deal with this *s in the normal
                 * fashion so that it handles end of string etc.
                 * properly.
                 */
                break;
            }
        }
    }
    *d = '\0';

    *sa = s;
    return NULL;
}

static char *parse_log_item(apr_pool_t *p, log_format_item *it, const char **sa)
{
    const char *s = *sa;
    ap_log_handler *handler = NULL;

    if (*s != '%') {
        return parse_log_misc_string(p, it, sa);
    }

    ++s;
    it->condition_sense = 0;
    it->conditions = NULL;

    if (*s == '%') {
        it->arg = "%";
        it->log_handler = apr_palloc(p, sizeof(*it->log_handler));
        it->log_handler->func = constant_item;
        *sa = ++s;

        return NULL;
    }

    it->want_orig = -1;
    it->arg = "";               /* For safety's sake... */
    it->tag = NULL;

    while (*s) {
        int i;

        switch (*s) {
        case '!':
            ++s;
            it->condition_sense = !it->condition_sense;
            break;

        case '<':
            ++s;
            it->want_orig = 1;
            break;

        case '>':
            ++s;
            it->want_orig = 0;
            break;

        case ',':
            ++s;
            break;

        case '{':
            ++s;
            it->arg = ap_getword(p, &s, '}');
            break;

        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            i = *s - '0';
            while (apr_isdigit(*++s)) {
                i = i * 10 + (*s) - '0';
            }
            if (!it->conditions) {
                it->conditions = apr_array_make(p, 4, sizeof(int));
            }
            *(int *) apr_array_push(it->conditions) = i;
            break;

        default:
            /* check for '^' + two character format first */
            if (*s == '^' && *(s+1) && *(s+2)) {
                handler = (ap_log_handler *)apr_hash_get(log_hash, s, 3);
                if (handler) {
                   it->tag = apr_pstrmemdup(p, s, 3);
                   s += 3;
                }
            }
            if (!handler) {
                handler = (ap_log_handler *)apr_hash_get(log_hash, s, 1);
                if (!handler) {
                    char dummy[2];

                    dummy[0] = s[0];
                    dummy[1] = '\0';
                    return apr_pstrcat(p, "Unrecognized LogFormat directive %",
                                   dummy, NULL);
                }
                it->tag = apr_pstrmemdup(p, s++, 1);
            }
            it->log_handler = handler;
            if (it->want_orig == -1) {
                it->want_orig = handler->want_orig_default;
            }
            *sa = s;
            return NULL;
        }
    }

    return "Ran off end of LogFormat parsing args to some directive";
}

static apr_array_header_t *parse_log_string(apr_pool_t *p, const char *s, const char **err)
{
    apr_array_header_t *a = apr_array_make(p, 30, sizeof(log_format_item));
    char *res;

    while (*s) {
        if ((res = parse_log_item(p, (log_format_item *) apr_array_push(a), &s))) {
            *err = res;
            return NULL;
        }
    }

    s = APR_EOL_STR;
    parse_log_item(p, (log_format_item *) apr_array_push(a), &s);
    return a;
}

/*****************************************************************
 *
 * Actually logging.
 */

static const char *process_item(request_rec *r, request_rec *orig,
                          log_format_item *item)
{
    const char *cp;

    /* First, see if we need to process this thing at all... */

    if (item->conditions && item->conditions->nelts != 0) {
        int i;
        int *conds = (int *) item->conditions->elts;
        int in_list = 0;

        for (i = 0; i < item->conditions->nelts; ++i) {
            if (r->status == conds[i]) {
                in_list = 1;
                break;
            }
        }

        if ((item->condition_sense && in_list)
            || (!item->condition_sense && !in_list)) {
            return NULL;
        }
    }

    /* We do.  Do it... */

    cp = (*item->log_handler->func) (item->want_orig ? orig : r, (char *)item->arg);
    return cp;
}

static void flush_log(buffered_log *buf)
{
    if (buf->outcnt && buf->handle != NULL) {
        /* XXX: error handling */
        apr_file_write_full(buf->handle, buf->outbuf, buf->outcnt, NULL);
        buf->outcnt = 0;
    }
}


static int config_log_transaction(request_rec *r, config_log_state *cls,
                                  apr_array_header_t *default_format)
{
    log_format_item *items;
    ap_log_formatted_data *lfd;
    request_rec *orig;
    int i;
    apr_array_header_t *format;
    char *envar;
    apr_status_t rv;

    if (cls->fname == NULL) {
        return DECLINED;
    }

    /*
     * See if we've got any conditional envariable-controlled logging decisions
     * to make.
     */
    if (cls->condition_var != NULL) {
        envar = cls->condition_var;
        if (*envar != '!') {
            if (apr_table_get(r->subprocess_env, envar) == NULL) {
                return DECLINED;
            }
        }
        else {
            if (apr_table_get(r->subprocess_env, &envar[1]) != NULL) {
                return DECLINED;
            }
        }
    }
    else if (cls->condition_expr != NULL) {
        const char *err;
        int rc = ap_expr_exec(r, cls->condition_expr, &err);
        if (rc < 0)
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(00644)
                           "Error evaluating log condition: %s", err);
        if (rc <= 0)
            return DECLINED;
    }

    format = cls->format ? cls->format : default_format;

    lfd = apr_palloc(r->pool, sizeof(ap_log_formatted_data));
    lfd->portions = apr_palloc(r->pool, sizeof(char *) * (format->nelts));
    lfd->lengths = apr_palloc(r->pool, sizeof(int) * (format->nelts));
    lfd->nelts = format->nelts;
    lfd->total_len = 0;
    items = (log_format_item *) format->elts;

    orig = r;
    while (orig->prev) {
        orig = orig->prev;
    }
    while (r->next) {
        r = r->next;
    }

    for (i = 0; i < format->nelts; ++i) {
        lfd->portions[i] = process_item(r, orig, &items[i]);

        /* if we don't have a custom log formatter,
         * handle NULL, and empty string also escape all values unconditionally,
         * else let the custom log formatter handle the escaping/formatting
         */
        if (!cls->log_formatter && !items[i].log_handler->does_escape) {
            if (!lfd->portions[i]) {
                lfd->portions[i] = "-";
            }
            else if (!*lfd->portions[i]) {
                lfd->portions[i] = "\"\"";
            }
            else {
                if(items[i].tag) { /* or check for constant_item function, don't escape those */
                    lfd->portions[i] = ap_escape_logitem(r->pool, lfd->portions[i]);
                }
            }
        }

        if(lfd->portions[i]) {
            lfd->total_len += lfd->lengths[i] = strlen(lfd->portions[i]);
        }
    }

    if (!log_writer) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00645)
                "log writer isn't correctly setup");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (cls->log_formatter) {
        lfd = cls->log_formatter(r, cls->log_formatter_data, lfd, items);
    }

    rv = log_writer(r, cls->log_writer_data, lfd->portions, lfd->lengths, lfd->nelts, lfd->total_len);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00646)
                      "Error writing to %s", cls->fname);
    }
    return OK;
}

static int multi_log_transaction(request_rec *r)
{
    multi_log_state *mls = ap_get_module_config(r->server->module_config,
                                                &log_config_module);
    config_log_state *clsarray;
    int i;

    /*
     * Initialize per request state
     */
    log_request_state *state = apr_pcalloc(r->pool, sizeof(log_request_state));
    ap_set_module_config(r->request_config, &log_config_module, state);

    /*
     * Log this transaction..
     */
    if (mls->config_logs->nelts) {
        clsarray = (config_log_state *) mls->config_logs->elts;
        for (i = 0; i < mls->config_logs->nelts; ++i) {
            config_log_state *cls = &clsarray[i];

            config_log_transaction(r, cls, mls->default_format);
        }
    }

    if (mls->server_config_logs) {
        clsarray = (config_log_state *) mls->server_config_logs->elts;
        for (i = 0; i < mls->server_config_logs->nelts; ++i) {
            config_log_state *cls = &clsarray[i];

            if (cls->inherit || !mls->config_logs->nelts) {
                config_log_transaction(r, cls, mls->default_format);
            }
        }
    }

    return OK;
}

/*****************************************************************
 *
 * Module glue...
 */

static void *make_config_log_state(apr_pool_t *p, server_rec *s)
{
    multi_log_state *mls;

    mls = (multi_log_state *) apr_palloc(p, sizeof(multi_log_state));
    mls->config_logs = apr_array_make(p, 1, sizeof(config_log_state));
    mls->default_format_string = NULL;
    mls->default_format = NULL;
    mls->server_config_logs = NULL;
    mls->formats = apr_table_make(p, 4);
    apr_table_setn(mls->formats, "CLF", DEFAULT_LOG_FORMAT);

    return mls;
}

/*
 * Use the merger to simply add a pointer from the vhost log state
 * to the log of logs specified for the non-vhost configuration.  Make sure
 * vhosts inherit any globally-defined format names.
 */

static void *merge_config_log_state(apr_pool_t *p, void *basev, void *addv)
{
    multi_log_state *base = (multi_log_state *) basev;
    multi_log_state *add = (multi_log_state *) addv;

    add->server_config_logs = base->config_logs;
    if (!add->default_format) {
        add->default_format_string = base->default_format_string;
        add->default_format = base->default_format;
    }
    add->formats = apr_table_overlay(p, base->formats, add->formats);

    return add;
}

/*
 * Set the default logfile format, or define a nickname for a format string.
 */
static const char *log_format(cmd_parms *cmd, void *dummy, const char *fmt,
                              const char *name)
{
    const char *err_string = NULL;
    multi_log_state *mls = ap_get_module_config(cmd->server->module_config,
                                                &log_config_module);

    /*
     * If we were given two arguments, the second is a name to be given to the
     * format.  This syntax just defines the nickname - it doesn't actually
     * make the format the default.
     */
    if (name != NULL) {
        parse_log_string(cmd->pool, fmt, &err_string);
        if (err_string == NULL) {
            apr_table_setn(mls->formats, name, fmt);
        }
    }
    else {
        mls->default_format_string = fmt;
        mls->default_format = parse_log_string(cmd->pool, fmt, &err_string);
    }
    return err_string;
}


static int compare_log_format_item_by_tag(const void *i1, const void *i2) {
    const log_format_item *lfi1 = i1;
    const log_format_item *lfi2 = i2;
    const char *t1 = lfi1->tag;
    const char* t2 = lfi2->tag;
    if(!t1) {
        t1 = "";
    }
    if(!t2) {
        t2 = "";
    }
    return strcmp(t1, t2);
}

static const char *add_custom_log(cmd_parms *cmd, void *dummy,
                                  int argc,
                                  char *const argv[])
{
    const char *err_string = NULL;
    multi_log_state *mls = ap_get_module_config(cmd->server->module_config,
                                                &log_config_module);
    config_log_state *cls;

    const char *fn;
    const char *fmt;

    const char* envclause = NULL;
    char* token;

    int i;

    cls = (config_log_state *) apr_array_push(mls->config_logs);
    cls->condition_var = NULL;
    cls->condition_expr = NULL;
    cls->log_writer_data = NULL;
    cls->log_formatter = NULL;
    cls->log_formatter_data = NULL;

    if (argc < 2) {
           return "wrong number of arguments";
    }

    fn = argv[0];
    fmt = argv[1];

    for (i = 2; i < argc; i++) {
        if (argv[i] == NULL)
            continue;

        envclause = argv[i];
        if (strncasecmp(argv[i], "env=", 4) == 0) {
            if ((envclause[4] == '\0')
                || ((envclause[4] == '!') && (envclause[5] == '\0'))) {
                return "missing environment variable name";
            }
            cls->condition_var = apr_pstrdup(cmd->pool, &envclause[4]);
        }
        else if (strncasecmp(argv[i], "expr=", 5) == 0) {
            const char *err;
            if ((envclause[5] == '\0'))
                return "missing condition";
            cls->condition_expr = ap_expr_parse_cmd(cmd, &envclause[5],
                                                    AP_EXPR_FLAG_DONT_VARY,
                                                    &err, NULL);
            if (err)
                return err;
        }
        else if (strncasecmp(argv[i], "formatter=", 10) == 0) {
            if (strncasecmp(argv[i], "formatter=json", 14) == 0) {
                cls->log_formatter = ap_json_log_formatter;
                cls->log_formatter_data = apr_pcalloc(cmd->pool, sizeof(json_log_formatter_options));
                ((json_log_formatter_options *)cls->log_formatter_data)->omit_null_values = 1;

                token = strtok(argv[i], ",");
                while (token != NULL) {
                    if(strcasecmp(token, "short") == 0) {
                        ((json_log_formatter_options *)cls->log_formatter_data)->use_short_attribute_names = 1;
                    }
                    token = strtok(NULL, ",");
                }
            }
        }
        else {
            return "error in condition clause";
        }
    }

    cls->fname = fn;
    cls->format_string = fmt;
    cls->directive = cmd->directive;
    if (fmt == NULL) {
        cls->format = NULL;
    }
    else {
        cls->format = parse_log_string(cmd->pool, fmt, &err_string);
        /* if fmt string was actually a nickname,
         * cls->format will not be NULL, but an array with one entry (APR_EOL_STR)
         * but cls->format_string will have the nickname
         * lookup will then happen in open_multi_logs()!
         * TODO: I assume the lookup cannot happen here for ordering reasons
         *       of the config processing?!
         * TODO: actually those kind of consistency checks should be done in
         *       "ap_hook_check_config(log_check_config" IMHO and not in open_multi_logs!
         */
    }

    return err_string;
}

static const char *add_global_log(cmd_parms *cmd, void *dummy,
                                  int argc,
                                  char *const argv[]) {
    multi_log_state *mls = ap_get_module_config(cmd->server->module_config,
                                                &log_config_module);
    config_log_state *clsarray;
    config_log_state *cls;
    const char *ret;

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err) {
        return err;
    }

    /* Add a custom log through the normal channel */
    ret = add_custom_log(cmd, dummy, argc, argv);

    /* Set the inherit flag unless there was some error */
    if (ret == NULL) {
        clsarray = (config_log_state*)mls->config_logs->elts;
        cls = &clsarray[mls->config_logs->nelts-1];
        cls->inherit = 1;
    }

    return ret;
}

static const char *set_transfer_log(cmd_parms *cmd, void *dummy,
                                    const char *fn)
{
    char *const argv[] = {(char *)fn, NULL, NULL};
    return add_custom_log(cmd, dummy, sizeof(argv)/sizeof(argv[0]), argv);
}

static const char *set_buffered_logs_on(cmd_parms *parms, void *dummy, int flag)
{
    buffered_logs = flag;
    if (buffered_logs) {
        ap_log_set_writer_init(ap_buffered_log_writer_init);
        ap_log_set_writer(ap_buffered_log_writer);
    }
    else {
        ap_log_set_writer_init(ap_default_log_writer_init);
        ap_log_set_writer(ap_default_log_writer);
    }
    return NULL;
}

static const command_rec config_log_cmds[] =
{
AP_INIT_TAKE_ARGV("CustomLog", add_custom_log, NULL, RSRC_CONF,
     "a file name, a custom log format string or format name, "
     "and an optional \"env=\" or \"expr=\" clause (see docs)"),
AP_INIT_TAKE_ARGV("GlobalLog", add_global_log, NULL, RSRC_CONF,
     "Same as CustomLog, but forces virtualhosts to inherit the log"),
AP_INIT_TAKE1("TransferLog", set_transfer_log, NULL, RSRC_CONF,
     "the filename of the access log"),
AP_INIT_TAKE12("LogFormat", log_format, NULL, RSRC_CONF,
     "a log format string (see docs) and an optional format name"),
AP_INIT_FLAG("BufferedLogs", set_buffered_logs_on, NULL, RSRC_CONF,
                 "Enable Buffered Logging (experimental)"),
    {NULL}
};

static config_log_state *open_config_log(server_rec *s, apr_pool_t *p,
                                         config_log_state *cls,
                                         apr_array_header_t *default_format)
{
    if (cls->log_writer_data != NULL) {
        return cls;             /* virtual config shared w/main server */
    }

    if (cls->fname == NULL) {
        return cls;             /* Leave it NULL to decline.  */
    }

    cls->log_writer_data = log_writer_init(p, s, cls->fname);
    if (cls->log_writer_data == NULL)
        return NULL;

    /* sort log_format_items array, to help json formatter in gruppenwechsel */
    if (cls->log_formatter == ap_json_log_formatter /* sort_log_format_items */ ) {
        /* no valid cls->format given in format string,
           use default_format, if any valid */
        if (!cls->format && default_format) {
            /* copy here to not confuse non-json formatters */
            cls->format = apr_array_copy(p, default_format);
        }
        qsort(cls->format->elts, cls->format->nelts, cls->format->elt_size, compare_log_format_item_by_tag);
    }

    return cls;
}

static int open_multi_logs(server_rec *s, apr_pool_t *p)
{
    int i;
    multi_log_state *mls = ap_get_module_config(s->module_config,
                                             &log_config_module);
    config_log_state *clsarray;
    const char *dummy;
    const char *format;

    if (mls->default_format_string) {
        format = apr_table_get(mls->formats, mls->default_format_string);
        if (format) {
            mls->default_format = parse_log_string(p, format, &dummy);
        }
    }

    if (!mls->default_format) {
        /* TODO: may use "CLF" instead from mls->formats here
         *       which is added in make_config_log_state
         */
        mls->default_format = parse_log_string(p, DEFAULT_LOG_FORMAT, &dummy);
    }

    if (mls->config_logs->nelts) {
        clsarray = (config_log_state *) mls->config_logs->elts;
        for (i = 0; i < mls->config_logs->nelts; ++i) {
            config_log_state *cls = &clsarray[i];

            if (cls->format_string) {
                format = apr_table_get(mls->formats, cls->format_string);
                if (format) {
                    cls->format = parse_log_string(p, format, &dummy);
                }
            }

            if (!open_config_log(s, p, cls, mls->default_format)) {
                /* Failure already logged by open_config_log */
                return DONE;
            }
        }
    }
    else if (mls->server_config_logs) {
        clsarray = (config_log_state *) mls->server_config_logs->elts;
        for (i = 0; i < mls->server_config_logs->nelts; ++i) {
            config_log_state *cls = &clsarray[i];

            if (cls->format_string) {
                format = apr_table_get(mls->formats, cls->format_string);
                if (format) {
                    cls->format = parse_log_string(p, format, &dummy);
                }
            }

            if (!open_config_log(s, p, cls, mls->default_format)) {
                /* Failure already logged by open_config_log */
                return DONE;
            }
        }
    }

    return OK;
}


static apr_status_t flush_all_logs(void *data)
{
    server_rec *s = data;
    multi_log_state *mls;
    apr_array_header_t *log_list;
    config_log_state *clsarray;
    buffered_log *buf;
    int i;

    if (!buffered_logs)
        return APR_SUCCESS;

    for (; s; s = s->next) {
        mls = ap_get_module_config(s->module_config, &log_config_module);
        log_list = NULL;
        if (mls->config_logs->nelts) {
            log_list = mls->config_logs;
        }
        else if (mls->server_config_logs) {
            log_list = mls->server_config_logs;
        }
        if (log_list) {
            clsarray = (config_log_state *) log_list->elts;
            for (i = 0; i < log_list->nelts; ++i) {
                buf = clsarray[i].log_writer_data;
                flush_log(buf);
            }
        }
    }
    return APR_SUCCESS;
}


static int init_config_log(apr_pool_t *pc, apr_pool_t *p, apr_pool_t *pt, server_rec *s)
{
    int res;

    /* First init the buffered logs array, which is needed when opening the logs. */
    if (buffered_logs) {
        all_buffered_logs = apr_array_make(p, 5, sizeof(buffered_log *));
    }

    /* Next, do "physical" server, which gets default log fd and format
     * for the virtual servers, if they don't override...
     */
    res = open_multi_logs(s, p);

    /* Then, virtual servers */

    for (s = s->next; (res == OK) && s; s = s->next) {
        res = open_multi_logs(s, p);
    }

    return res;
}

static void init_child(apr_pool_t *p, server_rec *s)
{
    int mpm_threads;

    ap_mpm_query(AP_MPMQ_MAX_THREADS, &mpm_threads);

    /* Now register the last buffer flush with the cleanup engine */
    if (buffered_logs) {
        int i;
        buffered_log **array = (buffered_log **)all_buffered_logs->elts;

        apr_pool_cleanup_register(p, s, flush_all_logs, flush_all_logs);

        for (i = 0; i < all_buffered_logs->nelts; i++) {
            buffered_log *this = array[i];

#if APR_HAS_THREADS
            if (mpm_threads > 1) {
                apr_status_t rv;

                this->mutex.type = apr_anylock_threadmutex;
                rv = apr_thread_mutex_create(&this->mutex.lock.tm,
                                             APR_THREAD_MUTEX_DEFAULT,
                                             p);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00647)
                                 "could not initialize buffered log mutex, "
                                 "transfer log may become corrupted");
                    this->mutex.type = apr_anylock_none;
                }
            }
            else
#endif
            {
                this->mutex.type = apr_anylock_none;
            }
        }
    }
}

static void ap_register_log_handler_ex(apr_pool_t *p, const char *tag,
                                    const char *long_name,
                                    ap_log_handler_fn_t *handler, int def, int does_escape)
{
    ap_log_handler *log_struct = apr_palloc(p, sizeof(*log_struct));
    log_struct->func = handler;
    log_struct->want_orig_default = def;
    log_struct->does_escape = does_escape;

    apr_hash_set(log_hash, tag, strlen(tag), (const void *)log_struct);
    if(long_name) {
        apr_hash_set(llog_hash, tag, strlen(tag), long_name);
    }
}

static void ap_register_log_handler(apr_pool_t *p, char *tag,
                                    ap_log_handler_fn_t *handler, int def)
{
    ap_register_log_handler_ex(p, tag, NULL, handler, def, 1);
}

static ap_log_writer_init *ap_log_set_writer_init(ap_log_writer_init *handle)
{
    ap_log_writer_init *old = log_writer_init;
    log_writer_init = handle;

    return old;
}

static ap_log_writer *ap_log_set_writer(ap_log_writer *handle)
{
    ap_log_writer *old = log_writer;
    log_writer = handle;

    return old;
}

#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 7)
static apr_status_t apr_brigade_to_log_formatted_data(apr_bucket_brigade *bb,
                                     ap_log_formatted_data *lfd,
                                     apr_pool_t *p)
{
    apr_status_t rv = APR_SUCCESS;
    const char *str;
    apr_size_t len;
    apr_bucket *b;
    int n = 0, i = 0;

    /* first count elements */
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b)) {
         n++;
    }

    lfd->portions = apr_palloc(p, sizeof(char*) * n);
    lfd->lengths = apr_palloc(p, sizeof(int) * n);
    lfd->total_len = 0;
    lfd->nelts = 0;

    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b), i++) {
        rv = apr_bucket_read(b, &str, &len, APR_NONBLOCK_READ);
        if (rv != APR_SUCCESS) {
            break;
        }
        if (len) {
            lfd->portions[i] = (void *)str;
            lfd->lengths[i] = len;
            lfd->total_len += len;
            lfd->nelts++;
        }
    }

    return rv;
}

static ap_log_formatted_data * ap_json_log_formatter( request_rec *r,
                           const void *handle,
                           ap_log_formatted_data *lfd,
                           const void *itms)

{
    const json_log_formatter_options * formatter_options = (json_log_formatter_options *) handle;
    const log_format_item *items = (log_format_item *) itms;

    const char* attribute_name;
    const char* attribute_value;

    int i,j;
    ap_log_formatted_data *lfdj = apr_palloc(r->pool, sizeof(ap_log_formatted_data));

    apr_bucket_alloc_t *ba;
    apr_bucket_brigade *bb;

    apr_json_value_t *sub_log_object;
    apr_json_value_t *json_null = apr_json_null_create(r->pool);
    apr_json_value_t *json_empty_string = apr_json_string_create(r->pool, "\"\"", APR_JSON_VALUE_STRING);

    /* build log object */
    apr_json_value_t *log_object = apr_json_object_create(r->pool);

    for (i = 0; i < lfd->nelts; ++i) {
        if(!items[i].tag) {
            continue;
        }

        if (formatter_options->use_short_attribute_names) {
            attribute_name = NULL;
        }
        else {
            attribute_name = apr_hash_get(llog_hash, items[i].tag, APR_HASH_KEY_STRING);
        }

        if (!attribute_name) {
            attribute_name = items[i].tag; /* fallback: use tag as attribute name */
        }

        /* if the current tag has arguments, i.e. "i" (requestHeaders)
         * create a sub object with items[i].arg as key and lfd->portions[i] values.
         *
         * as multiple same tags with different arguments can exist,
         * the log_format_item is sorted before, so we can easily check for
         * gruppenwechsel
         */
        if(items[i].arg != NULL && strlen(items[i].arg) > 0) {
            /* start sub object */
            sub_log_object = apr_json_object_create(r->pool);
            for (j = i; j < lfd->nelts; ++j) {
                /* skip empty tags, if any */
                if(!items[j].tag) {
                    continue;
                }

                /* is gruppenwechsel */
                if(j > i && strcmp(items[j].tag, items[i].tag) != 0) {
                    break;
                }

                attribute_name = items[j].arg;
                if (!lfd->portions[j]) {
                    if (!formatter_options->omit_null_values) {
                        apr_json_object_set(sub_log_object,
                                            attribute_name, APR_JSON_VALUE_STRING,
                                            json_null, r->pool);
                    }
                }
                else if (!*lfd->portions[j]) {
                    apr_json_object_set(sub_log_object,
                                        attribute_name, APR_JSON_VALUE_STRING,
                                        json_empty_string,
                                        r->pool);
                }
                else {
                    attribute_value = lfd->portions[j];
                    apr_json_object_set(sub_log_object,
                                        attribute_name, APR_JSON_VALUE_STRING,
                                        apr_json_string_create(r->pool, attribute_value,
                                                               APR_JSON_VALUE_STRING),
                                        r->pool);
                }
            }

            if (apr_json_object_first(sub_log_object)) {
                apr_json_object_set(log_object,
                                    attribute_name, APR_JSON_VALUE_STRING,
                                    sub_log_object,
                                    r->pool);
            }

            /* restart outer loop with current item */
            i = j - 1;
            continue;
        }

        if (!lfd->portions[i]) {
            if (!formatter_options->omit_null_values) {
                apr_json_object_set(log_object,
                                    attribute_name, APR_JSON_VALUE_STRING,
                                    json_null, r->pool);
            }
        }
        else if (!*lfd->portions[i]) {
            apr_json_object_set(log_object,
                                attribute_name, APR_JSON_VALUE_STRING,
                                json_empty_string,
                                r->pool);
        }
        else {
            attribute_value = lfd->portions[i];
            apr_json_object_set(log_object,
                                attribute_name, APR_JSON_VALUE_STRING,
                                apr_json_string_create(r->pool, attribute_value,
                                                       APR_JSON_VALUE_STRING),
                                r->pool);
        }
    }

    ba = apr_bucket_alloc_create(r->pool);
    bb = apr_brigade_create(r->pool, ba);

    /* encode into bucket brigade */
    apr_json_encode(bb, NULL, NULL, log_object, APR_JSON_FLAGS_WHITESPACE, r->pool);
    apr_brigade_puts(bb, NULL, NULL, APR_EOL_STR);
    apr_brigade_to_log_formatted_data(bb, lfdj, r->pool);
    return lfdj;
}
#else
static apr_size_t add_str(apr_array_header_t * ah_strs, apr_array_header_t * ah_strl, const char *str)
{
    char** strs = apr_array_push(ah_strs);
    int* strl = apr_array_push(ah_strl);

    *strs = (char*) str;
    *strl = strlen(str);

    return *strl;
}

static ap_log_formatted_data * ap_json_log_formatter( request_rec *r,
                           const void *handle,
                           ap_log_formatted_data *lfd,
                           const void *itms)

{
    const json_log_formatter_options * formatter_options = (json_log_formatter_options *) handle;
    const log_format_item *items = (log_format_item *) itms;

    const char* attribute_name;

    int i,j;

    apr_size_t total_len_sub;
    apr_array_header_t *strs_sub;
    apr_array_header_t *strl_sub;

    ap_log_formatted_data *lfdj = apr_palloc(r->pool, sizeof(ap_log_formatted_data));
    apr_array_header_t *strs = apr_array_make(r->pool, lfd->nelts * 3, sizeof(char *)); /* array of pointers to char */
    apr_array_header_t *strl = apr_array_make(r->pool, lfd->nelts * 3, sizeof(int));    /* array of int (strlen) */

    lfdj->total_len = 0;

    /* build json object */
    lfdj->total_len += add_str(strs, strl, "{");
    for (i = 0; i < lfd->nelts; ++i) {
        if(items[i].tag == NULL) {
            continue;
        }

        if (formatter_options->use_short_attribute_names) {
            attribute_name = NULL;
        }
        else {
            attribute_name = apr_hash_get(llog_hash, items[i].tag, APR_HASH_KEY_STRING);
        }

        if (!attribute_name) {
            attribute_name = ap_pescape_json(r->pool, items[i].tag, APR_ESCAPE_STRING, 0); /* use tag as attribute name as fallback */
        }

        /* if the current tag has arguments, i.e. "i" (requestHeaders)
         * create a sub object with items[i].arg as key and lfd->portions[i] values.
         *
         * as multiple same tags with different arguments can exist,
         * the log_format_item is sorted before, so we can easily check for
         * gruppenwechsel
         */
        if(items[i].arg != NULL && strlen(items[i].arg) > 0) {
            /* TODO: or allocate once at the begining and use apr_array_clear here? */
            /* start sub object */
            strs_sub = apr_array_make(r->pool, 3, sizeof(char *)); /* array of pointers to char */
            strl_sub = apr_array_make(r->pool, 3, sizeof(int));    /* array of int (strlen) */
            total_len_sub = 0;

            total_len_sub += add_str(strs_sub, strl_sub, "{");
            for (j = i; j < lfd->nelts; ++j) {
                /* skip empty tags, if any */
                if(!items[j].tag) {
                    continue;
                }

                /* is gruppenwechsel */
                if(j > i && strcmp(items[j].tag, items[i].tag) != 0) {
                    break;
                }

                if(!lfd->portions[j]) {
                    if (formatter_options->omit_null_values) {
                        continue;
                    }
                }

                total_len_sub += add_str(strs_sub, strl_sub, ap_pescape_json(r->pool, items[j].arg, APR_ESCAPE_STRING, 1));
                total_len_sub += add_str(strs_sub, strl_sub, ":");
                total_len_sub += add_str(strs_sub, strl_sub, ap_pescape_json(r->pool, lfd->portions[j], APR_ESCAPE_STRING, 1));
                total_len_sub += add_str(strs_sub, strl_sub, ",");
            }
            if (total_len_sub > 1) {
                /* remove last "," */
                apr_array_pop(strs_sub);
                total_len_sub -= *(int *)apr_array_pop(strl_sub);

                /* end sub object */
                total_len_sub += add_str(strs_sub, strl_sub, "}");

                /* append to super object */
                lfdj->total_len += add_str(strs, strl, "\"");
                lfdj->total_len += add_str(strs, strl, attribute_name);
                lfdj->total_len += add_str(strs, strl, "\":");

                apr_array_cat(strs, strs_sub);
                apr_array_cat(strl, strl_sub);
                lfdj->total_len += total_len_sub;

                lfdj->total_len += add_str(strs, strl, ",");
            }

            /* restart outer loop with current item */
            i = j - 1;
            continue;
        }

        if(!lfd->portions[i]) {
            if (formatter_options->omit_null_values) {
                continue;
            }
        }

        lfdj->total_len += add_str(strs, strl, "\"");
        lfdj->total_len += add_str(strs, strl, attribute_name);
        lfdj->total_len += add_str(strs, strl, "\":");
        lfdj->total_len += add_str(strs, strl, ap_pescape_json(r->pool, lfd->portions[i], APR_ESCAPE_STRING, 1));
        lfdj->total_len += add_str(strs, strl, ",");
    }

    if (lfdj->total_len > 1) {
        /* replace last ',' with '}' */
        apr_array_pop(strs);
        lfdj->total_len -= *(int *)apr_array_pop(strl);
    }

    /* close object */
    lfdj->total_len += add_str(strs, strl, "}" APR_EOL_STR);

    lfdj->portions = (const char **)strs->elts;
    lfdj->lengths = (int *)strl->elts;
    lfdj->nelts = strs->nelts;
    return lfdj;
}
#endif

static apr_status_t ap_default_log_writer( request_rec *r,
                           void *handle,
                           const char **strs,
                           int *strl,
                           int nelts,
                           apr_size_t len)
{
    default_log_writer *log_writer = handle;
    char *str;
    char *s;
    int i;
    apr_status_t rv;

    /*
     * We do this memcpy dance because write() is atomic for len < PIPE_BUF,
     * while writev() need not be.
     */
    str = apr_palloc(r->pool, len + 1);

    for (i = 0, s = str; i < nelts; ++i) {
        memcpy(s, strs[i], strl[i]);
        s += strl[i];
    }

    if (log_writer->type == LOG_WRITER_FD) {
        rv = apr_file_write_full((apr_file_t*)log_writer->log_writer, str,
                                 len, NULL);
    }
    else {
        errorlog_provider_data *data = log_writer->log_writer;
        ap_errorlog_info info;
        info.r             = r;
        info.s             = r->server;
        info.c             = r->connection;
        info.pool          = r->pool;
        info.file          = NULL;
        info.line          = 0;
        info.status        = 0;
        info.using_provider = 1;
        info.startup       = 0;
        info.format        = "";
        rv = data->provider->writer(&info, data->handle,
                                    str, len);
    }

    return rv;
}
static void *ap_default_log_writer_init(apr_pool_t *p, server_rec *s,
                                        const char* name)
{
    default_log_writer *log_writer;
    const char *provider_name = name;
    ap_errorlog_provider *provider = NULL;
    const char *sep;

    /* We support *Log "errorlog_provider:arg" syntax now, so get the provider
     * name from the name. */
    if ((sep = ap_strchr_c(name, ':')) != NULL) {
        provider_name = apr_pstrmemdup(p, name, sep - name);
        sep++;
    }

    if (*name == '|') {
        piped_log *pl;

        pl = ap_open_piped_log(p, name + 1);
        if (pl == NULL) {
           return NULL;
        }

        log_writer = apr_pcalloc(p, sizeof(default_log_writer));
        log_writer->type = LOG_WRITER_FD;
        log_writer->log_writer = ap_piped_log_write_fd(pl);
        if (!log_writer->log_writer) {
            return NULL;
        }
        return log_writer;
    }
    else if ((provider = ap_lookup_provider(AP_ERRORLOG_PROVIDER_GROUP,
        provider_name, AP_ERRORLOG_PROVIDER_VERSION)) != NULL) {
        void *provider_handle;
        errorlog_provider_data *provider_data;

        provider_handle = provider->init(p, s);
        if (!provider_handle) {
            /* provider must log something to the console */
            return NULL;
        }

        provider_data = apr_pcalloc(p, sizeof(errorlog_provider_data));
        provider_data->provider = provider;
        provider_data->handle = provider_handle;

        log_writer = apr_pcalloc(p, sizeof(default_log_writer));
        log_writer->type = LOG_WRITER_PROVIDER;
        log_writer->log_writer = provider_data;
        return log_writer;
    }
    else {
        const char *fname = ap_server_root_relative(p, name);
        apr_file_t *fd;
        apr_status_t rv;

        if (!fname) {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s, APLOGNO(00648)
                            "invalid transfer log path %s.", name);
            return NULL;
        }
        rv = apr_file_open(&fd, fname, xfer_flags, xfer_perms, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00649)
                            "could not open transfer log file %s.", fname);
            return NULL;
        }

        log_writer = apr_pcalloc(p, sizeof(default_log_writer));
        log_writer->type = LOG_WRITER_FD;
        log_writer->log_writer = fd;
        return log_writer;
    }
}
static void *ap_buffered_log_writer_init(apr_pool_t *p, server_rec *s,
                                        const char* name)
{
    buffered_log *b;
    b = apr_pcalloc(p, sizeof(buffered_log));
    b->handle = ap_default_log_writer_init(p, s, name);

    if (b->handle) {
        *(buffered_log **)apr_array_push(all_buffered_logs) = b;
        return b;
    }
    else
        return NULL;
}
static apr_status_t ap_buffered_log_writer(request_rec *r,
                                           void *handle,
                                           const char **strs,
                                           int *strl,
                                           int nelts,
                                           apr_size_t len)

{
    char *str;
    char *s;
    int i;
    apr_status_t rv;
    buffered_log *buf = (buffered_log*)handle;

    if ((rv = APR_ANYLOCK_LOCK(&buf->mutex)) != APR_SUCCESS) {
        return rv;
    }

    if (len + buf->outcnt > LOG_BUFSIZE) {
        flush_log(buf);
    }
    if (len >= LOG_BUFSIZE) {
        apr_size_t w;

        /*
         * We do this memcpy dance because write() is atomic for
         * len < PIPE_BUF, while writev() need not be.
         */
        str = apr_palloc(r->pool, len + 1);
        for (i = 0, s = str; i < nelts; ++i) {
            memcpy(s, strs[i], strl[i]);
            s += strl[i];
        }
        w = len;
        rv = apr_file_write_full(buf->handle, str, w, NULL);

    }
    else {
        for (i = 0, s = &buf->outbuf[buf->outcnt]; i < nelts; ++i) {
            memcpy(s, strs[i], strl[i]);
            s += strl[i];
        }
        buf->outcnt += len;
        rv = APR_SUCCESS;
    }

    APR_ANYLOCK_UNLOCK(&buf->mutex);
    return rv;
}

static int log_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static APR_OPTIONAL_FN_TYPE(ap_register_log_handler_ex) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler_ex);

    /*
     * long names should align with tomcat attribute names:
     * https://github.com/apache/tomcat/blob/9.0.x/java/org/apache/catalina/valves/JsonAccessLogValve.java#L78
     * also interessting is fluentd resp. fluent-bit:
     * - https://github.com/fluent/fluentd/blob/master/lib/fluent/plugin/parser_apache2.rb#L72
     */
    if (log_pfn_register) {
        log_pfn_register(p, "a", "remoteAddr", log_remote_address, 0, 0);
        log_pfn_register(p, "A", "localAddr", log_local_address, 0, 0);
        log_pfn_register(p, "b", "size", clf_log_bytes_sent, 0, 0);
        log_pfn_register(p, "B", "byteSentNC", log_bytes_sent, 0, 0);
        log_pfn_register(p, "C", "cookie", log_cookie, 0, 0); /* tomcat: "c" */
        log_pfn_register(p, "D", "elapsedTime", log_request_duration_microseconds, 1, 0);
        log_pfn_register(p, "e", "env", log_env_var, 0, 0);
        log_pfn_register(p, "f", "file", log_request_file, 0, 0);
        log_pfn_register(p, "F", "requestFlushed", log_request_flushed, 1, 0);
        log_pfn_register(p, "h", "host", log_remote_host, 0, 0);
        log_pfn_register(p, "H", "protocol", log_request_protocol, 0, 0);
        log_pfn_register(p, "i", "requestHeaders", log_header_in, 0, 0);
        log_pfn_register(p, "k", "requestsOnConnection", log_requests_on_connection, 0, 0);
        log_pfn_register(p, "l", "logicalUserName", log_remote_logname, 0, 0);
        log_pfn_register(p, "L", "logId", log_log_id, 1, 0);
        log_pfn_register(p, "m", "method", log_request_method, 0, 0);
        log_pfn_register(p, "n", "note", log_note, 0, 0);
        log_pfn_register(p, "o", "responseHeaders", log_header_out, 0, 0);
        log_pfn_register(p, "p", "port", log_server_port, 0, 0);
        log_pfn_register(p, "P", "threadId", log_pid_tid, 0, 0);
        log_pfn_register(p, "q", "query", log_request_query, 0, 0);
        log_pfn_register(p, "r", "request", log_request_line, 1, 0);
        log_pfn_register(p, "R", "handler", log_handler, 1, 0);
        log_pfn_register(p, "s", "statusCode", log_status, 1, 0);
        log_pfn_register(p, "t", "time", log_request_time, 0, 0);
        log_pfn_register(p, "T", "elapsedTimeS", log_request_duration_scaled, 1, 0);
        log_pfn_register(p, "u", "user", log_remote_user, 0, 0);
        log_pfn_register(p, "U", "path", log_request_uri, 1, 0);
        log_pfn_register(p, "v", "virtualHost", log_virtual_host, 0, 0); /* tomcat: localServerName */
        log_pfn_register(p, "V", "serverName", log_server_name, 0, 0);
        log_pfn_register(p, "X", "connectionStatus", log_connection_status, 0, 0);

        /* TODO: long names for
         * - "^ti", "^to", "c" and "x" -> new in trunk?
         * - mod_logio does register: "I", "O", "S", "^FU" and "^FB"
         */

        log_pfn_register(p, "^ti", NULL, log_trailer_in, 0, 0);
        log_pfn_register(p, "^to", NULL, log_trailer_out, 0, 0);

        /* these used to be part of mod_ssl, but with the introduction
         * of ap_ssl_var_lookup() they are added here directly so lookups
         * from all installed SSL modules work.
         * We keep the old tag names to remain backward compatible. */
        log_pfn_register(p, "c", NULL, log_ssl_var_short, 0, 0);
        log_pfn_register(p, "x", NULL, log_ssl_var, 0, 0);
    }

    /* reset to default conditions */
    ap_log_set_writer_init(ap_default_log_writer_init);
    ap_log_set_writer(ap_default_log_writer);
    buffered_logs = 0;

    return OK;
}

static int check_log_dir(apr_pool_t *p, server_rec *s, config_log_state *cls)
{
    if (!cls->fname || cls->fname[0] == '|' || !cls->directive) {
        return OK;
    }
    else {
        char *abs = ap_server_root_relative(p, cls->fname);
        char *dir = ap_make_dirstr_parent(p, abs);
        apr_finfo_t finfo;
        const ap_directive_t *directive = cls->directive;
        apr_status_t rv = apr_stat(&finfo, dir, APR_FINFO_TYPE, p);
        cls->directive = NULL; /* Don't check this config_log_state again */
        if (rv == APR_SUCCESS && finfo.filetype != APR_DIR)
            rv = APR_ENOTDIR;
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_EMERG, rv, s,
                         APLOGNO(02297)
                         "Cannot access directory '%s' for log file '%s' "
                         "defined at %s:%d", dir, cls->fname,
                         directive->filename, directive->line_num);
            return !OK;
        }
    }
    return OK;
}

static int log_check_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    int rv = OK;
    while (s) {
        multi_log_state *mls = ap_get_module_config(s->module_config,
                                                    &log_config_module);
        /*
         * We don't need to check mls->server_config_logs because it just
         * points to the parent server's mls->config_logs.
         */
        apr_array_header_t *log_list = mls->config_logs;
        config_log_state *clsarray = (config_log_state *) log_list->elts;
        int i;
        for (i = 0; i < log_list->nelts; ++i) {
            if (check_log_dir(ptemp, s, &clsarray[i]) != OK)
                rv = !OK;
        }

        s = s->next;
    }
    return rv;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(log_pre_config,NULL,NULL,APR_HOOK_REALLY_FIRST);
    ap_hook_check_config(log_check_config,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_child_init(init_child,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_open_logs(init_config_log,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_log_transaction(multi_log_transaction,NULL,NULL,APR_HOOK_MIDDLE);

    /* Init log_hash before we register the optional function. It is
     * possible for the optional function, ap_register_log_handler,
     * to be called before any other mod_log_config hooks are called.
     * As a policy, we should init everything required by an optional function
     * before calling APR_REGISTER_OPTIONAL_FN.
     */
    log_hash = apr_hash_make(p);
    llog_hash = apr_hash_make(p);
    APR_REGISTER_OPTIONAL_FN(ap_register_log_handler);
    APR_REGISTER_OPTIONAL_FN(ap_register_log_handler_ex);
    APR_REGISTER_OPTIONAL_FN(ap_log_set_writer_init);
    APR_REGISTER_OPTIONAL_FN(ap_log_set_writer);
}

AP_DECLARE_MODULE(log_config) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    make_config_log_state,      /* server config */
    merge_config_log_state,     /* merge server config */
    config_log_cmds,            /* command apr_table_t */
    register_hooks              /* register hooks */
};

