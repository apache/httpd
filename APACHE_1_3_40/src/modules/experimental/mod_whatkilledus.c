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
 * Documentation:
 *
 * mod_whatkilledus is an experimental module for Apache httpd 1.3 which
 * tracks the current request and logs a report of the active request
 * when a child process crashes.  You should verify that it works reasonably
 * on your system before putting it in production.
 *
 * mod_whatkilledus is called during request processing to save information
 * about the current request.  It also implements a fatal exception hook
 * that will be called when a child process crashes.
 *
 * Apache httpd requirements for mod_whatkilledus:
 *
 *   Apache httpd >= 1.3.30 must be built with the AP_ENABLE_EXCEPTION_HOOK
 *   symbol defined and mod_so enabled.  AP_ENABLE_EXCEPTION_HOOK is already
 *   defined in ap_config.h for some platforms, including AIX, Linux,
 *   Solaris, and HP-UX.  It can be enabled for other platforms by including
 *   -DAP_ENABLE_EXCEPTION_HOOK in CFLAGS when the configure script is
 *   invoked.
 *
 * Compiling mod_whatkilledus:
 *
 *   AIX:
 *     apxs -ci -I/path/to/apache/src/main -Wl,-bE:mod_whatkilledus.exp mod_whatkilledus.c
 *
 *   other:
 *     apxs -ci -I/path/to/apache/src/main mod_whatkilledus.c
 *
 * Activating mod_whatkilledus:
 *
 *   1. Load it like any other DSO, but the AddModule should come
 *      last so that if another module causes a crash early in
 *      request processing mod_whatkilledus will have already
 *      had a chance to save information about the request.
 *
 *        LoadModule whatkilledus_module libexec/mod_whatkilledus.so
 *        ...
 *        AddModule mod_whatkilledus.c
 *
 *   2. Enable exception hooks for modules like mod_whatkilledus:
 *        EnableExceptionHook On
 *
 *   3. Choose where the report on current activity should be written.  If
 *      you want it reported to some place other than the error log, use the
 *      WhatKilledUsLog directive to specify a fully-qualified filename for
 *      the log.  Note that the web server user id (e.g., "nobody") must
 *      be able to create or append to this log file, as the log file is
 *      not opened until a crash occurs.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include "test_char.h" /* an odd one since it is not installed */

/* this module is not thread-safe; it is intended for Apache 1.3 on
 * platforms that use single-threaded child processes for handling
 * client connections
 */
static char *log_fname;
static char *local_addr;
static char *remote_addr;
static char *request_plus_headers;
static char buffer[2048];

static void exception_hook(ap_exception_info_t *ei)
{
    int msg_len;
    int logfd;
    char msg_prefix[60];
    time_t now;
    char *newline;
    int using_errorlog = 1;

    time(&now);
    ap_snprintf(msg_prefix, sizeof msg_prefix,
                "[%s pid %ld mod_whatkilledus",
                asctime(localtime(&now)),
                (long)getpid());
    newline = strchr(msg_prefix, '\n'); /* dang asctime() */
    if (newline) {                      /* silly we are */
        *newline = ']';
    }

    if (log_fname) {
        logfd = open(log_fname, O_WRONLY|O_APPEND|O_CREAT, 0644);
        if (logfd == -1) {
            logfd = 2; /* unix, so fd 2 is the web server error log */
            ap_snprintf(buffer, sizeof buffer,
                        "%s error %d opening %s\n",
                        msg_prefix, errno, log_fname);
            write(logfd, buffer, strlen(buffer));
        }
        else {
            using_errorlog = 0;
        }
    }
    else {
        logfd = 2;
    }

    msg_len = ap_snprintf(buffer, sizeof buffer,
                          "%s sig %d crash\n",
                          msg_prefix, ei->sig);
    write(logfd, buffer, msg_len);

    if (local_addr) {
        msg_len = ap_snprintf(buffer, sizeof buffer,
                              "%s active connection: %s->%s\n",
                              msg_prefix, remote_addr, local_addr);
    }
    else {
        msg_len = ap_snprintf(buffer, sizeof buffer,
                              "%s no active connection at crash\n",
                              msg_prefix);
    }

    write(logfd, buffer, msg_len);

    if (request_plus_headers) {
        msg_len = ap_snprintf(buffer, sizeof buffer,
                              "%s active request:\n",
                              msg_prefix);
        write(logfd, buffer, msg_len);
        write(logfd, request_plus_headers, strlen(request_plus_headers));
    }
    else {
        msg_len = ap_snprintf(buffer, sizeof buffer,
                              "%s no request active at crash\n",
                              msg_prefix);
        write(logfd, buffer, msg_len);
    }
    msg_len = ap_snprintf(buffer, sizeof buffer,
                          "%s end of report\n",
                          msg_prefix);
    write(logfd, buffer, msg_len);
    if (!using_errorlog) {
        close(logfd);
    }
}

static void init(server_rec *s, pool *p)
{
    int rc = ap_add_fatal_exception_hook(exception_hook);

    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, s,
                     "fatal exception hooks are not enabled; please "
                     "enable them with the EnableExceptionHook directive "
                     "or disable mod_whatkilledus");
    }
}

static void clear_conn_info(void *ignored)
{
    local_addr = remote_addr = NULL;
}

static void save_conn_info(request_rec *r)
{
    conn_rec *c = r->connection;
    local_addr =  ap_psprintf(c->pool, "%pI", &c->local_addr);
    remote_addr = ap_psprintf(c->pool, "%pI", &c->remote_addr);

    ap_register_cleanup(c->pool, NULL, clear_conn_info, ap_null_cleanup);
}

static void clear_req_info(void *ignored)
{
    request_plus_headers = NULL;
}

#define FIELD_SEPARATOR   "|"
#define KEYVAL_SEPARATOR  ":"

/* graciously lifted from mod_log_forensic */

static int count_string(const char *p)
{
    int n;

    for (n = 0; *p; ++p, ++n) {
        if (test_char_table[*(unsigned char *)p] & T_ESCAPE_FORENSIC) {
            n += 2;
        }
    }
    return n;
}

static int count_headers(void *in_len, const char *key, const char *value)
{
    int *len = in_len;

    *len += strlen(FIELD_SEPARATOR);
    *len += count_string(key);
    *len += strlen(KEYVAL_SEPARATOR);
    *len += count_string(value);

    return 1;
}

static char *copy_and_escape(char *loc, const char *str) {
    /* mod_log_forensic will SIGABRT here if it messed up the count
     * and overflowed; mod_whatkilledus will segfault here or will
     * SIGABRT back in the caller if that happens
     */
    for ( ; *str; ++str) {
        if (test_char_table[*(unsigned char *)str] & T_ESCAPE_FORENSIC) {
            *loc++ = '%';
            sprintf(loc, "%02x", *(unsigned char *)str);
            loc += 2;
        }
        else {
            *loc++ = *str;
        }
    }
    *loc = '\0';
    return loc;
}

static int copy_headers(void *in_ch, const char *key, const char *value)
{
    char **ch = in_ch;

    strcpy(*ch, FIELD_SEPARATOR);
    *ch += strlen(FIELD_SEPARATOR);

    *ch = copy_and_escape(*ch, key);

    strcpy(*ch, KEYVAL_SEPARATOR);
    *ch += strlen(KEYVAL_SEPARATOR);

    *ch = copy_and_escape(*ch, value);

    return 1;
}

static void save_req_info(request_rec *r)
{
    /* to save for the request:
     * r->the_request + 
     * foreach header:
     *   '|' + header field
     */
    int len = strlen(r->the_request);
    char *ch;
    ap_table_do(count_headers, &len, r->headers_in, NULL);

    request_plus_headers = ap_palloc(r->pool, len + 2 /* 2 for the '\n' + '\0' at end */);
    ch = request_plus_headers;
    strcpy(ch, r->the_request);
    ch += strlen(ch);

    ap_table_do(copy_headers, &ch, r->headers_in, NULL);
    *ch = '\n';
    *(ch + 1) = '\0';

    ap_assert(ch == request_plus_headers + len);

    ap_register_cleanup(r->pool, NULL, clear_req_info, ap_null_cleanup);
}

static int post_read(request_rec *r)
{
    if (r->prev) { /* we were already called for this internal redirect */
        return DECLINED;
    }

    /* save whatever info, like client, which vhost, which port
     * (to know SSL or not), etc.
     */
    if (!local_addr) { /* first request on this connection */
        save_conn_info(r);
    }

    save_req_info(r);

    return DECLINED;
}

static const char *cmd_file(cmd_parms *cmd, void *dconf, char *fname)
{
    log_fname = ap_pstrdup(cmd->pool, fname);
    return NULL;
}

static const command_rec command_table[] = {
    {
        "WhatKilledUsLog", cmd_file, NULL, RSRC_CONF, TAKE1, "the fully-qualified filename of the mod_whatkilledus logfile"
    }
    ,
    {
        NULL
    }
};

module MODULE_VAR_EXPORT whatkilledus_module = {
    STANDARD_MODULE_STUFF,
    init,                       /* initializer */
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    command_table,              /* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    post_read                   /* post read-request */
};
