/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
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
 *    CookieLog fn        For backwards compatability with old Cookie
 *                        logging module - now deprecated.
 *
 * There can be any number of TransferLog and CustomLog
 * commands. Each request will be logged to _ALL_ the
 * named files, in the appropriate format.
 *
 * If no TransferLog or CustomLog directive appears in a VirtualHost,
 * the request will be logged to the log file(s) defined outside
 * the virtual host section. If a TransferLog or CustomLog directive
 * appears in the VirtualHost section, the log files defined outside
 * the VirtualHost will _not_ be used. This makes this module compatable
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
 * %...c:  Status of the connection.
 *         'X' = connection aborted before the response completed.
 *         '+' = connection may be kept alive after the response is sent.
 *         '-' = connection will be closed after the response is sent.
 * %...{FOOBAR}e:  The contents of the environment variable FOOBAR
 * %...f:  filename
 * %...h:  remote host
 * %...a:  remote IP-address
 * %...A:  local IP-address
 * %...{Foobar}i:  The contents of Foobar: header line(s) in the request
 *                 sent to the client.
 * %...l:  remote logname (from identd, if supplied)
 * %...{Foobar}n:  The contents of note "Foobar" from another module.
 * %...{Foobar}o:  The contents of Foobar: header line(s) in the reply.
 * %...p:  the port the request was served to
 * %...P:  the process ID of the child that serviced the request.
 * %...r:  first line of request
 * %...s:  status.  For requests that got internally redirected, this
 *         is status of the *original* request --- %...>s for the last.
 * %...t:  time, in common log format time format
 * %...{format}t:  The time, in the form given by format, which should
 *                 be in strftime(3) format.
 * %...T:  the time taken to serve the request, in seconds.
 * %...u:  remote user (from auth; may be bogus if return status (%s) is 401)
 * %...U:  the URL path requested.
 * %...v:  the configured name of the server (i.e. which virtual host?)
 * %...V:  the server name according to the UseCanonicalName setting
 * %...m:  the request method
 * %...H:  the request protocol
 * %...q:  the query string prepended by "?", or empty if no query string
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

#define DEFAULT_LOG_FORMAT "%h %l %u %t \"%r\" %>s %b"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"          /* For REMOTE_NAME */
#include "http_log.h"
#include <limits.h>

module MODULE_VAR_EXPORT config_log_module;

static int xfer_flags = (O_WRONLY | O_APPEND | O_CREAT);
#if defined(OS2) || defined(WIN32) || defined(NETWARE)
/* OS/2 dosen't support users and groups */
static mode_t xfer_mode = (S_IREAD | S_IWRITE);
#else
static mode_t xfer_mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif

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
 * and server_config_logs in empty. For a vhost, server_config_logs
 * points to the same array as config_logs in the main server, and
 * config_logs points to the array of logs defined inside this vhost,
 * which might be empty.
 */

typedef struct {
    char *default_format_string;
    array_header *default_format;
    array_header *config_logs;
    array_header *server_config_logs;
    table *formats;
} multi_log_state;

/*
 * config_log_state holds the status of a single log file. fname might
 * be NULL, which means this module does no logging for this
 * request. format might be NULL, in which case the default_format
 * from the multi_log_state should be used, or if that is NULL as
 * well, use the CLF. log_fd is -1 before the log file is opened and
 * set to a valid fd after it is opened.
 */

typedef struct {
    char *fname;
    char *format_string;
    array_header *format;
    int log_fd;
    char *condition_var;
#ifdef BUFFERED_LOGS
    int outcnt;
    char outbuf[LOG_BUFSIZE];
#endif
} config_log_state;

/*
 * Format items...
 * Note that many of these could have ap_sprintfs replaced with static buffers.
 */

typedef const char *(*item_key_func) (request_rec *, char *);

typedef struct {
    item_key_func func;
    char *arg;
    int condition_sense;
    int want_orig;
    array_header *conditions;
} log_format_item;

static char *format_integer(pool *p, int i)
{
    return ap_psprintf(p, "%d", i);
}

static char *pfmt(pool *p, int i)
{
    if (i <= 0) {
        return "-";
    }
    else {
        return format_integer(p, i);
    }
}

static const char *constant_item(request_rec *dummy, char *stuff)
{
    return stuff;
}

static const char *log_remote_host(request_rec *r, char *a)
{
    return ap_escape_logitem(r->pool, ap_get_remote_host(r->connection, r->per_dir_config,
                                    REMOTE_NAME));
}

static const char *log_remote_address(request_rec *r, char *a)
{
    return r->connection->remote_ip;
}

static const char *log_local_address(request_rec *r, char *a)
{
    return r->connection->local_ip;
}

static const char *log_remote_logname(request_rec *r, char *a)
{
    return ap_escape_logitem(r->pool, ap_get_remote_logname(r));
}

static const char *log_remote_user(request_rec *r, char *a)
{
    char *rvalue = r->connection->user;

    if (rvalue == NULL) {
        rvalue = "-";
    }
    else if (strlen(rvalue) == 0) {
        rvalue = "\"\"";
    }
    else
        rvalue = ap_escape_logitem(r->pool, rvalue);
    return rvalue;
}

static const char *log_request_line(request_rec *r, char *a)
{
	    /* NOTE: If the original request contained a password, we
	     * re-write the request line here to contain XXXXXX instead:
	     * (note the truncation before the protocol string for HTTP/0.9 requests)
	     * (note also that r->the_request contains the unmodified request)
	     */
    return ap_escape_logitem(r->pool,
			     (r->parsed_uri.password) ? ap_pstrcat(r->pool, r->method, " ",
					 ap_unparse_uri_components(r->pool, &r->parsed_uri, 0),
					 r->assbackwards ? NULL : " ", r->protocol, NULL)
					: r->the_request
			     );
}

static const char *log_request_file(request_rec *r, char *a)
{
    return r->filename;
}
static const char *log_request_uri(request_rec *r, char *a)
{
    return ap_escape_logitem(r->pool, r->uri);
}
static const char *log_request_method(request_rec *r, char *a)
{
    return ap_escape_logitem(r->pool, r->method);
}
static const char *log_request_protocol(request_rec *r, char *a)
{
    return ap_escape_logitem(r->pool, r->protocol);
}
static const char *log_request_query(request_rec *r, char *a)
{
    return (r->args != NULL) ? ap_pstrcat(r->pool, "?",
					  ap_escape_logitem(r->pool, r->args), NULL)
                             : "";
}
static const char *log_status(request_rec *r, char *a)
{
    return pfmt(r->pool, r->status);
}

static const char *clf_log_bytes_sent(request_rec *r, char *a)
{
    if (!r->sent_bodyct) {
        return "-";
    }
    else {
        long int bs;
        ap_bgetopt(r->connection->client, BO_BYTECT, &bs);
	return ap_psprintf(r->pool, "%ld", bs);
    }
}

static const char *log_bytes_sent(request_rec *r, char *a)
{
    if (!r->sent_bodyct) {
        return "0";
    }
    else {
        long int bs;
        ap_bgetopt(r->connection->client, BO_BYTECT, &bs);
	return ap_psprintf(r->pool, "%ld", bs);
    }
}


static const char *log_header_in(request_rec *r, char *a)
{
    return ap_escape_logitem(r->pool, ap_table_get(r->headers_in, a));
}

static const char *log_header_out(request_rec *r, char *a)
{
    const char *cp = ap_table_get(r->headers_out, a);
    if (!strcasecmp(a, "Content-type") && r->content_type) {
        cp = ap_field_noparam(r->pool, r->content_type);
    }
    if (cp) {
        return cp;
    }
    return ap_table_get(r->err_headers_out, a);
}

static const char *log_note(request_rec *r, char *a)
{
    return ap_table_get(r->notes, a);
}
static const char *log_env_var(request_rec *r, char *a)
{
    return ap_table_get(r->subprocess_env, a);
}

static const char *log_request_time(request_rec *r, char *a)
{
    int timz;
    struct tm *t;
    char tstr[MAX_STRING_LEN];

    t = ap_get_gmtoff(&timz);

    if (a && *a) {              /* Custom format */
        strftime(tstr, MAX_STRING_LEN, a, t);
    }
    else {                      /* CLF format */
        char sign = (timz < 0 ? '-' : '+');

        if (timz < 0) {
            timz = -timz;
        }
        ap_snprintf(tstr, sizeof(tstr), "[%02d/%s/%d:%02d:%02d:%02d %c%.2d%.2d]",
                t->tm_mday, ap_month_snames[t->tm_mon], t->tm_year+1900, 
                t->tm_hour, t->tm_min, t->tm_sec,
                sign, timz / 60, timz % 60);
    }

    return ap_pstrdup(r->pool, tstr);
}

static const char *log_request_duration(request_rec *r, char *a)
{
    return ap_psprintf(r->pool, "%ld", time(NULL) - r->request_time);
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
    return ap_psprintf(r->pool, "%u",
	r->server->port ? r->server->port : ap_default_port(r));
}

/* This respects the setting of UseCanonicalName so that
 * the dynamic mass virtual hosting trick works better.
 */
static const char *log_server_name(request_rec *r, char *a)
{
    return ap_get_server_name(r);
}

static const char *log_child_pid(request_rec *r, char *a)
{
    return ap_psprintf(r->pool, "%ld", (long) getpid());
}

static const char *log_connection_status(request_rec *r, char *a)
{
    if (r->connection->aborted)
        return "X";

    if ((r->connection->keepalive) &&
        ((r->server->keep_alive_max - r->connection->keepalives) > 0)) {
        return "+";
    }

    return "-";
}

/*****************************************************************
 *
 * Parsing the log format string
 */

static struct log_item_list {
    char ch;
    item_key_func func;
    int want_orig_default;
} log_item_keys[] = {

    {
        'h', log_remote_host, 0
    },
    {   
        'a', log_remote_address, 0 
    },
    {   
        'A', log_local_address, 0 
    },
    {
        'l', log_remote_logname, 0
    },
    {
        'u', log_remote_user, 0
    },
    {
        't', log_request_time, 0
    },
    {
        'T', log_request_duration, 1
    },
    {
        'r', log_request_line, 1
    },
    {
        'f', log_request_file, 0
    },
    {
        'U', log_request_uri, 1
    },
    {
        's', log_status, 1
    },
    {
        'b', clf_log_bytes_sent, 0
    },
    {
        'B', log_bytes_sent, 0
    },
    {
        'i', log_header_in, 0
    },
    {
        'o', log_header_out, 0
    },
    {
        'n', log_note, 0
    },
    {
        'e', log_env_var, 0
    },
    {
        'V', log_server_name, 0
    },
    {
        'v', log_virtual_host, 0
    },
    {
        'p', log_server_port, 0
    },
    {
        'P', log_child_pid, 0
    },
    {
        'H', log_request_protocol, 0
    },
    {
        'm', log_request_method, 0
    },
    {
        'q', log_request_query, 0
    },
    {
        'c', log_connection_status, 0
    },
    {
        '\0'
    }
};

static struct log_item_list *find_log_func(char k)
{
    int i;

    for (i = 0; log_item_keys[i].ch; ++i)
        if (k == log_item_keys[i].ch) {
            return &log_item_keys[i];
        }

    return NULL;
}

static char *parse_log_misc_string(pool *p, log_format_item *it,
                                   const char **sa)
{
    const char *s;
    char *d;

    it->func = constant_item;
    it->conditions = NULL;

    s = *sa;
    while (*s && *s != '%') {
	s++;
    }
    /*
     * This might allocate a few chars extra if there's a backslash
     * escape in the format string.
     */
    it->arg = ap_palloc(p, s - *sa + 1);

    d = it->arg;
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

static char *parse_log_item(pool *p, log_format_item *it, const char **sa)
{
    const char *s = *sa;

    if (*s != '%') {
        return parse_log_misc_string(p, it, sa);
    }

    ++s;
    it->condition_sense = 0;
    it->conditions = NULL;
    it->want_orig = -1;
    it->arg = "";               /* For safety's sake... */

    while (*s) {
        int i;
        struct log_item_list *l;

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
            while (ap_isdigit(*++s)) {
                i = i * 10 + (*s) - '0';
            }
            if (!it->conditions) {
                it->conditions = ap_make_array(p, 4, sizeof(int));
            }
            *(int *) ap_push_array(it->conditions) = i;
            break;

        default:
            l = find_log_func(*s++);
            if (!l) {
                char dummy[2];

                dummy[0] = s[-1];
                dummy[1] = '\0';
                return ap_pstrcat(p, "Unrecognized LogFormat directive %",
                               dummy, NULL);
            }
            it->func = l->func;
            if (it->want_orig == -1) {
                it->want_orig = l->want_orig_default;
            }
            *sa = s;
            return NULL;
        }
    }

    return "Ran off end of LogFormat parsing args to some directive";
}

static array_header *parse_log_string(pool *p, const char *s, const char **err)
{
    array_header *a = ap_make_array(p, 30, sizeof(log_format_item));
    char *res;

    while (*s) {
        if ((res = parse_log_item(p, (log_format_item *) ap_push_array(a), &s))) {
            *err = res;
            return NULL;
        }
    }

    s = "\n";
    parse_log_item(p, (log_format_item *) ap_push_array(a), &s);
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
            return "-";
        }
    }

    /* We do.  Do it... */

    cp = (*item->func) (item->want_orig ? orig : r, item->arg);
    return cp ? cp : "-";
}

#ifdef BUFFERED_LOGS
static void flush_log(config_log_state *cls)
{
    if (cls->outcnt && cls->log_fd != -1) {
        write(cls->log_fd, cls->outbuf, cls->outcnt);
        cls->outcnt = 0;
    }
}
#endif

static int config_log_transaction(request_rec *r, config_log_state *cls,
                                  array_header *default_format)
{
    log_format_item *items;
    char *str, *s;
    const char **strs;
    int *strl;
    request_rec *orig;
    int i;
    int len = 0;
    array_header *format;
    char *envar;

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
	    if (ap_table_get(r->subprocess_env, envar) == NULL) {
		return DECLINED;
	    }
	}
	else {
	    if (ap_table_get(r->subprocess_env, &envar[1]) != NULL) {
		return DECLINED;
	    }
	}
    }

    format = cls->format ? cls->format : default_format;

    strs = ap_palloc(r->pool, sizeof(char *) * (format->nelts));
    strl = ap_palloc(r->pool, sizeof(int) * (format->nelts));
    items = (log_format_item *) format->elts;

    orig = r;
    while (orig->prev) {
        orig = orig->prev;
    }
    while (r->next) {
        r = r->next;
    }

    for (i = 0; i < format->nelts; ++i) {
        strs[i] = process_item(r, orig, &items[i]);
    }

    for (i = 0; i < format->nelts; ++i) {
        len += strl[i] = strlen(strs[i]);
    }

#ifdef BUFFERED_LOGS
    if (len + cls->outcnt > LOG_BUFSIZE) {
        flush_log(cls);
    }
    if (len >= LOG_BUFSIZE) {
        str = ap_palloc(r->pool, len + 1);
        for (i = 0, s = str; i < format->nelts; ++i) {
            memcpy(s, strs[i], strl[i]);
            s += strl[i];
        }
        write(cls->log_fd, str, len);
    }
    else {
        for (i = 0, s = &cls->outbuf[cls->outcnt]; i < format->nelts; ++i) {
            memcpy(s, strs[i], strl[i]);
            s += strl[i];
        }
        cls->outcnt += len;
    }
#else
    str = ap_palloc(r->pool, len + 1);

    for (i = 0, s = str; i < format->nelts; ++i) {
        memcpy(s, strs[i], strl[i]);
        s += strl[i];
    }

    write(cls->log_fd, str, len);
#endif

    return OK;
}

static int multi_log_transaction(request_rec *r)
{
    multi_log_state *mls = ap_get_module_config(r->server->module_config,
						&config_log_module);
    config_log_state *clsarray;
    int i;

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
    else if (mls->server_config_logs) {
        clsarray = (config_log_state *) mls->server_config_logs->elts;
        for (i = 0; i < mls->server_config_logs->nelts; ++i) {
            config_log_state *cls = &clsarray[i];

            config_log_transaction(r, cls, mls->default_format);
        }
    }

    return OK;
}

/*****************************************************************
 *
 * Module glue...
 */

static void *make_config_log_state(pool *p, server_rec *s)
{
    multi_log_state *mls;

    mls = (multi_log_state *) ap_palloc(p, sizeof(multi_log_state));
    mls->config_logs = ap_make_array(p, 1, sizeof(config_log_state));
    mls->default_format_string = NULL;
    mls->default_format = NULL;
    mls->server_config_logs = NULL;
    mls->formats = ap_make_table(p, 4);
    ap_table_setn(mls->formats, "CLF", DEFAULT_LOG_FORMAT);

    return mls;
}

/*
 * Use the merger to simply add a pointer from the vhost log state
 * to the log of logs specified for the non-vhost configuration.  Make sure
 * vhosts inherit any globally-defined format names.
 */

static void *merge_config_log_state(pool *p, void *basev, void *addv)
{
    multi_log_state *base = (multi_log_state *) basev;
    multi_log_state *add = (multi_log_state *) addv;

    add->server_config_logs = base->config_logs;
    if (!add->default_format) {
        add->default_format_string = base->default_format_string;
        add->default_format = base->default_format;
    }
    add->formats = ap_overlay_tables(p, base->formats, add->formats);

    return add;
}

/*
 * Set the default logfile format, or define a nickname for a format string.
 */
static const char *log_format(cmd_parms *cmd, void *dummy, char *fmt,
                              char *name)
{
    const char *err_string = NULL;
    multi_log_state *mls = ap_get_module_config(cmd->server->module_config,
						&config_log_module);

    /*
     * If we were given two arguments, the second is a name to be given to the
     * format.  This syntax just defines the nickname - it doesn't actually
     * make the format the default.
     */
    if (name != NULL) {
        parse_log_string(cmd->pool, fmt, &err_string);
        if (err_string == NULL) {
            ap_table_setn(mls->formats, name, fmt);
        }
    }
    else {
        mls->default_format_string = fmt;
        mls->default_format = parse_log_string(cmd->pool, fmt, &err_string);
    }
    return err_string;
}


static const char *add_custom_log(cmd_parms *cmd, void *dummy, char *fn,
                                  char *fmt, char *envclause)
{
    const char *err_string = NULL;
    multi_log_state *mls = ap_get_module_config(cmd->server->module_config,
						&config_log_module);
    config_log_state *cls;

    cls = (config_log_state *) ap_push_array(mls->config_logs);
    cls->condition_var = NULL;
    if (envclause != NULL) {
	if (strncasecmp(envclause, "env=", 4) != 0) {
	    return "error in condition clause";
	}
	if ((envclause[4] == '\0')
	    || ((envclause[4] == '!') && (envclause[5] == '\0'))) {
	    return "missing environment variable name";
	}
	cls->condition_var = ap_pstrdup(cmd->pool, &envclause[4]);
    }

    cls->fname = fn;
    cls->format_string = fmt;
    if (fmt == NULL) {
        cls->format = NULL;
    }
    else {
        cls->format = parse_log_string(cmd->pool, fmt, &err_string);
    }
    cls->log_fd = -1;

    return err_string;
}

static const char *set_transfer_log(cmd_parms *cmd, void *dummy, char *fn)
{
    return add_custom_log(cmd, dummy, fn, NULL, NULL);
}

static const char *set_cookie_log(cmd_parms *cmd, void *dummy, char *fn)
{
    return add_custom_log(cmd, dummy, fn, "%{Cookie}n \"%r\" %t", NULL);
}

static const command_rec config_log_cmds[] =
{
    {"CustomLog", add_custom_log, NULL, RSRC_CONF, TAKE23,
     "a file name, a custom log format string or format name, "
     "and an optional \"env=\" clause (see docs)"},
    {"TransferLog", set_transfer_log, NULL, RSRC_CONF, TAKE1,
     "the filename of the access log"},
    {"LogFormat", log_format, NULL, RSRC_CONF, TAKE12,
     "a log format string (see docs) and an optional format name"},
    {"CookieLog", set_cookie_log, NULL, RSRC_CONF, TAKE1,
     "the filename of the cookie log"},
    {NULL}
};

static config_log_state *open_config_log(server_rec *s, pool *p,
                                         config_log_state *cls,
                                         array_header *default_format)
{
    if (cls->log_fd > 0) {
        return cls;             /* virtual config shared w/main server */
    }

    if (cls->fname == NULL) {
        return cls;             /* Leave it NULL to decline.  */
    }

    if (*cls->fname == '|') {
        piped_log *pl;

        pl = ap_open_piped_log(p, cls->fname + 1);
        if (pl == NULL) {
            exit(1);
        }
        cls->log_fd = ap_piped_log_write_fd(pl);
    }
    else {
        char *fname = ap_server_root_relative(p, cls->fname);
        if ((cls->log_fd = ap_popenf_ex(p, fname, xfer_flags, xfer_mode, 1))
             < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                         "could not open transfer log file %s.", fname);
            exit(1);
        }
    }
#ifdef BUFFERED_LOGS
    cls->outcnt = 0;
#endif

    return cls;
}

static config_log_state *open_multi_logs(server_rec *s, pool *p)
{
    int i;
    multi_log_state *mls = ap_get_module_config(s->module_config,
                                             &config_log_module);
    config_log_state *clsarray;
    const char *dummy;
    const char *format;

    if (mls->default_format_string) {
	format = ap_table_get(mls->formats, mls->default_format_string);
	if (format) {
	    mls->default_format = parse_log_string(p, format, &dummy);
	}
    }    

    if (!mls->default_format) {
        mls->default_format = parse_log_string(p, DEFAULT_LOG_FORMAT, &dummy);
    }

    if (mls->config_logs->nelts) {
        clsarray = (config_log_state *) mls->config_logs->elts;
        for (i = 0; i < mls->config_logs->nelts; ++i) {
            config_log_state *cls = &clsarray[i];

	    if (cls->format_string) {
		format = ap_table_get(mls->formats, cls->format_string);
		if (format) {
		    cls->format = parse_log_string(p, format, &dummy);
		}
	    }

            cls = open_config_log(s, p, cls, mls->default_format);
        }
    }
    else if (mls->server_config_logs) {
        clsarray = (config_log_state *) mls->server_config_logs->elts;
        for (i = 0; i < mls->server_config_logs->nelts; ++i) {
            config_log_state *cls = &clsarray[i];

	    if (cls->format_string) {
		format = ap_table_get(mls->formats, cls->format_string);
		if (format) {
		    cls->format = parse_log_string(p, format, &dummy);
		}
	    }

            cls = open_config_log(s, p, cls, mls->default_format);
        }
    }

    return NULL;
}

static void init_config_log(server_rec *s, pool *p)
{
    /* First, do "physical" server, which gets default log fd and format
     * for the virtual servers, if they don't override...
     */

    open_multi_logs(s, p);

    /* Then, virtual servers */

    for (s = s->next; s; s = s->next) {
        open_multi_logs(s, p);
    }
}

#ifdef BUFFERED_LOGS
static void flush_all_logs(server_rec *s, pool *p)
{
    multi_log_state *mls;
    array_header *log_list;
    config_log_state *clsarray;
    int i;

    for (; s; s = s->next) {
        mls = ap_get_module_config(s->module_config, &config_log_module);
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
                flush_log(&clsarray[i]);
            }
        }
    }
}
#endif

module MODULE_VAR_EXPORT config_log_module =
{
    STANDARD_MODULE_STUFF,
    init_config_log,            /* initializer */
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    make_config_log_state,      /* server config */
    merge_config_log_state,     /* merge server config */
    config_log_cmds,            /* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    multi_log_transaction,      /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
#ifdef BUFFERED_LOGS
    flush_all_logs,             /* child_exit */
#else
    NULL,
#endif
    NULL                        /* post read-request */
};
