/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/*
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
 * Except: no RefererIgnore functionality
 *         logs '-' if no Referer or User-Agent instead of nothing
 *
 * But using this method allows much easier modification of the
 * log format, e.g. to log hosts along with UA:
 *   CustomLog   logs/referer "%{referer}i %U %h"
 *
 * The argument to LogFormat and CustomLog is a string, which can include
 * literal characters copied into the log files, and '%' directives as
 * follows:
 *
 * %...b:  bytes sent, excluding HTTP headers.
 * %...{FOOBAR}e:  The contents of the environment variable FOOBAR
 * %...f:  filename
 * %...h:  remote host
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
 * %...v:  the name of the server (i.e. which virtual host?)
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
#include "http_core.h" /* For REMOTE_NAME */

module config_log_module;

static int xfer_flags = ( O_WRONLY | O_APPEND | O_CREAT );
#ifdef __EMX__
/* OS/2 dosen't support users and groups */
static mode_t xfer_mode = ( S_IREAD | S_IWRITE );
#else
static mode_t xfer_mode = ( S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
#endif

/*
 * multi_log_state is our per-(virtual)-server configuration. We store
 * an array of the logs we are going to use, each of type config_log_state.
 * If a default log format is given by LogFormat, store in default_format
 * (backward compat. with mod_log_config). We also store a pointer to
 * the logs specified for the main server for virtual servers, so that
 * if this vhost has now logs defined, we can use the main server's
 * logs instead.
 *
 * So, for the main server, config_logs contains a list of the log files
 * and server_config_logs in empty. For a vhost, server_config_logs
 * points to the same array as config_logs in the main server, and
 * config_logs points to the array of logs defined inside this vhost,
 * which might be empty.
 */

typedef struct {
  array_header *default_format;
  array_header *config_logs;    
  array_header *server_config_logs;
} multi_log_state;

/*
 * config_log_state holds the status of a single log file. fname cannot
 * be NULL. format might be NULL, in which case the default_format from
 * the multi_log_state should be used, or if that is NULL as well, use
 * the CLF. log_fd is -1 before the log file is opened and set to a valid
 * fd after it is opened.
 */

typedef struct {
    char *fname;
    array_header *format;
    int log_fd;
} config_log_state;

/*
 * Format items...
 */

typedef char *(*item_key_func)(request_rec *, char *);

typedef struct {
    item_key_func func;
    char *arg;
    int condition_sense;
    int want_orig;
    array_header *conditions;
} log_format_item;

char *format_integer(pool *p, int i)
{
    char dummy[40];
    ap_snprintf (dummy, sizeof(dummy), "%d", i);
    return pstrdup (p, dummy);
}

static char *pfmt(pool *p, int i)
{
    if (i <= 0) return "-";
    else return format_integer (p, i);
}

char *constant_item (request_rec *dummy, char *stuff) { return stuff; }

char *log_remote_host (request_rec *r, char *a)
{ return (char *)get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME); }

char *log_remote_logname(request_rec *r, char *a)
{return (char *)get_remote_logname(r);}

char *log_remote_user (request_rec *r, char *a) {
    char *rvalue = r->connection->user;

    if (rvalue == NULL) {
        rvalue = "-";
    } else if (strlen (rvalue) == 0) {
        rvalue = "\"\"";
    }
    return rvalue;
}

char *log_request_line (request_rec *r, char *a)
{ return r->the_request; }

char *log_request_file (request_rec *r, char *a)
{ return r->filename; }
char *log_request_uri (request_rec *r, char *a)
{ return r->uri; }
char *log_status (request_rec *r, char *a)
{ return pfmt(r->pool, r->status); }

char *log_bytes_sent (request_rec *r, char *a)
{
    if (!r->sent_bodyct) return "-";
    else
    {
	long int bs;
	char dummy[40];
	bgetopt(r->connection->client, BO_BYTECT, &bs);
	ap_snprintf(dummy, sizeof(dummy), "%ld", bs);
	return pstrdup(r->pool, dummy);
    }
}

char *log_header_in (request_rec *r, char *a)
{ return table_get (r->headers_in, a); }

char *log_header_out (request_rec *r, char *a)
{
    char *cp = table_get (r->headers_out, a);
    if (!strcasecmp(a, "Content-type") && r->content_type)
	cp = r->content_type;
    if (cp) return cp;
    return table_get (r->err_headers_out, a);
}

char *log_note (request_rec *r, char *a)
{ return table_get (r->notes, a); }
char *log_env_var (request_rec *r, char *a)
{ return table_get (r->subprocess_env, a); }

char *log_request_time (request_rec *r, char *a)
{
    int timz;
    struct tm *t;
    char tstr[MAX_STRING_LEN];
    
    t = get_gmtoff(&timz);

    if (a && *a) /* Custom format */
	strftime(tstr, MAX_STRING_LEN, a, t);
    else { /* CLF format */
	char sign = (timz < 0 ? '-' : '+');

	if(timz < 0) timz = -timz;

	strftime(tstr,MAX_STRING_LEN,"[%d/%b/%Y:%H:%M:%S ",t);
	ap_snprintf (tstr + strlen(tstr), sizeof(tstr)-strlen(tstr), 
		"%c%.2d%.2d]", sign, timz/60, timz%60);
    }

    return pstrdup (r->pool, tstr);
}

char *log_request_duration (request_rec *r, char *a) {
    char duration[22];	/* Long enough for 2^64 */

    ap_snprintf(duration, sizeof(duration), "%ld", time(NULL) - r->request_time);
    return pstrdup(r->pool, duration);
}

char *log_virtual_host (request_rec *r, char *a) {
    return pstrdup(r->pool, r->server->server_hostname);
}

char *log_server_port (request_rec *r, char *a) {
    char portnum[22];

    ap_snprintf(portnum, sizeof(portnum), "%u", r->server->port);
    return pstrdup(r->pool, portnum);
}

char *log_child_pid (request_rec *r, char *a) {
    char pidnum[22];
    ap_snprintf(pidnum, sizeof(pidnum), "%ld", (long)getpid());
    return pstrdup(r->pool, pidnum);
}
/*****************************************************************
 *
 * Parsing the log format string
 */

struct log_item_list {
    char ch;
    item_key_func func;
    int want_orig_default;
} log_item_keys[] = {
    { 'h', log_remote_host, 0 },
    { 'l', log_remote_logname, 0 },
    { 'u', log_remote_user, 0 },
    { 't', log_request_time, 0 },
    { 'T', log_request_duration, 1 },
    { 'r', log_request_line, 1 },
    { 'f', log_request_file, 0 },
    { 'U', log_request_uri, 1 },
    { 's', log_status, 1 },
    { 'b', log_bytes_sent, 0 },
    { 'i', log_header_in, 0 },
    { 'o', log_header_out, 0 },
    { 'n', log_note, 0 },
    { 'e', log_env_var, 0 },
    { 'v', log_virtual_host, 0 },
    { 'p', log_server_port, 0 },
    { 'P', log_child_pid, 0 },
    { '\0' }
};

struct log_item_list  *find_log_func (char k)
{
    int i;

    for (i = 0; log_item_keys[i].ch; ++i)
	if (k == log_item_keys[i].ch)
	    return &log_item_keys[i];

    return NULL;
}

char *log_format_substring (pool *p, const char *start, const char *end)
{
    char *res = palloc (p, end - start + 1);
    strncpy (res, start, end - start);
    res[end - start] = '\0';
    return res;
}

char *parse_log_misc_string (pool *p, log_format_item *it, const char **sa)
{
    const char *s = *sa;
    
    it->func = constant_item;
    it->conditions = NULL;

    while (*s && *s != '%') ++s;
    it->arg = log_format_substring (p, *sa, s);
    *sa = s;
    
    return NULL;
}

char *parse_log_item (pool *p, log_format_item *it, const char **sa)
{
    const char *s = *sa;
    if (*s != '%') return parse_log_misc_string (p, it, sa);

    ++s;
    it->condition_sense = 0;
    it->conditions = NULL;
    it->want_orig = -1;
    it->arg = "";		/* For safety's sake... */

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
	    it->arg = getword (p, &s, '}');
	    break;
	    
	case '0': case '1': case '2': case '3': case '4': 
	case '5': case '6': case '7': case '8': case '9':
	    i = *s - '0';
	    while (isdigit (*++s)) i = i * 10 + (*s) - '0';
	    if (!it->conditions)
		it->conditions = make_array (p, 4, sizeof(int));
	    *(int *)push_array(it->conditions) = i;
	    break;

	default:
	    l = find_log_func (*s++);
	    if (!l) {
		char dummy[] = { '\0', '\0'};
		dummy[0] = s[-1];
		return pstrcat (p, "Unrecognized LogFormat directive %",
				dummy, NULL);
	    }
	    it->func = l->func;
	    if (it->want_orig == -1) it->want_orig = l->want_orig_default;
	    *sa = s;
	    return NULL;
	}
    }

    return "Ran off end of LogFormat parsing args to some directive";
}

array_header *parse_log_string (pool *p, const char *s, const char **err)
{
    array_header *a = make_array (p, 30, sizeof (log_format_item));
    char *res;

    while (*s) {
	if ((res = parse_log_item (p, (log_format_item *)push_array(a), &s))) {
	    *err = res;
	    return NULL;
	}
    }

    s = "\n";
    parse_log_item (p, (log_format_item *)push_array(a), &s);
    return a;
}

/*****************************************************************
 *
 * Actually logging.
 */

char *process_item(request_rec *r, request_rec *orig, log_format_item *item)
{
    char *cp;
    
    /* First, see if we need to process this thing at all... */

    if (item->conditions && item->conditions->nelts != 0) {
	int i;
	int *conds = (int *)item->conditions->elts;
	int in_list = 0;

	for (i = 0; i < item->conditions->nelts; ++i)
	    if (r->status == conds[i]) {
		in_list = 1;
		break;
	    }

	if ((item->condition_sense && in_list)
	    || (!item->condition_sense && !in_list))
	{
	    return "-";
	}
    }

    /* We do.  Do it... */

    cp = (*item->func)(item->want_orig ? orig : r, item->arg);
    return cp ? cp : "-";
}

int config_log_transaction(request_rec *r, config_log_state *cls,
			   array_header *default_format) {
    array_header *strsa;
    log_format_item *items;
    char *str, **strs, *s;
    request_rec *orig;
    int i;
    int len = 0;
    array_header *format;

    format = cls->format ? cls->format : default_format;

    strsa= make_array(r->pool, format->nelts,sizeof(char*));
    items = (log_format_item *)format->elts;

    orig = r;
    while (orig->prev) orig = orig->prev;
    while (r->next) r = r->next;

    for (i = 0; i < format->nelts; ++i)
        *((char**)push_array (strsa)) = process_item (r, orig, &items[i]);

    strs = (char **)strsa->elts;
    
    for (i = 0; i < format->nelts; ++i)
        len += strlen (strs[i]);

    str = palloc (r->pool, len + 1);

    for (i = 0, s = str; i < format->nelts; ++i) {
        strcpy (s, strs[i]);
        s += strlen (strs[i]);
    }
    
    write(cls->log_fd, str, strlen(str));

    return OK;
}

int multi_log_transaction(request_rec *r)
{
    multi_log_state *mls = get_module_config (r->server->module_config,
                                               &config_log_module);
    config_log_state *clsarray;
    int i;

    if (mls->config_logs->nelts) {
        clsarray = (config_log_state *)mls->config_logs->elts;
        for (i = 0; i < mls->config_logs->nelts; ++i) {
            config_log_state *cls = &clsarray[i];
        
            config_log_transaction(r, cls, mls->default_format);
        }
    }
    else if (mls->server_config_logs) {
        clsarray = (config_log_state *)mls->server_config_logs->elts;
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

void *make_config_log_state (pool *p, server_rec *s)
{
    multi_log_state *mls =
	(multi_log_state *)palloc(p, sizeof (multi_log_state));
    
    mls->config_logs = 
	make_array(p, 5, sizeof (config_log_state));
    mls->default_format = NULL;
    mls->server_config_logs = NULL;
    
    return mls;
}

/*
 * Use the merger to simply add a pointer from the vhost log state
 * to the log of logs specified for the non-vhost configuration
 */

void *merge_config_log_state (pool *p, void *basev, void *addv)
{
    multi_log_state *base = (multi_log_state *)basev;
    multi_log_state *add = (multi_log_state *)addv;
    
    add->server_config_logs = base->config_logs;
    if (!add->default_format)
        add->default_format = base->default_format;
    
    return add;
}

const char *log_format (cmd_parms *cmd, void *dummy, char *arg)
{
    const char *err_string = NULL;
    multi_log_state *mls = get_module_config (cmd->server->module_config,
					       &config_log_module);
  
    mls->default_format = parse_log_string (cmd->pool, arg, &err_string);
    return err_string;
}

const char *add_custom_log(cmd_parms *cmd, void *dummy, char *fn, char *fmt)
{
    const char *err_string = NULL;
    multi_log_state *mls = get_module_config (cmd->server->module_config,
					      &config_log_module);
    config_log_state *cls;

    cls = (config_log_state*)push_array(mls->config_logs);
    cls->fname = fn;
    if (!fmt)
	cls->format = NULL;
    else
	cls->format = parse_log_string (cmd->pool, fmt, &err_string);
    cls->log_fd = -1;
    
    return err_string;
}

const char *set_transfer_log(cmd_parms *cmd, void *dummy, char *fn)
{
    return add_custom_log(cmd, dummy, fn, NULL);
}

const char *set_cookie_log(cmd_parms *cmd, void *dummy, char *fn)
{
    return add_custom_log(cmd, dummy, fn, "%{Cookie}n \"%r\" %t");
}

command_rec config_log_cmds[] = {
{ "CustomLog", add_custom_log, NULL, RSRC_CONF, TAKE2,
    "a file name and a custom log format string" },
{ "TransferLog", set_transfer_log, NULL, RSRC_CONF, TAKE1,
    "the filename of the access log" },
{ "LogFormat", log_format, NULL, RSRC_CONF, TAKE1,
    "a log format string (see docs)" },
{ "CookieLog", set_cookie_log, NULL, RSRC_CONF, TAKE1,
    "the filename of the cookie log" },
{ NULL }
};

void config_log_child (void *cmd)
{
    /* Child process code for 'TransferLog "|..."';
     * may want a common framework for this, since I expect it will
     * be common for other foo-loggers to want this sort of thing...
     */
    
    cleanup_for_exec();
    signal (SIGHUP, SIG_IGN);
#ifdef __EMX__
    /* For OS/2 we need to use a '/' */
    execl (SHELL_PATH, SHELL_PATH, "/c", (char *)cmd, NULL);
#else
    execl (SHELL_PATH, SHELL_PATH, "-c", (char *)cmd, NULL);
#endif
    perror ("exec");
    fprintf (stderr, "Exec of shell for logging failed!!!\n");
    exit (1);
}

config_log_state *open_config_log (server_rec *s, pool *p,
				   config_log_state *cls,
				   array_header *default_format) {
    if (cls->log_fd > 0) return cls; /* virtual config shared w/main server */

    if (*cls->fname == '|') {
        FILE *dummy;
        
        if (!spawn_child (p, config_log_child, (void *)(cls->fname+1),
                    kill_after_timeout, &dummy, NULL)) {
	    perror ("spawn_child");
            fprintf (stderr, "Couldn't fork child for TransferLog process\n");
            exit (1);
        }

        cls->log_fd = fileno (dummy);
    }
    else {
        char *fname = server_root_relative (p, cls->fname);
        if((cls->log_fd = popenf(p, fname, xfer_flags, xfer_mode)) < 0) {
            perror("open");
            fprintf (stderr,
                     "httpd: could not open transfer log file %s.\n", fname);
            exit(1);
        }
    }

    return cls;
}

config_log_state *open_multi_logs (server_rec *s, pool *p)
{
    int i;
    multi_log_state *mls = get_module_config(s->module_config,
                                             &config_log_module);
    config_log_state *clsarray;
    const char *dummy;

    if (!mls->default_format)
      mls->default_format = parse_log_string (p, DEFAULT_LOG_FORMAT, &dummy);

    if (mls->config_logs->nelts) {
        clsarray = (config_log_state *)mls->config_logs->elts;
        for (i = 0; i < mls->config_logs->nelts; ++i) {
            config_log_state *cls = &clsarray[i];

            cls = open_config_log(s, p, cls, mls->default_format);
                }
    }
    else if (mls->server_config_logs) {
        clsarray = (config_log_state *)mls->server_config_logs->elts;
        for (i = 0; i < mls->server_config_logs->nelts; ++i) {
            config_log_state *cls = &clsarray[i];

            cls = open_config_log(s, p, cls, mls->default_format);
        }
    }

    return NULL;
}

void init_config_log (server_rec *s, pool *p)
{
    /* First, do "physical" server, which gets default log fd and format
     * for the virtual servers, if they don't override...
     */
    
    open_multi_logs (s, p);
    
    /* Then, virtual servers */
    
    for (s = s->next; s; s = s->next) open_multi_logs (s, p);
}

module config_log_module = {
   STANDARD_MODULE_STUFF,
   init_config_log,		/* initializer */
   NULL,			/* create per-dir config */
   NULL,			/* merge per-dir config */
   make_config_log_state,	/* server config */
   merge_config_log_state,     	/* merge server config */
   config_log_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   multi_log_transaction,	/* logger */
   NULL				/* header parser */
};
