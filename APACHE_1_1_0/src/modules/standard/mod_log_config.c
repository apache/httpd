
/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
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
 * common log module), and an additional directive, LogFormat.
 *
 * The argument to LogFormat is a string, which can include literal
 * characters copied into the log files, and '%' directives as follows:
 *
 * %...h:  remote host
 * %...l:  remote logname (from identd, if supplied)
 * %...u:  remote user (from auth; may be bogus if return status (%s) is 401)
 * %...t:  time, in common log format time format
 * %...r:  first line of request
 * %...s:  status.  For requests that got internally redirected, this
 *         is status of the *original* request --- %...>s for the last.
 * %...b:  bytes sent.
 * %...{Foobar}i:  The contents of Foobar: header line(s) in the request
 *                 sent to the client.
 * %...{Foobar}o:  The contents of Foobar: header line(s) in the reply.
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
 * That means that you can do things like:
 *
 * <VirtualHost hosta.com>
 * LogFormat "hosta ..."
 * ...
 * </VirtualHost>
 *
 * <VirtualHost hosta.com>
 * LogFormat "hostb ..."
 * ...
 * </VirtualHost>
 *
 * ... to have different virtual servers write into the same log file,
 * but have some indication which host they came from, though a %v
 * directive may well be a better way to handle this.
 *
 * --- rst */

#define DEFAULT_LOG_FORMAT "%h %l %u %t \"%r\" %s %b"

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
    sprintf (dummy, "%d", i);
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

char *log_remote_user (request_rec *r, char *a)
{ return r->connection->user; }

char *log_request_line (request_rec *r, char *a)
{ return r->the_request; }

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
	sprintf(dummy, "%ld", bs);
	return pstrdup(r->pool, dummy);
    }
}

char *log_header_in (request_rec *r, char *a)
{ return table_get (r->headers_in, a); }

char *log_header_out (request_rec *r, char *a)
{
    char *cp = table_get (r->headers_out, a);
    if (cp) return cp;
    return table_get (r->err_headers_out, a);
}

char *log_env_var (request_rec *r, char *a)
{ return table_get (r->subprocess_env, a); }

char *log_request_time (request_rec *r, char *a)
{
    long timz;
    struct tm *t;
    char tstr[MAX_STRING_LEN],sign;
    
    t = get_gmtoff(&timz);
    sign = (timz < 0 ? '-' : '+');
    if(timz < 0) 
        timz = -timz;

    strftime(tstr,MAX_STRING_LEN,"[%d/%b/%Y:%H:%M:%S ",t);

    sprintf (tstr + strlen(tstr), "%c%02ld%02ld]",
	     sign, timz/3600, timz%3600);

    return pstrdup (r->pool, tstr);
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
    { 'r', log_request_line, 1 },
    { 's', log_status, 1 },
    { 'b', log_bytes_sent, 0 },
    { 'i', log_header_in, 0 },
    { 'o', log_header_out, 0 },
    { 'e', log_env_var, 0 },
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

char *log_format_substring (pool *p, char *start, char *end)
{
    char *res = palloc (p, end - start + 1);
    strncpy (res, start, end - start);
    res[end - start] = '\0';
    return res;
}

char *parse_log_misc_string (pool *p, log_format_item *it, char **sa)
{
    char *s = *sa;
    
    it->func = constant_item;
    it->conditions = NULL;

    while (*s && *s != '%') ++s;
    it->arg = log_format_substring (p, *sa, s);
    *sa = s;
    
    return NULL;
}

char *parse_log_item (pool *p, log_format_item *it, char **sa)
{
    char *s = *sa;
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

array_header *parse_log_string (pool *p, char *s, char **err)
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

int config_log_transaction(request_rec *r)
{
    config_log_state *cls = get_module_config (r->server->module_config,
					       &config_log_module);
  
    array_header *strsa= make_array(r->pool, cls->format->nelts,sizeof(char*));
    log_format_item *items = (log_format_item *)cls->format->elts;
    char *str, **strs, *s;
    request_rec *orig;
    int i;
    int len = 0;

    orig = r;
    while (orig->prev) orig = orig->prev;
    while (r->next) r = r->next;

    for (i = 0; i < cls->format->nelts; ++i)
	*((char**)push_array (strsa)) = process_item (r, orig, &items[i]);

    strs = (char **)strsa->elts;
    
    for (i = 0; i < cls->format->nelts; ++i)
	len += strlen (strs[i]);

    str = palloc (r->pool, len + 1);

    for (i = 0, s = str; i < cls->format->nelts; ++i) {
	strcpy (s, strs[i]);
	s += strlen (strs[i]);
    }
    
    write(cls->log_fd, str, strlen(str));

    return OK;
}

/*****************************************************************
 *
 * Module glue...
 */

void *make_config_log_state (pool *p, server_rec *s)
{
    config_log_state *cls =
      (config_log_state *)palloc (p, sizeof (config_log_state));

    cls->fname = NULL;
    cls->format = NULL;
    cls->log_fd = -1;

    return (void *)cls;
}

char *set_config_log (cmd_parms *parms, void *dummy, char *arg)
{
    config_log_state *cls = get_module_config (parms->server->module_config,
					       &config_log_module);
  
    cls->fname = arg;
    return NULL;
}

char *log_format (cmd_parms *cmd, void *dummy, char *arg)
{
    char *err_string = NULL;
    config_log_state *cls = get_module_config (cmd->server->module_config,
					       &config_log_module);
  
    cls->format = parse_log_string (cmd->pool, arg, &err_string);
    return err_string;
}

command_rec config_log_cmds[] = {
{ "TransferLog", set_config_log, NULL, RSRC_CONF, TAKE1,
    "the filename of the access log" },
{ "LogFormat", log_format, NULL, RSRC_CONF, TAKE1,
      "a log format string (see docs)" },
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
    execl (SHELL_PATH, SHELL_PATH, "-c", (char *)cmd, NULL);
    fprintf (stderr, "Exec of shell for logging failed!!!\n");
    exit (1);
}

config_log_state *open_config_log (server_rec *s, pool *p,
				   config_log_state *defaults)
{
    config_log_state *cls = get_module_config (s->module_config,
					       &config_log_module);
  
    if (cls->log_fd > 0) return cls; /* virtual config shared w/main server */
    
    if (cls->format == NULL) {
	char *dummy;
	
	if (defaults) cls->format = defaults->format;
	else cls->format = parse_log_string (p, DEFAULT_LOG_FORMAT, &dummy);
    }

    if (cls->fname == NULL) {
	if (defaults) {
	    cls->log_fd = defaults->log_fd;
	    return cls;
	}
	else cls->fname = DEFAULT_XFERLOG;
    }
    
    if (*cls->fname == '|') {
	FILE *dummy;
	
	spawn_child(p, config_log_child, (void *)(cls->fname+1),
		    kill_after_timeout, &dummy, NULL);

	if (dummy == NULL) {
	    fprintf (stderr, "Couldn't fork child for TransferLog process\n");
	    exit (1);
	}

	cls->log_fd = fileno (dummy);
    }
    else {
	char *fname = server_root_relative (p, cls->fname);
	if((cls->log_fd = popenf(p, fname, xfer_flags, xfer_mode)) < 0) {
	    fprintf (stderr,
		     "httpd: could not open transfer log file %s.\n", fname);
	    perror("open");
	    exit(1);
	}
    }

    return cls;
}

void init_config_log (server_rec *s, pool *p)
{
    /* First, do "physical" server, which gets default log fd and format
     * for the virtual servers, if they don't override...
     */
    
    config_log_state *default_conf = open_config_log (s, p, NULL);
    
    /* Then, virtual servers */
    
    for (s = s->next; s; s = s->next) open_config_log (s, p, default_conf);
}

module config_log_module = {
   STANDARD_MODULE_STUFF,
   init_config_log,		/* initializer */
   NULL,			/* create per-dir config */
   NULL,			/* merge per-dir config */
   make_config_log_state,	/* server config */
   NULL,			/* merge server config */
   config_log_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   config_log_transaction	/* logger */
};
