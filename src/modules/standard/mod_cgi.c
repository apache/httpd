/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
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
 * http_script: keeps all script-related ramblings together.
 * 
 * Compliant to CGI/1.1 spec
 * 
 * Adapted by rst from original NCSA code by Rob McCool
 *
 * Apache adds some new env vars; REDIRECT_URL and REDIRECT_QUERY_STRING for
 * custom error responses, and DOCUMENT_ROOT because we found it useful.
 * It also adds SERVER_ADMIN - useful for scripts to know who to mail when 
 * they fail.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"
#include "http_conf_globals.h"

module MODULE_VAR_EXPORT cgi_module;

/* KLUDGE --- for back-combatibility, we don't have to check ExecCGI
 * in ScriptAliased directories, which means we need to know if this
 * request came through ScriptAlias or not... so the Alias module
 * leaves a note for us.
 */

static int is_scriptaliased(request_rec *r)
{
    const char *t = ap_table_get(r->notes, "alias-forced-type");
    return t && (!strcasecmp(t, "cgi-script"));
}

/* Configuration stuff */

#define DEFAULT_LOGBYTES 10385760
#define DEFAULT_BUFBYTES 1024

typedef struct {
    char *logname;
    long logbytes;
    int bufbytes;
} cgi_server_conf;

static void *create_cgi_config(pool *p, server_rec *s)
{
    cgi_server_conf *c =
    (cgi_server_conf *) ap_pcalloc(p, sizeof(cgi_server_conf));

    c->logname = NULL;
    c->logbytes = DEFAULT_LOGBYTES;
    c->bufbytes = DEFAULT_BUFBYTES;

    return c;
}

static void *merge_cgi_config(pool *p, void *basev, void *overridesv)
{
    cgi_server_conf *base = (cgi_server_conf *) basev, *overrides = (cgi_server_conf *) overridesv;

    return overrides->logname ? overrides : base;
}

static const char *set_scriptlog(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    cgi_server_conf *conf =
    (cgi_server_conf *) ap_get_module_config(s->module_config, &cgi_module);

    conf->logname = arg;
    return NULL;
}

static const char *set_scriptlog_length(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    cgi_server_conf *conf =
    (cgi_server_conf *) ap_get_module_config(s->module_config, &cgi_module);

    conf->logbytes = atol(arg);
    return NULL;
}

static const char *set_scriptlog_buffer(cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *s = cmd->server;
    cgi_server_conf *conf =
    (cgi_server_conf *) ap_get_module_config(s->module_config, &cgi_module);

    conf->bufbytes = atoi(arg);
    return NULL;
}

static const command_rec cgi_cmds[] =
{
    {"ScriptLog", set_scriptlog, NULL, RSRC_CONF, TAKE1,
     "the name of a log for script debugging info"},
    {"ScriptLogLength", set_scriptlog_length, NULL, RSRC_CONF, TAKE1,
     "the maximum length (in bytes) of the script debug log"},
    {"ScriptLogBuffer", set_scriptlog_buffer, NULL, RSRC_CONF, TAKE1,
     "the maximum size (in bytes) to record of a POST request"},
    {NULL}
};

static int log_scripterror(request_rec *r, cgi_server_conf * conf, int ret,
			   int show_errno, char *error)
{
    FILE *f;
    struct stat finfo;

    ap_log_rerror(APLOG_MARK, show_errno|APLOG_ERR, r, 
		"%s: %s", error, r->filename);

    if (!conf->logname ||
	((stat(ap_server_root_relative(r->pool, conf->logname), &finfo) == 0)
	 &&   (finfo.st_size > conf->logbytes)) ||
         ((f = ap_pfopen(r->pool, ap_server_root_relative(r->pool, conf->logname),
		      "a")) == NULL)) {
	return ret;
    }

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgi-bin/printenv HTTP/1.0" */
    fprintf(f, "%%%% [%s] %s %s%s%s %s\n", ap_get_time(), r->method, r->uri,
	    r->args ? "?" : "", r->args ? r->args : "", r->protocol);
    /* "%% 500 /usr/local/apache/cgi-bin */
    fprintf(f, "%%%% %d %s\n", ret, r->filename);

    fprintf(f, "%%error\n%s\n", error);

    ap_pfclose(r->pool, f);
    return ret;
}

static int log_script(request_rec *r, cgi_server_conf * conf, int ret,
		  char *dbuf, const char *sbuf, BUFF *script_in, BUFF *script_err)
{
    array_header *hdrs_arr = ap_table_elts(r->headers_in);
    table_entry *hdrs = (table_entry *) hdrs_arr->elts;
    char argsbuffer[HUGE_STRING_LEN];
    FILE *f;
    int i;
    struct stat finfo;

    if (!conf->logname ||
	((stat(ap_server_root_relative(r->pool, conf->logname), &finfo) == 0)
	 &&   (finfo.st_size > conf->logbytes)) ||
         ((f = ap_pfopen(r->pool, ap_server_root_relative(r->pool, conf->logname),
		      "a")) == NULL)) {
	/* Soak up script output */
	while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_in) > 0)
	    continue;
#if defined(WIN32) || defined(NETWARE)
        /* Soak up stderr and redirect it to the error log.
         * Script output to stderr is already directed to the error log
         * on Unix, thanks to the magic of fork().
         */
        while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_err) > 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, r, 
                          "%s", argsbuffer);            
        }
#else
	while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_err) > 0)
	    continue;
#endif
	return ret;
    }

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgi-bin/printenv HTTP/1.0" */
    fprintf(f, "%%%% [%s] %s %s%s%s %s\n", ap_get_time(), r->method, r->uri,
	    r->args ? "?" : "", r->args ? r->args : "", r->protocol);
    /* "%% 500 /usr/local/apache/cgi-bin" */
    fprintf(f, "%%%% %d %s\n", ret, r->filename);

    fputs("%request\n", f);
    for (i = 0; i < hdrs_arr->nelts; ++i) {
	if (!hdrs[i].key)
	    continue;
	fprintf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val);
    }
    if ((r->method_number == M_POST || r->method_number == M_PUT)
	&& *dbuf) {
	fprintf(f, "\n%s\n", dbuf);
    }

    fputs("%response\n", f);
    hdrs_arr = ap_table_elts(r->err_headers_out);
    hdrs = (table_entry *) hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; ++i) {
	if (!hdrs[i].key)
	    continue;
	fprintf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val);
    }

    if (sbuf && *sbuf)
	fprintf(f, "%s\n", sbuf);

    if (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_in) > 0) {
	fputs("%stdout\n", f);
	fputs(argsbuffer, f);
	while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_in) > 0)
	    fputs(argsbuffer, f);
	fputs("\n", f);
    }

    if (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_err) > 0) {
	fputs("%stderr\n", f);
	fputs(argsbuffer, f);
	while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_err) > 0)
	    fputs(argsbuffer, f);
	fputs("\n", f);
    }

    ap_bclose(script_in);
    ap_bclose(script_err);

    ap_pfclose(r->pool, f);
    return ret;
}

/****************************************************************
 *
 * Actual CGI handling...
 */


struct cgi_child_stuff {
#ifdef TPF
    TPF_FORK_CHILD t;
#endif
    request_rec *r;
    int nph;
    int debug;
    char *argv0;
};

static int cgi_child(void *child_stuff, child_info *pinfo)
{
    struct cgi_child_stuff *cld = (struct cgi_child_stuff *) child_stuff;
    request_rec *r = cld->r;
    char *argv0 = cld->argv0;
    int child_pid;

#ifdef DEBUG_CGI
#ifdef OS2
    /* Under OS/2 need to use device con. */
    FILE *dbg = fopen("con", "w");
#else
    FILE *dbg = fopen("/dev/tty", "w");
#endif
    int i;
#endif

    char **env;

    RAISE_SIGSTOP(CGI_CHILD);
#ifdef DEBUG_CGI
    fprintf(dbg, "Attempting to exec %s as %sCGI child (argv0 = %s)\n",
	    r->filename, cld->nph ? "NPH " : "", argv0);
#endif

    ap_add_cgi_vars(r);
    env = ap_create_environment(r->pool, r->subprocess_env);

#ifdef DEBUG_CGI
    fprintf(dbg, "Environment: \n");
    for (i = 0; env[i]; ++i)
	fprintf(dbg, "'%s'\n", env[i]);
#endif

#ifndef WIN32
    ap_chdir_file(r->filename);
#endif
    if (!cld->debug)
	ap_error_log2stderr(r->server);

    /* Transumute outselves into the script.
     * NB only ISINDEX scripts get decoded arguments.
     */

#ifdef TPF
    return (0);
#else
    ap_cleanup_for_exec();

    child_pid = ap_call_exec(r, pinfo, argv0, env, 0);
#if defined(WIN32) || defined(OS2)
    return (child_pid);
#else

    /* Uh oh.  Still here.  Where's the kaboom?  There was supposed to be an
     * EARTH-shattering kaboom!
     *
     * Oh, well.  Muddle through as best we can...
     *
     * Note that only stderr is available at this point, so don't pass in
     * a server to aplog_error.
     */

    ap_log_error(APLOG_MARK, APLOG_ERR, NULL, "exec of %s failed", r->filename);
    exit(0);
    /* NOT REACHED */
    return (0);
#endif
#endif  /* TPF */
}

static int cgi_handler(request_rec *r)
{
    int retval, nph, dbpos = 0;
    char *argv0, *dbuf = NULL;
    BUFF *script_out, *script_in, *script_err;
    char argsbuffer[HUGE_STRING_LEN];
    int is_included = !strcmp(r->protocol, "INCLUDED");
    void *sconf = r->server->module_config;
    cgi_server_conf *conf =
    (cgi_server_conf *) ap_get_module_config(sconf, &cgi_module);

    struct cgi_child_stuff cld;

    if (r->method_number == M_OPTIONS) {
	/* 99 out of 100 CGI scripts, this is all they support */
	r->allowed |= (1 << M_GET);
	r->allowed |= (1 << M_POST);
	return DECLINED;
    }

    if ((argv0 = strrchr(r->filename, '/')) != NULL)
	argv0++;
    else
	argv0 = r->filename;

    nph = !(strncmp(argv0, "nph-", 4));

    if (!(ap_allow_options(r) & OPT_EXECCGI) && !is_scriptaliased(r))
	return log_scripterror(r, conf, FORBIDDEN, APLOG_NOERRNO,
			       "Options ExecCGI is off in this directory");
    if (nph && is_included)
	return log_scripterror(r, conf, FORBIDDEN, APLOG_NOERRNO,
			       "attempt to include NPH CGI script");

#if defined(OS2) || defined(WIN32)
    /* Allow for cgi files without the .EXE extension on them under OS/2 */
    if (r->finfo.st_mode == 0) {
	struct stat statbuf;
	char *newfile;

	newfile = ap_pstrcat(r->pool, r->filename, ".EXE", NULL);

	if ((stat(newfile, &statbuf) != 0) || (!S_ISREG(statbuf.st_mode))) {
	    return log_scripterror(r, conf, NOT_FOUND, 0,
				   "script not found or unable to stat");
	} else {
	    r->filename = newfile;
	}
    }
#else
    if (r->finfo.st_mode == 0)
	return log_scripterror(r, conf, NOT_FOUND, APLOG_NOERRNO,
			       "script not found or unable to stat");
#endif
    if (S_ISDIR(r->finfo.st_mode))
	return log_scripterror(r, conf, FORBIDDEN, APLOG_NOERRNO,
			       "attempt to invoke directory as script");
    if (!ap_suexec_enabled) {
	if (!ap_can_exec(&r->finfo))
	    return log_scripterror(r, conf, FORBIDDEN, APLOG_NOERRNO,
				   "file permissions deny server execution");
    }

    if ((retval = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)))
	return retval;

    ap_add_common_vars(r);
    cld.argv0 = argv0;
    cld.r = r;
    cld.nph = nph;
    cld.debug = conf->logname ? 1 : 0;
#ifdef TPF
    cld.t.filename = r->filename;
    cld.t.subprocess_env = r->subprocess_env;
    cld.t.prog_type = FORK_FILE;
#endif   /* TPF */

#ifdef CHARSET_EBCDIC
    /* XXX:@@@ Is the generated/included output ALWAYS in text/ebcdic format? */
    /* Or must we check the Content-Type first? */
    ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, 1);
#endif /*CHARSET_EBCDIC*/

    /*
     * we spawn out of r->main if it's there so that we can avoid
     * waiting for free_proc_chain to cleanup in the middle of an
     * SSI request -djg
     */
    if (!ap_bspawn_child(r->main ? r->main->pool : r->pool, cgi_child,
			 (void *) &cld, kill_after_timeout,
			 &script_out, &script_in, &script_err)) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "couldn't spawn child process: %s", r->filename);
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Transfer any put/post args, CERN style...
     * Note that we already ignore SIGPIPE in the core server.
     */

    if (ap_should_client_block(r)) {
	int dbsize, len_read;

	if (conf->logname) {
	    dbuf = ap_pcalloc(r->pool, conf->bufbytes + 1);
	    dbpos = 0;
	}

	ap_hard_timeout("copy script args", r);

	while ((len_read =
		ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN)) > 0) {
	    if (conf->logname) {
		if ((dbpos + len_read) > conf->bufbytes) {
		    dbsize = conf->bufbytes - dbpos;
		}
		else {
		    dbsize = len_read;
		}
		memcpy(dbuf + dbpos, argsbuffer, dbsize);
		dbpos += dbsize;
	    }
	    ap_reset_timeout(r);
	    if (ap_bwrite(script_out, argsbuffer, len_read) < len_read) {
		/* silly script stopped reading, soak up remaining message */
		while (ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN) > 0) {
		    /* dump it */
		}
		break;
	    }
	}

	ap_bflush(script_out);

	ap_kill_timeout(r);
    }

    ap_bclose(script_out);

    /* Handle script return... */
    if (script_in && !nph) {
	const char *location;
	char sbuf[MAX_STRING_LEN];
	int ret;

	if ((ret = ap_scan_script_header_err_buff(r, script_in, sbuf))) {
	    return log_script(r, conf, ret, dbuf, sbuf, script_in, script_err);
	}

#ifdef CHARSET_EBCDIC
        /* Now check the Content-Type to decide if conversion is needed */
        ap_checkconv(r);
#endif /*CHARSET_EBCDIC*/

	location = ap_table_get(r->headers_out, "Location");

	if (location && location[0] == '/' && r->status == 200) {

	    /* Soak up all the script output */
	    ap_hard_timeout("read from script", r);
	    while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_in) > 0) {
		continue;
	    }
	    while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_err) > 0) {
		continue;
	    }
	    ap_kill_timeout(r);


	    /* This redirect needs to be a GET no matter what the original
	     * method was.
	     */
	    r->method = ap_pstrdup(r->pool, "GET");
	    r->method_number = M_GET;

	    /* We already read the message body (if any), so don't allow
	     * the redirected request to think it has one.  We can ignore 
	     * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
	     */
	    ap_table_unset(r->headers_in, "Content-Length");

	    ap_internal_redirect_handler(location, r);
	    return OK;
	}
	else if (location && r->status == 200) {
	    /* XX Note that if a script wants to produce its own Redirect
	     * body, it now has to explicitly *say* "Status: 302"
	     */
	    return REDIRECT;
	}

	ap_send_http_header(r);
	if (!r->header_only) {
	    ap_send_fb(script_in, r);
	}
	ap_bclose(script_in);

	ap_soft_timeout("soaking script stderr", r);
	while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_err) > 0) {
	    continue;
	}
	ap_kill_timeout(r);
	ap_bclose(script_err);
    }

    if (script_in && nph) {
	ap_send_fb(script_in, r);
    }

    return OK;			/* NOT r->status, even if it has changed. */
}

static const handler_rec cgi_handlers[] =
{
    {CGI_MAGIC_TYPE, cgi_handler},
    {"cgi-script", cgi_handler},
    {NULL}
};

module MODULE_VAR_EXPORT cgi_module =
{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    NULL,			/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    create_cgi_config,		/* server config */
    merge_cgi_config,		/* merge server config */
    cgi_cmds,			/* command table */
    cgi_handlers,		/* handlers */
    NULL,			/* filename translation */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
