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

module cgi_module;

/* KLUDGE --- for back-combatibility, we don't have to check ExecCGI
 * in ScriptAliased directories, which means we need to know if this
 * request came through ScriptAlias or not... so the Alias module
 * leaves a note for us.
 */

int is_scriptaliased (request_rec *r)
{
    char *t = table_get (r->notes, "alias-forced-type");
    return t && (!strcmp (t, "cgi-script"));
}

/* Configuration stuff */

#define DEFAULT_LOGBYTES 10385760
#define DEFAULT_BUFBYTES 1024

typedef struct {
    char *logname;
    long logbytes;
    int bufbytes;
} cgi_server_conf;

void *create_cgi_config (pool *p, server_rec *s)
{
    cgi_server_conf *c = 
      (cgi_server_conf *)pcalloc (p, sizeof(cgi_server_conf));

    c->logname = NULL;
    c->logbytes = DEFAULT_LOGBYTES;
    c->bufbytes = DEFAULT_BUFBYTES;

    return c;
}

void *merge_cgi_config (pool *p, void *basev, void *overridesv)
{
    cgi_server_conf *base = (cgi_server_conf *)basev,
      *overrides = (cgi_server_conf *)overridesv;

    return overrides->logname ? overrides : base;
}

const char *set_scriptlog (cmd_parms *cmd, void *dummy, char *arg) {
    server_rec *s = cmd->server;
    cgi_server_conf *conf = 
      (cgi_server_conf *)get_module_config(s->module_config, &cgi_module);

    conf->logname = arg;
    return NULL;
}

const char *set_scriptlog_length (cmd_parms *cmd, void *dummy, char *arg) {
    server_rec *s = cmd->server;
    cgi_server_conf *conf = 
      (cgi_server_conf *)get_module_config(s->module_config, &cgi_module);

    conf->logbytes = atol (arg);
    return NULL;
}

const char *set_scriptlog_buffer (cmd_parms *cmd, void *dummy, char *arg) {
    server_rec *s = cmd->server;
    cgi_server_conf *conf = 
      (cgi_server_conf *)get_module_config(s->module_config, &cgi_module);

    conf->bufbytes = atoi (arg);
    return NULL;
}

command_rec cgi_cmds[] = {
{ "ScriptLog", set_scriptlog, NULL, RSRC_CONF, TAKE1,
  "the name of a log for script debugging info"},
{ "ScriptLogLength", set_scriptlog_length, NULL, RSRC_CONF, TAKE1,
  "the maximum length (in bytes) of the script debug log"},
{ "ScriptLogBuffer", set_scriptlog_buffer, NULL, RSRC_CONF, TAKE1,
  "the maximum size (in bytes) to record of a POST request"},
{ NULL}
};

static int log_scripterror(request_rec *r, cgi_server_conf *conf, int ret,
		    char *error)
{
    FILE *f;

    log_reason(error, r->filename, r);

    if (!conf->logname ||
	((stat(server_root_relative(r->pool, conf->logname), &r->finfo) == 0)
	&& (r->finfo.st_size > conf->logbytes)) ||
	((f = pfopen(r->pool, server_root_relative(r->pool, conf->logname),
		     "a")) == NULL)) {
      return ret;
    }

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgi-bin/printenv HTTP/1.0" */
    fprintf(f, "%%%% [%s] %s %s%s%s %s\n", get_time(), r->method, r->uri,
	    r->args ? "?" : "", r->args ? r->args : "", r->protocol);
    /* "%% 500 /usr/local/etc/httpd/cgi-bin */
    fprintf(f, "%%%% %d %s\n", ret, r->filename);

    fprintf(f, "%%error\n%s\n", error);

    pfclose(r->pool, f);
    return ret;
}

static int log_script(request_rec *r, cgi_server_conf *conf, int ret,
	       char *dbuf, char *sbuf, FILE *script_in, FILE *script_err)
{
    table *hdrs_arr = r->headers_in;
    table_entry *hdrs = (table_entry *)hdrs_arr->elts;
    char argsbuffer[HUGE_STRING_LEN];
    FILE *f;
    int i;

    if (!conf->logname ||
	((stat(server_root_relative(r->pool, conf->logname), &r->finfo) == 0)
	&& (r->finfo.st_size > conf->logbytes)) ||
	((f = pfopen(r->pool, server_root_relative(r->pool, conf->logname),
		     "a")) == NULL)) {
      /* Soak up script output */
      while (fgets(argsbuffer, MAX_STRING_LEN-1, script_in) != NULL)
	continue;
      while (fgets(argsbuffer, MAX_STRING_LEN-1, script_err) != NULL)
	continue;
      return ret;
    }

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgi-bin/printenv HTTP/1.0" */
    fprintf(f, "%%%% [%s] %s %s%s%s %s\n", get_time(), r->method, r->uri,
	    r->args ? "?" : "", r->args ? r->args : "", r->protocol);
    /* "%% 500 /usr/local/etc/httpd/cgi-bin */
    fprintf(f, "%%%% %d %s\n", ret, r->filename);

    fputs("%request\n", f);
    for (i = 0; i < hdrs_arr->nelts; ++i) {
      if (!hdrs[i].key) continue;
      fprintf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val);
    }
    if ((r->method_number == M_POST || r->method_number == M_PUT)
	&& dbuf && *dbuf) {
      fprintf(f, "\n%s\n", dbuf);
    }

    fputs("%response\n", f);
    hdrs_arr = r->err_headers_out;
    hdrs = (table_entry *)hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; ++i) {
      if (!hdrs[i].key) continue;
      fprintf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val);
    }

    if (sbuf && *sbuf)
      fprintf(f, "%s\n", sbuf);

    *argsbuffer = '\0';
    fgets(argsbuffer, HUGE_STRING_LEN-1, script_in);
    if (*argsbuffer) {
      fputs("%stdout\n", f);
      fputs(argsbuffer, f);
      while (fgets(argsbuffer, HUGE_STRING_LEN-1, script_in) != NULL)
	fputs(argsbuffer, f);
      fputs("\n", f);
    }

    *argsbuffer = '\0';
    fgets(argsbuffer, HUGE_STRING_LEN-1, script_err);
    if (*argsbuffer) {
      fputs("%stderr\n", f);
      fputs(argsbuffer, f);
      while (fgets(argsbuffer, HUGE_STRING_LEN-1, script_err) != NULL)
	fputs(argsbuffer, f);
      fputs("\n", f);
    }

    pfclose(r->main ? r->main->pool : r->pool, script_in);
    pfclose(r->main ? r->main->pool : r->pool, script_err);

    pfclose(r->pool, f);
    return ret;
}

/****************************************************************
 *
 * Actual CGI handling...
 */


struct cgi_child_stuff {
    request_rec *r;
    int nph;
    int debug;
    char *argv0;
};

void cgi_child (void *child_stuff)
{
    struct cgi_child_stuff *cld = (struct cgi_child_stuff *)child_stuff;
    request_rec *r = cld->r;
    char *argv0 = cld->argv0;
    int nph = cld->nph;

#ifdef DEBUG_CGI    
#ifdef __EMX__
    /* Under OS/2 need to use device con. */
    FILE *dbg = fopen ("con", "w");
#else    
    FILE *dbg = fopen ("/dev/tty", "w");
#endif    
    int i;
#endif
    
    char **env;
    char err_string[HUGE_STRING_LEN];
    
#ifdef DEBUG_CGI    
    fprintf (dbg, "Attempting to exec %s as %sCGI child (argv0 = %s)\n",
	    r->filename, nph ? "NPH " : "", argv0);
#endif    

    add_cgi_vars (r);
    env = create_environment (r->pool, r->subprocess_env);
    
#ifdef DEBUG_CGI    
    fprintf (dbg, "Environment: \n");
    for (i = 0; env[i]; ++i) fprintf (dbg, "'%s'\n", env[i]);
#endif
    
    chdir_file (r->filename);
    if (!cld->debug)
      error_log2stderr (r->server);

#ifndef __EMX__
    if (nph) client_to_stdout (r->connection);
#endif    

    /* Transumute outselves into the script.
     * NB only ISINDEX scripts get decoded arguments.
     */
    
    cleanup_for_exec();
    
    call_exec(r, argv0, env, 0);

    /* Uh oh.  Still here.  Where's the kaboom?  There was supposed to be an
     * EARTH-shattering kaboom!
     *
     * Oh, well.  Muddle through as best we can...
     *
     * (NB we can't use log_error, or anything like that, because we
     * just closed the file descriptor which r->server->error_log
     * was tied to in cleanup_for_exec().  It's only available on stderr
     * now, so that's what we use).
     */
    
    ap_snprintf(err_string, sizeof(err_string),
	    "exec of %s failed, reason: %s (errno = %d)\n", 
            r->filename, strerror(errno), errno);
    write(2, err_string, strlen(err_string));
    exit(0);
}

int cgi_handler (request_rec *r)
{
    int retval, nph, dbpos = 0;
    char *argv0, *dbuf = NULL;
    FILE *script_out, *script_in, *script_err;
    char argsbuffer[HUGE_STRING_LEN];
    int is_included = !strcmp (r->protocol, "INCLUDED");
    void *sconf = r->server->module_config;
    cgi_server_conf *conf =
	(cgi_server_conf *)get_module_config(sconf, &cgi_module);

    struct cgi_child_stuff cld;
    pid_t child_pid;

    if (r->method_number == M_OPTIONS) {
        /* 99 out of 100 CGI scripts, this is all they support */
        r->allowed |= (1 << M_GET);
        r->allowed |= (1 << M_POST);
	return DECLINED;
    }

    if((argv0 = strrchr(r->filename,'/')) != NULL)
        argv0++;
    else argv0 = r->filename;

    nph = !(strncmp(argv0,"nph-",4));

    if (!(allow_options (r) & OPT_EXECCGI) && !is_scriptaliased (r))
	return log_scripterror(r, conf, FORBIDDEN,
			       "Options ExecCGI is off in this directory");
    if (nph && is_included)
	return log_scripterror(r, conf, FORBIDDEN,
			       "attempt to include NPH CGI script");
    
    if (S_ISDIR(r->finfo.st_mode))
	return log_scripterror(r, conf, FORBIDDEN,
			       "attempt to invoke directory as script");
#ifdef __EMX__
    /* Allow for cgi files without the .EXE extension on them under OS/2 */
    if (r->finfo.st_mode == 0) {
        struct stat statbuf;

        r->filename = pstrcat (r->pool, r->filename, ".EXE", NULL);

        if ((stat(r->filename, &statbuf) != 0) || (!S_ISREG(statbuf.st_mode))) {
            return log_scripterror(r, conf, NOT_FOUND,
                                   "script not found or unable to stat");
        }
    }
#else
    if (r->finfo.st_mode == 0)
	return log_scripterror(r, conf, NOT_FOUND,
			       "script not found or unable to stat");
#endif
    if (!suexec_enabled) {
        if (!can_exec(&r->finfo))
            return log_scripterror(r, conf, FORBIDDEN,
                                   "file permissions deny server execution");
    }

    if ((retval = setup_client_block(r, REQUEST_CHUNKED_ERROR)))
	return retval;

    add_common_vars (r);
    cld.argv0 = argv0; cld.r = r; cld.nph = nph;
    cld.debug = conf->logname ? 1 : 0;
    
    if (!(child_pid =
	  /*
	   * we spawn out of r->main if it's there so that we can avoid
	   * waiting for free_proc_chain to cleanup in the middle of an
	   * SSI request -djg
	   */
	  spawn_child_err (r->main ? r->main->pool : r->pool, cgi_child,
			    (void *)&cld,
			   nph ? just_wait : kill_after_timeout,
#ifdef __EMX__
			   &script_out, &script_in, &script_err))) {
#else
			   &script_out, nph ? NULL : &script_in,
	    		   &script_err))) {
#endif
        log_reason ("couldn't spawn child process", r->filename, r);
        return SERVER_ERROR;
    }

    /* Transfer any put/post args, CERN style...
     * Note that if a buggy script fails to read everything we throw
     * at it, or a buggy client sends too much, we get a SIGPIPE, so
     * we have to ignore SIGPIPE while doing this.  CERN does the same
     * (and in fact, they pretty nearly guarantee themselves a SIGPIPE
     * on every invocation by chasing the real client data with a
     * spurious newline).
     */
    
     if (should_client_block(r)) {
        void (*handler)();
	int dbsize, len_read;

	if (conf->logname) {
	    dbuf = pcalloc(r->pool, conf->bufbytes+1);
	    dbpos = 0;
	}

        hard_timeout ("copy script args", r);
        handler = signal (SIGPIPE, SIG_IGN);
    
	while ((len_read =
                get_client_block(r, argsbuffer, HUGE_STRING_LEN)) > 0)
	{
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
	    reset_timeout(r);
	    if (fwrite(argsbuffer, sizeof(char), len_read, script_out)
	            < (size_t)len_read) {
	        /* silly script stopped reading, soak up remaining message */
	        while (get_client_block(r, argsbuffer, HUGE_STRING_LEN) > 0)
	            ; /* dump it */
	        break;
	    }
	}

	fflush (script_out);
	signal (SIGPIPE, handler);
	
	kill_timeout (r);
    }
    
    pfclose (r->main ? r->main->pool : r->pool, script_out);
    
    /* Handle script return... */
    if (script_in && !nph) {
        char *location, sbuf[MAX_STRING_LEN];
	int ret;
      
        if ((ret = scan_script_header_err(r, script_in, sbuf)))
	    return log_script(r, conf, ret, dbuf, sbuf, script_in, script_err);
	
	location = table_get (r->headers_out, "Location");

        if (location && location[0] == '/' && r->status == 200) {
	  
	    /* Soak up all the script output */
	    hard_timeout ("read from script", r);
	    while (fread(argsbuffer, sizeof(char), HUGE_STRING_LEN, script_in)
	           > 0)
	        continue;
	    while (fread(argsbuffer, sizeof(char), HUGE_STRING_LEN, script_err)
	           > 0)
	        continue;
	    kill_timeout (r);


	   /* This redirect needs to be a GET no matter what the original
	    * method was.
	    */
	    r->method = pstrdup(r->pool, "GET");
	    r->method_number = M_GET;

	    /* We already read the message body (if any), so don't allow
	     * the redirected request to think it has one.  We can ignore 
	     * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
	     */
	    table_unset(r->headers_in, "Content-Length");

	    internal_redirect_handler (location, r);
	    return OK;
        }
	else if (location && r->status == 200) {
	    /* XX Note that if a script wants to produce its own Redirect
	     * body, it now has to explicitly *say* "Status: 302"
	     */
	    return REDIRECT;
	}
	
	send_http_header(r);
	if (!r->header_only)
	    send_fd(script_in, r);
	pfclose (r->main ? r->main->pool : r->pool, script_in);

	/* Soak up stderr */
	soft_timeout("soaking script stderr", r);
	while (!r->connection->aborted &&
	  (fread(argsbuffer, sizeof(char), HUGE_STRING_LEN, script_err) > 0))
	    continue;
	kill_timeout(r);
	pfclose (r->main ? r->main->pool : r->pool, script_err);
    }

    if (nph) {
#ifdef __EMX__
        while (fgets(argsbuffer, HUGE_STRING_LEN-1, script_in) != NULL) {
            bputs(argsbuffer, r->connection->client);
        }
#else
	waitpid(child_pid, (int*)0, 0);
#endif
    }    

    return OK;			/* NOT r->status, even if it has changed. */
}

handler_rec cgi_handlers[] = {
{ CGI_MAGIC_TYPE, cgi_handler },
{ "cgi-script", cgi_handler },
{ NULL }
};

module cgi_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   NULL,			/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   create_cgi_config,		/* server config */
   merge_cgi_config,	       	/* merge server config */
   cgi_cmds,			/* command table */
   cgi_handlers,		/* handlers */
   NULL,			/* filename translation */ 
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL,			/* logger */
   NULL				/* header parser */
};
