
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

/****************************************************************
 *
 * Actual CGI handling...
 */


struct cgi_child_stuff {
    request_rec *r;
    int nph;
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
    error_log2stderr (r->server);

#ifndef __EMX__
    if (nph) client_to_stdout (r->connection);
#endif    
    
    /* Transumute outselves into the script.
     * NB only ISINDEX scripts get decoded arguments.
     */
    
    cleanup_for_exec();
    
#ifdef __EMX__    
    if((!r->args) || (!r->args[0]) || (ind(r->args,'=') >= 0)) {
            int emxloop;
            char *emxtemp;

            /* For OS/2 place the variables in the current
            enviornment then it will be inherited. This way
            the program will also get all of OS/2's other SETs. */
            for (emxloop=0; ((emxtemp = env[emxloop]) != NULL); emxloop++)
                putenv(emxtemp);
                
            if (strstr(strupr(r->filename), ".CMD") > 0) {
                /* Special case to allow use of REXX commands as scripts. */
                os2pathname(r->filename);
                execl("CMD.EXE", "CMD.EXE", "/C", r->filename, NULL);
            } else {
                execl(r->filename, argv0, NULL);
            }
    } else {
            int emxloop;
            char *emxtemp;
            
            /* For OS/2 place the variables in the current
            enviornment then it will be inherited. This way
            the program will also get all of OS/2's other SETs. */
            for (emxloop=0; ((emxtemp = env[emxloop]) != NULL); emxloop++)
                putenv(emxtemp);
                
            if (strstr(strupr(r->filename), ".CMD") > 0) {
                /* Special case to allow use of REXX commands as scripts. */
                os2pathname(r->filename);
                execv("CMD.EXE", create_argv_cmd(r->pool, argv0, r->args, r->filename));
            } else {
                execv(r->filename, create_argv(r->pool, argv0, r->args));
            }
    }
#else
    if((!r->args) || (!r->args[0]) || (ind(r->args,'=') >= 0)) 
        execle(r->filename, argv0, NULL, env);
    else 
        execve(r->filename, create_argv(r->pool, argv0, r->args), env);
#endif        

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
    
    sprintf(err_string,
	    "exec of %s failed, errno is %d\n", r->filename, errno);
    write(2, err_string, strlen(err_string));
    exit(0);
}

int cgi_handler (request_rec *r)
{
    int nph;
    char *argv0;
    FILE *script_out, *script_in;
    char argsbuffer[HUGE_STRING_LEN];
    int is_included = !strcmp (r->protocol, "INCLUDED");
    char *lenp = table_get (r->headers_in, "Content-length");

    struct cgi_child_stuff cld;

    if((argv0 = strrchr(r->filename,'/')) != NULL)
        argv0++;
    else argv0 = r->filename;

    nph = !(strncmp(argv0,"nph-",4));
    
    if (!(allow_options (r) & OPT_EXECCGI) && !is_scriptaliased (r)) {
        log_reason("Options ExecCGI is off in this directory", r->filename, r);
	return FORBIDDEN;
    }
    if (nph && is_included) {
        log_reason("attempt to include NPH CGI script", r->filename, r);
	return FORBIDDEN;
    }
    
    if (S_ISDIR(r->finfo.st_mode)) {
        log_reason("attempt to invoke directory as script", r->filename, r);
	return FORBIDDEN;
    }
    if (r->finfo.st_mode == 0) {
        log_reason("script not found or unable to stat", r->filename, r);
	return NOT_FOUND;
    }
    if(!can_exec(&r->finfo)) {
        log_reason("file permissions deny server execution", r->filename, r);
        return FORBIDDEN;
    }
    if ((r->method_number == M_POST || r->method_number == M_PUT)
	&& !lenp) {
        log_reason("POST or PUT without Content-length:", r->filename, r);
	return BAD_REQUEST;
    }

    add_common_vars (r);
    cld.argv0 = argv0; cld.r = r; cld.nph = nph;
    
#ifdef __EMX__
    if (r->method_number == M_POST || r->method_number == M_PUT) {
        int len_to_read = atoi (lenp);
    
        if (len_to_read > HUGE_STRING_LEN) len_to_read = HUGE_STRING_LEN;
        read_client_block (r, argsbuffer, len_to_read);

        if (!spawn_child_os2 (r->connection->pool, cgi_child, (void *)&cld,
                  nph ? just_wait : kill_after_timeout, 
                  &script_out, &script_in, argsbuffer, atoi(lenp))) { 
            log_reason ("couldn't spawn child process", r->filename, r);
            return SERVER_ERROR;
        }
    } else {
        if (!spawn_child (r->connection->pool, cgi_child, (void *)&cld,
                  nph ? just_wait : kill_after_timeout,
                  &script_out, &script_in)) {
            log_reason ("couldn't spawn child process", r->filename, r);
            return SERVER_ERROR;
        }
    }
    
#else
     if (!spawn_child (r->connection->pool, cgi_child, (void *)&cld,
		       nph ? just_wait : kill_after_timeout, 
		       &script_out, nph ? NULL : &script_in)) {
        log_reason ("couldn't spawn child process", r->filename, r);
        return SERVER_ERROR;
    }
#endif

    /* Transfer any put/post args, CERN style...
     * Note that if a buggy script fails to read everything we throw
     * at it, or a buggy client sends too much, we get a SIGPIPE, so
     * we have to ignore SIGPIPE while doing this.  CERN does the same
     * (and in fact, they pretty nearly guarantee themselves a SIGPIPE
     * on every invocation by chasing the real client data with a
     * spurious newline).
     */
    
#ifndef __EMX__
    if (r->method_number == M_POST || r->method_number == M_PUT) {
        void (*handler)();
	int remaining = atoi (lenp);
	
        hard_timeout ("copy script args", r);
        handler = signal (SIGPIPE, SIG_IGN);
    
	while ((remaining > 0))
	{
	    int len_read, len_to_read = remaining;

	    if (len_to_read > HUGE_STRING_LEN) len_to_read = HUGE_STRING_LEN;
	    
	    len_read = read_client_block (r, argsbuffer, len_to_read);
	    if (len_read == 0)
		break;
	    if (fwrite (argsbuffer, 1, len_read, script_out) == 0)
		break;
	    remaining -= len_read;
	}

	/* If script stopped reading early, soak up remaining stuff from
	 * client...
	 */
	
	while (remaining > 0) {
	    int len_read, len_to_read = remaining;
	    if (len_to_read > HUGE_STRING_LEN) len_to_read = HUGE_STRING_LEN;
	    
	    len_read = read_client_block (r, argsbuffer, len_to_read);
	    if (len_read == 0) break;
	}
    
	fflush (script_out);
	signal (SIGPIPE, handler);
	
	kill_timeout (r);
    }
#endif    
    
    pfclose (r->connection->pool, script_out);
    
    /* Handle script return... */
    if (script_in && !nph) {
        char *location;
	int ret;
      
        if ((ret = scan_script_header(r, script_in)))
	    return ret;
	
	location = table_get (r->headers_out, "Location");

        if (location && location[0] == '/' && r->status == 200) {
	  
            /* Soak up all the script output */
	    hard_timeout ("read from script", r);
	    while (fgets(argsbuffer, HUGE_STRING_LEN-1, script_in) != NULL)
	        continue;
	    kill_timeout (r);


	   /* This redirect needs to be a GET no matter what the original
	    * method was.
	    */
	    r->method = pstrdup(r->pool, "GET");
	    r->method_number = M_GET;

	    internal_redirect_handler (location, r);
	    return OK;
        }
	else if (location && r->status == 200) {
	    /* XX Note that if a script wants to produce its own Redirect
	     * body, it now has to explicitly *say* "Status: 302"
	     */
	    return REDIRECT;
	}
	
	hard_timeout ("send script output", r);
	send_http_header(r);
        if(!r->header_only) send_fd (script_in, r);
	kill_timeout (r);
	pfclose (r->connection->pool, script_in);
    }

#ifdef __EMX__
    if (nph) {
        while (fgets(argsbuffer, HUGE_STRING_LEN-1, script_in) != NULL) {
            bputs(argsbuffer, r->connection->client);
        }
    }    
#endif

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
   NULL,			/* server config */
   NULL,			/* merge server config */
   NULL,			/* command table */
   cgi_handlers,		/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
