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


#include "httpd.h"
#include "http_config.h"

module agent_log_module;

static int xfer_flags = ( O_WRONLY | O_APPEND | O_CREAT );
#ifdef __EMX__
/* OS/2 dosen't support users and groups */
static mode_t xfer_mode = ( S_IREAD | S_IWRITE );
#else
static mode_t xfer_mode = ( S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
#endif

typedef struct {
    char *fname;
    int agent_fd;
} agent_log_state;

void *make_agent_log_state (pool *p, server_rec *s)
{
    agent_log_state *cls =
      (agent_log_state *)palloc (p, sizeof (agent_log_state));

    cls->fname = "";
    cls->agent_fd = -1;


    return (void *)cls;
}

const char *set_agent_log (cmd_parms *parms, void *dummy, char *arg)
{
    agent_log_state *cls = get_module_config (parms->server->module_config,
					       &agent_log_module);
  
    cls->fname = arg;
    return NULL;
}

command_rec agent_log_cmds[] = {
{ "AgentLog", set_agent_log, NULL, RSRC_CONF, TAKE1,
    "the filename of the agent log" },
{ NULL }
};

void agent_log_child (void *cmd)
{
    /* Child process code for 'AgentLog "|..."';
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

void open_agent_log (server_rec *s, pool *p)
{
    agent_log_state *cls = get_module_config (s->module_config,
					       &agent_log_module);
  
    char *fname = server_root_relative (p, cls->fname);
    
    if (cls->agent_fd > 0) return; /* virtual log shared w/main server */
    
    if (*cls->fname == '|') {
	FILE *dummy;
	
	if (!spawn_child (p, agent_log_child, (void *)(cls->fname+1),
		    kill_after_timeout, &dummy, NULL)) {
	    perror ("spawn_child");
	    fprintf (stderr, "Couldn't fork child for AgentLog process\n");
	    exit (1);
	}

	cls->agent_fd = fileno (dummy);
    }
    else if(*cls->fname != '\0') {
      if((cls->agent_fd = popenf(p, fname, xfer_flags, xfer_mode)) < 0) {
        perror("open");
        fprintf(stderr,"httpd: could not open agent log file %s.\n", fname);
        exit(1);
      }
    }
}

void init_agent_log (server_rec *s, pool *p)
{
    for (; s; s = s->next) open_agent_log (s, p);
}

int agent_log_transaction(request_rec *orig)
{
    agent_log_state *cls = get_module_config (orig->server->module_config,
					       &agent_log_module);
  
    char str[HUGE_STRING_LEN];
    char *agent;
    request_rec *r;

    if(cls->agent_fd <0)
      return OK;

    for (r = orig; r->next; r = r->next)
        continue;
    if (*cls->fname == '\0')	/* Don't log agent */
	return DECLINED;

    agent = table_get(orig->headers_in, "User-Agent");
    if(agent != NULL) 
      {
	ap_snprintf(str, sizeof(str), "%s\n", agent);
	write(cls->agent_fd, str, strlen(str));
      }
    
    return OK;
}

module agent_log_module = {
   STANDARD_MODULE_STUFF,
   init_agent_log,		/* initializer */
   NULL,			/* create per-dir config */
   NULL,			/* merge per-dir config */
   make_agent_log_state,	/* server config */
   NULL,			/* merge server config */
   agent_log_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   agent_log_transaction,	/* logger */
   NULL				/* header parser */
};
