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


#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

module agent_log_module;

static int xfer_flags = (O_WRONLY | O_APPEND | O_CREAT);
#ifdef OS2
/* OS/2 dosen't support users and groups */
static mode_t xfer_mode = (S_IREAD | S_IWRITE);
#else
static mode_t xfer_mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif

typedef struct {
    char *fname;
    int agent_fd;
} agent_log_state;

static void *make_agent_log_state(pool *p, server_rec *s)
{
    agent_log_state *cls =
    (agent_log_state *) ap_palloc(p, sizeof(agent_log_state));

    cls->fname = "";
    cls->agent_fd = -1;

    return (void *) cls;
}

static const char *set_agent_log(cmd_parms *parms, void *dummy, char *arg)
{
    agent_log_state *cls = ap_get_module_config(parms->server->module_config,
                                             &agent_log_module);

    cls->fname = arg;
    return NULL;
}

static const command_rec agent_log_cmds[] =
{
    {"AgentLog", set_agent_log, NULL, RSRC_CONF, TAKE1,
     "the filename of the agent log"},
    {NULL}
};

static void open_agent_log(server_rec *s, pool *p)
{
    agent_log_state *cls = ap_get_module_config(s->module_config,
                                             &agent_log_module);

    char *fname = ap_server_root_relative(p, cls->fname);

    if (cls->agent_fd > 0)
        return;                 /* virtual log shared w/main server */

    if (*cls->fname == '|') {
        piped_log *pl;

        pl = ap_open_piped_log(p, cls->fname + 1);
        if (pl == NULL) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, s,
			 "couldn't spawn agent log pipe");
            exit(1);
        }
        cls->agent_fd = ap_piped_log_write_fd(pl);
    }
    else if (*cls->fname != '\0') {
        if ((cls->agent_fd = ap_popenf_ex(p, fname, xfer_flags, xfer_mode, 1))
             < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, s,
                         "could not open agent log file %s.", fname);
            exit(1);
        }
    }
}

static void init_agent_log(server_rec *s, pool *p)
{
    for (; s; s = s->next)
        open_agent_log(s, p);
}

static int agent_log_transaction(request_rec *orig)
{
    agent_log_state *cls = ap_get_module_config(orig->server->module_config,
                                             &agent_log_module);

    char str[HUGE_STRING_LEN];
    const char *agent;
    request_rec *r;

    if (cls->agent_fd < 0)
        return OK;

    for (r = orig; r->next; r = r->next)
        continue;
    if (*cls->fname == '\0')    /* Don't log agent */
        return DECLINED;

    agent = ap_table_get(orig->headers_in, "User-Agent");
    if (agent != NULL) {
        ap_snprintf(str, sizeof(str), "%s\n", agent);
        write(cls->agent_fd, str, strlen(str));
    }

    return OK;
}

module agent_log_module =
{
    STANDARD_MODULE_STUFF,
    init_agent_log,             /* initializer */
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    make_agent_log_state,       /* server config */
    NULL,                       /* merge server config */
    agent_log_cmds,             /* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    agent_log_transaction,      /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    NULL                        /* post read-request */
};
