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
 * Security options etc.
 * 
 * Module derived from code originally written by Rob McCool
 * 
 */

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

typedef struct {
    char *from;
    int limited;
} allowdeny;

/* things in the 'order' array */
#define DENY_THEN_ALLOW 0
#define ALLOW_THEN_DENY 1
#define MUTUAL_FAILURE 2

typedef struct {
    int order[METHODS];
    array_header *allows;
    array_header *denys;
} access_dir_conf;

module access_module;

void *create_access_dir_config (pool *p, char *dummy)
{
    access_dir_conf *conf =
        (access_dir_conf *)pcalloc(p, sizeof(access_dir_conf));
    int i;
    
    for (i = 0; i < METHODS; ++i) conf->order[i] = DENY_THEN_ALLOW;
    conf->allows = make_array (p, 1, sizeof (allowdeny));
    conf->denys = make_array (p, 1, sizeof (allowdeny));
    
    return (void *)conf;
}

const char *order (cmd_parms *cmd, void *dv, char *arg)
{
    access_dir_conf *d = (access_dir_conf *)dv;
    int i, order;
  
    if (!strcasecmp (arg, "allow,deny")) order = ALLOW_THEN_DENY;
    else if (!strcasecmp (arg, "deny,allow")) order = DENY_THEN_ALLOW;
    else if (!strcasecmp (arg, "mutual-failure")) order = MUTUAL_FAILURE;
    else return "unknown order";

    for (i = 0; i < METHODS; ++i) 
        if (cmd->limited & (1 << i))
	    d->order[i] = order;
    
    return NULL;
}

const char *allow_cmd (cmd_parms *cmd, void *dv, char *from, char *where)
{
    access_dir_conf *d = (access_dir_conf *)dv;
    allowdeny *a;
  
    if (strcasecmp (from, "from"))
        return "allow and deny must be followed by 'from'";
    
    a = (allowdeny *)push_array (cmd->info ? d->allows : d->denys);
    a->from = pstrdup (cmd->pool, where);
    a->limited = cmd->limited;
    return NULL;
}

static char its_an_allow;

command_rec access_cmds[] = {
{ "order", order, NULL, OR_LIMIT, TAKE1,
    "'allow,deny', 'deny,allow', or 'mutual-failure'" },
{ "allow", allow_cmd, &its_an_allow, OR_LIMIT, ITERATE2,
    "'from' followed by hostnames or IP-address wildcards" },
{ "deny", allow_cmd, NULL, OR_LIMIT, ITERATE2,
    "'from' followed by hostnames or IP-address wildcards" },
{NULL}
};

int in_domain(const char *domain, const char *what) {
    int dl=strlen(domain);
    int wl=strlen(what);

    if((wl-dl) >= 0) {
        if (strcasecmp(domain,&what[wl-dl]) != 0) return 0;

	/* Make sure we matched an *entire* subdomain --- if the user
	 * said 'allow from good.com', we don't want people from nogood.com
	 * to be able to get in.
	 */
	
	if (wl == dl) return 1;	/* matched whole thing */
	else return (domain[0] == '.' || what[wl - dl - 1] == '.');
    } else
        return 0;
}

int in_ip(char *domain, char *what) {

    /* Check a similar screw case to the one checked above ---
     * "allow from 204.26.2" shouldn't let in people from 204.26.23
     */
    
    int l = strlen(domain);
    if (strncmp(domain,what,l) != 0) return 0;
    if (domain[l - 1] == '.') return 1;
    return (what[l] == '\0' || what[l] == '.');
}

static int is_ip(const char *host)
{
    while ((*host == '.') || isdigit(*host))
        host++;
    return (*host == '\0');
}

int find_allowdeny (request_rec *r, array_header *a, int method)
{
    allowdeny *ap = (allowdeny *)a->elts;
    int mmask = (1 << method);
    int i;
    int gothost = 0;
    const char *remotehost = NULL;

    for (i = 0; i < a->nelts; ++i) {
        if (!(mmask & ap[i].limited))
	    continue;

	if (!strncmp(ap[i].from,"env=",4) && table_get(r->subprocess_env,ap[i].from+4))
	    return 1;
	    
        if (ap[i].from && !strcmp(ap[i].from, "user-agents")) {
	    char * this_agent = table_get(r->headers_in, "User-Agent");
	    int j;
  
	    if (!this_agent) return 0;
  
	    for (j = i+1; j < a->nelts; ++j) {
	        if (strstr(this_agent, ap[j].from)) return 1;
	    }
	    return 0;
	}
	
	if (!strcmp (ap[i].from, "all"))
	    return 1;

	if (!gothost) {
	    remotehost = get_remote_host(r->connection, r->per_dir_config,
	                                 REMOTE_HOST);

	    if ((remotehost == NULL) || is_ip(remotehost))
	        gothost = 1;
	    else
	        gothost = 2;
	}

        if ((gothost == 2) && in_domain(ap[i].from, remotehost))
            return 1;

        if (in_ip (ap[i].from, r->connection->remote_ip))
            return 1;
    }

    return 0;
}

int check_dir_access (request_rec *r)
{
    int method = r->method_number;
    access_dir_conf *a =
        (access_dir_conf *)
	   get_module_config (r->per_dir_config, &access_module);
    int ret = OK;
						
    if (a->order[method] == ALLOW_THEN_DENY) {
        ret = FORBIDDEN;
        if (find_allowdeny (r, a->allows, method))
            ret = OK;
        if (find_allowdeny (r, a->denys, method))
            ret = FORBIDDEN;
    } else if (a->order[method] == DENY_THEN_ALLOW) {
        if (find_allowdeny (r, a->denys, method))
            ret = FORBIDDEN;
        if (find_allowdeny (r, a->allows, method))
            ret = OK;
    }
    else {
        if (find_allowdeny(r, a->allows, method) 
	    && !find_allowdeny(r, a->denys, method))
	    ret = OK;
	else
	    ret = FORBIDDEN;
    }

    if (ret == FORBIDDEN && (
        satisfies(r) != SATISFY_ANY || !some_auth_required(r)
    )) {
	log_reason ("Client denied by server configuration", r->filename, r);
    }

    return ret;
}



module access_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_access_dir_config,	/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   access_cmds,
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   check_dir_access,		/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL,			/* logger */
   NULL				/* header parser */
};
