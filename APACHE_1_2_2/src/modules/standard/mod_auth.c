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
 * http_auth: authentication
 * 
 * Rob McCool
 * 
 * Adapted to Apache by rst.
 *
 * dirkx - Added Authoritative control to allow passing on to lower
 *	   modules if and only if the user-id is not known to this
 *	   module. A known user with a faulty or absent password still
 *	   causes an AuthRequired. The default is 'Authoritative', i.e.
 *	   no control is passed along.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#if defined(HAVE_CRYPT_H)
#include <crypt.h>
#endif

typedef struct auth_config_struct {
    char *auth_pwfile;
    char *auth_grpfile;
    int auth_authoritative;
} auth_config_rec;

void *create_auth_dir_config (pool *p, char *d)
{
    auth_config_rec *sec =
    	(auth_config_rec *) pcalloc (p, sizeof(auth_config_rec));
    sec->auth_pwfile = NULL; /* just to illustrate the default really */ 
    sec->auth_grpfile = NULL; /* unless you have a broken HP cc */
    sec->auth_authoritative = 1; /* keep the fortress secure by default */
    return sec;
}

const char *set_auth_slot (cmd_parms *cmd, void *offset, char *f, char *t)
{
    if (t && strcmp(t, "standard"))
        return pstrcat(cmd->pool, "Invalid auth file type: ",  t, NULL);

    return set_string_slot(cmd, offset, f);
}

command_rec auth_cmds[] = {
{ "AuthUserFile", set_auth_slot,
  (void*)XtOffsetOf(auth_config_rec,auth_pwfile), OR_AUTHCFG, TAKE12, NULL },
{ "AuthGroupFile", set_auth_slot,
  (void*)XtOffsetOf(auth_config_rec,auth_grpfile), OR_AUTHCFG, TAKE12, NULL },
{ "AuthAuthoritative", set_flag_slot,
  (void*)XtOffsetOf(auth_config_rec,auth_authoritative), 
    OR_AUTHCFG, FLAG, 
   "Set to 'no' to allow access control to be passed along to lower modules if the UserID is not known to this module" },
{ NULL }
};

module auth_module;

char *get_pw(request_rec *r, char *user, char *auth_pwfile)
{
    FILE *f;
    char l[MAX_STRING_LEN];
    const char *rpw, *w;

    if(!(f=pfopen(r->pool, auth_pwfile, "r"))) {
        log_reason ("Could not open password file", auth_pwfile, r);
	return NULL;
    }
    while(!(cfg_getline(l,MAX_STRING_LEN,f))) {
        if((l[0] == '#') || (!l[0])) continue;
	rpw = l;
        w = getword(r->pool, &rpw, ':');

        if(!strcmp(user,w)) {
	    pfclose(r->pool, f);
            return pstrdup (r->pool, rpw);
	}
    }
    pfclose(r->pool, f);
    return NULL;
}

table *groups_for_user (pool *p, char *user, char *grpfile) {
    FILE *f;
    table *grps = make_table (p, 15);
    pool *sp;
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;

    if(!(f=pfopen(p, grpfile, "r")))
        return NULL;

    sp = make_sub_pool (p);
    
    while(!(cfg_getline(l,MAX_STRING_LEN,f))) {
        if((l[0] == '#') || (!l[0])) continue;
	ll = l;
	clear_pool (sp);
	
        group_name = getword(sp, &ll, ':');

	while(ll[0]) {
	    w = getword_conf (sp, &ll);
	    if(!strcmp(w,user)) {
		table_set (grps, group_name, "in");
		break;
	    }
	}
    }
    pfclose(p, f);
    destroy_pool (sp);
    return grps;
}

/* These functions return 0 if client is OK, and proper error status
 * if not... either AUTH_REQUIRED, if we made a check, and it failed, or
 * SERVER_ERROR, if things are so totally confused that we couldn't
 * figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

/* Determine user ID, and check if it really is that user, for HTTP
 * basic authentication...
 */

int authenticate_basic_user (request_rec *r)
{
    auth_config_rec *sec =
      (auth_config_rec *)get_module_config (r->per_dir_config, &auth_module);
    conn_rec *c = r->connection;
    char *sent_pw, *real_pw;
    char errstr[MAX_STRING_LEN];
    int res;
    
    if ((res = get_basic_auth_pw (r, &sent_pw))) return res;
    
    if(!sec->auth_pwfile) 
        return DECLINED;
	
    if (!(real_pw = get_pw(r, c->user, sec->auth_pwfile))) {
	if (!(sec->auth_authoritative))
	    return DECLINED;
        ap_snprintf(errstr, sizeof(errstr), "user %s not found",c->user);
	log_reason (errstr, r->uri, r);
	note_basic_auth_failure (r);
	return AUTH_REQUIRED;
    }
    /* anyone know where the prototype for crypt is? */
    if(strcmp(real_pw,(char *)crypt(sent_pw,real_pw))) {
        ap_snprintf(errstr, sizeof(errstr), "user %s: password mismatch",c->user);
	log_reason (errstr, r->uri, r);
	note_basic_auth_failure (r);
	return AUTH_REQUIRED;
    }
    return OK;
}
    
/* Checking ID */
    
int check_user_access (request_rec *r) {
    auth_config_rec *sec =
      (auth_config_rec *)get_module_config (r->per_dir_config, &auth_module);
    char *user = r->connection->user;
    int m = r->method_number;
    int method_restricted = 0;
    register int x;
    const char *t, *w;
    table *grpstatus;
    array_header *reqs_arr = requires (r);
    require_line *reqs;

    /* BUG FIX: tadc, 11-Nov-1995.  If there is no "requires" directive, 
     * then any user will do.
     */
    if (!reqs_arr)
        return (OK);
    reqs = (require_line *)reqs_arr->elts;

    if(sec->auth_grpfile)
        grpstatus = groups_for_user (r->pool, user, sec->auth_grpfile);
    else
        grpstatus = NULL;

    for(x=0; x < reqs_arr->nelts; x++) {
      
	if (! (reqs[x].method_mask & (1 << m))) continue;
	
	method_restricted = 1;

        t = reqs[x].requirement;
        w = getword(r->pool, &t, ' ');
        if(!strcmp(w,"valid-user"))
            return OK;
        if(!strcmp(w,"user")) {
            while(t[0]) {
                w = getword_conf (r->pool, &t);
                if(!strcmp(user,w))
                    return OK;
            }
        }
        else if(!strcmp(w,"group")) {
            if(!grpstatus) 
	        return DECLINED;	/* DBM group?  Something else? */
	    
            while(t[0]) {
                w = getword_conf(r->pool, &t);
                if(table_get (grpstatus, w))
		    return OK;
            }
        }
    }
    
    if (!method_restricted)
      return OK;

    if (!(sec -> auth_authoritative))
      return DECLINED;

    note_basic_auth_failure (r);
    return AUTH_REQUIRED;
}

module auth_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_auth_dir_config,	/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   auth_cmds,			/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   authenticate_basic_user,	/* check_user_id */
   check_user_access,		/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL,			/* logger */
   NULL				/* header parser */
};
