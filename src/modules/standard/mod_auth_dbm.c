
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
 * http_auth: authentication
 * 
 * Rob McCool & Brian Behlendorf.
 * 
 * Adapted to Shambhala by rst.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include <ndbm.h>

typedef struct  {

    char *auth_dbmpwfile;
    char *auth_dbmgrpfile;

} dbm_auth_config_rec;

void *create_dbm_auth_dir_config (pool *p, char *d)
{
    return pcalloc (p, sizeof(dbm_auth_config_rec));
}

command_rec dbm_auth_cmds[] = {
{ "AuthDBMUserFile", set_string_slot,
    (void*)XtOffsetOf(dbm_auth_config_rec, auth_dbmpwfile),
    OR_AUTHCFG, TAKE1, NULL },
{ "AuthDBMGroupFile", set_string_slot,
    (void*)XtOffsetOf(dbm_auth_config_rec, auth_dbmgrpfile),
    OR_AUTHCFG, TAKE1, NULL },
{ NULL }
};

module dbm_auth_module;

char *get_dbm_pw(request_rec *r, char *user, char *auth_dbmpwfile) {
    DBM *f; 
    datum d, q; 
    char *pw = NULL;

    q.dptr = user; 
    q.dsize = strlen(q.dptr); 
    
    if(!(f=dbm_open(auth_dbmpwfile,O_RDONLY,0664))) {
        log_reason ("could not open dbm auth file", auth_dbmpwfile, r);
	return NULL;
    }

    d = dbm_fetch(f, q);

    if (d.dptr) {
        pw = palloc (r->pool, d.dsize + 1);
	strncpy(pw,d.dptr,d.dsize);
	pw[d.dsize] = '\0';         /* Terminate the string */
    }

    dbm_close(f);
    return pw; 
}

/* We do something strange with the group file.  If the group file
 * contains any : we assume the format is
 *      key=username value=":"groupname [":"anything here is ignored]
 * otherwise we now (0.8.14+) assume that the format is
 *      key=username value=groupname
 * The first allows the password and group files to be the same 
 * physical DBM file;   key=username value=password":"groupname[":"anything]
 *
 * mark@telescope.org, 22Sep95
 */

char  *get_dbm_grp(request_rec *r, char *user, char *auth_dbmgrpfile) {
    char *grp_data = get_dbm_pw (r, user, auth_dbmgrpfile);
    char *grp_colon; char *grp_colon2;

    if (grp_data == NULL) return NULL;
    
    if ((grp_colon = strchr(grp_data, ':'))!=NULL) {
        grp_colon2 = strchr(++grp_colon, ':');
        if (grp_colon2) *grp_colon2='\0';
        return grp_colon;
    }
    return grp_data;
}

int dbm_authenticate_basic_user (request_rec *r)
{
    dbm_auth_config_rec *sec =
      (dbm_auth_config_rec *)get_module_config (r->per_dir_config,
						&dbm_auth_module);
    conn_rec *c = r->connection;
    char *sent_pw, *real_pw, *colon_pw;
    char errstr[MAX_STRING_LEN];
    int res;
    
    if ((res = get_basic_auth_pw (r, &sent_pw)))
        return res;
    
    if(!sec->auth_dbmpwfile)
        return DECLINED;
	
    if(!(real_pw = get_dbm_pw(r, c->user, sec->auth_dbmpwfile))) {
        sprintf(errstr,"DBM user %s not found", c->user);
	log_reason (errstr, r->filename, r);
	note_basic_auth_failure (r);
	return AUTH_REQUIRED;
    }    
    /* Password is up to first : if exists */
    colon_pw = strchr(real_pw,':');
    if (colon_pw) *colon_pw='\0';   
    /* anyone know where the prototype for crypt is? */
    if(strcmp(real_pw,(char *)crypt(sent_pw,real_pw))) {
        sprintf(errstr,"user %s: password mismatch",c->user);
	log_reason (errstr, r->uri, r);
	note_basic_auth_failure (r);
	return AUTH_REQUIRED;
    }
    return OK;
}
    
/* Checking ID */
    
int dbm_check_auth(request_rec *r) {
    dbm_auth_config_rec *sec =
      (dbm_auth_config_rec *)get_module_config (r->per_dir_config,
						&dbm_auth_module);
    char *user = r->connection->user;
    int m = r->method_number;
    char errstr[MAX_STRING_LEN];
    
    array_header *reqs_arr = requires (r);
    require_line *reqs = reqs_arr ? (require_line *)reqs_arr->elts : NULL;

    register int x;
    char *t, *w;

    if (!sec->auth_dbmgrpfile) return DECLINED;
    if (!reqs_arr) return DECLINED;
    
    for(x=0; x < reqs_arr->nelts; x++) {
      
	if (! (reqs[x].method_mask & (1 << m))) continue;
	
        t = reqs[x].requirement;
        w = getword(r->pool, &t, ' ');
	
        if(!strcmp(w,"group") && sec->auth_dbmgrpfile) {
           char *orig_groups,*groups,*v;

           if (!(groups = get_dbm_grp(r, user, sec->auth_dbmgrpfile))) {
               sprintf(errstr,"user %s not in DBM group file %s",
		       user, sec->auth_dbmgrpfile);
	       log_reason (errstr, r->filename, r);
	       note_basic_auth_failure (r);
	       return AUTH_REQUIRED;
           }
           orig_groups = groups;
           while(t[0]) {
               w = getword(r->pool, &t, ' ');
               groups = orig_groups;
               while(groups[0]) {
                   v = getword(r->pool, &groups,',');
                   if(!strcmp(v,w))
                       return OK;
               }
           }
           sprintf(errstr,"user %s not in right group",user);
	   log_reason (errstr, r->filename, r);
           note_basic_auth_failure(r);
	   return AUTH_REQUIRED;
       }
    }
    
    return DECLINED;
}


module dbm_auth_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_dbm_auth_dir_config,	/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   dbm_auth_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   dbm_authenticate_basic_user,	/* check_user_id */
   dbm_check_auth,		/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
