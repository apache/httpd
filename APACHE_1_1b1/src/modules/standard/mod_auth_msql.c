
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
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
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
 * 
 * Addapted for use with the mSQL database 
 * (see ftp:/ftp.bond.edu.au/pub/Minerva/mSQL)
 *
 * Version 0.5 Feb 1996
 *
 * Outline:
 *
 * One mSQL database, and one (or two) tables.
 * one table holds the username (preferably as
 * a primary key) and the encryped password. 
 * the other table holds the username and the
 * names of the group to which the user belongs.
 * It is possible to have username, groupname and
 * password in the same table.
 * 
 * Directives:
 *
 * Auth_MSQLhost   	Hostname of the machine running
 *		   	the mSQL demon. The effective uid
 *		   	of the server should be allowed
 *		   	access. If not given, or if it is
 *		   	the magic name 'localhost', it is
 *		   	passed to the mSQL libary as a null
 *	  	 	pointer. This effectively forces it
 *		   	to use /dev/msql rather than the
 *		   	(slower) socket communication.
 *
 * Auth_MSQLdatabase	Name of the database in which the following
 *			table(s) are
 *			
 * Auth_MSQLpwd_table	Contains at least the fields with the
 *			username and the (encrypted) password
 *
 * Auth_MSQLgrp_table	Contains at least the fields with the
 *			username and the groupname. A user which
 *			is in multiple groups has therefore
 *			multiple entries
 *
 * Auth_MSQLuid_field	Name of the field containing the username
 * Auth_MSQLpwd_field   Fieldname for the passwords
 * Auth_MSQLgrp_field	Fieldname for the groupname
 *
 * Auth_MSQL_nopasswd	<on|off>
 *			skip password comparison if passwd field is
 *			empty.
 *
 * Dirk.vanGulik@jrc.it; http://ewse.ceo.org; http://me-www.jrc.it/~dirkx
 * 23 Nov 1995
 *
 * Version 0.0  First release
 *         0.1  Update to apache 1.00
 *         0.2  added lines which got missing god knows when
 *              and which did the valid-user authentification
 *              no good at all !
 *	   0.3  Added 'Auth_MSQL_nopasswd' option
 *	   0.4  Cleaned out the error messages mess.
 *	   0.6  Inconsistency with gid/grp in comment/token/source
 *  	 	Make sure you really use 'Auth_MSQLgrp_field' as
 *		indicated above.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include <msql.h>

typedef struct  {

    char *auth_msql_host;
    char *auth_msql_database;

    char *auth_msql_pwd_table;
    char *auth_msql_grp_table;

    char *auth_msql_pwd_field;
    char *auth_msql_uname_field;
    char *auth_msql_grp_field;

    int auth_msql_nopasswd;

} msql_auth_config_rec;

void *create_msql_auth_dir_config (pool *p, char *d)
{
    return pcalloc (p, sizeof(msql_auth_config_rec));
}

char *set_passwd_flag (cmd_parms *cmd, msql_auth_config_rec *sec, int arg) {
    sec->auth_msql_nopasswd=arg;
    return NULL;
}

char *msql_set_string_slot (cmd_parms *cmd, char *struct_ptr, char *arg)
{
 
    int offset = (int)cmd->info; 
    *(char **)(struct_ptr + offset) = pstrdup (cmd->pool, arg);
    /* do we want to check anything ? */
    return NULL;
}

command_rec msql_auth_cmds[] = {
{ "Auth_MSQLhost", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_host),
    OR_AUTHCFG, TAKE1, "The Host must be set to something (or localhost)" },

{ "Auth_MSQLdatabase", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_database),
    OR_AUTHCFG, TAKE1, "The Database field must be set to something. " },

{ "Auth_MSQLpwd_table", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_pwd_table),
    OR_AUTHCFG, TAKE1, "You must give a password table name" },

{ "Auth_MSQLgrp_table", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_grp_table),
    OR_AUTHCFG, TAKE1, "If you want to use groups, you must give a group table name" },

{ "Auth_MSQLpwd_field", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_pwd_field),
    OR_AUTHCFG, TAKE1, "The Password-field name must be set to something" },

{ "Auth_MSQLuid_field", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_uname_field),
    OR_AUTHCFG, TAKE1, "The UserID field name must be set to something" },

{ "Auth_MSQLgrp_field", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_grp_field),
    OR_AUTHCFG, TAKE1, 
	"GID field name must be set to something if you want to use groups" },

{ "Auth_MSQL_nopasswd", set_passwd_flag, NULL, OR_AUTHCFG, FLAG, 
	"Limited to 'on' or 'off'" },

{ NULL }
};

module msql_auth_module;

char msql_errstr[MAX_STRING_LEN];
		 /* global errno to be able to handle config/sql 
		 * failures separately
		 */

/* get the password for uname=user, and copy it
 * into r. Assume that user is a string and stored
 * as such in the mSQL database
 */
char *do_msql_query(request_rec *r, char *query, msql_auth_config_rec *sec) {

    	int 		sock;
    	m_result 	*results;
    	m_row 		currow;

 	char 		*result=NULL;
	char		*host=sec->auth_msql_host;

	msql_errstr[0]='\0';

	/* force fast access over /dev/msql */
	if ((host) && (!(strcasecmp(host,"localhost"))))
		*host=NULL;

    	if ((sock=msqlConnect(host)) == -1) {
		sprintf (msql_errstr,
			"mSQL: Could not connect to Msql DB %s (%s)",
			(sec->auth_msql_host ? sec->auth_msql_host : "\'unset!\'"),
			msqlErrMsg);
		return NULL;
    		}

    	if (msqlSelectDB(sock,sec->auth_msql_database) == -1 ) {
		sprintf (msql_errstr,"mSQL: Could not switch to Msql Table %s (%s)",
			(sec->auth_msql_database ? sec->auth_msql_database : "\'unset!\'"),
			msqlErrMsg);
		return NULL;
		}

    	if (msqlQuery(sock,query) == -1 ) {
		sprintf (msql_errstr,"mSQL: Could not Query %s (%s) with [%s]",
			(sec->auth_msql_database ? sec->auth_msql_database : "\'unset!\'"),
			msqlErrMsg,
			( query ? query : "\'unset!\'") );
		return NULL;
		}

	if (!(results=msqlStoreResult())) {
		sprintf (msql_errstr,"mSQL: Could not get the results from mSQL %s (%s) with [%s]",
			(sec->auth_msql_database ? sec->auth_msql_database : "\'unset!\'"),
			msqlErrMsg,
			( query ? query : "\'unset!\'") );
		return NULL;
		};

	if (msqlNumFields(results) == 1) 
		if (currow=msqlFetchRow(results)) {
			/* copy the first matching field value */
			if (!(result=palloc(r->pool,strlen(currow[0])+1))) {
				sprintf (msql_errstr,"mSQL: Could not get memory for mSQL %s (%s) with [%s]",
					(sec->auth_msql_database ? sec->auth_msql_database : "\'unset!\'"),
					msqlErrMsg,
					( query ? query : "\'unset!\'") );
				return NULL;
				};
			strcpy(result,currow[0]); 
			}

	/* ignore errors here ! */
	msqlFreeResult(results); 
	msqlClose(sock);
	return result;
}
	
char *get_msql_pw(request_rec *r, char *user, msql_auth_config_rec *sec) {
  	char 		query[MAX_STRING_LEN];

	if (
	    (!sec->auth_msql_pwd_table) ||
	    (!sec->auth_msql_pwd_field) ||
	    (!sec->auth_msql_uname_field)
	   ) {
		sprintf(msql_errstr,
			"mSQL: Missing parameters for password lookup: %s%s%s",
			(sec->auth_msql_pwd_table ? "" : "Password table "),
			(sec->auth_msql_pwd_field ? "" : "Password field name "),
			(sec->auth_msql_uname_field ? "" : "UserID field name ")
			);
		return NULL;
		};

    	sprintf(query,"select %s from %s where %s='%s'",
		sec->auth_msql_pwd_field,
		sec->auth_msql_pwd_table,
		sec->auth_msql_uname_field,
		user);

	return do_msql_query(r,query,sec);
}	   

char *get_msql_grp(request_rec *r, char *group,char *user, msql_auth_config_rec *sec) {
  	char 		query[MAX_STRING_LEN];

	if (
	    (!sec->auth_msql_grp_table) ||
	    (!sec->auth_msql_grp_field) ||
	    (!sec->auth_msql_uname_field)
	   ) {
		sprintf(msql_errstr,
			"mSQL: Missing parameters for password lookup: %s%s%s",
			(sec->auth_msql_grp_table ? "" : "Group table "),
			(sec->auth_msql_grp_field ? "" : "GroupID field name "),
			(sec->auth_msql_uname_field ? "" : "UserID field name ")
			);
		return NULL;
		};

    	sprintf(query,"select %s from %s where %s='%s' and %s='%s'",
		sec->auth_msql_grp_field,
		sec->auth_msql_grp_table,
		sec->auth_msql_uname_field,user,
		sec->auth_msql_grp_field,group
		);

	return do_msql_query(r,query,sec);
}	   


int msql_authenticate_basic_user (request_rec *r)
{
    msql_auth_config_rec *sec =
      (msql_auth_config_rec *)get_module_config (r->per_dir_config,
						&msql_auth_module);
    conn_rec *c = r->connection;
    char *sent_pw, *real_pw, *colon_pw;
    int res;
    
    msql_errstr[0]='\0';

    if ((res = get_basic_auth_pw (r, &sent_pw)))
        return res;

    /* if mSQL *password* checking is configured in any way, i.e. then
     * handle it, if not decline and leave it to the next in line..  
     * We do not check on dbase, group, userid or host name, as it is
     * perfectly possible to only do group control with mSQL and leave
     * user control to the next (dbm) guy in line.
     */
    if (
    	(!sec->auth_msql_pwd_table) && 
    	(!sec->auth_msql_pwd_field) 
	 ) return DECLINED;

    if(!(real_pw = get_msql_pw(r, c->user, sec ))) {
	if ( msql_errstr[0] ) {
		res = SERVER_ERROR;
		} else {
        	sprintf(msql_errstr,"mSQL: Password for user %s not found", c->user);
		note_basic_auth_failure (r);
		res = AUTH_REQUIRED;
		};
	log_reason (msql_errstr, r->filename, r);
	return res;
    }    

    /* allow no password, if the flag is set and the password
     * is empty. But be sure to log this.
     */

    if ((sec->auth_msql_nopasswd) && (!strlen(real_pw))) {
        sprintf(msql_errstr,"mSQL: user %s: Empty password accepted",c->user);
	log_reason (msql_errstr, r->uri, r);
	return OK;
	};

    /* if the flag is off however, keep that kind of stuff at
     * an arms length.
     */
    if ((!strlen(real_pw)) || (!strlen(sent_pw))) {
        sprintf(msql_errstr,"mSQL: user %s: Empty Password(s) Rejected",c->user);
	log_reason (msql_errstr, r->uri, r);
	note_basic_auth_failure (r);
	return AUTH_REQUIRED;
	};

    /* anyone know where the prototype for crypt is? */
    if(strcmp(real_pw,(char *)crypt(sent_pw,real_pw))) {
        sprintf(msql_errstr,"mSQL user %s: password mismatch",c->user);
	log_reason (msql_errstr, r->uri, r);
	note_basic_auth_failure (r);
	return AUTH_REQUIRED;
    }
    return OK;
}
    
/* Checking ID */
    
int msql_check_auth(request_rec *r) {
    msql_auth_config_rec *sec =
      (msql_auth_config_rec *)get_module_config (r->per_dir_config,
						&msql_auth_module);
    char *user = r->connection->user;
    int m = r->method_number;


    array_header *reqs_arr = requires (r);
    require_line *reqs = reqs_arr ? (require_line *)reqs_arr->elts : NULL;

    register int x,res;
    char *t, *w;

    msql_errstr[0]='\0';

    /* if we cannot do it; leave it to some other guy 
     */
    if ((!sec->auth_msql_grp_table)&&(!sec->auth_msql_grp_field)) 
	return DECLINED;

    if (!reqs_arr) return DECLINED;
    
    for(x=0; x < reqs_arr->nelts; x++) {
      
	if (! (reqs[x].method_mask & (1 << m))) continue;
	
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

        if (!strcmp(w,"group")) {
	   /* look up the membership for each of the groups in the table */
           while(t[0]) {
                if (get_msql_grp(r,getword(r->pool, &t, ' '),user,sec)) {
			return OK;
			};
       		};
	   if (msql_errstr[0]) {
		res = SERVER_ERROR;
		} else {
           	sprintf(msql_errstr,"user %s not in right groups (%s) ",user,w);
           	note_basic_auth_failure(r);
		res = AUTH_REQUIRED;
		};
	   log_reason (msql_errstr, r->filename, r);
	   return res;
           }
        }
    
    return DECLINED;
}


module msql_auth_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_msql_auth_dir_config,	/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   msql_auth_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   msql_authenticate_basic_user,	/* check_user_id */
   msql_check_auth,		/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* pre-run fixups */
   NULL				/* logger */
};
