
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
 * Version 0.3 Feb 1996
 *
 * Brutally raped by Dirk.vanGulik@jrc.it to
 * 
 * Adapted to allow anonymous logins, just like with Anon-FTP, when
 * one gives the magic user name 'anonymous' and ones email address
 * as the password.
 *
 * Just add the following tokes to your <directory> setup:
 * 
 * Anonymous 			'magic-user-id'
 *
 * Anonymous_MustGiveEmail	[on | off]
 * Anonymous_NoUserId		[on | off]
 *
 * The magic user id is something like 'anonymous', it is NOT case sensitive. 
 *
 * The MustGiveEmail flag can be used to force users to enter something
 * in the password field (like an email address).
 *
 * Furthermore the 'NoUserID' flag can be set to allow completely empty
 * usernames in as well; this can be is convenient as a single return
 * in broken GUIs like W95 is often given by the user.
 *
 * Dirk.vanGulik@jrc.it; http://ewse.ceo.org; http://me-www.jrc.it/~dirkx
 * 
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

typedef struct  {

    char *auth_anon;
    int   auth_anon_nouserid;
    int   auth_anon_mustemail;

} anon_auth_config_rec;

void *create_anon_auth_dir_config (pool *p, char *d)
{
    return pcalloc (p, sizeof(anon_auth_config_rec));
}

char *anon_set_passwd_flag (cmd_parms *cmd, anon_auth_config_rec *sec, int arg) {
    sec->auth_anon_mustemail=arg;
    return NULL;
}

char *anon_set_userid_flag (cmd_parms *cmd, anon_auth_config_rec *sec, int arg) {
    sec->auth_anon_nouserid=arg;
    return NULL;
}

command_rec anon_auth_cmds[] = {
{ "Anonymous", set_string_slot,
    (void*)XtOffsetOf(anon_auth_config_rec, auth_anon),
    OR_AUTHCFG, TAKE1, NULL },
{ "Anonymous_MustGiveEmail", anon_set_passwd_flag, NULL, OR_AUTHCFG, FLAG, 
	"Limited to 'on' or 'off'" },
{ "Anonymous_NoUserId", anon_set_userid_flag, NULL, OR_AUTHCFG, FLAG, 
	"Limited to 'on' or 'off'" },

{ NULL }
};

module anon_auth_module;

int anon_authenticate_basic_user (request_rec *r)
{
    anon_auth_config_rec *sec =
      (anon_auth_config_rec *)get_module_config (r->per_dir_config,
						&anon_auth_module);
    conn_rec *c = r->connection;
    char *send_pw;
    char errstr[MAX_STRING_LEN];
    int res;
    
    if ((res=get_basic_auth_pw (r,&send_pw)))
	return res;

    /* Ignore if we are not configured */
    if (!sec->auth_anon) return DECLINED;

    /* Do we allow an empty userID and/or is it the magic one
     */
	
    if ( (!strcasecmp(c->user,sec->auth_anon)) || 
	( (!(c->user[0])) && (sec->auth_anon_nouserid))) {

	/* Do we *insist* in a password of some flavour ? */
	if ((!sec->auth_anon_mustemail) || strlen(send_pw)) {
		sprintf(errstr,"Anonymous: Passwd <%s> Accepted", send_pw ? send_pw : "\'none\'");
   		log_error (errstr, r->server );
		return OK;
		};
	};
     

   return DECLINED;
}
    
int check_anon_access (request_rec *r) {

    conn_rec *c = r->connection;
    anon_auth_config_rec *sec =
      (anon_auth_config_rec *)get_module_config (r->per_dir_config,
						&anon_auth_module);
	
/*
    if (!sec->auth_anon) return DECLINED;

    if ( strcasecmp(r->connection->user,sec->auth_anon ))
     	return DECLINED;

   return OK;
*/
   return DECLINED;
}
 

module anon_auth_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_anon_auth_dir_config,	/* dir config creater */
   NULL,			/* dir merger ensure strictness */
   NULL,			/* server config */
   NULL,			/* merge server config */
   anon_auth_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   anon_authenticate_basic_user,/* check_user_id */
   check_anon_access,		/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
