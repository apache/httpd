
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
 * mod_digest: MD5 digest authentication
 * 
 * by Alexei Kosut <akosut@nueva.pvt.k12.ca.us>
 * based on mod_auth, by Rob McCool and Robert S. Thau
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "util_md5.h"

typedef struct digest_config_struct {
    char *pwfile;
} digest_config_rec;

typedef struct digest_header_struct {
    char *username;
    char *realm;
    char *nonce;
    char *requested_uri;
    char *digest;
} digest_header_rec;

void *create_digest_dir_config (pool *p, char *d)
{
    return pcalloc (p, sizeof(digest_config_rec));
}

command_rec digest_cmds[] = {
{ "AuthDigestFile", set_string_slot,
    (void*)XtOffsetOf(digest_config_rec,pwfile), OR_AUTHCFG, TAKE1, NULL },
{ NULL }
};

module digest_module;

char *get_hash(request_rec *r, char *user, char *auth_pwfile)
{
    FILE *f;
    char l[MAX_STRING_LEN];
    char *rpw, *w, *x;

    if(!(f=pfopen(r->pool, auth_pwfile, "r"))) {
        log_reason ("Could not open password file", auth_pwfile, r);
	return NULL;
    }
    while(!(cfg_getline(l,MAX_STRING_LEN,f))) {
        if((l[0] == '#') || (!l[0])) continue;
	rpw = l;
        w = getword(r->pool, &rpw, ':');
	x = getword(r->pool, &rpw, ':');

        if(x && w && !strcmp(user,w) && !strcmp(auth_name(r), x)) {
	    pfclose(r->pool, f);
            return pstrdup (r->pool, rpw);
	}
    }
    pfclose(r->pool, f);
    return NULL;
}

/* Parse the Authorization header, if it exists */

int get_digest_rec(request_rec *r, digest_header_rec *response) {
  char *auth_line = table_get(r->headers_in, "Authorization");
  int l;
  int s = 0, vk = 0, vv = 0;
  char *t, *key, *value;

  if (!(t = auth_type(r)) || strcasecmp(t, "Digest"))
    return DECLINED;

  if (!auth_name (r)) {
    log_reason ("need AuthName", r->uri, r);
    return SERVER_ERROR;
  }

  if (!auth_line) {
    note_digest_auth_failure (r);
    return AUTH_REQUIRED;
  }

  if (strcmp(getword (r->pool, &auth_line, ' '), "Digest")) {
    /* Client tried to authenticate using wrong auth scheme */
    log_reason ("client used wrong authentication scheme", r->uri, r);
    note_digest_auth_failure (r);
    return AUTH_REQUIRED;
  }

  l = strlen(auth_line);

  key=palloc(r->pool,l);
  value=palloc(r->pool,l);

  /* There's probably a better way to do this, but for the time being... */

#define D_KEY 0
#define D_VALUE 1
#define D_STRING 2
#define D_EXIT -1

  while (s != D_EXIT) {
    switch (s) {
    case D_STRING:
      if (auth_line[0] == '\"') {
	s = D_VALUE;
      }
      else {
	value[vv] = auth_line[0];
	vv++;
      }
      auth_line++;
      break;

    case D_VALUE:
      if (isalnum(auth_line[0])) {
	value[vv] = auth_line[0];
	vv++;
      }
      else if (auth_line[0] == '\"') {
	s = D_STRING;
      }
      else {
	value[vv] = '\0';

	if (!strcasecmp(key, "username"))
	  response->username = pstrdup(r->pool, value);
	else if (!strcasecmp(key, "realm"))
	  response->realm = pstrdup(r->pool, value);
	else if (!strcasecmp(key, "nonce"))
	  response->nonce = pstrdup(r->pool, value);
	else if (!strcasecmp(key, "uri"))
	  response->requested_uri = pstrdup(r->pool, value);
	else if (!strcasecmp(key, "response"))
	  response->digest = pstrdup(r->pool, value);

	vv = 0;
	s = D_KEY;
      }
      auth_line++;
      break;

    case D_KEY:
      if (isalnum(auth_line[0])) {
	key[vk] = auth_line[0];
	vk++;
      }
      else if (auth_line[0] == '=') {
	key[vk] = '\0';
	vk = 0;
	s = D_VALUE;
      }
      auth_line++;
      break;
    }

    if (auth_line[-1] == '\0')
      s = D_EXIT;
  }

  if (!response->username || !response->realm || !response->nonce ||
      !response->requested_uri || !response->digest) {
    note_digest_auth_failure (r);
    return AUTH_REQUIRED;
  }

  r->connection->user = response->username;
  r->connection->auth_type = "Digest";

  return OK;
}

/* The actual MD5 code... whee */

char *find_digest(request_rec *r, digest_header_rec *h, char *a1) {
  return md5(r->pool,
	     (unsigned char *)pstrcat(r->pool, a1, ":", h->nonce, ":", 
			  md5(r->pool,
			      (unsigned char *)pstrcat(r->pool,r->method,":",
						       h->requested_uri,NULL)),
				      NULL));
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

int authenticate_digest_user (request_rec *r)
{
    digest_config_rec *sec =
      (digest_config_rec *)get_module_config (r->per_dir_config,
					      &digest_module);
    digest_header_rec *response = pcalloc (r->pool, sizeof(digest_header_rec));
    conn_rec *c = r->connection;
    char *a1;
    char errstr[MAX_STRING_LEN];
    int res;
    
    if ((res = get_digest_rec (r, response))) return res;
    
    if(!sec->pwfile) 
        return DECLINED;
	
    if (!(a1 = get_hash(r, c->user, sec->pwfile))) {
        sprintf(errstr,"user %s not found",c->user);
	log_reason (errstr, r->uri, r);
	note_digest_auth_failure (r);
	return AUTH_REQUIRED;
    }
    /* anyone know where the prototype for crypt is? */
    if(strcmp(response->digest, find_digest(r, response, a1))) {
        sprintf(errstr,"user %s: password mismatch",c->user);
	log_reason (errstr, r->uri, r);
	note_digest_auth_failure (r);
	return AUTH_REQUIRED;
    }
    return OK;
}
    
/* Checking ID */
    
int digest_check_auth (request_rec *r) {
    char *user = r->connection->user;
    int m = r->method_number;
    int method_restricted = 0;    
    register int x;
    char *t, *w;
    array_header *reqs_arr;
    require_line *reqs;

    if (!(t = auth_type(r)) || strcasecmp(t, "Digest"))
      return DECLINED;

    reqs_arr = requires (r);
    /* If there is no "requires" directive, 
     * then any user will do.
     */
    if (!reqs_arr)
        return OK;
    reqs = (require_line *)reqs_arr->elts;

    for(x=0; x < reqs_arr->nelts; x++) {
      
	if (! (reqs[x].method_mask & (1 << m))) continue;
	
        method_restricted = 1;

	t = reqs[x].requirement;
        w = getword(r->pool, &t, ' ');
        if(!strcmp(w,"valid-user"))
            return OK;
        else if(!strcmp(w,"user")) {
            while(t[0]) {
                w = getword_conf (r->pool, &t);
                if(!strcmp(user,w))
                    return OK;
            }
	  }
	else
	  return DECLINED;
    }
    
    if (!method_restricted)
      return OK;

    note_digest_auth_failure(r);
    return AUTH_REQUIRED;
}

module digest_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_digest_dir_config,	/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   digest_cmds,			/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   authenticate_digest_user,	/* check_user_id */
   digest_check_auth,		/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};


