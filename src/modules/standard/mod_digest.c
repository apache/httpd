/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
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

static void *create_digest_dir_config(pool *p, char *d)
{
    return ap_pcalloc(p, sizeof(digest_config_rec));
}

static const char *set_digest_slot(cmd_parms *cmd, void *offset, char *f, char *t)
{
    if (t && strcmp(t, "standard"))
	return ap_pstrcat(cmd->pool, "Invalid auth file type: ", t, NULL);

    return ap_set_string_slot(cmd, offset, f);
}

static const command_rec digest_cmds[] =
{
    {"AuthDigestFile", set_digest_slot,
  (void *) XtOffsetOf(digest_config_rec, pwfile), OR_AUTHCFG, TAKE12, NULL},
    {NULL}
};

module MODULE_VAR_EXPORT digest_module;

static char *get_hash(request_rec *r, char *user, char *auth_pwfile)
{
    configfile_t *f;
    char l[MAX_STRING_LEN];
    const char *rpw;
    char *w, *x;

    if (!(f = ap_pcfg_openfile(r->pool, auth_pwfile))) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "Could not open password file: %s", auth_pwfile);
	return NULL;
    }
    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
	if ((l[0] == '#') || (!l[0]))
	    continue;
	rpw = l;
	w = ap_getword(r->pool, &rpw, ':');
	x = ap_getword(r->pool, &rpw, ':');

	if (x && w && !strcmp(user, w) && !strcmp(ap_auth_name(r), x)) {
	    ap_cfg_closefile(f);
	    return ap_pstrdup(r->pool, rpw);
	}
    }
    ap_cfg_closefile(f);
    return NULL;
}

/* Parse the Authorization header, if it exists */

static int get_digest_rec(request_rec *r, digest_header_rec * response)
{
    const char *auth_line = ap_table_get(r->headers_in,
                                    r->proxyreq ? "Proxy-Authorization"
                                    : "Authorization");
    int l;
    int s, vk = 0, vv = 0;
    const char *t;
    char *key, *value;
    const char *scheme;

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Digest"))
	return DECLINED;

    if (!ap_auth_name(r)) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		    "need AuthName: %s", r->uri);
	return SERVER_ERROR;
    }

    if (!auth_line) {
	ap_note_digest_auth_failure(r);
	return AUTH_REQUIRED;
    }

    if (strcasecmp(scheme = ap_getword_white(r->pool, &auth_line), "Digest")) {
	/* Client tried to authenticate using wrong auth scheme */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		    "client used wrong authentication scheme: %s for %s", 
		    scheme, r->uri);
	ap_note_digest_auth_failure(r);
	return AUTH_REQUIRED;
    }

    l = strlen(auth_line);

    /* Note we don't allocate l + 1 bytes for these deliberately, because
     * there has to be at least one '=' character for either of these two
     * new strings to be terminated.  That takes care of the need for +1.
     */
    key = ap_palloc(r->pool, l);
    value = ap_palloc(r->pool, l);

    /* There's probably a better way to do this, but for the time being... */

#define D_KEY 0
#define D_VALUE 1
#define D_STRING 2
#define D_EXIT -1

    s = D_KEY;
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
	    if (ap_isalnum(auth_line[0])) {
		value[vv] = auth_line[0];
		vv++;
	    }
	    else if (auth_line[0] == '\"') {
		s = D_STRING;
	    }
	    else {
		value[vv] = '\0';

		if (!strcasecmp(key, "username"))
		    response->username = ap_pstrdup(r->pool, value);
		else if (!strcasecmp(key, "realm"))
		    response->realm = ap_pstrdup(r->pool, value);
		else if (!strcasecmp(key, "nonce"))
		    response->nonce = ap_pstrdup(r->pool, value);
		else if (!strcasecmp(key, "uri"))
		    response->requested_uri = ap_pstrdup(r->pool, value);
		else if (!strcasecmp(key, "response"))
		    response->digest = ap_pstrdup(r->pool, value);

		vv = 0;
		s = D_KEY;
	    }
	    auth_line++;
	    break;

	case D_KEY:
	    if (ap_isalnum(auth_line[0])) {
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
	ap_note_digest_auth_failure(r);
	return AUTH_REQUIRED;
    }

    r->connection->user = response->username;
    r->connection->ap_auth_type = "Digest";

    return OK;
}

/* The actual MD5 code... whee */

static char *find_digest(request_rec *r, digest_header_rec * h, char *a1)
{
    return ap_md5(r->pool,
		  (unsigned char *)ap_pstrcat(r->pool, a1, ":", h->nonce, ":",
					   ap_md5(r->pool,
		           (unsigned char *)ap_pstrcat(r->pool, r->method, ":",
						    h->requested_uri, NULL)),
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

static int authenticate_digest_user(request_rec *r)
{
    digest_config_rec *sec =
    (digest_config_rec *) ap_get_module_config(r->per_dir_config,
					    &digest_module);
    digest_header_rec *response = ap_pcalloc(r->pool, sizeof(digest_header_rec));
    conn_rec *c = r->connection;
    char *a1;
    int res;

    if ((res = get_digest_rec(r, response)))
	return res;

    if (!sec->pwfile)
	return DECLINED;

    if (!(a1 = get_hash(r, c->user, sec->pwfile))) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		    "user %s not found: %s", c->user, r->uri);
	ap_note_digest_auth_failure(r);
	return AUTH_REQUIRED;
    }
    if (strcmp(response->digest, find_digest(r, response, a1))) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		    "user %s: password mismatch: %s", c->user, r->uri);
	ap_note_digest_auth_failure(r);
	return AUTH_REQUIRED;
    }
    return OK;
}

/* Checking ID */

static int digest_check_auth(request_rec *r)
{
    char *user = r->connection->user;
    int m = r->method_number;
    int method_restricted = 0;
    register int x;
    const char *t;
    char *w;
    const array_header *reqs_arr;
    require_line *reqs;

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Digest"))
	return DECLINED;

    reqs_arr = ap_requires(r);
    /* If there is no "requires" directive, 
     * then any user will do.
     */
    if (!reqs_arr)
	return OK;
    reqs = (require_line *) reqs_arr->elts;

    for (x = 0; x < reqs_arr->nelts; x++) {

	if (!(reqs[x].method_mask & (1 << m)))
	    continue;

	method_restricted = 1;

	t = reqs[x].requirement;
	w = ap_getword_white(r->pool, &t);
	if (!strcmp(w, "valid-user"))
	    return OK;
	else if (!strcmp(w, "user")) {
	    while (t[0]) {
		w = ap_getword_conf(r->pool, &t);
		if (!strcmp(user, w))
		    return OK;
	    }
	}
	else
	    return DECLINED;
    }

    if (!method_restricted)
	return OK;

    ap_note_digest_auth_failure(r);
    return AUTH_REQUIRED;
}

module MODULE_VAR_EXPORT digest_module =
{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    create_digest_dir_config,	/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server config */
    digest_cmds,		/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    authenticate_digest_user,	/* check_user_id */
    digest_check_auth,		/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
