/* ====================================================================
 * Copyright (c) 1995-1998 The Apache Group.  All rights reserved.
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
 * mod_auth_db: authentication
 * 
 * Original work by Rob McCool & Brian Behlendorf.
 * 
 * Adapted to Apache by rst (mod_auth_dbm)
 *
 * Adapted for Berkeley DB by Andrew Cohen 
 *
 * mod_auth_db was based on mod_auth_dbm.
 * 
 * Warning, this is not a drop in replacement for mod_auth_dbm, 
 * for people wanting to switch from dbm to Berkeley DB.
 * It requires the use of AuthDBUserFile and AuthDBGroupFile
 *           instead of   AuthDBMUserFile    AuthDBMGroupFile
 *
 * Also, in the configuration file you need to specify
 *  db_auth_module rather than dbm_auth_module
 *
 * On some BSD systems (e.g. FreeBSD and NetBSD) dbm is automatically
 * mapped to Berkeley DB. You can use either mod_auth_dbm or
 * mod_auth_db. The latter makes it more obvious that it's Berkeley.
 * On other platforms where you want to use the DB library you
 * usually have to install it first. See http://www.sleepycat.com/
 * for the distribution. The interface this module uses is the
 * one from DB version 1.85 and 1.86, but DB version 2.x
 * can also be used when compatibility mode is enabled.
 *
 * dirkx - Added Authoritative control to allow passing on to lower  
 *         modules if and only if the user-id is not known to this
 *         module. A known user with a faulty or absent password still
 *         causes an AuthRequired. The default is 'Authoritative', i.e.
 *         no control is passed along.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include <db.h>

#if defined(DB_VERSION_MAJOR) && (DB_VERSION_MAJOR == 2)
#define DB2
#endif

typedef struct {

    char *auth_dbpwfile;
    char *auth_dbgrpfile;
    int auth_dbauthoritative;
} db_auth_config_rec;

static void *create_db_auth_dir_config(pool *p, char *d)
{
    db_auth_config_rec *sec
    = (db_auth_config_rec *) ap_pcalloc(p, sizeof(db_auth_config_rec));
    sec->auth_dbpwfile = NULL;
    sec->auth_dbgrpfile = NULL;
    sec->auth_dbauthoritative = 1;	/* fortress is secure by default */
    return sec;
}

static const char *set_db_slot(cmd_parms *cmd, void *offset, char *f, char *t)
{
    if (!t || strcmp(t, "db"))
	return DECLINE_CMD;

    return ap_set_file_slot(cmd, offset, f);
}

static const command_rec db_auth_cmds[] =
{
    {"AuthDBUserFile", ap_set_file_slot,
     (void *) XtOffsetOf(db_auth_config_rec, auth_dbpwfile),
     OR_AUTHCFG, TAKE1, NULL},
    {"AuthDBGroupFile", ap_set_file_slot,
     (void *) XtOffsetOf(db_auth_config_rec, auth_dbgrpfile),
     OR_AUTHCFG, TAKE1, NULL},
    {"AuthUserFile", set_db_slot,
     (void *) XtOffsetOf(db_auth_config_rec, auth_dbpwfile),
     OR_AUTHCFG, TAKE12, NULL},
    {"AuthGroupFile", set_db_slot,
     (void *) XtOffsetOf(db_auth_config_rec, auth_dbgrpfile),
     OR_AUTHCFG, TAKE12, NULL},
    {"AuthDBAuthoritative", ap_set_flag_slot,
     (void *) XtOffsetOf(db_auth_config_rec, auth_dbauthoritative),
     OR_AUTHCFG, FLAG,
     "Set to 'no' to allow access control to be passed along to lower modules if the userID is not known to this module"},
    {NULL}
};

module db_auth_module;

static char *get_db_pw(request_rec *r, char *user, const char *auth_dbpwfile)
{
    DB *f;
    DBT d, q;
    char *pw = NULL;

    q.data = user;
    q.size = strlen(q.data);

#ifdef DB2
    if (db_open(auth_dbpwfile, DB_HASH, O_RDONLY, 0664, NULL, NULL,  &f) != 0) {
#else
    if (!(f = dbopen(auth_dbpwfile, O_RDONLY, 0664, DB_HASH, NULL))) {
#endif
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "could not open db auth file: %s", auth_dbpwfile);
	return NULL;
    }

#ifdef DB2
    if (!((f->get) (f, NULL, &q, &d, 0))) {
#else
    if (!((f->get) (f, &q, &d, 0))) {
#endif
	pw = ap_palloc(r->pool, d.size + 1);
	strncpy(pw, d.data, d.size);
	pw[d.size] = '\0';	/* Terminate the string */
    }

#ifdef DB2
    (f->close) (f, 0);
#else
    (f->close) (f);
#endif
    return pw;
}

/* We do something strange with the group file.  If the group file
 * contains any : we assume the format is
 *      key=username value=":"groupname [":"anything here is ignored]
 * otherwise we now (0.8.14+) assume that the format is
 *      key=username value=groupname
 * The first allows the password and group files to be the same 
 * physical DB file;   key=username value=password":"groupname[":"anything]
 *
 * mark@telescope.org, 22Sep95
 */

static char *get_db_grp(request_rec *r, char *user, const char *auth_dbgrpfile)
{
    char *grp_data = get_db_pw(r, user, auth_dbgrpfile);
    char *grp_colon;
    char *grp_colon2;

    if (grp_data == NULL)
	return NULL;

    if ((grp_colon = strchr(grp_data, ':')) != NULL) {
	grp_colon2 = strchr(++grp_colon, ':');
	if (grp_colon2)
	    *grp_colon2 = '\0';
	return grp_colon;
    }
    return grp_data;
}

static int db_authenticate_basic_user(request_rec *r)
{
    db_auth_config_rec *sec =
    (db_auth_config_rec *) ap_get_module_config(r->per_dir_config,
					     &db_auth_module);
    conn_rec *c = r->connection;
    const char *sent_pw;
    char *real_pw, *colon_pw;
    int res;

    if ((res = ap_get_basic_auth_pw(r, &sent_pw)))
	return res;

    if (!sec->auth_dbpwfile)
	return DECLINED;

    if (!(real_pw = get_db_pw(r, c->user, sec->auth_dbpwfile))) {
	if (!(sec->auth_dbauthoritative))
	    return DECLINED;
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		    "DB user %s not found: %s", c->user, r->filename);
	ap_note_basic_auth_failure(r);
	return AUTH_REQUIRED;
    }
    /* Password is up to first : if exists */
    colon_pw = strchr(real_pw, ':');
    if (colon_pw)
	*colon_pw = '\0';
    /* anyone know where the prototype for crypt is? */
    if (strcmp(real_pw, (char *) crypt(sent_pw, real_pw))) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		    "DB user %s: password mismatch: %s", c->user, r->uri);
	ap_note_basic_auth_failure(r);
	return AUTH_REQUIRED;
    }
    return OK;
}

/* Checking ID */

static int db_check_auth(request_rec *r)
{
    db_auth_config_rec *sec =
    (db_auth_config_rec *) ap_get_module_config(r->per_dir_config,
					     &db_auth_module);
    char *user = r->connection->user;
    int m = r->method_number;

    const array_header *reqs_arr = ap_requires(r);
    require_line *reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

    register int x;
    const char *t;
    char *w;

    if (!sec->auth_dbgrpfile)
	return DECLINED;
    if (!reqs_arr)
	return DECLINED;

    for (x = 0; x < reqs_arr->nelts; x++) {

	if (!(reqs[x].method_mask & (1 << m)))
	    continue;

	t = reqs[x].requirement;
	w = ap_getword(r->pool, &t, ' ');

	if (!strcmp(w, "group") && sec->auth_dbgrpfile) {
	    const char *orig_groups, *groups;
	    char *v;

	    if (!(groups = get_db_grp(r, user, sec->auth_dbgrpfile))) {
		if (!(sec->auth_dbauthoritative))
		    return DECLINED;
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			    "user %s not in DB group file %s: %s",
			    user, sec->auth_dbgrpfile, r->filename);
		ap_note_basic_auth_failure(r);
		return AUTH_REQUIRED;
	    }
	    orig_groups = groups;
	    while (t[0]) {
		w = ap_getword(r->pool, &t, ' ');
		groups = orig_groups;
		while (groups[0]) {
		    v = ap_getword(r->pool, &groups, ',');
		    if (!strcmp(v, w))
			return OK;
		}
	    }
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			"user %s not in right group: %s", user, r->filename);
	    ap_note_basic_auth_failure(r);
	    return AUTH_REQUIRED;
	}
    }

    return DECLINED;
}


module db_auth_module =
{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    create_db_auth_dir_config,	/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server config */
    db_auth_cmds,		/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    db_authenticate_basic_user,	/* check_user_id */
    db_check_auth,		/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
