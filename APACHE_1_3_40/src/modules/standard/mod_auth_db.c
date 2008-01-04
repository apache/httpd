/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

#if defined(DB_VERSION_MAJOR)
#if (DB_VERSION_MAJOR == 2)
#define DB2
#endif
#if (DB_VERSION_MAJOR == 3)
#define DB3
#endif
#if (DB_VERSION_MAJOR == 4)
#define DB4
#endif
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

    memset(&d, 0, sizeof(d));
    memset(&q, 0, sizeof(q));

    q.data = user;
    q.size = strlen(q.data);

#if defined(DB3) || defined(DB4)
    if (   db_create(&f, NULL, 0) != 0 
#if DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR > 0
        || f->open(f, NULL, auth_dbpwfile, NULL, DB_HASH, DB_RDONLY, 0664) != 0) {
#else
        || f->open(f, auth_dbpwfile, NULL, DB_HASH, DB_RDONLY, 0664) != 0) {
#endif
#elif defined(DB2)
    if (db_open(auth_dbpwfile, DB_HASH, DB_RDONLY, 0664, NULL, NULL, &f) != 0) {
#else
    if (!(f = dbopen(auth_dbpwfile, O_RDONLY, 0664, DB_HASH, NULL))) {
#endif
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "could not open db auth file: %s", auth_dbpwfile);
	return NULL;
    }

#if defined(DB2) || defined(DB3) || defined(DB4)
    if (!((f->get) (f, NULL, &q, &d, 0))) {
#else
    if (!((f->get) (f, &q, &d, 0))) {
#endif
	pw = ap_palloc(r->pool, d.size + 1);
	strncpy(pw, d.data, d.size);
	pw[d.size] = '\0';	/* Terminate the string */
    }

#if defined(DB2) || defined(DB3) || defined(DB4)
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
    char *invalid_pw;
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
    if (colon_pw) {
	*colon_pw = '\0';
    }
    invalid_pw = ap_validate_password(sent_pw, real_pw);
    if (invalid_pw != NULL) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "DB user %s: authentication failure for \"%s\": %s",
		      c->user, r->uri, invalid_pw);
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
	w = ap_getword_white(r->pool, &t);

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
		w = ap_getword_white(r->pool, &t);
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
