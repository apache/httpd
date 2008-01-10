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
 * http_auth: authentication
 * 
 * Rob McCool & Brian Behlendorf.
 * 
 * Adapted to Apache by rst.
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
#if (defined(WIN32) || defined(NETWARE))
#include <sdbm.h>
#define dbm_open sdbm_open
#define dbm_fetch sdbm_fetch
#define dbm_close sdbm_close
#else
#include <ndbm.h>
#endif

/*
 * Module definition information - the part between the -START and -END
 * lines below is used by Configure. This could be stored in a separate
 * instead.
 *
 * MODULE-DEFINITION-START
 * Name: dbm_auth_module
 * ConfigStart
    . ./helpers/find-dbm-lib
 * ConfigEnd
 * MODULE-DEFINITION-END
 */

typedef struct {

    char *auth_dbmpwfile;
    char *auth_dbmgrpfile;
    int auth_dbmauthoritative;

} dbm_auth_config_rec;

static void *create_dbm_auth_dir_config(pool *p, char *d)
{
    dbm_auth_config_rec *sec
    = (dbm_auth_config_rec *) ap_pcalloc(p, sizeof(dbm_auth_config_rec));

    sec->auth_dbmpwfile = NULL;
    sec->auth_dbmgrpfile = NULL;
    sec->auth_dbmauthoritative = 1;	/* fortress is secure by default */

    return sec;
}

static const char *set_dbm_slot(cmd_parms *cmd, void *offset, char *f, char *t)
{
    if (!t || strcmp(t, "dbm"))
	return DECLINE_CMD;

    return ap_set_file_slot(cmd, offset, f);
}

static const command_rec dbm_auth_cmds[] =
{
    {"AuthDBMUserFile", ap_set_file_slot,
     (void *) XtOffsetOf(dbm_auth_config_rec, auth_dbmpwfile),
     OR_AUTHCFG, TAKE1, NULL},
    {"AuthDBMGroupFile", ap_set_file_slot,
     (void *) XtOffsetOf(dbm_auth_config_rec, auth_dbmgrpfile),
     OR_AUTHCFG, TAKE1, NULL},
    {"AuthUserFile", set_dbm_slot,
     (void *) XtOffsetOf(dbm_auth_config_rec, auth_dbmpwfile),
     OR_AUTHCFG, TAKE12, NULL},
    {"AuthGroupFile", set_dbm_slot,
     (void *) XtOffsetOf(dbm_auth_config_rec, auth_dbmgrpfile),
     OR_AUTHCFG, TAKE12, NULL},
    {"AuthDBMAuthoritative", ap_set_flag_slot,
     (void *) XtOffsetOf(dbm_auth_config_rec, auth_dbmauthoritative),
     OR_AUTHCFG, FLAG, "Set to 'no' to allow access control to be passed along to lower modules, if the UserID is not known in this module"},
    {NULL}
};

module MODULE_VAR_EXPORT dbm_auth_module;

static char *get_dbm_pw(request_rec *r, char *user, char *auth_dbmpwfile)
{
    DBM *f;
    datum d, q;
    char *pw = NULL;

    q.dptr = user;
#ifndef NETSCAPE_DBM_COMPAT
    q.dsize = strlen(q.dptr);
#else
    q.dsize = strlen(q.dptr) + 1;
#endif


    if (!(f = dbm_open(auth_dbmpwfile, O_RDONLY, 0664))) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		    "could not open dbm auth file: %s", auth_dbmpwfile);
	return NULL;
    }

    d = dbm_fetch(f, q);

    if (d.dptr) {
	pw = ap_palloc(r->pool, d.dsize + 1);
	strncpy(pw, d.dptr, d.dsize);
	pw[d.dsize] = '\0';	/* Terminate the string */
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

static char *get_dbm_grp(request_rec *r, char *user, char *auth_dbmgrpfile)
{
    char *grp_data = get_dbm_pw(r, user, auth_dbmgrpfile);
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

static int dbm_authenticate_basic_user(request_rec *r)
{
    dbm_auth_config_rec *sec =
    (dbm_auth_config_rec *) ap_get_module_config(r->per_dir_config,
					      &dbm_auth_module);
    conn_rec *c = r->connection;
    const char *sent_pw;
    char *real_pw, *colon_pw;
    char *invalid_pw;
    int res;

    if ((res = ap_get_basic_auth_pw(r, &sent_pw)))
	return res;

    if (!sec->auth_dbmpwfile)
	return DECLINED;

    if (!(real_pw = get_dbm_pw(r, c->user, sec->auth_dbmpwfile))) {
	if (!(sec->auth_dbmauthoritative))
	    return DECLINED;
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		    "DBM user %s not found: %s", c->user, r->filename);
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
		      "DBM user %s: authentication failure for \"%s\": %s",
		      c->user, r->uri, invalid_pw);
	ap_note_basic_auth_failure(r);
	return AUTH_REQUIRED;
    }
    return OK;
}

/* Checking ID */

static int dbm_check_auth(request_rec *r)
{
    dbm_auth_config_rec *sec =
    (dbm_auth_config_rec *) ap_get_module_config(r->per_dir_config,
					      &dbm_auth_module);
    char *user = r->connection->user;
    int m = r->method_number;

    const array_header *reqs_arr = ap_requires(r);
    require_line *reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

    register int x;
    const char *t;
    char *w;

    if (!sec->auth_dbmgrpfile)
	return DECLINED;
    if (!reqs_arr)
	return DECLINED;

    for (x = 0; x < reqs_arr->nelts; x++) {

	if (!(reqs[x].method_mask & (1 << m)))
	    continue;

	t = reqs[x].requirement;
	w = ap_getword_white(r->pool, &t);

	if (!strcmp(w, "group") && sec->auth_dbmgrpfile) {
	    const char *orig_groups, *groups;
	    char *v;

	    if (!(groups = get_dbm_grp(r, user, sec->auth_dbmgrpfile))) {
		if (!(sec->auth_dbmauthoritative))
		    return DECLINED;
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			    "user %s not in DBM group file %s: %s",
			    user, sec->auth_dbmgrpfile, r->filename);
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
			"user %s not in right group: %s",
			user, r->filename);
	    ap_note_basic_auth_failure(r);
	    return AUTH_REQUIRED;
	}
    }

    return DECLINED;
}


module MODULE_VAR_EXPORT dbm_auth_module =
{
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
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
