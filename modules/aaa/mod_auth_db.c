/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
 * reserved.
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
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
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
 * apache 2 port by Brian Martin 
 *
 * mod_auth_db was based on mod_auth_dbm.
 * 
 * Warning, this is not a drop in replacement for mod_auth_dbm, 
 * for people wanting to switch from dbm to Berkeley DB.
 * It requires the use of AuthDBUserFile and AuthDBGroupFile
 *           instead of   AuthDBMUserFile    AuthDBMGroupFile
 *
 * Also, in the configuration file you need to specify
 *  auth_db_module rather than auth_dbm_module
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
 *         modules if and only if the userid is not known to this
 *         module. A known user with a faulty or absent password still
 *         causes an AuthRequired. The default is 'Authoritative', i.e.
 *         no control is passed along.
 */

#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"  /* for ap_hook_(check_user_id | auth_check) */

#ifdef HAVE_DB_H
#include <db.h>
#endif

#if   defined(DB_VERSION_MAJOR) && (DB_VERSION_MAJOR == 3)
#define DB_VER 3
#elif defined(DB_VERSION_MAJOR) && (DB_VERSION_MAJOR == 2)
#define DB_VER 2
#else
#define DB_VER 1
#endif

typedef struct {

    char *auth_dbpwfile;
    char *auth_dbgrpfile;
    int auth_dbauthoritative;
} db_auth_config_rec;

static void *create_db_auth_dir_config(apr_pool_t *p, char *d)
{
    db_auth_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->auth_dbpwfile = NULL;
    conf->auth_dbgrpfile = NULL;
    conf->auth_dbauthoritative = 1;	/* fortress is secure by default */
    return conf;
}

static const char *set_db_slot(cmd_parms *cmd, void *offset, const char *f, const char *t)
{
    if (!t || strcmp(t, "db"))
	return DECLINE_CMD;

    return ap_set_file_slot(cmd, offset, f);
}

static const command_rec db_auth_cmds[] =
{
    AP_INIT_TAKE1("AuthDBUserFile", ap_set_file_slot,
     (void *) APR_XtOffsetOf(db_auth_config_rec, auth_dbpwfile),
     OR_AUTHCFG, "db database file containing user IDs and passwords"),
    AP_INIT_TAKE1("AuthDBGroupFile", ap_set_file_slot,
     (void *) APR_XtOffsetOf(db_auth_config_rec, auth_dbgrpfile),
     OR_AUTHCFG, "db database file containing group names and member user IDs"),
    AP_INIT_TAKE12("AuthUserFile", set_db_slot,
     (void *) APR_XtOffsetOf(db_auth_config_rec, auth_dbpwfile),
     OR_AUTHCFG, NULL),
    AP_INIT_TAKE12("AuthGroupFile", set_db_slot,
     (void *) APR_XtOffsetOf(db_auth_config_rec, auth_dbgrpfile),
     OR_AUTHCFG, NULL),
    AP_INIT_FLAG("AuthDBAuthoritative", ap_set_flag_slot,
     (void *) APR_XtOffsetOf(db_auth_config_rec, auth_dbauthoritative),
     OR_AUTHCFG,
     "Set to 'no' to allow access control to be passed along to lower modules if the userID is not known to this module"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA auth_db_module;

static char *get_db_pw(request_rec *r, char *user, const char *auth_dbpwfile)
{
    DB *f;
    DBT d, q;
    char *pw = NULL;
#if DB_VER > 1
    int retval;
#endif

    memset(&d, 0, sizeof(d));
    memset(&q, 0, sizeof(q));

    q.data = user;
    q.size = strlen(q.data);

#if DB_VER == 3
    db_create(&f, NULL, 0);
    if ((retval = f->open(f, auth_dbpwfile, NULL, DB_HASH, DB_RDONLY, 0664)) != 0) {
	char * reason;
	switch(retval) {
	case DB_OLD_VERSION:
	    reason = "Old database version.  Upgrade to version 3";
	    break;

	case EEXIST:
	    reason = "DB_CREATE and DB_EXCL were specified and the file exists";
	    break;

	case EINVAL:
	    reason = "An invalid flag value or parameter was specified";
	    break;

	case ENOENT:
	    reason = "A non-existent re_source file was specified";
	    break;

	default:
	    reason = "And I don't know why";
	    break;
	}
	ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
		      "could not open db auth file %s: %s", 
		      auth_dbpwfile, reason);
	return NULL;
    }
#elif DB_VER == 2
    if ((retval = db_open(auth_dbpwfile, DB_HASH, DB_RDONLY, 0664, NULL, NULL, &f)) != 0) {
	char * reason;
	switch(retval) {

	case EEXIST:
	    reason = "DB_CREATE and DB_EXCL were specified and the file exists.";
	    break;

	case EINVAL:
	    reason = "An invalid flag value or parameter was specified";
	    break;

	case ENOENT:
	    reason = "A non-existent re_source file was specified";
	    break;

	default:
	    reason = "And I don't know why";
	    break;
	}
	ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
		      "could not open db auth file %s: %s", 
		      auth_dbpwfile, reason);
	return NULL;
    }
#else
    if (!(f = dbopen(auth_dbpwfile, O_RDONLY, 0664, DB_HASH, NULL))) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
		      "could not open db auth file: %s", auth_dbpwfile);
	return NULL;
    }
#endif

#if DB_VER == 3 || DB_VER == 2
    if (!((f->get) (f, NULL, &q, &d, 0))) {
#else
    if (!((f->get) (f, &q, &d, 0))) {
#endif
	pw = apr_palloc(r->pool, d.size + 1);
	strncpy(pw, d.data, d.size);
	pw[d.size] = '\0';	/* Terminate the string */
    }

#if DB_VER == 3 || DB_VER == 2
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
    db_auth_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                    &auth_db_module);
    const char *sent_pw;
    char *real_pw, *colon_pw;
    apr_status_t invalid_pw;
    int res;

    if ((res = ap_get_basic_auth_pw(r, &sent_pw)))
	return res;

    if (!conf->auth_dbpwfile) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		      "DB file %s not found", conf->auth_dbpwfile);
	return DECLINED;
    }

    if (!(real_pw = get_db_pw(r, r->user, conf->auth_dbpwfile))) {
	if (!(conf->auth_dbauthoritative))
	    return DECLINED;
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		    "DB user %s not found: %s", r->user, r->filename);
	ap_note_basic_auth_failure(r);
	return HTTP_UNAUTHORIZED;
    }
    /* Password is up to first : if exists */
    colon_pw = strchr(real_pw, ':');
    if (colon_pw) {
	*colon_pw = '\0';
    }

    invalid_pw = apr_password_validate(sent_pw, real_pw);

    if (invalid_pw != APR_SUCCESS) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		      "DB user %s: authentication failure for \"%s\": "
                      "Password Mismatch",
		      r->user, r->uri);
	ap_note_basic_auth_failure(r);
	return HTTP_UNAUTHORIZED;
    }
    return OK;
}

/* Checking ID */

static int db_check_auth(request_rec *r)
{
    db_auth_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                    &auth_db_module);
    char *user = r->user;
    int m = r->method_number;

    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

    register int x;
    const char *t;
    char *w;

    if (!conf->auth_dbgrpfile)
	return DECLINED;
    if (!reqs_arr)
	return DECLINED;

    for (x = 0; x < reqs_arr->nelts; x++) {

	if (!(reqs[x].method_mask & (AP_METHOD_BIT << m)))
	    continue;

	t = reqs[x].requirement;
	w = ap_getword_white(r->pool, &t);

	if (!strcmp(w, "group") && conf->auth_dbgrpfile) {
	    const char *orig_groups, *groups;
	    char *v;

	    if (!(groups = get_db_grp(r, user, conf->auth_dbgrpfile))) {
		if (!(conf->auth_dbauthoritative))
		    return DECLINED;
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			      "user %s not in DB group file %s: %s",
			      user, conf->auth_dbgrpfile, r->filename);
		ap_note_basic_auth_failure(r);
		return HTTP_UNAUTHORIZED;
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
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "user %s not in right group: %s", user, r->filename);
	    ap_note_basic_auth_failure(r);
	    return HTTP_UNAUTHORIZED;
	}
    }

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(db_authenticate_basic_user, NULL, NULL,
                          APR_HOOK_MIDDLE);
    ap_hook_auth_checker(db_check_auth, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_db_module =
{
    STANDARD20_MODULE_STUFF,
    create_db_auth_dir_config,	/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server config */
    db_auth_cmds,		/* command apr_table_t */
    register_hooks		/* register hooks */
};

