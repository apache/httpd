/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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
 * http_auth: authentication
 * 
 * Rob McCool & Brian Behlendorf.
 * 
 * Adapted to Apache by rst.
 *
 * dirkx - Added Authoritative control to allow passing on to lower  
 *         modules if and only if the userid is not known to this
 *         module. A known user with a faulty or absent password still
 *         causes an AuthRequired. The default is 'Authoritative', i.e.
 *         no control is passed along.
 */

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_dbm.h"
#include "apr_md5.h"        /* for apr_password_validate */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/


typedef struct {
    char *pwfile;
    char *dbmtype;
    int authoritative;
} authn_dbm_config_rec;

static void *create_authn_dbm_dir_config(apr_pool_t *p, char *d)
{
    authn_dbm_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->pwfile = NULL;
    conf->dbmtype = "default";
    conf->authoritative = 1;  /* fortress is secure by default */

    return conf;
}

static const char *set_dbm_type(cmd_parms *cmd, 
                                void *dir_config, 
                                const char *arg)
{
    authn_dbm_config_rec *conf = dir_config;
   
    conf->dbmtype = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const command_rec authn_dbm_cmds[] =
{
    AP_INIT_TAKE1("AuthDBMUserFile", ap_set_file_slot,
     (void *)APR_OFFSETOF(authn_dbm_config_rec, pwfile),
     OR_AUTHCFG, "dbm database file containing user IDs and passwords"),
    AP_INIT_TAKE1("AuthDBMType", set_dbm_type,
     NULL,
     OR_AUTHCFG, "what type of DBM file the user file is"),
    AP_INIT_FLAG("AuthDBMAuthoritative", ap_set_flag_slot,
     (void *)APR_OFFSETOF(authn_dbm_config_rec, authoritative),
     OR_AUTHCFG, "Set to 'no' to allow access control to be passed along to lower modules, if the UserID is not known in this module"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_dbm_module;

/* This should go into APR; perhaps with some nice
 * caching/locking/flocking of the open dbm file.
 *
 * Duplicated in mod_auth_dbm.c
 */
static apr_status_t
get_dbm_entry_as_str(request_rec *r, 
                     char *user, 
                     char *auth_dbmfile, 
                     char *dbtype,
                     char **str)
{
    apr_dbm_t *f;
    apr_datum_t d, q;
    char *pw = NULL;
    apr_status_t retval;
    q.dptr = user;

#ifndef NETSCAPE_DBM_COMPAT
    q.dsize = strlen(q.dptr);
#else
    q.dsize = strlen(q.dptr) + 1;
#endif

    retval = apr_dbm_open_ex(&f, dbtype, auth_dbmfile, APR_DBM_READONLY, 
                             APR_OS_DEFAULT, r->pool);

    if (retval != APR_SUCCESS) {
        return retval;
    }

    *str = NULL;

    if (apr_dbm_fetch(f, q, &d) == APR_SUCCESS && d.dptr) {
        *str = apr_palloc(r->pool, d.dsize + 1);
        strncpy(pw, d.dptr, d.dsize);
        *str[d.dsize] = '\0'; /* Terminate the string */
    }

    apr_dbm_close(f);

    return retval;
}

static int dbm_authenticate_basic_user(request_rec *r)
{
    authn_dbm_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                     &authn_dbm_module);
    const char *sent_pw;
    char *real_pw,*colon_pw;
    apr_status_t status;
    int res;

    if ((res = ap_get_basic_auth_pw(r, &sent_pw))) {
        return res;
    }

    if (!conf->pwfile) {
        return DECLINED;
    }

    status = get_dbm_entry_as_str(r, r->user, conf->pwfile,
                                  conf->dbmtype, &real_pw);

    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "could not open dbm (type %s) user auth file: %s",
                      conf->dbmtype, 
                      conf->pwfile);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if(real_pw == NULL) {

        if (!conf->authoritative) {
            return DECLINED;
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "DBM user %s not found: %s", r->user, r->filename);
        ap_note_basic_auth_failure(r);

        return HTTP_UNAUTHORIZED;
    }

    /* Password is up to first : if exists */
    colon_pw = strchr(real_pw, ':');
    if (colon_pw) {
        *colon_pw = '\0';
    }

    status = apr_password_validate(sent_pw, real_pw);

    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "DBM user %s: authentication failure for \"%s\": "
                      "Password Mismatch",
                      r->user, r->uri);
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(dbm_authenticate_basic_user, NULL, NULL,
                          APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authn_dbm_module =
{
    STANDARD20_MODULE_STUFF,
    create_authn_dbm_dir_config, /* dir config creater */
    NULL,                        /* dir merger --- default is to override */
    NULL,                        /* server config */
    NULL,                        /* merge server config */
    authn_dbm_cmds,              /* command apr_table_t */
    register_hooks               /* register hooks */
};
