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
 */

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_dbm.h"
#include "apr_md5.h"        /* for apr_password_validate */

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/

#include "mod_auth.h"

typedef struct {
    char *pwfile;
    char *dbmtype;
} authn_dbm_config_rec;

static void *create_authn_dbm_dir_config(apr_pool_t *p, char *d)
{
    authn_dbm_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->pwfile = NULL;
    conf->dbmtype = "default";

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
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_dbm_module;

static apr_status_t fetch_dbm_value(const char *dbmtype, const char *dbmfile,
                                    const char *user, char **value,
                                    apr_pool_t *pool)
{
    apr_dbm_t *f;
    apr_datum_t key, val;
    apr_status_t rv;

    rv = apr_dbm_open_ex(&f, dbmtype, dbmfile, APR_DBM_READONLY, 
                         APR_OS_DEFAULT, pool);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    key.dptr = (char*)user;
#ifndef NETSCAPE_DBM_COMPAT
    key.dsize = strlen(key.dptr);
#else
    key.dsize = strlen(key.dptr) + 1;
#endif

    *value = NULL;

    if (apr_dbm_fetch(f, key, &val) == APR_SUCCESS && val.dptr) {
        *value = apr_pstrmemdup(pool, val.dptr, val.dsize);
    }

    apr_dbm_close(f);
    
    return rv;
}

static authn_status check_dbm_pw(request_rec *r, const char *user,
                                 const char *password)
{
    authn_dbm_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authn_dbm_module);
    apr_status_t rv;
    char *dbm_password;
    char *colon_pw;

    rv = fetch_dbm_value(conf->dbmtype, conf->pwfile, user, &dbm_password,
                         r->pool);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "could not open dbm (type %s) auth file: %s",
                      conf->dbmtype, conf->pwfile);
        return AUTH_GENERAL_ERROR;
    }

    if (!dbm_password) {
        return AUTH_USER_NOT_FOUND;
    }

    colon_pw = ap_strchr(dbm_password, ':');
    if (colon_pw) {
        *colon_pw = '\0';
    }

    rv = apr_password_validate(password, dbm_password);

    if (rv != APR_SUCCESS) {
        return AUTH_DENIED;
    }

    return AUTH_GRANTED;
}

static authn_status get_dbm_realm_hash(request_rec *r, const char *user,
                                       const char *realm, char **rethash)
{
    authn_dbm_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authn_dbm_module);
    apr_status_t rv;
    char *dbm_hash;
    char *colon_hash;

    rv = fetch_dbm_value(conf->dbmtype, conf->pwfile,
                         apr_pstrcat(r->pool, user, ":", realm, NULL),
                         &dbm_hash, r->pool);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "Could not open dbm (type %s) hash file: %s",
                      conf->dbmtype, conf->pwfile);
        return AUTH_GENERAL_ERROR;
    }

    if (!dbm_hash) {
        return AUTH_USER_NOT_FOUND;
    }

    colon_hash = ap_strchr(dbm_hash, ':');
    if (colon_hash) {
        *colon_hash = '\0';
    }

    *rethash = dbm_hash;

    return AUTH_USER_FOUND;
}

static const authn_provider authn_dbm_provider =
{
    &check_dbm_pw,
    &get_dbm_realm_hash
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "dbm", "0",
                         &authn_dbm_provider);
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
