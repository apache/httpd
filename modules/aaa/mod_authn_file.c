/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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
 * Rob McCool
 * 
 * Adapted to Apache by rst.
 *
 * dirkx - Added Authoritative control to allow passing on to lower
 *         modules if and only if the userid is not known to this
 *         module. A known user with a faulty or absent password still
 *         causes an AuthRequired. The default is 'Authoritative', i.e.
 *         no control is passed along.
 */

#include "apr_strings.h"
#include "apr_md5.h"            /* for apr_password_validate */

#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

typedef struct {
    char *pwfile;
} authn_file_config_rec;

static void *create_authn_file_dir_config(apr_pool_t *p, char *d)
{
    authn_file_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->pwfile = NULL;     /* just to illustrate the default really */
    return conf;
}

static const char *set_authn_file_slot(cmd_parms *cmd, void *offset,
                                       const char *f, const char *t)
{
    if (t && strcmp(t, "standard")) {
        return apr_pstrcat(cmd->pool, "Invalid auth file type: ", t, NULL);
    }

    return ap_set_file_slot(cmd, offset, f);
}

static const command_rec authn_file_cmds[] =
{
    AP_INIT_TAKE12("AuthUserFile", set_authn_file_slot,
                   (void *)APR_OFFSETOF(authn_file_config_rec, pwfile),
                   OR_AUTHCFG, "text file containing user IDs and passwords"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_file_module;

static authn_status check_password(request_rec *r, const char *user,
                                   const char *password)
{
    authn_file_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &authn_file_module);
    ap_configfile_t *f;
    char l[MAX_STRING_LEN];
    apr_status_t status;
    char *file_password = NULL;

    status = ap_pcfg_openfile(&f, r->pool, conf->pwfile);

    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "Could not open password file: %s", conf->pwfile);
        return AUTH_GENERAL_ERROR;
    }

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        const char *rpw, *w;

        /* Skip # or blank lines. */
        if ((l[0] == '#') || (!l[0])) {
            continue;
        }

        rpw = l;
        w = ap_getword(r->pool, &rpw, ':');

        if (!strcmp(user, w)) {
            file_password = ap_getword(r->pool, &rpw, ':');
            break;
        }
    }
    ap_cfg_closefile(f);

    if (!file_password) {
        return AUTH_USER_NOT_FOUND;
    }

    status = apr_password_validate(password, file_password);
    if (status != APR_SUCCESS) {
        return AUTH_DENIED;
    }

    return AUTH_GRANTED;
}

static authn_status get_realm_hash(request_rec *r, const char *user,
                                   const char *realm, char **rethash)
{
    authn_file_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &authn_file_module);
    ap_configfile_t *f;
    char l[MAX_STRING_LEN];
    apr_status_t status;
    char *file_hash = NULL;

    status = ap_pcfg_openfile(&f, r->pool, conf->pwfile);

    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "Could not open password file: %s", conf->pwfile);
        return AUTH_GENERAL_ERROR;
    }

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        const char *rpw, *w, *x;

        /* Skip # or blank lines. */
        if ((l[0] == '#') || (!l[0])) {
            continue;
        }

        rpw = l;
        w = ap_getword(r->pool, &rpw, ':');
        x = ap_getword(r->pool, &rpw, ':');

        if (x && w && !strcmp(user, w) && !strcmp(realm, x)) {
            /* Remember that this is a md5 hash of user:realm:password.  */
            file_hash = ap_getword(r->pool, &rpw, ':');
            break;
        }
    }
    ap_cfg_closefile(f);

    if (!file_hash) {
        return AUTH_USER_NOT_FOUND;
    }

    *rethash = file_hash;

    return AUTH_USER_FOUND;
}

static const authn_provider authn_file_provider =
{
    &check_password,
    &get_realm_hash,
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "file", "0",
                         &authn_file_provider);
}

module AP_MODULE_DECLARE_DATA authn_file_module =
{
    STANDARD20_MODULE_STUFF,
    create_authn_file_dir_config,    /* dir config creater */
    NULL,                            /* dir merger --- default is to override */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    authn_file_cmds,                 /* command apr_table_t */
    register_hooks                   /* register hooks */
};
