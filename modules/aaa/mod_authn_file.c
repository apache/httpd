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
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

typedef struct {
    char *pwfile;
    int authoritative;
} authn_file_config_rec;

static void *create_authn_file_dir_config(apr_pool_t *p, char *d)
{
    authn_file_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->pwfile = NULL;     /* just to illustrate the default really */
    conf->authoritative = 1; /* keep the fortress secure by default */
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
    AP_INIT_FLAG("AuthUserFileAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authn_file_config_rec, authoritative),
                 OR_AUTHCFG,
                 "Set to 'no' to allow access control to be passed along to "
                 "other modules if the BasicAuth username is not in "
                 "AuthUserFile. (default is yes)." ),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_file_module;

static apr_status_t get_pw(request_rec *r, char *user, char *pwfile, 
                           char ** out)
{
    ap_configfile_t *f;
    char l[MAX_STRING_LEN];
    const char *rpw, *w;
    apr_status_t status;

    *out = NULL;

    if ((status = ap_pcfg_openfile(&f, r->pool, pwfile)) != APR_SUCCESS) {
        return status;
    }

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        if ((l[0] == '#') || (!l[0])) {
            continue;
        }
        rpw = l;
        w = ap_getword(r->pool, &rpw, ':');

        if (!strcmp(user, w)) {
            ap_cfg_closefile(f);
            *out = ap_getword(r->pool, &rpw, ':');
            return APR_SUCCESS;
        }
    }
    ap_cfg_closefile(f);

    return APR_SUCCESS;
}

/* These functions return 0 if client is OK, and proper error status
 * if not... either HTTP_UNAUTHORIZED, if we made a check, and it failed, or
 * HTTP_INTERNAL_SERVER_ERROR, if things are so totally confused that we
 * couldn't figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

/* Determine user ID, and check if it really is that user, for HTTP
 * basic authentication...
 */

static int authenticate_basic_user(request_rec *r)
{
    authn_file_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &authn_file_module);
    const char *sent_pw;
    char *real_pw = NULL;
    apr_status_t status;
    int res;

    if ((res = ap_get_basic_auth_pw(r, &sent_pw))) {
        return res;
    }

    if (!conf->pwfile) {
        return DECLINED;
    }

    if ((status = get_pw(r, r->user, conf->pwfile, &real_pw)) != APR_SUCCESS) 
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "Could not open password file: %s", conf->pwfile);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (real_pw == NULL) {
        if (!conf->authoritative) {
           return DECLINED;
        } 
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "user %s not found: %s", r->user, r->uri);
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    status = apr_password_validate(sent_pw, real_pw);

    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "user %s: authentication failure for \"%s\": "
                      "Password Mismatch",
                      r->user, r->uri);
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(authenticate_basic_user,NULL,NULL,APR_HOOK_MIDDLE);
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
