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
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

typedef struct {
    int authoritative;
} authz_default_config_rec;

static void *create_authz_default_dir_config(apr_pool_t *p, char *d)
{
    authz_default_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static const command_rec authz_default_cmds[] =
{
    AP_INIT_FLAG("AuthzDefaultAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authz_default_config_rec, authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules. (default is On.)"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_default_module;

static int check_user_access(request_rec *r)
{
    authz_default_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                 &authz_default_module);
    int m = r->method_number;
    int method_restricted = 0;
    register int x;
    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;

    /* BUG FIX: tadc, 11-Nov-1995.  If there is no "requires" directive, 
     * then any user will do.
     */
    if (!reqs_arr) {
        return OK;
    }
    reqs = (require_line *)reqs_arr->elts;

    for (x = 0; x < reqs_arr->nelts; x++) {
        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) {
            continue;
        }
        method_restricted = 1;
        break;
    }

    if (method_restricted == 0) {
        return OK;
    }

    if (!(conf->authoritative)) {
        return DECLINED;
    }

    /* if we aren't authoritative, any require directive could be
     * considered valid even if noone groked it.  However, if we are 
     * authoritative, we can warn the user they did something wrong.
     *
     * That something could be a missing "AuthAuthoritative off", but
     * more likely is a typo in the require directive.
     */
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "access to %s failed, reason: require directives "
                          "present and no Authoritative handler.", r->uri);

    ap_note_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_auth_checker(check_user_access,NULL,NULL,APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA authz_default_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_default_dir_config, /* dir config creater */
    NULL,                            /* dir merger --- default is to override */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    authz_default_cmds,              /* command apr_table_t */
    register_hooks                   /* register hooks */
};
