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

/* This module is triggered by an
 *
 *          AuthGroupFile standard /path/to/file
 *
 * and the presense of a
 *
 *         require group <list-of-groups>
 * 
 * In an applicable limit/directory block for that method.
 *
 * If there are no AuthGroupFile directives valid for 
 * the request; we DECLINED.
 * 
 * If the AuthGroupFile is defined; but somehow not
 * accessible: we SERVER_ERROR (was DECLINED).
 *
 * If there are no 'require ' directives defined for
 * this request then we DECLINED (was OK).
 * 
 * If there are no 'require ' directives valid for
 * this request method then we DECLINED. (was OK)
 *
 * If there are any 'require group' blocks and we
 * are not in any group - we HTTP_UNAUTHORIZE
 * unless we are non-authoritative; in which  
 * case we DECLINED.
 *
 */

#include "apr_strings.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

typedef struct {
    char *groupfile;
    int authoritative;
} authz_groupfile_config_rec;

static void *create_authz_groupfile_dir_config(apr_pool_t *p, char *d)
{
    authz_groupfile_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->groupfile = NULL;    
    conf->authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static const char *set_authz_groupfile_slot(cmd_parms *cmd, void *offset, const char *f, 
                                 const char *t)
{
    if (t && strcmp(t, "standard")) {
        return apr_pstrcat(cmd->pool, "Invalid auth file type: ", t, NULL);
    }

    return ap_set_file_slot(cmd, offset, f);
}

static const command_rec authz_groupfile_cmds[] =
{
    AP_INIT_TAKE12("AuthGroupFile", set_authz_groupfile_slot,
                   (void *)APR_OFFSETOF(authz_groupfile_config_rec, groupfile),
                   OR_AUTHCFG,
                   "text file containing group names and member user IDs"),
    AP_INIT_FLAG("AuthzGroupFileAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authz_groupfile_config_rec,
                                      authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the 'require group' fails. (default is "
                 "On)."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_groupfile_module;

static apr_status_t groups_for_user(apr_pool_t *p, char *user, char *grpfile,
                                    apr_table_t ** out)
{
    ap_configfile_t *f;
    apr_table_t *grps = apr_table_make(p, 15);
    apr_pool_t *sp;
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;
    apr_status_t status;

    if ((status = ap_pcfg_openfile(&f, p, grpfile)) != APR_SUCCESS) {
        return status ;
    }

    apr_pool_create(&sp, p);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        if ((l[0] == '#') || (!l[0])) {
            continue;
        }
        ll = l;
        apr_pool_clear(sp);

        group_name = ap_getword(sp, &ll, ':');

        while (ll[0]) {
            w = ap_getword_conf(sp, &ll);
            if (!strcmp(w, user)) {
                apr_table_setn(grps, apr_pstrdup(p, group_name), "in");
                break;
            }
        }
    }
    ap_cfg_closefile(f);
    apr_pool_destroy(sp);

    *out = grps;
    return APR_SUCCESS;
}

/* Checking ID */

static int check_user_access(request_rec *r)
{
    authz_groupfile_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authz_groupfile_module);
    char *user = r->user;
    int m = r->method_number;
    int required_group = 0;
    register int x,has_entries;
    const char *t, *w;
    apr_table_t *grpstatus;
    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;
    apr_status_t status;

    if (!reqs_arr) {
        return DECLINED; /* XXX change from legacy */
    } 
    
    reqs = (require_line *)reqs_arr->elts;

    /* If there is no group file - then we are not
     * configured. So decline. 
     */
    if (!(conf->groupfile))
         return DECLINED; 

    if ((status = groups_for_user(r->pool, user, conf->groupfile,
                                  &grpstatus)) != APR_SUCCESS) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                       "Could not open group file: %s", conf->groupfile);
         return HTTP_INTERNAL_SERVER_ERROR;
    };

    has_entries = apr_table_elts(grpstatus)->nelts;

    for (x = 0; x < reqs_arr->nelts; x++) {

        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) {
            continue;
        }

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);

        if (!strcmp(w, "group")) {
            required_group = 1;

            if (!has_entries) {
                /* we will never match, so exit immediately */
                break;
            }

            while (t[0]) {
                w = ap_getword_conf(r->pool, &t);
                if (apr_table_get(grpstatus, w)) {
                    return OK;
                }
            }
        }
    }

    /* No applicable "requires group" for this method seen */
    if (!required_group) {
        return DECLINED;
    }

    if (!(conf->authoritative)) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "access to %s failed, reason: user %s not part of the "
                  "'require'ed group(s).", r->uri, user);
        
    ap_note_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_auth_checker(check_user_access,NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authz_groupfile_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_groupfile_dir_config,/* dir config creater */
    NULL,                             /* dir merger -- default is to override */
    NULL,                             /* server config */
    NULL,                             /* merge server config */
    authz_groupfile_cmds,             /* command apr_table_t */
    register_hooks                    /* register hooks */
};
