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
#include "apr_file_info.h"
#include "apr_user.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"     /* for AUTHZ_GROUP_NOTE */

typedef struct {
    int authoritative;
} authz_owner_config_rec;

static void *create_authz_owner_dir_config(apr_pool_t *p, char *d)
{
    authz_owner_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static const command_rec authz_owner_cmds[] =
{
    AP_INIT_FLAG("AuthzOwnerAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authz_owner_config_rec, authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules. (default is On.)"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_owner_module;

static int check_file_owner(request_rec *r)
{
    authz_owner_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                        &authz_owner_module);
    int m = r->method_number;
    register int x;
    const char *t, *w;
    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;
    int required_owner = 0;
    apr_status_t status = 0;
    char *reason = NULL;

    if (!reqs_arr) {
        return DECLINED;
    }

    reqs = (require_line *)reqs_arr->elts;
    for (x = 0; x < reqs_arr->nelts; x++) {

        /* if authoritative = On then break if a require already failed. */
        if (reason && conf->authoritative) {
            break;
        }

        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) {
            continue;
        }

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);

        if (!strcmp(w, "file-owner")) {
#if !APR_HAS_USER
            if ((required_owner & ~1) && conf->authoritative) {
                break;
            }

            required_owner |= 1; /* remember the requirement */
            reason = "'Require file-owner' is not supported on this platform.";
            continue;
#else  /* APR_HAS_USER */
            char *owner = NULL;
            apr_finfo_t finfo;

            if ((required_owner & ~1) && conf->authoritative) {
                break;
            }

            required_owner |= 1; /* remember the requirement */

            if (!r->filename) {
                reason = "no filename available";
                continue;
            }

            status = apr_stat(&finfo, r->filename, APR_FINFO_USER, r->pool);
            if (status != APR_SUCCESS) {
                reason = apr_pstrcat(r->pool, "could not stat file ",
                                     r->filename, NULL);
                continue;
            }

            if (!(finfo.valid & APR_FINFO_USER)) {
                reason = "no file owner information available";
                continue;
            }

            status = apr_uid_name_get(&owner, finfo.user, r->pool);
            if (status != APR_SUCCESS || !owner) {
                reason = "could not get name of file owner";
                continue;
            }

            if (strcmp(owner, r->user)) {
                reason = apr_psprintf(r->pool, "file owner %s does not match.",
                                      owner);
                continue;
            }

            /* this user is authorized */
            return OK;
#endif /* APR_HAS_USER */
        }

        /* file-group only figures out the file's group and lets
         * other modules do the actual authorization (against a group file/db).
         * Thus, these modules have to hook themselves after
         * mod_authz_owner and of course recognize 'file-group', too.
         */
        if (!strcmp(w, "file-group")) {
#if !APR_HAS_USER
            if ((required_owner & ~6) && conf->authoritative) {
                break;
            }

            required_owner |= 2; /* remember the requirement */
            reason = "'Require file-group' is not supported on this platform.";
            continue;
#else  /* APR_HAS_USER */
            char *group = NULL;
            apr_finfo_t finfo;

            if ((required_owner & ~6) && conf->authoritative) {
                break;
            }

            required_owner |= 2; /* remember the requirement */

            if (!r->filename) {
                reason = "no filename available";
                continue;
            }

            status = apr_stat(&finfo, r->filename, APR_FINFO_GROUP, r->pool);
            if (status != APR_SUCCESS) {
                reason = apr_pstrcat(r->pool, "could not stat file ",
                                     r->filename, NULL);
                continue;
            }

            if (!(finfo.valid & APR_FINFO_GROUP)) {
                reason = "no file group information available";
                continue;
            }

            status = apr_gid_name_get(&group, finfo.group, r->pool);
            if (status != APR_SUCCESS || !group) {
                reason = "could not get name of file group";
                continue;
            }

            /* store group name in a note and let others decide... */
            apr_table_setn(r->notes, AUTHZ_GROUP_NOTE, group);
            required_owner |= 4;
            continue;
#endif /* APR_HAS_USER */
        }
    }

    if (!required_owner || !conf->authoritative) {
        return DECLINED;
    }
    
    /* allow file-group passed to group db modules either if this is the
     * only applicable requirement here or if a file-owner failed but we're
     * not authoritative.
     * This allows configurations like:
     *
     * AuthzOwnerAuthoritative Off
     * require file-owner
     * require file-group
     *
     * with the semantical meaning of "either owner or group must match"
     * (inclusive or)
     *
     * [ 6 == 2 | 4; 7 == 1 | 2 | 4 ] should I use #defines instead?
     */
    if (required_owner == 6 || (required_owner == 7 && !conf->authoritative)) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                  "Authorization of user %s to access %s failed, reason: %s",
                  r->user, r->uri, reason ? reason : "unknown");

    ap_note_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_auth_checker(check_file_owner, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authz_owner_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_owner_dir_config, /* dir config creater */
    NULL,                          /* dir merger --- default is to override */
    NULL,                          /* server config */
    NULL,                          /* merge server config */
    authz_owner_cmds,              /* command apr_table_t */
    register_hooks                 /* register hooks */
};
