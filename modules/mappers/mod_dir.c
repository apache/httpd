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
 * mod_dir.c: handle default index files, and trailing-/ redirects
 */

#include "apr_strings.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"

module AP_MODULE_DECLARE_DATA dir_module;

typedef enum {
    SLASH_OFF = 0,
    SLASH_ON,
    SLASH_UNSET
} slash_cfg;

typedef struct dir_config_struct {
    apr_array_header_t *index_names;
    slash_cfg do_slash;
    const char *dflt;
} dir_config_rec;

#define DIR_CMD_PERMS OR_INDEXES

static const char *add_index(cmd_parms *cmd, void *dummy, const char *arg)
{
    dir_config_rec *d = dummy;
    const char *t, *w;
    int count = 0;

    if (!d->index_names) {
        d->index_names = apr_array_make(cmd->pool, 2, sizeof(char *));
    }

    t = arg;
    while ((w = ap_getword_conf(cmd->pool, &t)) && w[0]) {
        if (count == 0 && !strcasecmp(w, "disabled")) {
            /* peek to see if "disabled" is first in a series of arguments */
            const char *tt = t;
            const char *ww = ap_getword_conf(cmd->pool, &tt);
            if (ww == NULL || !ww[0]) {
               /* "disabled" is first, and alone */
               break;
            }
        }
        *(const char **)apr_array_push(d->index_names) = w;
        count++;
    }

    return NULL;
}

static const char *configure_slash(cmd_parms *cmd, void *d_, int arg)
{
    dir_config_rec *d = d_;

    d->do_slash = arg ? SLASH_ON : SLASH_OFF;
    return NULL;
}

static const command_rec dir_cmds[] =
{
    AP_INIT_TAKE1("DefaultHandler", ap_set_string_slot,
                  (void*)APR_OFFSETOF(dir_config_rec, dflt),
                  DIR_CMD_PERMS, "Set a default handler"),
    AP_INIT_RAW_ARGS("DirectoryIndex", add_index, NULL, DIR_CMD_PERMS,
                    "a list of file names"),
    AP_INIT_FLAG("DirectorySlash", configure_slash, NULL, DIR_CMD_PERMS,
                 "On or Off"),
    {NULL}
};

static void *create_dir_config(apr_pool_t *p, char *dummy)
{
    dir_config_rec *new = apr_pcalloc(p, sizeof(dir_config_rec));

    new->index_names = NULL;
    new->do_slash = SLASH_UNSET;
    return (void *) new;
}

static void *merge_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    dir_config_rec *new = apr_pcalloc(p, sizeof(dir_config_rec));
    dir_config_rec *base = (dir_config_rec *)basev;
    dir_config_rec *add = (dir_config_rec *)addv;

    new->index_names = add->index_names ? add->index_names : base->index_names;
    new->do_slash =
        (add->do_slash == SLASH_UNSET) ? base->do_slash : add->do_slash;
    new->dflt = add->dflt ? add->dflt : base->dflt;
    return new;
}

static int fixup_dflt(request_rec *r)
{
    dir_config_rec *d = ap_get_module_config(r->per_dir_config, &dir_module);
    const char *name_ptr;
    request_rec *rr;
    int error_notfound = 0;
    if ((r->finfo.filetype != APR_NOFILE) || (r->handler != NULL)) {
        return DECLINED;
    }
    name_ptr = d->dflt;
    if (name_ptr == NULL) {
        return DECLINED;
    }
    /* XXX: if DefaultHandler points to something that doesn't exist,
     * this may recurse until it hits the limit for internal redirects
     * before returning an Internal Server Error.
     */

    /* The logic of this function is basically cloned and simplified
     * from fixup_dir below.  See the comments there.
     */
    if (r->args != NULL) {
        name_ptr = apr_pstrcat(r->pool, name_ptr, "?", r->args, NULL);
    }
    rr = ap_sub_req_lookup_uri(name_ptr, r, r->output_filters);
    if (rr->status == HTTP_OK
        && (   (rr->handler && !strcmp(rr->handler, "proxy-server"))
            || rr->finfo.filetype == APR_REG)) {
        ap_internal_fast_redirect(rr, r);
        return OK;
    }
    else if (ap_is_HTTP_REDIRECT(rr->status)) {

        apr_pool_join(r->pool, rr->pool);
        r->notes = apr_table_overlay(r->pool, r->notes, rr->notes);
        r->headers_out = apr_table_overlay(r->pool, r->headers_out,
                                           rr->headers_out);
        r->err_headers_out = apr_table_overlay(r->pool, r->err_headers_out,
                                               rr->err_headers_out);
        error_notfound = rr->status;
    }
    else if (rr->status && rr->status != HTTP_NOT_FOUND
             && rr->status != HTTP_OK) {
        error_notfound = rr->status;
    }

    ap_destroy_sub_req(rr);
    if (error_notfound) {
        return error_notfound;
    }

    /* nothing for us to do, pass on through */
    return DECLINED;
}
static int fixup_dir(request_rec *r)
{
    dir_config_rec *d;
    char *dummy_ptr[1];
    char **names_ptr;
    int num_names;
    int error_notfound = 0;

    /* only handle requests against directories */
    if (r->finfo.filetype != APR_DIR) {
        return DECLINED;
    }

    /* In case mod_mime wasn't present, and no handler was assigned. */
    if (!r->handler) {
        r->handler = DIR_MAGIC_TYPE;
    }

    /* Never tolerate path_info on dir requests */
    if (r->path_info && *r->path_info) {
        return DECLINED;
    }

    d = (dir_config_rec *)ap_get_module_config(r->per_dir_config,
                                               &dir_module);

    /* Redirect requests that are not '/' terminated */
    if (r->uri[0] == '\0' || r->uri[strlen(r->uri) - 1] != '/')
    {
        char *ifile;

        if (!d->do_slash) {
            return DECLINED;
        }

        /* Only redirect non-get requests if we have no note to warn
         * that this browser cannot handle redirs on non-GET requests
         * (such as Microsoft's WebFolders).
         */
        if ((r->method_number != M_GET)
                && apr_table_get(r->subprocess_env, "redirect-carefully")) {
            return DECLINED;
        }

        if (r->args != NULL) {
            ifile = apr_pstrcat(r->pool, ap_escape_uri(r->pool, r->uri),
                                "/", "?", r->args, NULL);
        }
        else {
            ifile = apr_pstrcat(r->pool, ap_escape_uri(r->pool, r->uri),
                                "/", NULL);
        }

        apr_table_setn(r->headers_out, "Location",
                       ap_construct_url(r->pool, ifile, r));
        return HTTP_MOVED_PERMANENTLY;
    }

    if (d->index_names) {
        names_ptr = (char **)d->index_names->elts;
        num_names = d->index_names->nelts;
    }
    else {
        dummy_ptr[0] = AP_DEFAULT_INDEX;
        names_ptr = dummy_ptr;
        num_names = 1;
    }

    for (; num_names; ++names_ptr, --num_names) {
        /* XXX: Is this name_ptr considered escaped yet, or not??? */
        char *name_ptr = *names_ptr;
        request_rec *rr;

        /* Once upon a time args were handled _after_ the successful redirect.
         * But that redirect might then _refuse_ the given r->args, creating
         * a nasty tangle.  It seems safer to consider the r->args while we
         * determine if name_ptr is our viable index, and therefore set them
         * up correctly on redirect.
         */
        if (r->args != NULL) {
            name_ptr = apr_pstrcat(r->pool, name_ptr, "?", r->args, NULL);
        }

        rr = ap_sub_req_lookup_uri(name_ptr, r, r->output_filters);

        /* The sub request lookup is very liberal, and the core map_to_storage
         * handler will almost always result in HTTP_OK as /foo/index.html
         * may be /foo with PATH_INFO="/index.html", or even / with
         * PATH_INFO="/foo/index.html". To get around this we insist that the
         * the index be a regular filetype.
         *
         * Another reason is that the core handler also makes the assumption
         * that if r->finfo is still NULL by the time it gets called, the
         * file does not exist.
         */
        if (rr->status == HTTP_OK
            && (   (rr->handler && !strcmp(rr->handler, "proxy-server"))
                || rr->finfo.filetype == APR_REG)) {
            ap_internal_fast_redirect(rr, r);
            return OK;
        }

        /* If the request returned a redirect, propagate it to the client */

        if (ap_is_HTTP_REDIRECT(rr->status)
            || (rr->status == HTTP_NOT_ACCEPTABLE && num_names == 1)
            || (rr->status == HTTP_UNAUTHORIZED && num_names == 1)) {

            apr_pool_join(r->pool, rr->pool);
            error_notfound = rr->status;
            r->notes = apr_table_overlay(r->pool, r->notes, rr->notes);
            r->headers_out = apr_table_overlay(r->pool, r->headers_out,
                                               rr->headers_out);
            r->err_headers_out = apr_table_overlay(r->pool, r->err_headers_out,
                                                   rr->err_headers_out);
            return error_notfound;
        }

        /* If the request returned something other than 404 (or 200),
         * it means the module encountered some sort of problem. To be
         * secure, we should return the error, rather than allow autoindex
         * to create a (possibly unsafe) directory index.
         *
         * So we store the error, and if none of the listed files
         * exist, we return the last error response we got, instead
         * of a directory listing.
         */
        if (rr->status && rr->status != HTTP_NOT_FOUND
                && rr->status != HTTP_OK) {
            error_notfound = rr->status;
        }

        ap_destroy_sub_req(rr);
    }

    if (error_notfound) {
        return error_notfound;
    }

    /* nothing for us to do, pass on through */
    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    /* the order of these is of no consequence */
    ap_hook_fixups(fixup_dir,NULL,NULL,APR_HOOK_LAST);
    ap_hook_fixups(fixup_dflt,NULL,NULL,APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA dir_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,          /* create per-directory config structure */
    merge_dir_configs,          /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    dir_cmds,                   /* command apr_table_t */
    register_hooks              /* register hooks */
};
