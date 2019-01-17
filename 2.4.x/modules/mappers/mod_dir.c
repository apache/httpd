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
#include "apr_lib.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"
#include "mod_rewrite.h"

module AP_MODULE_DECLARE_DATA dir_module;

typedef enum {
    MODDIR_OFF = 0,
    MODDIR_ON,
    MODDIR_UNSET
} moddir_cfg;

#define REDIRECT_OFF   0
#define REDIRECT_UNSET 1

typedef struct dir_config_struct {
    apr_array_header_t *index_names;
    moddir_cfg do_slash;
    moddir_cfg checkhandler;
    int redirect_index;
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
            const char *ww = ap_getword_conf(cmd->temp_pool, &tt);
            if (ww[0] == '\0') {
               /* "disabled" is first, and alone */
               apr_array_clear(d->index_names); 
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

    d->do_slash = arg ? MODDIR_ON : MODDIR_OFF;
    return NULL;
}
static const char *configure_checkhandler(cmd_parms *cmd, void *d_, int arg)
{
    dir_config_rec *d = d_;

    d->checkhandler = arg ? MODDIR_ON : MODDIR_OFF;
    return NULL;
}
static const char *configure_redirect(cmd_parms *cmd, void *d_, const char *arg1)
{
    dir_config_rec *d = d_;
    int status;

    if (!strcasecmp(arg1, "ON"))
        status = HTTP_MOVED_TEMPORARILY;
    else if (!strcasecmp(arg1, "OFF"))
        status = REDIRECT_OFF;
    else if (!strcasecmp(arg1, "permanent"))
        status = HTTP_MOVED_PERMANENTLY;
    else if (!strcasecmp(arg1, "temp"))
        status = HTTP_MOVED_TEMPORARILY;
    else if (!strcasecmp(arg1, "seeother"))
        status = HTTP_SEE_OTHER;
    else if (apr_isdigit(*arg1)) {
        status = atoi(arg1);
        if (!ap_is_HTTP_REDIRECT(status)) {
            return "DirectoryIndexRedirect only accepts values between 300 and 399";
        }
    }
    else {
        return "DirectoryIndexRedirect ON|OFF|permanent|temp|seeother|3xx";
    }

    d->redirect_index = status;
    return NULL;
}
static const command_rec dir_cmds[] =
{
    AP_INIT_TAKE1("FallbackResource", ap_set_string_slot,
                  (void*)APR_OFFSETOF(dir_config_rec, dflt),
                  DIR_CMD_PERMS, "Set a default handler"),
    AP_INIT_RAW_ARGS("DirectoryIndex", add_index, NULL, DIR_CMD_PERMS,
                    "a list of file names"),
    AP_INIT_FLAG("DirectorySlash", configure_slash, NULL, DIR_CMD_PERMS,
                 "On or Off"),
    AP_INIT_FLAG("DirectoryCheckHandler", configure_checkhandler, NULL, DIR_CMD_PERMS,
                 "On or Off"),
    AP_INIT_TAKE1("DirectoryIndexRedirect", configure_redirect,
                   NULL, DIR_CMD_PERMS, "On, Off, or a 3xx status code."),

    {NULL}
};

static void *create_dir_config(apr_pool_t *p, char *dummy)
{
    dir_config_rec *new = apr_pcalloc(p, sizeof(dir_config_rec));

    new->index_names = NULL;
    new->do_slash = MODDIR_UNSET;
    new->checkhandler = MODDIR_UNSET;
    new->redirect_index = REDIRECT_UNSET;
    return (void *) new;
}

static void *merge_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    dir_config_rec *new = apr_pcalloc(p, sizeof(dir_config_rec));
    dir_config_rec *base = (dir_config_rec *)basev;
    dir_config_rec *add = (dir_config_rec *)addv;

    new->index_names = add->index_names ? add->index_names : base->index_names;
    new->do_slash =
        (add->do_slash == MODDIR_UNSET) ? base->do_slash : add->do_slash;
    new->checkhandler =
        (add->checkhandler == MODDIR_UNSET) ? base->checkhandler : add->checkhandler;
    new->redirect_index=
        (add->redirect_index == REDIRECT_UNSET) ? base->redirect_index : add->redirect_index;
    new->dflt = add->dflt ? add->dflt : base->dflt;
    return new;
}

static int fixup_dflt(request_rec *r)
{
    dir_config_rec *d = ap_get_module_config(r->per_dir_config, &dir_module);
    const char *name_ptr;
    request_rec *rr;
    int error_notfound = 0;

    name_ptr = d->dflt;
    if ((name_ptr == NULL) || !(strcasecmp(name_ptr,"disabled"))){
        return DECLINED;
    }
    /* XXX: if FallbackResource points to something that doesn't exist,
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
                                "/?", r->args, NULL);
        }
        else {
            ifile = apr_pstrcat(r->pool, ap_escape_uri(r->pool, r->uri),
                                "/", NULL);
        }

        apr_table_setn(r->headers_out, "Location",
                       ap_construct_url(r->pool, ifile, r));
        return HTTP_MOVED_PERMANENTLY;
    }

    /* we're running between mod_rewrites fixup and its internal redirect handler, step aside */
    if (!strcmp(r->handler, REWRITE_REDIRECT_HANDLER_NAME)) { 
        /* Prevent DIR_MAGIC_TYPE from leaking out when someone has taken over */
        if (!strcmp(r->content_type, DIR_MAGIC_TYPE)) { 
            r->content_type = NULL;
        }
        return DECLINED;
    }

    if (d->checkhandler == MODDIR_ON && strcmp(r->handler, DIR_MAGIC_TYPE)) {
        /* Prevent DIR_MAGIC_TYPE from leaking out when someone has taken over */
        if (!strcmp(r->content_type, DIR_MAGIC_TYPE)) { 
            r->content_type = NULL;
        }
        return DECLINED;
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

            if (ap_is_HTTP_REDIRECT(d->redirect_index)) {
                apr_table_setn(r->headers_out, "Location", ap_construct_url(r->pool, rr->uri, r));
                return d->redirect_index;
            }

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

    /* record what we tried, mostly for the benefit of mod_autoindex */
    apr_table_setn(r->notes, "dir-index-names",
                   d->index_names ?
                       apr_array_pstrcat(r->pool, d->index_names, ',') :
                       AP_DEFAULT_INDEX);

    /* nothing for us to do, pass on through */
    return DECLINED;
}

static int dir_fixups(request_rec *r)
{
    if (r->finfo.filetype == APR_DIR) {
        /* serve up a directory */
        return fixup_dir(r);
    }
    else if ((r->finfo.filetype == APR_NOFILE) && (r->handler == NULL)) {
        /* No handler and nothing in the filesystem - use fallback */
        return fixup_dflt(r);
    }
    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(dir_fixups,NULL,NULL,APR_HOOK_LAST);
}

AP_DECLARE_MODULE(dir) = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,          /* create per-directory config structure */
    merge_dir_configs,          /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    dir_cmds,                   /* command apr_table_t */
    register_hooks              /* register hooks */
};
