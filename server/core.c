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

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_fnmatch.h"
#include "apr_hash.h"
#include "apr_thread_proc.h"    /* for RLIMIT stuff */
#include "apr_hooks.h"

#define APR_WANT_IOVEC
#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h" /* For index_of_response().  Grump. */
#include "http_request.h"
#include "http_vhost.h"
#include "http_main.h"     /* For the default_handler below... */
#include "http_log.h"
#include "util_md5.h"
#include "http_connection.h"
#include "apr_buckets.h"
#include "util_filter.h"
#include "util_ebcdic.h"
#include "mpm.h"
#include "mpm_common.h"
#include "scoreboard.h"
#include "mod_core.h"
#include "mod_proxy.h"
#include "ap_listen.h"

/* LimitXMLRequestBody handling */
#define AP_LIMIT_UNSET                  ((long) -1)
#define AP_DEFAULT_LIMIT_XML_BODY       ((size_t)1000000)

#define AP_MIN_SENDFILE_BYTES           (256)

APR_HOOK_STRUCT(
    APR_HOOK_LINK(get_mgmt_items)
)

AP_IMPLEMENT_HOOK_RUN_ALL(int, get_mgmt_items,
                          (apr_pool_t *p, const char *val, apr_hash_t *ht),
                          (p, val, ht), OK, DECLINED)

/* Server core module... This module provides support for really basic
 * server operations, including options and commands which control the
 * operation of other modules.  Consider this the bureaucracy module.
 *
 * The core module also defines handlers, etc., do handle just enough
 * to allow a server with the core module ONLY to actually serve documents
 * (though it slaps DefaultType on all of 'em); this was useful in testing,
 * but may not be worth preserving.
 *
 * This file could almost be mod_core.c, except for the stuff which affects
 * the http_conf_globals.
 */

/* Handles for core filters */
AP_DECLARE_DATA ap_filter_rec_t *ap_subreq_core_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_core_output_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_content_length_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_net_time_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_core_input_filter_handle;

static void *create_core_dir_config(apr_pool_t *a, char *dir)
{
    core_dir_config *conf;

    conf = (core_dir_config *)apr_pcalloc(a, sizeof(core_dir_config));

    /* conf->r and conf->d[_*] are initialized by dirsection() or left NULL */

    conf->opts = dir ? OPT_UNSET : OPT_UNSET|OPT_ALL;
    conf->opts_add = conf->opts_remove = OPT_NONE;
    conf->override = dir ? OR_UNSET : OR_UNSET|OR_ALL;

    conf->content_md5 = 2;
    conf->accept_path_info = 3;

    conf->use_canonical_name = USE_CANONICAL_NAME_UNSET;

    conf->hostname_lookups = HOSTNAME_LOOKUP_UNSET;
    conf->satisfy = SATISFY_NOSPEC;

#ifdef RLIMIT_CPU
    conf->limit_cpu = NULL;
#endif
#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS)
    conf->limit_mem = NULL;
#endif
#ifdef RLIMIT_NPROC
    conf->limit_nproc = NULL;
#endif

    conf->limit_req_body = 0;
    conf->limit_xml_body = AP_LIMIT_UNSET;
    conf->sec_file = apr_array_make(a, 2, sizeof(ap_conf_vector_t *));

    conf->server_signature = srv_sig_unset;

    conf->add_default_charset = ADD_DEFAULT_CHARSET_UNSET;
    conf->add_default_charset_name = DEFAULT_ADD_DEFAULT_CHARSET_NAME;

    /* Overriding all negotiation
     */
    conf->mime_type = NULL;
    conf->handler = NULL;
    conf->output_filters = NULL;
    conf->input_filters = NULL;

    /*
     * Flag for use of inodes in ETags.
     */
    conf->etag_bits = ETAG_UNSET;
    conf->etag_add = ETAG_UNSET;
    conf->etag_remove = ETAG_UNSET;

    conf->enable_mmap = ENABLE_MMAP_UNSET;
    conf->enable_sendfile = ENABLE_SENDFILE_UNSET;
    conf->allow_encoded_slashes = 0;

    return (void *)conf;
}

/*
 * Overlay one hash table of ct_output_filters onto another
 */
static void *merge_ct_filters(apr_pool_t *p,
                              const void *key,
                              apr_ssize_t klen,
                              const void *overlay_val,
                              const void *base_val,
                              const void *data)
{
    ap_filter_rec_t *cur;
    const ap_filter_rec_t *overlay_info = (const ap_filter_rec_t *)overlay_val;
    const ap_filter_rec_t *base_info = (const ap_filter_rec_t *)base_val;

    cur = NULL;

    while (overlay_info) {
        ap_filter_rec_t *new;

        new = apr_pcalloc(p, sizeof(ap_filter_rec_t));
        new->name = apr_pstrdup(p, overlay_info->name);
        new->next = cur;
        cur = new;
        overlay_info = overlay_info->next;
    }

    while (base_info) {
        ap_filter_rec_t *f;
        int found = 0;

        /* We can't have dups. */
        f = cur;
        while (f) {
            if (!strcasecmp(base_info->name, f->name)) {
                found = 1;
                break;
            }

            f = f->next;
        }

        if (!found) {
            f = apr_pcalloc(p, sizeof(ap_filter_rec_t));
            f->name = apr_pstrdup(p, base_info->name);
            f->next = cur;
            cur = f;
        }

        base_info = base_info->next;
    }

    return cur;
}

static void *merge_core_dir_configs(apr_pool_t *a, void *basev, void *newv)
{
    core_dir_config *base = (core_dir_config *)basev;
    core_dir_config *new = (core_dir_config *)newv;
    core_dir_config *conf;
    int i;

    /* Create this conf by duplicating the base, replacing elements
     * (or creating copies for merging) where new-> values exist.
     */
    conf = (core_dir_config *)apr_palloc(a, sizeof(core_dir_config));
    memcpy(conf, base, sizeof(core_dir_config));

    conf->d = new->d;
    conf->d_is_fnmatch = new->d_is_fnmatch;
    conf->d_components = new->d_components;
    conf->r = new->r;

    if (new->opts & OPT_UNSET) {
        /* there was no explicit setting of new->opts, so we merge
         * preserve the invariant (opts_add & opts_remove) == 0
         */
        conf->opts_add = (conf->opts_add & ~new->opts_remove) | new->opts_add;
        conf->opts_remove = (conf->opts_remove & ~new->opts_add)
                            | new->opts_remove;
        conf->opts = (conf->opts & ~conf->opts_remove) | conf->opts_add;
        if ((base->opts & OPT_INCNOEXEC) && (new->opts & OPT_INCLUDES)) {
            conf->opts = (conf->opts & ~OPT_INCNOEXEC) | OPT_INCLUDES;
        }
    }
    else {
        /* otherwise we just copy, because an explicit opts setting
         * overrides all earlier +/- modifiers
         */
        conf->opts = new->opts;
        conf->opts_add = new->opts_add;
        conf->opts_remove = new->opts_remove;
    }

    if (!(new->override & OR_UNSET)) {
        conf->override = new->override;
    }

    if (new->ap_default_type) {
        conf->ap_default_type = new->ap_default_type;
    }

    if (new->ap_auth_type) {
        conf->ap_auth_type = new->ap_auth_type;
    }

    if (new->ap_auth_name) {
        conf->ap_auth_name = new->ap_auth_name;
    }

    if (new->ap_requires) {
        conf->ap_requires = new->ap_requires;
    }

    if (conf->response_code_strings == NULL) {
        conf->response_code_strings = new->response_code_strings;
    }
    else if (new->response_code_strings != NULL) {
        /* If we merge, the merge-result must have it's own array
         */
        conf->response_code_strings = apr_palloc(a,
            sizeof(*conf->response_code_strings) * RESPONSE_CODES);
        memcpy(conf->response_code_strings, base->response_code_strings,
               sizeof(*conf->response_code_strings) * RESPONSE_CODES);

        for (i = 0; i < RESPONSE_CODES; ++i) {
            if (new->response_code_strings[i] != NULL) {
                conf->response_code_strings[i] = new->response_code_strings[i];
            }
        }
    }
    /* Otherwise we simply use the base->response_code_strings array
     */

    if (new->hostname_lookups != HOSTNAME_LOOKUP_UNSET) {
        conf->hostname_lookups = new->hostname_lookups;
    }

    if ((new->content_md5 & 2) == 0) {
        conf->content_md5 = new->content_md5;
    }

    if (new->accept_path_info != 3) {
        conf->accept_path_info = new->accept_path_info;
    }

    if (new->use_canonical_name != USE_CANONICAL_NAME_UNSET) {
        conf->use_canonical_name = new->use_canonical_name;
    }

#ifdef RLIMIT_CPU
    if (new->limit_cpu) {
        conf->limit_cpu = new->limit_cpu;
    }
#endif

#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS)
    if (new->limit_mem) {
        conf->limit_mem = new->limit_mem;
    }
#endif

#ifdef RLIMIT_NPROC
    if (new->limit_nproc) {
        conf->limit_nproc = new->limit_nproc;
    }
#endif

    if (new->limit_req_body) {
        conf->limit_req_body = new->limit_req_body;
    }

    if (new->limit_xml_body != AP_LIMIT_UNSET)
        conf->limit_xml_body = new->limit_xml_body;
    else
        conf->limit_xml_body = base->limit_xml_body;

    if (!conf->sec_file) {
        conf->sec_file = new->sec_file;
    }
    else if (new->sec_file) {
        /* If we merge, the merge-result must have it's own array
         */
        conf->sec_file = apr_array_append(a, base->sec_file, new->sec_file);
    }
    /* Otherwise we simply use the base->sec_file array
     */

    if (new->satisfy != SATISFY_NOSPEC) {
        conf->satisfy = new->satisfy;
    }

    if (new->server_signature != srv_sig_unset) {
        conf->server_signature = new->server_signature;
    }

    if (new->add_default_charset != ADD_DEFAULT_CHARSET_UNSET) {
        conf->add_default_charset = new->add_default_charset;
        conf->add_default_charset_name = new->add_default_charset_name;
    }

    /* Overriding all negotiation
     */
    if (new->mime_type) {
        conf->mime_type = new->mime_type;
    }

    if (new->handler) {
        conf->handler = new->handler;
    }

    if (new->output_filters) {
        conf->output_filters = new->output_filters;
    }

    if (new->input_filters) {
        conf->input_filters = new->input_filters;
    }

    if (conf->ct_output_filters && new->ct_output_filters) {
        conf->ct_output_filters = apr_hash_merge(a,
                                                 new->ct_output_filters,
                                                 conf->ct_output_filters,
                                                 merge_ct_filters,
                                                 NULL);
    }
    else if (new->ct_output_filters) {
        conf->ct_output_filters = apr_hash_copy(a, new->ct_output_filters);
    }
    else if (conf->ct_output_filters) {
        /* That memcpy above isn't enough. */
        conf->ct_output_filters = apr_hash_copy(a, base->ct_output_filters);
    }

    /*
     * Now merge the setting of the FileETag directive.
     */
    if (new->etag_bits == ETAG_UNSET) {
        conf->etag_add =
            (conf->etag_add & (~ new->etag_remove)) | new->etag_add;
        conf->etag_remove =
            (conf->opts_remove & (~ new->etag_add)) | new->etag_remove;
        conf->etag_bits =
            (conf->etag_bits & (~ conf->etag_remove)) | conf->etag_add;
    }
    else {
        conf->etag_bits = new->etag_bits;
        conf->etag_add = new->etag_add;
        conf->etag_remove = new->etag_remove;
    }

    if (conf->etag_bits != ETAG_NONE) {
        conf->etag_bits &= (~ ETAG_NONE);
    }

    if (new->enable_mmap != ENABLE_MMAP_UNSET) {
        conf->enable_mmap = new->enable_mmap;
    }

    if (new->enable_sendfile != ENABLE_SENDFILE_UNSET) {
        conf->enable_sendfile = new->enable_sendfile;
    }

    conf->allow_encoded_slashes = new->allow_encoded_slashes;
    
    return (void*)conf;
}

static void *create_core_server_config(apr_pool_t *a, server_rec *s)
{
    core_server_config *conf;
    int is_virtual = s->is_virtual;

    conf = (core_server_config *)apr_pcalloc(a, sizeof(core_server_config));

#ifdef GPROF
    conf->gprof_dir = NULL;
#endif

    conf->access_name = is_virtual ? NULL : DEFAULT_ACCESS_FNAME;
    conf->ap_document_root = is_virtual ? NULL : DOCUMENT_LOCATION;
    conf->sec_dir = apr_array_make(a, 40, sizeof(ap_conf_vector_t *));
    conf->sec_url = apr_array_make(a, 40, sizeof(ap_conf_vector_t *));

    return (void *)conf;
}

static void *merge_core_server_configs(apr_pool_t *p, void *basev, void *virtv)
{
    core_server_config *base = (core_server_config *)basev;
    core_server_config *virt = (core_server_config *)virtv;
    core_server_config *conf;

    conf = (core_server_config *)apr_palloc(p, sizeof(core_server_config));
    memcpy(conf, virt, sizeof(core_server_config));

    if (!conf->access_name) {
        conf->access_name = base->access_name;
    }

    if (!conf->ap_document_root) {
        conf->ap_document_root = base->ap_document_root;
    }

    conf->sec_dir = apr_array_append(p, base->sec_dir, virt->sec_dir);
    conf->sec_url = apr_array_append(p, base->sec_url, virt->sec_url);

    return conf;
}

/* Add per-directory configuration entry (for <directory> section);
 * these are part of the core server config.
 */

AP_CORE_DECLARE(void) ap_add_per_dir_conf(server_rec *s, void *dir_config)
{
    core_server_config *sconf = ap_get_module_config(s->module_config,
                                                     &core_module);
    void **new_space = (void **)apr_array_push(sconf->sec_dir);

    *new_space = dir_config;
}

AP_CORE_DECLARE(void) ap_add_per_url_conf(server_rec *s, void *url_config)
{
    core_server_config *sconf = ap_get_module_config(s->module_config,
                                                     &core_module);
    void **new_space = (void **)apr_array_push(sconf->sec_url);

    *new_space = url_config;
}

AP_CORE_DECLARE(void) ap_add_file_conf(core_dir_config *conf, void *url_config)
{
    void **new_space = (void **)apr_array_push(conf->sec_file);

    *new_space = url_config;
}

/* We need to do a stable sort, qsort isn't stable.  So to make it stable
 * we'll be maintaining the original index into the list, and using it
 * as the minor key during sorting.  The major key is the number of
 * components (where the root component is zero).
 */
struct reorder_sort_rec {
    ap_conf_vector_t *elt;
    int orig_index;
};

static int reorder_sorter(const void *va, const void *vb)
{
    const struct reorder_sort_rec *a = va;
    const struct reorder_sort_rec *b = vb;
    core_dir_config *core_a;
    core_dir_config *core_b;

    core_a = ap_get_module_config(a->elt, &core_module);
    core_b = ap_get_module_config(b->elt, &core_module);

    /* a regex always sorts after a non-regex
     */
    if (!core_a->r && core_b->r) {
        return -1;
    }
    else if (core_a->r && !core_b->r) {
        return 1;
    }

    /* we always sort next by the number of components
     */
    if (core_a->d_components < core_b->d_components) {
        return -1;
    }
    else if (core_a->d_components > core_b->d_components) {
        return 1;
    }

    /* They have the same number of components, we now have to compare
     * the minor key to maintain the original order (from the config.)
     */
    return a->orig_index - b->orig_index;
}

void ap_core_reorder_directories(apr_pool_t *p, server_rec *s)
{
    core_server_config *sconf;
    apr_array_header_t *sec_dir;
    struct reorder_sort_rec *sortbin;
    int nelts;
    ap_conf_vector_t **elts;
    int i;
    apr_pool_t *tmp;

    sconf = ap_get_module_config(s->module_config, &core_module);
    sec_dir = sconf->sec_dir;
    nelts = sec_dir->nelts;
    elts = (ap_conf_vector_t **)sec_dir->elts;

    if (!nelts) {
        /* simple case of already being sorted... */
        /* We're not checking this condition to be fast... we're checking
         * it to avoid trying to palloc zero bytes, which can trigger some
         * memory debuggers to barf
         */
        return;
    }

    /* we have to allocate tmp space to do a stable sort */
    apr_pool_create(&tmp, p);
    sortbin = apr_palloc(tmp, sec_dir->nelts * sizeof(*sortbin));
    for (i = 0; i < nelts; ++i) {
        sortbin[i].orig_index = i;
        sortbin[i].elt = elts[i];
    }

    qsort(sortbin, nelts, sizeof(*sortbin), reorder_sorter);

    /* and now copy back to the original array */
    for (i = 0; i < nelts; ++i) {
        elts[i] = sortbin[i].elt;
    }

    apr_pool_destroy(tmp);
}

/*****************************************************************
 *
 * There are some elements of the core config structures in which
 * other modules have a legitimate interest (this is ugly, but necessary
 * to preserve NCSA back-compatibility).  So, we have a bunch of accessors
 * here...
 */

AP_DECLARE(int) ap_allow_options(request_rec *r)
{
    core_dir_config *conf =
      (core_dir_config *)ap_get_module_config(r->per_dir_config, &core_module);

    return conf->opts;
}

AP_DECLARE(int) ap_allow_overrides(request_rec *r)
{
    core_dir_config *conf;
    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &core_module);

    return conf->override;
}

AP_DECLARE(const char *) ap_auth_type(request_rec *r)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &core_module);

    return conf->ap_auth_type;
}

AP_DECLARE(const char *) ap_auth_name(request_rec *r)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &core_module);

    return conf->ap_auth_name;
}

AP_DECLARE(const char *) ap_default_type(request_rec *r)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &core_module);

    return conf->ap_default_type
               ? conf->ap_default_type
               : DEFAULT_CONTENT_TYPE;
}

AP_DECLARE(const char *) ap_document_root(request_rec *r) /* Don't use this! */
{
    core_server_config *conf;

    conf = (core_server_config *)ap_get_module_config(r->server->module_config,
                                                      &core_module);

    return conf->ap_document_root;
}

AP_DECLARE(const apr_array_header_t *) ap_requires(request_rec *r)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &core_module);

    return conf->ap_requires;
}

AP_DECLARE(int) ap_satisfies(request_rec *r)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &core_module);

    return conf->satisfy;
}

/* Should probably just get rid of this... the only code that cares is
 * part of the core anyway (and in fact, it isn't publicised to other
 * modules).
 */

char *ap_response_code_string(request_rec *r, int error_index)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &core_module);

    if (conf->response_code_strings == NULL) {
        return NULL;
    }

    return conf->response_code_strings[error_index];
}


/* Code from Harald Hanche-Olsen <hanche@imf.unit.no> */
static APR_INLINE void do_double_reverse (conn_rec *conn)
{
    apr_sockaddr_t *sa;
    apr_status_t rv;

    if (conn->double_reverse) {
        /* already done */
        return;
    }

    if (conn->remote_host == NULL || conn->remote_host[0] == '\0') {
        /* single reverse failed, so don't bother */
        conn->double_reverse = -1;
        return;
    }

    rv = apr_sockaddr_info_get(&sa, conn->remote_host, APR_UNSPEC, 0, 0, conn->pool);
    if (rv == APR_SUCCESS) {
        while (sa) {
            if (apr_sockaddr_equal(sa, conn->remote_addr)) {
                conn->double_reverse = 1;
                return;
            }

            sa = sa->next;
        }
    }

    conn->double_reverse = -1;
}

AP_DECLARE(const char *) ap_get_remote_host(conn_rec *conn, void *dir_config,
                                            int type, int *str_is_ip)
{
    int hostname_lookups;

    if (str_is_ip) { /* if caller wants to know */
        *str_is_ip = 0;
    }

    /* If we haven't checked the host name, and we want to */
    if (dir_config) {
        hostname_lookups =
            ((core_dir_config *)ap_get_module_config(dir_config, &core_module))
            ->hostname_lookups;

        if (hostname_lookups == HOSTNAME_LOOKUP_UNSET) {
            hostname_lookups = HOSTNAME_LOOKUP_OFF;
        }
    }
    else {
        /* the default */
        hostname_lookups = HOSTNAME_LOOKUP_OFF;
    }

    if (type != REMOTE_NOLOOKUP
        && conn->remote_host == NULL
        && (type == REMOTE_DOUBLE_REV
        || hostname_lookups != HOSTNAME_LOOKUP_OFF)) {

        if (apr_getnameinfo(&conn->remote_host, conn->remote_addr, 0)
            == APR_SUCCESS) {
            ap_str_tolower(conn->remote_host);

            if (hostname_lookups == HOSTNAME_LOOKUP_DOUBLE) {
                do_double_reverse(conn);
                if (conn->double_reverse != 1) {
                    conn->remote_host = NULL;
                }
            }
        }

        /* if failed, set it to the NULL string to indicate error */
        if (conn->remote_host == NULL) {
            conn->remote_host = "";
        }
    }

    if (type == REMOTE_DOUBLE_REV) {
        do_double_reverse(conn);
        if (conn->double_reverse == -1) {
            return NULL;
        }
    }

    /*
     * Return the desired information; either the remote DNS name, if found,
     * or either NULL (if the hostname was requested) or the IP address
     * (if any identifier was requested).
     */
    if (conn->remote_host != NULL && conn->remote_host[0] != '\0') {
        return conn->remote_host;
    }
    else {
        if (type == REMOTE_HOST || type == REMOTE_DOUBLE_REV) {
            return NULL;
        }
        else {
            if (str_is_ip) { /* if caller wants to know */
                *str_is_ip = 1;
            }

            return conn->remote_ip;
        }
    }
}

/*
 * Optional function coming from mod_ident, used for looking up ident user
 */
static APR_OPTIONAL_FN_TYPE(ap_ident_lookup) *ident_lookup;

AP_DECLARE(const char *) ap_get_remote_logname(request_rec *r)
{
    if (r->connection->remote_logname != NULL) {
        return r->connection->remote_logname;
    }

    if (ident_lookup) {
        return ident_lookup(r);
    }

    return NULL;
}

/* There are two options regarding what the "name" of a server is.  The
 * "canonical" name as defined by ServerName and Port, or the "client's
 * name" as supplied by a possible Host: header or full URI.  We never
 * trust the port passed in the client's headers, we always use the
 * port of the actual socket.
 *
 * The DNS option to UseCanonicalName causes this routine to do a
 * reverse lookup on the local IP address of the connection and use
 * that for the ServerName. This makes its value more reliable while
 * at the same time allowing Demon's magic virtual hosting to work.
 * The assumption is that DNS lookups are sufficiently quick...
 * -- fanf 1998-10-03
 */
AP_DECLARE(const char *) ap_get_server_name(request_rec *r)
{
    conn_rec *conn = r->connection;
    core_dir_config *d;

    d = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &core_module);

    if (d->use_canonical_name == USE_CANONICAL_NAME_OFF) {
        return r->hostname ? r->hostname : r->server->server_hostname;
    }

    if (d->use_canonical_name == USE_CANONICAL_NAME_DNS) {
        if (conn->local_host == NULL) {
            if (apr_getnameinfo(&conn->local_host,
                                conn->local_addr, 0) != APR_SUCCESS)
                conn->local_host = apr_pstrdup(conn->pool,
                                               r->server->server_hostname);
            else {
                ap_str_tolower(conn->local_host);
            }
        }

        return conn->local_host;
    }

    /* default */
    return r->server->server_hostname;
}

/*
 * Get the current server name from the request for the purposes
 * of using in a URL.  If the server name is an IPv6 literal
 * address, it will be returned in URL format (e.g., "[fe80::1]").
 */
static const char *get_server_name_for_url(request_rec *r)
{
    const char *plain_server_name = ap_get_server_name(r);

#ifdef APR_HAVE_IPV6
    if (ap_strchr_c(plain_server_name, ':')) { /* IPv6 literal? */
        return apr_psprintf(r->pool, "[%s]", plain_server_name);
    }
#endif
    return plain_server_name;
}

AP_DECLARE(apr_port_t) ap_get_server_port(const request_rec *r)
{
    apr_port_t port;
    core_dir_config *d =
      (core_dir_config *)ap_get_module_config(r->per_dir_config, &core_module);

    if (d->use_canonical_name == USE_CANONICAL_NAME_OFF
        || d->use_canonical_name == USE_CANONICAL_NAME_DNS) {

        /* With UseCanonicalName off Apache will form self-referential
         * URLs using the hostname and port supplied by the client if
         * any are supplied (otherwise it will use the canonical name).
         */
        port = r->parsed_uri.port ? r->parsed_uri.port :
               r->server->port ? r->server->port :
               ap_default_port(r);
    }
    else { /* d->use_canonical_name == USE_CANONICAL_NAME_ON */

        /* With UseCanonicalName on (and in all versions prior to 1.3)
         * Apache will use the hostname and port specified in the
         * ServerName directive to construct a canonical name for the
         * server. (If no port was specified in the ServerName
         * directive, Apache uses the port supplied by the client if
         * any is supplied, and finally the default port for the protocol
         * used.
         */
        port = r->server->port ? r->server->port :
               r->connection->local_addr->port ? r->connection->local_addr->port :
               ap_default_port(r);
    }

    /* default */
    return port;
}

AP_DECLARE(char *) ap_construct_url(apr_pool_t *p, const char *uri,
                                    request_rec *r)
{
    unsigned port = ap_get_server_port(r);
    const char *host = get_server_name_for_url(r);

    if (ap_is_default_port(port, r)) {
        return apr_pstrcat(p, ap_http_method(r), "://", host, uri, NULL);
    }

    return apr_psprintf(p, "%s://%s:%u%s", ap_http_method(r), host, port, uri);
}

AP_DECLARE(apr_off_t) ap_get_limit_req_body(const request_rec *r)
{
    core_dir_config *d =
      (core_dir_config *)ap_get_module_config(r->per_dir_config, &core_module);

    return d->limit_req_body;
}


/*****************************************************************
 *
 * Commands... this module handles almost all of the NCSA httpd.conf
 * commands, but most of the old srm.conf is in the the modules.
 */


/* returns a parent if it matches the given directive */
static const ap_directive_t * find_parent(const ap_directive_t *dirp,
                                          const char *what)
{
    while (dirp->parent != NULL) {
        dirp = dirp->parent;

        /* ### it would be nice to have atom-ized directives */
        if (strcasecmp(dirp->directive, what) == 0)
            return dirp;
    }

    return NULL;
}

AP_DECLARE(const char *) ap_check_cmd_context(cmd_parms *cmd,
                                              unsigned forbidden)
{
    const char *gt = (cmd->cmd->name[0] == '<'
                      && cmd->cmd->name[strlen(cmd->cmd->name)-1] != '>')
                         ? ">" : "";
    const ap_directive_t *found;

    if ((forbidden & NOT_IN_VIRTUALHOST) && cmd->server->is_virtual) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, gt,
                           " cannot occur within <VirtualHost> section", NULL);
    }

    if ((forbidden & NOT_IN_LIMIT) && cmd->limited != -1) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, gt,
                           " cannot occur within <Limit> section", NULL);
    }

    if ((forbidden & NOT_IN_DIR_LOC_FILE) == NOT_IN_DIR_LOC_FILE) {
        if (cmd->path != NULL) {
            return apr_pstrcat(cmd->pool, cmd->cmd->name, gt,
                            " cannot occur within <Directory/Location/Files> "
                            "section", NULL);
        }
        if (cmd->cmd->req_override & EXEC_ON_READ) {
            /* EXEC_ON_READ must be NOT_IN_DIR_LOC_FILE, if not, it will
             * (deliberately) segfault below in the individual tests...
             */
            return NULL;
        }
    }
    
    if (((forbidden & NOT_IN_DIRECTORY)
         && ((found = find_parent(cmd->directive, "<Directory"))
             || (found = find_parent(cmd->directive, "<DirectoryMatch"))))
        || ((forbidden & NOT_IN_LOCATION)
            && ((found = find_parent(cmd->directive, "<Location"))
                || (found = find_parent(cmd->directive, "<LocationMatch"))))
        || ((forbidden & NOT_IN_FILES)
            && ((found = find_parent(cmd->directive, "<Files"))
                || (found = find_parent(cmd->directive, "<FilesMatch"))))) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, gt,
                           " cannot occur within ", found->directive,
                           "> section", NULL);
    }

    return NULL;
}

static const char *set_access_name(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    void *sconf = cmd->server->module_config;
    core_server_config *conf = ap_get_module_config(sconf, &core_module);

    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    conf->access_name = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

#ifdef GPROF
static const char *set_gprof_dir(cmd_parms *cmd, void *dummy, const char *arg)
{
    void *sconf = cmd->server->module_config;
    core_server_config *conf = ap_get_module_config(sconf, &core_module);

    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    conf->gprof_dir = apr_pstrdup(cmd->pool, arg);
    return NULL;
}
#endif /*GPROF*/

static const char *set_add_default_charset(cmd_parms *cmd,
                                           void *d_, const char *arg)
{
    core_dir_config *d = d_;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    if (!strcasecmp(arg, "Off")) {
       d->add_default_charset = ADD_DEFAULT_CHARSET_OFF;
    }
    else if (!strcasecmp(arg, "On")) {
       d->add_default_charset = ADD_DEFAULT_CHARSET_ON;
       d->add_default_charset_name = DEFAULT_ADD_DEFAULT_CHARSET_NAME;
    }
    else {
       d->add_default_charset = ADD_DEFAULT_CHARSET_ON;
       d->add_default_charset_name = arg;
    }

    return NULL;
}

static const char *set_document_root(cmd_parms *cmd, void *dummy,
                                     const char *arg)
{
    void *sconf = cmd->server->module_config;
    core_server_config *conf = ap_get_module_config(sconf, &core_module);

    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    /* TODO: ap_configtestonly && ap_docrootcheck && */
    /* XXX Shouldn't this be relative to ServerRoot ??? */
    if (apr_filepath_merge((char**)&conf->ap_document_root, NULL, arg,
                           APR_FILEPATH_TRUENAME, cmd->pool) != APR_SUCCESS
        || !ap_is_directory(cmd->pool, arg)) {
        if (cmd->server->is_virtual) {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0,
                          cmd->pool,
                          "Warning: DocumentRoot [%s] does not exist",
                          arg);
            conf->ap_document_root = arg;
        }
        else {
            return "DocumentRoot must be a directory";
        }
    }
    return NULL;
}

AP_DECLARE(void) ap_custom_response(request_rec *r, int status,
                                    const char *string)
{
    core_dir_config *conf =
        ap_get_module_config(r->per_dir_config, &core_module);
    int idx;

    if(conf->response_code_strings == NULL) {
        conf->response_code_strings =
            apr_pcalloc(r->pool,
                        sizeof(*conf->response_code_strings) * RESPONSE_CODES);
    }

    idx = ap_index_of_response(status);

    conf->response_code_strings[idx] =
       ((ap_is_url(string) || (*string == '/')) && (*string != '"')) ?
       apr_pstrdup(r->pool, string) : apr_pstrcat(r->pool, "\"", string, NULL);
}

static const char *set_error_document(cmd_parms *cmd, void *conf_,
                                      const char *errno_str, const char *msg)
{
    core_dir_config *conf = conf_;
    int error_number, index_number, idx500;
    enum { MSG, LOCAL_PATH, REMOTE_PATH } what = MSG;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    /* 1st parameter should be a 3 digit number, which we recognize;
     * convert it into an array index
     */
    error_number = atoi(errno_str);
    idx500 = ap_index_of_response(HTTP_INTERNAL_SERVER_ERROR);

    if (error_number == HTTP_INTERNAL_SERVER_ERROR) {
        index_number = idx500;
    }
    else if ((index_number = ap_index_of_response(error_number)) == idx500) {
        return apr_pstrcat(cmd->pool, "Unsupported HTTP response code ",
                           errno_str, NULL);
    }

    /* Heuristic to determine second argument. */
    if (ap_strchr_c(msg,' '))
        what = MSG;
    else if (msg[0] == '/')
        what = LOCAL_PATH;
    else if (ap_is_url(msg))
        what = REMOTE_PATH;
    else
        what = MSG;

    /* The entry should be ignored if it is a full URL for a 401 error */

    if (error_number == 401 && what == REMOTE_PATH) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, cmd->server,
                     "cannot use a full URL in a 401 ErrorDocument "
                     "directive --- ignoring!");
    }
    else { /* Store it... */
        if (conf->response_code_strings == NULL) {
            conf->response_code_strings =
                apr_pcalloc(cmd->pool,
                            sizeof(*conf->response_code_strings) *
                            RESPONSE_CODES);
        }

        /* hack. Prefix a " if it is a msg; as that is what
         * http_protocol.c relies on to distinguish between
         * a msg and a (local) path.
         */
        conf->response_code_strings[index_number] = (what == MSG) ?
                apr_pstrcat(cmd->pool, "\"",msg,NULL) :
                apr_pstrdup(cmd->pool, msg);
    }

    return NULL;
}

static const char *set_override(cmd_parms *cmd, void *d_, const char *l)
{
    core_dir_config *d = d_;
    char *w;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    /* Throw a warning if we're in <Location> or <Files> */
    if (ap_check_cmd_context(cmd, NOT_IN_LOCATION | NOT_IN_FILES)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                     "Useless use of AllowOverride in line %d.",
                     cmd->directive->line_num);
    }

    d->override = OR_NONE;
    while (l[0]) {
        w = ap_getword_conf(cmd->pool, &l);
        if (!strcasecmp(w, "Limit")) {
            d->override |= OR_LIMIT;
        }
        else if (!strcasecmp(w, "Options")) {
            d->override |= OR_OPTIONS;
        }
        else if (!strcasecmp(w, "FileInfo")) {
            d->override |= OR_FILEINFO;
        }
        else if (!strcasecmp(w, "AuthConfig")) {
            d->override |= OR_AUTHCFG;
        }
        else if (!strcasecmp(w, "Indexes")) {
            d->override |= OR_INDEXES;
        }
        else if (!strcasecmp(w, "None")) {
            d->override = OR_NONE;
        }
        else if (!strcasecmp(w, "All")) {
            d->override = OR_ALL;
        }
        else {
            return apr_pstrcat(cmd->pool, "Illegal override option ", w, NULL);
        }

        d->override &= ~OR_UNSET;
    }

    return NULL;
}

static const char *set_options(cmd_parms *cmd, void *d_, const char *l)
{
    core_dir_config *d = d_;
    allow_options_t opt;
    int first = 1;
    char action;

    while (l[0]) {
        char *w = ap_getword_conf(cmd->pool, &l);
        action = '\0';

        if (*w == '+' || *w == '-') {
            action = *(w++);
        }
        else if (first) {
              d->opts = OPT_NONE;
            first = 0;
        }

        if (!strcasecmp(w, "Indexes")) {
            opt = OPT_INDEXES;
        }
        else if (!strcasecmp(w, "Includes")) {
            opt = OPT_INCLUDES;
        }
        else if (!strcasecmp(w, "IncludesNOEXEC")) {
            opt = (OPT_INCLUDES | OPT_INCNOEXEC);
        }
        else if (!strcasecmp(w, "FollowSymLinks")) {
            opt = OPT_SYM_LINKS;
        }
        else if (!strcasecmp(w, "SymLinksIfOwnerMatch")) {
            opt = OPT_SYM_OWNER;
        }
        else if (!strcasecmp(w, "execCGI")) {
            opt = OPT_EXECCGI;
        }
        else if (!strcasecmp(w, "MultiViews")) {
            opt = OPT_MULTI;
        }
        else if (!strcasecmp(w, "RunScripts")) { /* AI backcompat. Yuck */
            opt = OPT_MULTI|OPT_EXECCGI;
        }
        else if (!strcasecmp(w, "None")) {
            opt = OPT_NONE;
        }
        else if (!strcasecmp(w, "All")) {
            opt = OPT_ALL;
        }
        else {
            return apr_pstrcat(cmd->pool, "Illegal option ", w, NULL);
        }

        /* we ensure the invariant (d->opts_add & d->opts_remove) == 0 */
        if (action == '-') {
            d->opts_remove |= opt;
            d->opts_add &= ~opt;
            d->opts &= ~opt;
        }
        else if (action == '+') {
            d->opts_add |= opt;
            d->opts_remove &= ~opt;
            d->opts |= opt;
        }
        else {
            d->opts |= opt;
        }
    }

    return NULL;
}

/*
 * Note what data should be used when forming file ETag values.
 * It would be nicer to do this as an ITERATE, but then we couldn't
 * remember the +/- state properly.
 */
static const char *set_etag_bits(cmd_parms *cmd, void *mconfig,
                                 const char *args_p)
{
    core_dir_config *cfg;
    etag_components_t bit;
    char action;
    char *token;
    const char *args;
    int valid;
    int first;
    int explicit;

    cfg = (core_dir_config *)mconfig;

    args = args_p;
    first = 1;
    explicit = 0;
    while (args[0] != '\0') {
        action = '*';
        bit = ETAG_UNSET;
        valid = 1;
        token = ap_getword_conf(cmd->pool, &args);
        if ((*token == '+') || (*token == '-')) {
            action = *token;
            token++;
        }
        else {
            /*
             * The occurrence of an absolute setting wipes
             * out any previous relative ones.  The first such
             * occurrence forgets any inherited ones, too.
             */
            if (first) {
                cfg->etag_bits = ETAG_UNSET;
                cfg->etag_add = ETAG_UNSET;
                cfg->etag_remove = ETAG_UNSET;
                first = 0;
            }
        }

        if (strcasecmp(token, "None") == 0) {
            if (action != '*') {
                valid = 0;
            }
            else {
                cfg->etag_bits = bit = ETAG_NONE;
                explicit = 1;
            }
        }
        else if (strcasecmp(token, "All") == 0) {
            if (action != '*') {
                valid = 0;
            }
            else {
                explicit = 1;
                cfg->etag_bits = bit = ETAG_ALL;
            }
        }
        else if (strcasecmp(token, "Size") == 0) {
            bit = ETAG_SIZE;
        }
        else if ((strcasecmp(token, "LMTime") == 0)
                 || (strcasecmp(token, "MTime") == 0)
                 || (strcasecmp(token, "LastModified") == 0)) {
            bit = ETAG_MTIME;
        }
        else if (strcasecmp(token, "INode") == 0) {
            bit = ETAG_INODE;
        }
        else {
            return apr_pstrcat(cmd->pool, "Unknown keyword '",
                               token, "' for ", cmd->cmd->name,
                               " directive", NULL);
        }

        if (! valid) {
            return apr_pstrcat(cmd->pool, cmd->cmd->name, " keyword '",
                               token, "' cannot be used with '+' or '-'",
                               NULL);
        }

        if (action == '+') {
            /*
             * Make sure it's in the 'add' list and absent from the
             * 'subtract' list.
             */
            cfg->etag_add |= bit;
            cfg->etag_remove &= (~ bit);
        }
        else if (action == '-') {
            cfg->etag_remove |= bit;
            cfg->etag_add &= (~ bit);
        }
        else {
            /*
             * Non-relative values wipe out any + or - values
             * accumulated so far.
             */
            cfg->etag_bits |= bit;
            cfg->etag_add = ETAG_UNSET;
            cfg->etag_remove = ETAG_UNSET;
            explicit = 1;
        }
    }

    /*
     * Any setting at all will clear the 'None' and 'Unset' bits.
     */

    if (cfg->etag_add != ETAG_UNSET) {
        cfg->etag_add &= (~ ETAG_UNSET);
    }

    if (cfg->etag_remove != ETAG_UNSET) {
        cfg->etag_remove &= (~ ETAG_UNSET);
    }

    if (explicit) {
        cfg->etag_bits &= (~ ETAG_UNSET);

        if ((cfg->etag_bits & ETAG_NONE) != ETAG_NONE) {
            cfg->etag_bits &= (~ ETAG_NONE);
        }
    }

    return NULL;
}

static const char *set_enable_mmap(cmd_parms *cmd, void *d_,
                                   const char *arg)
{
    core_dir_config *d = d_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "on") == 0) {
        d->enable_mmap = ENABLE_MMAP_ON;
    }
    else if (strcasecmp(arg, "off") == 0) {
        d->enable_mmap = ENABLE_MMAP_OFF;
    }
    else {
        return "parameter must be 'on' or 'off'";
    }

    return NULL;
}

static const char *set_enable_sendfile(cmd_parms *cmd, void *d_,
                                   const char *arg)
{
    core_dir_config *d = d_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "on") == 0) {
        d->enable_sendfile = ENABLE_SENDFILE_ON;
    }
    else if (strcasecmp(arg, "off") == 0) {
        d->enable_sendfile = ENABLE_SENDFILE_OFF;
    }
    else {
        return "parameter must be 'on' or 'off'";
    }

    return NULL;
}

static const char *satisfy(cmd_parms *cmd, void *c_, const char *arg)
{
    core_dir_config *c = c_;

    if (!strcasecmp(arg, "all")) {
        c->satisfy = SATISFY_ALL;
    }
    else if (!strcasecmp(arg, "any")) {
        c->satisfy = SATISFY_ANY;
    }
    else {
        return "Satisfy either 'any' or 'all'.";
    }

    return NULL;
}

static const char *require(cmd_parms *cmd, void *c_, const char *arg)
{
    require_line *r;
    core_dir_config *c = c_;

    if (!c->ap_requires) {
        c->ap_requires = apr_array_make(cmd->pool, 2, sizeof(require_line));
    }

    r = (require_line *)apr_array_push(c->ap_requires);
    r->requirement = apr_pstrdup(cmd->pool, arg);
    r->method_mask = cmd->limited;

    return NULL;
}

AP_CORE_DECLARE_NONSTD(const char *) ap_limit_section(cmd_parms *cmd,
                                                      void *dummy,
                                                      const char *arg)
{
    const char *limited_methods = ap_getword(cmd->pool, &arg, '>');
    void *tog = cmd->cmd->cmd_data;
    apr_int64_t limited = 0;
    const char *errmsg;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    while (limited_methods[0]) {
        char *method = ap_getword_conf(cmd->pool, &limited_methods);
        int methnum;

        /* check for builtin or module registered method number */
        methnum = ap_method_number_of(method);

        if (methnum == M_TRACE && !tog) {
            return "TRACE cannot be controlled by <Limit>";
        }
        else if (methnum == M_INVALID) {
            /* method has not been registered yet, but resorce restriction
             * is always checked before method handling, so register it.
             */
            methnum = ap_method_register(cmd->pool, method);
        }

        limited |= (AP_METHOD_BIT << methnum);
    }

    /* Killing two features with one function,
     * if (tog == NULL) <Limit>, else <LimitExcept>
     */
    cmd->limited = tog ? ~limited : limited;

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, cmd->context);

    cmd->limited = -1;

    return errmsg;
}

/* XXX: Bogus - need to do this differently (at least OS2/Netware suffer
 * the same problem!!!
 * We use this in <DirectoryMatch> and <FilesMatch>, to ensure that
 * people don't get bitten by wrong-cased regex matches
 */

#ifdef WIN32
#define USE_ICASE REG_ICASE
#else
#define USE_ICASE 0
#endif

/*
 * Report a missing-'>' syntax error.
 */
static char *unclosed_directive(cmd_parms *cmd)
{
    return apr_pstrcat(cmd->pool, cmd->cmd->name,
                       "> directive missing closing '>'", NULL);
}

static const char *dirsection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    ap_conf_vector_t *new_dir_conf = ap_create_per_dir_config(cmd->pool);
    regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;

    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp - arg);

    if (!arg) {
        if (thiscmd->cmd_data)
            return "<DirectoryMatch > block must specify a path";
        else
            return "<Directory > block must specify a path";
    }

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    cmd->override = OR_ALL|ACCESS_CONF;

    if (!strcmp(cmd->path, "~")) {
        cmd->path = ap_getword_conf(cmd->pool, &arg);
        if (!cmd->path)
            return "<Directory ~ > block must specify a path";
        r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else if (thiscmd->cmd_data) { /* <DirectoryMatch> */
        r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else if (!strcmp(cmd->path, "/") == 0)
    {
        char *newpath;

        /*
         * Ensure that the pathname is canonical, and append the trailing /
         */
        apr_status_t rv = apr_filepath_merge(&newpath, NULL, cmd->path,
                                             APR_FILEPATH_TRUENAME, cmd->pool);
        if (rv != APR_SUCCESS && rv != APR_EPATHWILD) {
            return apr_pstrcat(cmd->pool, "<Directory \"", cmd->path,
                               "\"> path is invalid.", NULL);
        }

        cmd->path = newpath;
        if (cmd->path[strlen(cmd->path) - 1] != '/')
            cmd->path = apr_pstrcat(cmd->pool, cmd->path, "/", NULL);
    }

    /* initialize our config and fetch it */
    conf = ap_set_config_vectors(cmd->server, new_dir_conf, cmd->path,
                                 &core_module, cmd->pool);

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_dir_conf);
    if (errmsg != NULL)
        return errmsg;

    conf->r = r;
    conf->d = cmd->path;
    conf->d_is_fnmatch = (apr_fnmatch_test(conf->d) != 0);

    /* Make this explicit - the "/" root has 0 elements, that is, we
     * will always merge it, and it will always sort and merge first.
     * All others are sorted and tested by the number of slashes.
     */
    if (strcmp(conf->d, "/") == 0)
        conf->d_components = 0;
    else
        conf->d_components = ap_count_dirs(conf->d);

    ap_add_per_dir_conf(cmd->server, new_dir_conf);

    if (*arg != '\0') {
        return apr_pstrcat(cmd->pool, "Multiple ", thiscmd->name,
                           "> arguments not (yet) supported.", NULL);
    }

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static const char *urlsection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;
    ap_conf_vector_t *new_url_conf = ap_create_per_dir_config(cmd->pool);
    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp - arg);

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    cmd->override = OR_ALL|ACCESS_CONF;

    if (thiscmd->cmd_data) { /* <LocationMatch> */
        r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED);
    }
    else if (!strcmp(cmd->path, "~")) {
        cmd->path = ap_getword_conf(cmd->pool, &arg);
        r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED);
    }

    /* initialize our config and fetch it */
    conf = ap_set_config_vectors(cmd->server, new_url_conf, cmd->path,
                                 &core_module, cmd->pool);

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_url_conf);
    if (errmsg != NULL)
        return errmsg;

    conf->d = apr_pstrdup(cmd->pool, cmd->path);     /* No mangling, please */
    conf->d_is_fnmatch = apr_fnmatch_test(conf->d) != 0;
    conf->r = r;

    ap_add_per_url_conf(cmd->server, new_url_conf);

    if (*arg != '\0') {
        return apr_pstrcat(cmd->pool, "Multiple ", thiscmd->name,
                           "> arguments not (yet) supported.", NULL);
    }

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static const char *filesection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;
    core_dir_config *c = mconfig;
    ap_conf_vector_t *new_file_conf = ap_create_per_dir_config(cmd->pool);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT|NOT_IN_LOCATION);

    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp - arg);

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    /* Only if not an .htaccess file */
    if (!old_path) {
        cmd->override = OR_ALL|ACCESS_CONF;
    }

    if (thiscmd->cmd_data) { /* <FilesMatch> */
        r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else if (!strcmp(cmd->path, "~")) {
        cmd->path = ap_getword_conf(cmd->pool, &arg);
        r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else {
        char *newpath;
        /* Ensure that the pathname is canonical, but we
         * can't test the case/aliases without a fixed path */
        if (apr_filepath_merge(&newpath, "", cmd->path,
                               0, cmd->pool) != APR_SUCCESS)
                return apr_pstrcat(cmd->pool, "<Files \"", cmd->path,
                               "\"> is invalid.", NULL);
        cmd->path = newpath;
    }

    /* initialize our config and fetch it */
    conf = ap_set_config_vectors(cmd->server, new_file_conf, cmd->path,
                                 &core_module, cmd->pool);

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_file_conf);
    if (errmsg != NULL)
        return errmsg;

    conf->d = cmd->path;
    conf->d_is_fnmatch = apr_fnmatch_test(conf->d) != 0;
    conf->r = r;

    ap_add_file_conf(c, new_file_conf);

    if (*arg != '\0') {
        return apr_pstrcat(cmd->pool, "Multiple ", thiscmd->name,
                           "> arguments not (yet) supported.", NULL);
    }

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static const char *start_ifmod(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *endp = ap_strrchr_c(arg, '>');
    int not = (arg[0] == '!');
    module *found;

    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp - arg);

    if (not) {
        arg++;
    }

    found = ap_find_linked_module(arg);

    if ((!not && found) || (not && !found)) {
        ap_directive_t *parent = NULL;
        ap_directive_t *current = NULL;
        const char *retval;

        retval = ap_build_cont_config(cmd->pool, cmd->temp_pool, cmd,
                                      &current, &parent, "<IfModule");
        *(ap_directive_t **)mconfig = current;
        return retval;
    }
    else {
        *(ap_directive_t **)mconfig = NULL;
        return ap_soak_end_container(cmd, "<IfModule");
    }
}

AP_DECLARE(int) ap_exists_config_define(const char *name)
{
    char **defines;
    int i;

    defines = (char **)ap_server_config_defines->elts;
    for (i = 0; i < ap_server_config_defines->nelts; i++) {
        if (strcmp(defines[i], name) == 0) {
            return 1;
        }
    }

    return 0;
}

static const char *start_ifdefine(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *endp;
    int defined;
    int not = 0;

    endp = ap_strrchr_c(arg, '>');
    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp - arg);

    if (arg[0] == '!') {
        not = 1;
        arg++;
    }

    defined = ap_exists_config_define(arg);
    if ((!not && defined) || (not && !defined)) {
        ap_directive_t *parent = NULL;
        ap_directive_t *current = NULL;
        const char *retval;

        retval = ap_build_cont_config(cmd->pool, cmd->temp_pool, cmd,
                                      &current, &parent, "<IfDefine");
        *(ap_directive_t **)dummy = current;
        return retval;
    }
    else {
        *(ap_directive_t **)dummy = NULL;
        return ap_soak_end_container(cmd, "<IfDefine");
    }
}

/* httpd.conf commands... beginning with the <VirtualHost> business */

static const char *virtualhost_section(cmd_parms *cmd, void *dummy,
                                       const char *arg)
{
    server_rec *main_server = cmd->server, *s;
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    apr_pool_t *p = cmd->pool;

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp - arg);

    /* FIXME: There's another feature waiting to happen here -- since you
        can now put multiple addresses/names on a single <VirtualHost>
        you might want to use it to group common definitions and then
        define other "subhosts" with their individual differences.  But
        personally I'd rather just do it with a macro preprocessor. -djg */
    if (main_server->is_virtual) {
        return "<VirtualHost> doesn't nest!";
    }

    errmsg = ap_init_virtual_host(p, arg, main_server, &s);
    if (errmsg) {
        return errmsg;
    }

    s->next = main_server->next;
    main_server->next = s;

    s->defn_name = cmd->directive->filename;
    s->defn_line_number = cmd->directive->line_num;

    cmd->server = s;

    errmsg = ap_walk_config(cmd->directive->first_child, cmd,
                            s->lookup_defaults);

    cmd->server = main_server;

    return errmsg;
}

static const char *set_server_alias(cmd_parms *cmd, void *dummy,
                                    const char *arg)
{
    if (!cmd->server->names) {
        return "ServerAlias only used in <VirtualHost>";
    }

    while (*arg) {
        char **item, *name = ap_getword_conf(cmd->pool, &arg);

        if (ap_is_matchexp(name)) {
            item = (char **)apr_array_push(cmd->server->wild_names);
        }
        else {
            item = (char **)apr_array_push(cmd->server->names);
        }

        *item = name;
    }

    return NULL;
}

static const char *set_server_string_slot(cmd_parms *cmd, void *dummy,
                                          const char *arg)
{
    /* This one's pretty generic... */

    int offset = (int)(long)cmd->info;
    char *struct_ptr = (char *)cmd->server;

    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    *(const char **)(struct_ptr + offset) = arg;
    return NULL;
}

static const char *server_hostname_port(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    const char *portstr;
    int port;

    if (err != NULL) {
        return err;
    }

    portstr = ap_strchr_c(arg, ':');
    if (portstr) {
        cmd->server->server_hostname = apr_pstrndup(cmd->pool, arg,
                                                    portstr - arg);
        portstr++;
        port = atoi(portstr);
        if (port <= 0 || port >= 65536) { /* 65536 == 1<<16 */
            return apr_pstrcat(cmd->temp_pool, "The port number \"", arg,
                          "\" is outside the appropriate range "
                          "(i.e., 1..65535).", NULL);
        }
    }
    else {
        cmd->server->server_hostname = apr_pstrdup(cmd->pool, arg);
        port = 0;
    }

    cmd->server->port = port;
    return NULL;
}

static const char *set_signature_flag(cmd_parms *cmd, void *d_,
                                      const char *arg)
{
    core_dir_config *d = d_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "On") == 0) {
        d->server_signature = srv_sig_on;
    }
    else if (strcasecmp(arg, "Off") == 0) {
        d->server_signature = srv_sig_off;
    }
    else if (strcasecmp(arg, "EMail") == 0) {
        d->server_signature = srv_sig_withmail;
    }
    else {
        return "ServerSignature: use one of: off | on | email";
    }

    return NULL;
}

static const char *set_server_root(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    if ((apr_filepath_merge((char**)&ap_server_root, NULL, arg,
                            APR_FILEPATH_TRUENAME, cmd->pool) != APR_SUCCESS)
        || !ap_is_directory(cmd->pool, ap_server_root)) {
        return "ServerRoot must be a valid directory";
    }

    return NULL;
}

static const char *set_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    cmd->server->timeout = apr_time_from_sec(atoi(arg));
    return NULL;
}

static const char *set_allow2f(cmd_parms *cmd, void *d_, int arg)
{
    core_dir_config *d = d_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    d->allow_encoded_slashes = arg != 0;
    return NULL;
}

static const char *set_hostname_lookups(cmd_parms *cmd, void *d_,
                                        const char *arg)
{
    core_dir_config *d = d_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    if (!strcasecmp(arg, "on")) {
        d->hostname_lookups = HOSTNAME_LOOKUP_ON;
    }
    else if (!strcasecmp(arg, "off")) {
        d->hostname_lookups = HOSTNAME_LOOKUP_OFF;
    }
    else if (!strcasecmp(arg, "double")) {
        d->hostname_lookups = HOSTNAME_LOOKUP_DOUBLE;
    }
    else {
        return "parameter must be 'on', 'off', or 'double'";
    }

    return NULL;
}

static const char *set_serverpath(cmd_parms *cmd, void *dummy,
                                  const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    cmd->server->path = arg;
    cmd->server->pathlen = strlen(arg);
    return NULL;
}

static const char *set_content_md5(cmd_parms *cmd, void *d_, int arg)
{
    core_dir_config *d = d_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    d->content_md5 = arg != 0;
    return NULL;
}

static const char *set_accept_path_info(cmd_parms *cmd, void *d_, const char *arg)
{
    core_dir_config *d = d_;

    if (strcasecmp(arg, "on") == 0) {
        d->accept_path_info = AP_REQ_ACCEPT_PATH_INFO;
    }
    else if (strcasecmp(arg, "off") == 0) {
        d->accept_path_info = AP_REQ_REJECT_PATH_INFO;
    }
    else if (strcasecmp(arg, "default") == 0) {
        d->accept_path_info = AP_REQ_DEFAULT_PATH_INFO;
    }
    else {
        return "AcceptPathInfo must be set to on, off or default";
    }

    return NULL;
}

static const char *set_use_canonical_name(cmd_parms *cmd, void *d_,
                                          const char *arg)
{
    core_dir_config *d = d_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "on") == 0) {
        d->use_canonical_name = USE_CANONICAL_NAME_ON;
    }
    else if (strcasecmp(arg, "off") == 0) {
        d->use_canonical_name = USE_CANONICAL_NAME_OFF;
    }
    else if (strcasecmp(arg, "dns") == 0) {
        d->use_canonical_name = USE_CANONICAL_NAME_DNS;
    }
    else {
        return "parameter must be 'on', 'off', or 'dns'";
    }

    return NULL;
}


static const char *include_config (cmd_parms *cmd, void *dummy,
                                   const char *name)
{
    ap_directive_t *conftree = NULL;
    const char* conffile = ap_server_root_relative(cmd->pool, name);

    if (!conffile) {
        return apr_pstrcat(cmd->pool, "Invalid Include path ", 
                           name, NULL);
    }

    ap_process_resource_config(cmd->server, conffile,
                               &conftree, cmd->pool, cmd->temp_pool);
    *(ap_directive_t **)dummy = conftree;
    return NULL;
}

static const char *set_loglevel(cmd_parms *cmd, void *dummy, const char *arg)
{
    char *str;

    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    if ((str = ap_getword_conf(cmd->pool, &arg))) {
        if (!strcasecmp(str, "emerg")) {
            cmd->server->loglevel = APLOG_EMERG;
        }
        else if (!strcasecmp(str, "alert")) {
            cmd->server->loglevel = APLOG_ALERT;
        }
        else if (!strcasecmp(str, "crit")) {
            cmd->server->loglevel = APLOG_CRIT;
        }
        else if (!strcasecmp(str, "error")) {
            cmd->server->loglevel = APLOG_ERR;
        }
        else if (!strcasecmp(str, "warn")) {
            cmd->server->loglevel = APLOG_WARNING;
        }
        else if (!strcasecmp(str, "notice")) {
            cmd->server->loglevel = APLOG_NOTICE;
        }
        else if (!strcasecmp(str, "info")) {
            cmd->server->loglevel = APLOG_INFO;
        }
        else if (!strcasecmp(str, "debug")) {
            cmd->server->loglevel = APLOG_DEBUG;
        }
        else {
            return "LogLevel requires level keyword: one of "
                   "emerg/alert/crit/error/warn/notice/info/debug";
        }
    }
    else {
        return "LogLevel requires level keyword";
    }

    return NULL;
}

AP_DECLARE(const char *) ap_psignature(const char *prefix, request_rec *r)
{
    char sport[20];
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &core_module);
    if ((conf->server_signature == srv_sig_off)
            || (conf->server_signature == srv_sig_unset)) {
        return "";
    }

    apr_snprintf(sport, sizeof sport, "%u", (unsigned) ap_get_server_port(r));

    if (conf->server_signature == srv_sig_withmail) {
        return apr_pstrcat(r->pool, prefix, "<address>", 
                           ap_get_server_version(),
                           " Server at <a href=\"mailto:",
                           r->server->server_admin, "\">",
                           ap_escape_html(r->pool, ap_get_server_name(r)),
                           "</a> Port ", sport,
                           "</address>\n", NULL);
    }

    return apr_pstrcat(r->pool, prefix, "<address>", ap_get_server_version(),
                       " Server at ",
                       ap_escape_html(r->pool, ap_get_server_name(r)),
                       " Port ", sport,
                       "</address>\n", NULL);
}

/*
 * Load an authorisation realm into our location configuration, applying the
 * usual rules that apply to realms.
 */
static const char *set_authname(cmd_parms *cmd, void *mconfig,
                                const char *word1)
{
    core_dir_config *aconfig = (core_dir_config *)mconfig;

    aconfig->ap_auth_name = ap_escape_quotes(cmd->pool, word1);
    return NULL;
}

#ifdef _OSD_POSIX /* BS2000 Logon Passwd file */
static const char *set_bs2000_account(cmd_parms *cmd, void *dummy, char *name)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    return os_set_account(cmd->pool, name);
}
#endif /*_OSD_POSIX*/

/*
 * Handle a request to include the server's OS platform in the Server
 * response header field (the ServerTokens directive).  Unfortunately
 * this requires a new global in order to communicate the setting back to
 * http_main so it can insert the information in the right place in the
 * string.
 */

static char *server_version = NULL;
static int version_locked = 0;

enum server_token_type {
    SrvTk_MAJOR,        /* eg: Apache/2 */
    SrvTk_MINOR,        /* eg. Apache/2.0 */
    SrvTk_MINIMAL,      /* eg: Apache/2.0.41 */
    SrvTk_OS,           /* eg: Apache/2.0.41 (UNIX) */
    SrvTk_FULL,         /* eg: Apache/2.0.41 (UNIX) PHP/4.2.2 FooBar/1.2b */
    SrvTk_PRODUCT_ONLY  /* eg: Apache */
};
static enum server_token_type ap_server_tokens = SrvTk_FULL;

static apr_status_t reset_version(void *dummy)
{
    version_locked = 0;
    ap_server_tokens = SrvTk_FULL;
    server_version = NULL;
    return APR_SUCCESS;
}

AP_DECLARE(const char *) ap_get_server_version(void)
{
    return (server_version ? server_version : AP_SERVER_BASEVERSION);
}

AP_DECLARE(void) ap_add_version_component(apr_pool_t *pconf, const char *component)
{
    if (! version_locked) {
        /*
         * If the version string is null, register our cleanup to reset the
         * pointer on pool destruction. We also know that, if NULL,
         * we are adding the original SERVER_BASEVERSION string.
         */
        if (server_version == NULL) {
            apr_pool_cleanup_register(pconf, NULL, reset_version,
                                      apr_pool_cleanup_null);
            server_version = apr_pstrdup(pconf, component);
        }
        else {
            /*
             * Tack the given component identifier to the end of
             * the existing string.
             */
            server_version = apr_pstrcat(pconf, server_version, " ",
                                         component, NULL);
        }
    }
}

/*
 * This routine adds the real server base identity to the version string,
 * and then locks out changes until the next reconfig.
 */
static void ap_set_version(apr_pool_t *pconf)
{
    if (ap_server_tokens == SrvTk_PRODUCT_ONLY) {
        ap_add_version_component(pconf, AP_SERVER_BASEPRODUCT);
    }
    else if (ap_server_tokens == SrvTk_MINIMAL) {
        ap_add_version_component(pconf, AP_SERVER_BASEVERSION);
    }
    else if (ap_server_tokens == SrvTk_MINOR) {
        ap_add_version_component(pconf, AP_SERVER_BASEPRODUCT "/" AP_SERVER_MINORREVISION);
    }
    else if (ap_server_tokens == SrvTk_MAJOR) {
        ap_add_version_component(pconf, AP_SERVER_BASEPRODUCT "/" AP_SERVER_MAJORVERSION);
    }
    else {
        ap_add_version_component(pconf, AP_SERVER_BASEVERSION " (" PLATFORM ")");
    }

    /*
     * Lock the server_version string if we're not displaying
     * the full set of tokens
     */
    if (ap_server_tokens != SrvTk_FULL) {
        version_locked++;
    }
}

static const char *set_serv_tokens(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    if (!strcasecmp(arg, "OS")) {
        ap_server_tokens = SrvTk_OS;
    }
    else if (!strcasecmp(arg, "Min") || !strcasecmp(arg, "Minimal")) {
        ap_server_tokens = SrvTk_MINIMAL;
    }
    else if (!strcasecmp(arg, "Major")) {
        ap_server_tokens = SrvTk_MAJOR;
    }
    else if (!strcasecmp(arg, "Minor") ) {
        ap_server_tokens = SrvTk_MINOR;
    }
    else if (!strcasecmp(arg, "Prod") || !strcasecmp(arg, "ProductOnly")) {
        ap_server_tokens = SrvTk_PRODUCT_ONLY;
    }
    else {
        ap_server_tokens = SrvTk_FULL;
    }

    return NULL;
}

static const char *set_limit_req_line(cmd_parms *cmd, void *dummy,
                                      const char *arg)
{
    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    int lim;

    if (err != NULL) {
        return err;
    }

    lim = atoi(arg);
    if (lim < 0) {
        return apr_pstrcat(cmd->temp_pool, "LimitRequestLine \"", arg,
                           "\" must be a non-negative integer", NULL);
    }

    if (lim > DEFAULT_LIMIT_REQUEST_LINE) {
        return apr_psprintf(cmd->temp_pool, "LimitRequestLine \"%s\" "
                            "must not exceed the precompiled maximum of %d",
                            arg, DEFAULT_LIMIT_REQUEST_LINE);
    }

    cmd->server->limit_req_line = lim;
    return NULL;
}

static const char *set_limit_req_fieldsize(cmd_parms *cmd, void *dummy,
                                           const char *arg)
{
    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    int lim;

    if (err != NULL) {
        return err;
    }

    lim = atoi(arg);
    if (lim < 0) {
        return apr_pstrcat(cmd->temp_pool, "LimitRequestFieldsize \"", arg,
                          "\" must be a non-negative integer (0 = no limit)",
                          NULL);
    }

    if (lim > DEFAULT_LIMIT_REQUEST_FIELDSIZE) {
        return apr_psprintf(cmd->temp_pool, "LimitRequestFieldsize \"%s\" "
                           "must not exceed the precompiled maximum of %d",
                            arg, DEFAULT_LIMIT_REQUEST_FIELDSIZE);
    }

    cmd->server->limit_req_fieldsize = lim;
    return NULL;
}

static const char *set_limit_req_fields(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    int lim;

    if (err != NULL) {
        return err;
    }

    lim = atoi(arg);
    if (lim < 0) {
        return apr_pstrcat(cmd->temp_pool, "LimitRequestFields \"", arg,
                           "\" must be a non-negative integer (0 = no limit)",
                           NULL);
    }

    cmd->server->limit_req_fields = lim;
    return NULL;
}

static const char *set_limit_req_body(cmd_parms *cmd, void *conf_,
                                      const char *arg)
{
    core_dir_config *conf = conf_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    char *errp;

    if (err != NULL) {
        return err;
    }

    /* WTF: If strtoul is not portable, then write a replacement.
     *      Instead we have an idiotic define in httpd.h that prevents
     *      it from being used even when it is available. Sheesh.
     */
    conf->limit_req_body = (apr_off_t)strtol(arg, &errp, 10);
    if (*errp != '\0') {
        return "LimitRequestBody requires a non-negative integer.";
    }

    return NULL;
}

static const char *set_limit_xml_req_body(cmd_parms *cmd, void *conf_,
                                          const char *arg)
{
    core_dir_config *conf = conf_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    conf->limit_xml_body = atol(arg);
    if (conf->limit_xml_body < 0)
        return "LimitXMLRequestBody requires a non-negative integer.";

    return NULL;
}

AP_DECLARE(size_t) ap_get_limit_xml_body(const request_rec *r)
{
    core_dir_config *conf;

    conf = ap_get_module_config(r->per_dir_config, &core_module);
    if (conf->limit_xml_body == AP_LIMIT_UNSET)
        return AP_DEFAULT_LIMIT_XML_BODY;

    return (size_t)conf->limit_xml_body;
}

#if !defined (RLIMIT_CPU) || !(defined (RLIMIT_DATA) || defined (RLIMIT_VMEM) || defined(RLIMIT_AS)) || !defined (RLIMIT_NPROC)
static const char *no_set_limit(cmd_parms *cmd, void *conf_,
                                const char *arg, const char *arg2)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                "%s not supported on this platform", cmd->cmd->name);

    return NULL;
}
#endif

#ifdef RLIMIT_CPU
static const char *set_limit_cpu(cmd_parms *cmd, void *conf_,
                                 const char *arg, const char *arg2)
{
    core_dir_config *conf = conf_;

    unixd_set_rlimit(cmd, &conf->limit_cpu, arg, arg2, RLIMIT_CPU);
    return NULL;
}
#endif

#if defined (RLIMIT_DATA) || defined (RLIMIT_VMEM) || defined(RLIMIT_AS)
static const char *set_limit_mem(cmd_parms *cmd, void *conf_,
                                 const char *arg, const char * arg2)
{
    core_dir_config *conf = conf_;

#if defined(RLIMIT_AS)
    unixd_set_rlimit(cmd, &conf->limit_mem, arg, arg2 ,RLIMIT_AS);
#elif defined(RLIMIT_DATA)
    unixd_set_rlimit(cmd, &conf->limit_mem, arg, arg2, RLIMIT_DATA);
#elif defined(RLIMIT_VMEM)
    unixd_set_rlimit(cmd, &conf->limit_mem, arg, arg2, RLIMIT_VMEM);
#endif

    return NULL;
}
#endif

#ifdef RLIMIT_NPROC
static const char *set_limit_nproc(cmd_parms *cmd, void *conf_,
                                   const char *arg, const char * arg2)
{
    core_dir_config *conf = conf_;

    unixd_set_rlimit(cmd, &conf->limit_nproc, arg, arg2, RLIMIT_NPROC);
    return NULL;
}
#endif

static const char *add_ct_output_filters(cmd_parms *cmd, void *conf_,
                                         const char *arg, const char *arg2)
{
    core_dir_config *conf = conf_;
    ap_filter_rec_t *old, *new = NULL;
    const char *filter_name;

    if (!conf->ct_output_filters) {
        conf->ct_output_filters = apr_hash_make(cmd->pool);
        old = NULL;
    }
    else {
        old = (ap_filter_rec_t*) apr_hash_get(conf->ct_output_filters, arg2,
                                              APR_HASH_KEY_STRING);
    }

    while (*arg &&
           (filter_name = ap_getword(cmd->pool, &arg, ';')) &&
           strcmp(filter_name, "")) {
        new = apr_pcalloc(cmd->pool, sizeof(ap_filter_rec_t));
        new->name = filter_name;

        /* We found something, so let's append it.  */
        if (old) {
            new->next = old;
        }
        old = new;
    }

    if (!new) {
        return "invalid filter name";
    }
    
    apr_hash_set(conf->ct_output_filters, arg2, APR_HASH_KEY_STRING, new);

    return NULL;
}
/* 
 * Insert filters requested by the AddOutputFilterByType 
 * configuration directive. We cannot add filters based 
 * on content-type until after the handler has started 
 * to run. Only then do we reliably know the content-type.
 */
void ap_add_output_filters_by_type(request_rec *r)
{
    core_dir_config *conf;
    const char *ctype, *ctypes;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &core_module);

    /* We can't do anything with proxy requests, no content-types or if
     * we don't have a filter configured.
     */
    if (r->proxyreq != PROXYREQ_NONE || !r->content_type ||
        !conf->ct_output_filters) {
        return;
    }

    ctypes = r->content_type;

    /* We must be able to handle decorated content-types.  */
    while (*ctypes && (ctype = ap_getword(r->pool, &ctypes, ';'))) {
        ap_filter_rec_t *ct_filter;
        ct_filter = apr_hash_get(conf->ct_output_filters, ctype,
                                 APR_HASH_KEY_STRING);
        while (ct_filter) {
            ap_add_output_filter(ct_filter->name, NULL, r, r->connection);
            ct_filter = ct_filter->next;
        }
    }

    return;
}

static apr_status_t writev_it_all(apr_socket_t *s,
                                  struct iovec *vec, int nvec,
                                  apr_size_t len, apr_size_t *nbytes)
{
    apr_size_t bytes_written = 0;
    apr_status_t rv;
    apr_size_t n = len;
    int i = 0;

    *nbytes = 0;

    /* XXX handle checking for non-blocking socket */
    while (bytes_written != len) {
        rv = apr_sendv(s, vec + i, nvec - i, &n);
        bytes_written += n;
        if (rv != APR_SUCCESS)
            return rv;

        *nbytes += n;

        /* If the write did not complete, adjust the iovecs and issue
         * apr_sendv again
         */
        if (bytes_written < len) {
            /* Skip over the vectors that have already been written */
            apr_size_t cnt = vec[i].iov_len;
            while (n >= cnt && i + 1 < nvec) {
                i++;
                cnt += vec[i].iov_len;
            }

            if (n < cnt) {
                /* Handle partial write of vec i */
                vec[i].iov_base = (char *) vec[i].iov_base +
                    (vec[i].iov_len - (cnt - n));
                vec[i].iov_len = cnt -n;
            }
        }

        n = len - bytes_written;
    }

    return APR_SUCCESS;
}

/* sendfile_it_all()
 *  send the entire file using sendfile()
 *  handle partial writes
 *  return only when all bytes have been sent or an error is encountered.
 */

#if APR_HAS_SENDFILE
static apr_status_t sendfile_it_all(core_net_rec *c,
                                    apr_file_t *fd,
                                    apr_hdtr_t *hdtr,
                                    apr_off_t   file_offset,
                                    apr_size_t  file_bytes_left,
                                    apr_size_t  total_bytes_left,
                                    apr_size_t  *bytes_sent,
                                    apr_int32_t flags)
{
    apr_status_t rv;
#ifdef AP_DEBUG
    apr_interval_time_t timeout = 0;
#endif

    AP_DEBUG_ASSERT((apr_socket_timeout_get(c->client_socket, &timeout) 
                         == APR_SUCCESS)
                    && timeout > 0);  /* socket must be in timeout mode */

    /* Reset the bytes_sent field */
    *bytes_sent = 0;

    do {
        apr_size_t tmplen = file_bytes_left;

        rv = apr_sendfile(c->client_socket, fd, hdtr, &file_offset, &tmplen,
                          flags);
        *bytes_sent += tmplen;
        total_bytes_left -= tmplen;
        if (!total_bytes_left || rv != APR_SUCCESS) {
            return rv;        /* normal case & error exit */
        }

        AP_DEBUG_ASSERT(total_bytes_left > 0 && tmplen > 0);

        /* partial write, oooh noooo...
         * Skip over any header data which was written
         */
        while (tmplen && hdtr->numheaders) {
            if (tmplen >= hdtr->headers[0].iov_len) {
                tmplen -= hdtr->headers[0].iov_len;
                --hdtr->numheaders;
                ++hdtr->headers;
            }
            else {
                char *iov_base = (char *)hdtr->headers[0].iov_base;

                hdtr->headers[0].iov_len -= tmplen;
                iov_base += tmplen;
                hdtr->headers[0].iov_base = iov_base;
                tmplen = 0;
            }
        }

        /* Skip over any file data which was written */

        if (tmplen <= file_bytes_left) {
            file_offset += tmplen;
            file_bytes_left -= tmplen;
            continue;
        }

        tmplen -= file_bytes_left;
        file_bytes_left = 0;
        file_offset = 0;

        /* Skip over any trailer data which was written */

        while (tmplen && hdtr->numtrailers) {
            if (tmplen >= hdtr->trailers[0].iov_len) {
                tmplen -= hdtr->trailers[0].iov_len;
                --hdtr->numtrailers;
                ++hdtr->trailers;
            }
            else {
                char *iov_base = (char *)hdtr->trailers[0].iov_base;

                hdtr->trailers[0].iov_len -= tmplen;
                iov_base += tmplen;
                hdtr->trailers[0].iov_base = iov_base;
                tmplen = 0;
            }
        }
    } while (1);
}
#endif

/*
 * emulate_sendfile()
 * Sends the contents of file fd along with header/trailer bytes, if any,
 * to the network. emulate_sendfile will return only when all the bytes have been
 * sent (i.e., it handles partial writes) or on a network error condition.
 */
static apr_status_t emulate_sendfile(core_net_rec *c, apr_file_t *fd,
                                     apr_hdtr_t *hdtr, apr_off_t offset,
                                     apr_size_t length, apr_size_t *nbytes)
{
    apr_status_t rv = APR_SUCCESS;
    apr_int32_t togo;        /* Remaining number of bytes in the file to send */
    apr_size_t sendlen = 0;
    apr_size_t bytes_sent;
    apr_int32_t i;
    apr_off_t o;             /* Track the file offset for partial writes */
    char buffer[8192];

    *nbytes = 0;

    /* Send the headers
     * writev_it_all handles partial writes.
     * XXX: optimization... if headers are less than MIN_WRITE_SIZE, copy
     * them into buffer
     */
    if (hdtr && hdtr->numheaders > 0 ) {
        for (i = 0; i < hdtr->numheaders; i++) {
            sendlen += hdtr->headers[i].iov_len;
        }

        rv = writev_it_all(c->client_socket, hdtr->headers, hdtr->numheaders,
                           sendlen, &bytes_sent);
        if (rv == APR_SUCCESS)
            *nbytes += bytes_sent;     /* track total bytes sent */
    }

    /* Seek the file to 'offset' */
    if (offset != 0 && rv == APR_SUCCESS) {
        rv = apr_file_seek(fd, APR_SET, &offset);
    }

    /* Send the file, making sure to handle partial writes */
    togo = length;
    while (rv == APR_SUCCESS && togo) {
        sendlen = togo > sizeof(buffer) ? sizeof(buffer) : togo;
        o = 0;
        rv = apr_file_read(fd, buffer, &sendlen);
        while (rv == APR_SUCCESS && sendlen) {
            bytes_sent = sendlen;
            rv = apr_send(c->client_socket, &buffer[o], &bytes_sent);
            if (rv == APR_SUCCESS) {
                sendlen -= bytes_sent; /* sendlen != bytes_sent ==> partial write */
                o += bytes_sent;       /* o is where we are in the buffer */
                *nbytes += bytes_sent;
                togo -= bytes_sent;    /* track how much of the file we've sent */
            }
        }
    }

    /* Send the trailers
     * XXX: optimization... if it will fit, send this on the last send in the
     * loop above
     */
    sendlen = 0;
    if ( rv == APR_SUCCESS && hdtr && hdtr->numtrailers > 0 ) {
        for (i = 0; i < hdtr->numtrailers; i++) {
            sendlen += hdtr->trailers[i].iov_len;
        }
        rv = writev_it_all(c->client_socket, hdtr->trailers, hdtr->numtrailers,
                           sendlen, &bytes_sent);
        if (rv == APR_SUCCESS)
            *nbytes += bytes_sent;
    }

    return rv;
}

/* Note --- ErrorDocument will now work from .htaccess files.
 * The AllowOverride of Fileinfo allows webmasters to turn it off
 */

static const command_rec core_cmds[] = {

/* Old access config file commands */

AP_INIT_RAW_ARGS("<Directory", dirsection, NULL, RSRC_CONF,
  "Container for directives affecting resources located in the specified "
  "directories"),
AP_INIT_RAW_ARGS("<Location", urlsection, NULL, RSRC_CONF,
  "Container for directives affecting resources accessed through the "
  "specified URL paths"),
AP_INIT_RAW_ARGS("<VirtualHost", virtualhost_section, NULL, RSRC_CONF,
  "Container to map directives to a particular virtual host, takes one or "
  "more host addresses"),
AP_INIT_RAW_ARGS("<Files", filesection, NULL, OR_ALL,
  "Container for directives affecting files matching specified patterns"),
AP_INIT_RAW_ARGS("<Limit", ap_limit_section, NULL, OR_ALL,
  "Container for authentication directives when accessed using specified HTTP "
  "methods"),
AP_INIT_RAW_ARGS("<LimitExcept", ap_limit_section, (void*)1, OR_ALL,
  "Container for authentication directives to be applied when any HTTP "
  "method other than those specified is used to access the resource"),
AP_INIT_TAKE1("<IfModule", start_ifmod, NULL, EXEC_ON_READ | OR_ALL,
  "Container for directives based on existance of specified modules"),
AP_INIT_TAKE1("<IfDefine", start_ifdefine, NULL, EXEC_ON_READ | OR_ALL,
  "Container for directives based on existance of command line defines"),
AP_INIT_RAW_ARGS("<DirectoryMatch", dirsection, (void*)1, RSRC_CONF,
  "Container for directives affecting resources located in the "
  "specified directories"),
AP_INIT_RAW_ARGS("<LocationMatch", urlsection, (void*)1, RSRC_CONF,
  "Container for directives affecting resources accessed through the "
  "specified URL paths"),
AP_INIT_RAW_ARGS("<FilesMatch", filesection, (void*)1, OR_ALL,
  "Container for directives affecting files matching specified patterns"),
AP_INIT_TAKE1("AuthType", ap_set_string_slot,
  (void*)APR_OFFSETOF(core_dir_config, ap_auth_type), OR_AUTHCFG,
  "An HTTP authorization type (e.g., \"Basic\")"),
AP_INIT_TAKE1("AuthName", set_authname, NULL, OR_AUTHCFG,
  "The authentication realm (e.g. \"Members Only\")"),
AP_INIT_RAW_ARGS("Require", require, NULL, OR_AUTHCFG,
  "Selects which authenticated users or groups may access a protected space"),
AP_INIT_TAKE1("Satisfy", satisfy, NULL, OR_AUTHCFG,
  "access policy if both allow and require used ('all' or 'any')"),
#ifdef GPROF
AP_INIT_TAKE1("GprofDir", set_gprof_dir, NULL, RSRC_CONF,
  "Directory to plop gmon.out files"),
#endif
AP_INIT_TAKE1("AddDefaultCharset", set_add_default_charset, NULL, OR_FILEINFO,
  "The name of the default charset to add to any Content-Type without one or 'Off' to disable"),
AP_INIT_TAKE1("AcceptPathInfo", set_accept_path_info, NULL, OR_FILEINFO,
  "Set to on or off for PATH_INFO to be accepted by handlers, or default for the per-handler preference"),

/* Old resource config file commands */

AP_INIT_RAW_ARGS("AccessFileName", set_access_name, NULL, RSRC_CONF,
  "Name(s) of per-directory config files (default: .htaccess)"),
AP_INIT_TAKE1("DocumentRoot", set_document_root, NULL, RSRC_CONF,
  "Root directory of the document tree"),
AP_INIT_TAKE2("ErrorDocument", set_error_document, NULL, OR_FILEINFO,
  "Change responses for HTTP errors"),
AP_INIT_RAW_ARGS("AllowOverride", set_override, NULL, ACCESS_CONF,
  "Controls what groups of directives can be configured by per-directory "
  "config files"),
AP_INIT_RAW_ARGS("Options", set_options, NULL, OR_OPTIONS,
  "Set a number of attributes for a given directory"),
AP_INIT_TAKE1("DefaultType", ap_set_string_slot,
  (void*)APR_OFFSETOF(core_dir_config, ap_default_type),
  OR_FILEINFO, "the default MIME type for untypable files"),
AP_INIT_RAW_ARGS("FileETag", set_etag_bits, NULL, OR_FILEINFO,
  "Specify components used to construct a file's ETag"),
AP_INIT_TAKE1("EnableMMAP", set_enable_mmap, NULL, OR_FILEINFO,
  "Controls whether memory-mapping may be used to read files"),
AP_INIT_TAKE1("EnableSendfile", set_enable_sendfile, NULL, OR_FILEINFO,
  "Controls whether sendfile may be used to transmit files"),

/* Old server config file commands */

AP_INIT_TAKE1("Port", ap_set_deprecated, NULL, RSRC_CONF,
  "Port was replaced with Listen in Apache 2.0"),
AP_INIT_TAKE1("HostnameLookups", set_hostname_lookups, NULL,
  ACCESS_CONF|RSRC_CONF,
  "\"on\" to enable, \"off\" to disable reverse DNS lookups, or \"double\" to "
  "enable double-reverse DNS lookups"),
AP_INIT_TAKE1("ServerAdmin", set_server_string_slot,
  (void *)APR_OFFSETOF(server_rec, server_admin), RSRC_CONF,
  "The email address of the server administrator"),
AP_INIT_TAKE1("ServerName", server_hostname_port, NULL, RSRC_CONF,
  "The hostname and port of the server"),
AP_INIT_TAKE1("ServerSignature", set_signature_flag, NULL, OR_ALL,
  "En-/disable server signature (on|off|email)"),
AP_INIT_TAKE1("ServerRoot", set_server_root, NULL, RSRC_CONF | EXEC_ON_READ,
  "Common directory of server-related files (logs, confs, etc.)"),
AP_INIT_TAKE1("ErrorLog", set_server_string_slot,
  (void *)APR_OFFSETOF(server_rec, error_fname), RSRC_CONF,
  "The filename of the error log"),
AP_INIT_RAW_ARGS("ServerAlias", set_server_alias, NULL, RSRC_CONF,
  "A name or names alternately used to access the server"),
AP_INIT_TAKE1("ServerPath", set_serverpath, NULL, RSRC_CONF,
  "The pathname the server can be reached at"),
AP_INIT_TAKE1("Timeout", set_timeout, NULL, RSRC_CONF,
  "Timeout duration (sec)"),
AP_INIT_FLAG("ContentDigest", set_content_md5, NULL, OR_OPTIONS,
  "whether or not to send a Content-MD5 header with each request"),
AP_INIT_TAKE1("UseCanonicalName", set_use_canonical_name, NULL,
  RSRC_CONF|ACCESS_CONF,
  "How to work out the ServerName : Port when constructing URLs"),
/* TODO: RlimitFoo should all be part of mod_cgi, not in the core */
/* TODO: ListenBacklog in MPM */
AP_INIT_TAKE1("Include", include_config, NULL,
  (RSRC_CONF | ACCESS_CONF | EXEC_ON_READ),
  "Name of the config file to be included"),
AP_INIT_TAKE1("LogLevel", set_loglevel, NULL, RSRC_CONF,
  "Level of verbosity in error logging"),
AP_INIT_TAKE1("NameVirtualHost", ap_set_name_virtual_host, NULL, RSRC_CONF,
  "A numeric IP address:port, or the name of a host"),
#ifdef _OSD_POSIX
AP_INIT_TAKE1("BS2000Account", set_bs2000_account, NULL, RSRC_CONF,
  "Name of server User's bs2000 logon account name"),
#endif
AP_INIT_TAKE1("ServerTokens", set_serv_tokens, NULL, RSRC_CONF,
  "Determine tokens displayed in the Server: header - Min(imal), OS or Full"),
AP_INIT_TAKE1("LimitRequestLine", set_limit_req_line, NULL, RSRC_CONF,
  "Limit on maximum size of an HTTP request line"),
AP_INIT_TAKE1("LimitRequestFieldsize", set_limit_req_fieldsize, NULL,
  RSRC_CONF,
  "Limit on maximum size of an HTTP request header field"),
AP_INIT_TAKE1("LimitRequestFields", set_limit_req_fields, NULL, RSRC_CONF,
  "Limit (0 = unlimited) on max number of header fields in a request message"),
AP_INIT_TAKE1("LimitRequestBody", set_limit_req_body,
  (void*)APR_OFFSETOF(core_dir_config, limit_req_body), OR_ALL,
  "Limit (in bytes) on maximum size of request message body"),
AP_INIT_TAKE1("LimitXMLRequestBody", set_limit_xml_req_body, NULL, OR_ALL,
              "Limit (in bytes) on maximum size of an XML-based request "
              "body"),

/* System Resource Controls */
#ifdef RLIMIT_CPU
AP_INIT_TAKE12("RLimitCPU", set_limit_cpu,
  (void*)APR_OFFSETOF(core_dir_config, limit_cpu),
  OR_ALL, "Soft/hard limits for max CPU usage in seconds"),
#else
AP_INIT_TAKE12("RLimitCPU", no_set_limit, NULL,
  OR_ALL, "Soft/hard limits for max CPU usage in seconds"),
#endif
#if defined (RLIMIT_DATA) || defined (RLIMIT_VMEM) || defined (RLIMIT_AS)
AP_INIT_TAKE12("RLimitMEM", set_limit_mem,
  (void*)APR_OFFSETOF(core_dir_config, limit_mem),
  OR_ALL, "Soft/hard limits for max memory usage per process"),
#else
AP_INIT_TAKE12("RLimitMEM", no_set_limit, NULL,
  OR_ALL, "Soft/hard limits for max memory usage per process"),
#endif
#ifdef RLIMIT_NPROC
AP_INIT_TAKE12("RLimitNPROC", set_limit_nproc,
  (void*)APR_OFFSETOF(core_dir_config, limit_nproc),
  OR_ALL, "soft/hard limits for max number of processes per uid"),
#else
AP_INIT_TAKE12("RLimitNPROC", no_set_limit, NULL,
   OR_ALL, "soft/hard limits for max number of processes per uid"),
#endif

AP_INIT_TAKE1("ForceType", ap_set_string_slot_lower,
       (void *)APR_OFFSETOF(core_dir_config, mime_type), OR_FILEINFO,
     "a mime type that overrides other configured type"),
AP_INIT_TAKE1("SetHandler", ap_set_string_slot_lower,
       (void *)APR_OFFSETOF(core_dir_config, handler), OR_FILEINFO,
   "a handler name that overrides any other configured handler"),
AP_INIT_TAKE1("SetOutputFilter", ap_set_string_slot,
       (void *)APR_OFFSETOF(core_dir_config, output_filters), OR_FILEINFO,
   "filter (or ; delimited list of filters) to be run on the request content"),
AP_INIT_TAKE1("SetInputFilter", ap_set_string_slot,
       (void *)APR_OFFSETOF(core_dir_config, input_filters), OR_FILEINFO,
   "filter (or ; delimited list of filters) to be run on the request body"),
AP_INIT_ITERATE2("AddOutputFilterByType", add_ct_output_filters,
       (void *)APR_OFFSETOF(core_dir_config, ct_output_filters), OR_FILEINFO,
     "output filter name followed by one or more content-types"),
AP_INIT_FLAG("AllowEncodedSlashes", set_allow2f, NULL, RSRC_CONF,
             "Allow URLs containing '/' encoded as '%2F'"),

/*
 * These are default configuration directives that mpms can/should
 * pay attention to. If an mpm wishes to use these, they should
 * #defined them in mpm.h.
 */
#ifdef AP_MPM_WANT_SET_PIDFILE
AP_INIT_TAKE1("PidFile",  ap_mpm_set_pidfile, NULL, RSRC_CONF,
              "A file for logging the server process ID"),
#endif
#ifdef AP_MPM_WANT_SET_SCOREBOARD
AP_INIT_TAKE1("ScoreBoardFile", ap_mpm_set_scoreboard, NULL, RSRC_CONF,
              "A file for Apache to maintain runtime process management information"),
#endif
#ifdef AP_MPM_WANT_SET_LOCKFILE
AP_INIT_TAKE1("LockFile",  ap_mpm_set_lockfile, NULL, RSRC_CONF,
              "The lockfile used when Apache needs to lock the accept() call"),
#endif
#ifdef AP_MPM_WANT_SET_MAX_REQUESTS
AP_INIT_TAKE1("MaxRequestsPerChild", ap_mpm_set_max_requests, NULL, RSRC_CONF,
              "Maximum number of requests a particular child serves before dying."),
#endif
#ifdef AP_MPM_WANT_SET_COREDUMPDIR
AP_INIT_TAKE1("CoreDumpDirectory", ap_mpm_set_coredumpdir, NULL, RSRC_CONF,
              "The location of the directory Apache changes to before dumping core"),
#endif
#ifdef AP_MPM_WANT_SET_ACCEPT_LOCK_MECH
AP_INIT_TAKE1("AcceptMutex", ap_mpm_set_accept_lock_mech, NULL, RSRC_CONF,
              ap_valid_accept_mutex_string),
#endif
#ifdef AP_MPM_WANT_SET_MAX_MEM_FREE
AP_INIT_TAKE1("MaxMemFree", ap_mpm_set_max_mem_free, NULL, RSRC_CONF,
              "Maximum number of 1k blocks a particular childs allocator may hold."),
#endif
{ NULL }
};

/*****************************************************************
 *
 * Core handlers for various phases of server operation...
 */

AP_DECLARE_NONSTD(int) ap_core_translate(request_rec *r)
{
    void *sconf = r->server->module_config;
    core_server_config *conf = ap_get_module_config(sconf, &core_module);

    /* XXX this seems too specific, this should probably become
     * some general-case test
     */
    if (r->proxyreq) {
        return HTTP_FORBIDDEN;
    }
    if (!r->uri || ((r->uri[0] != '/') && strcmp(r->uri, "*"))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                     "Invalid URI in request %s", r->the_request);
        return HTTP_BAD_REQUEST;
    }

    if (r->server->path
        && !strncmp(r->uri, r->server->path, r->server->pathlen)
        && (r->server->path[r->server->pathlen - 1] == '/'
            || r->uri[r->server->pathlen] == '/'
            || r->uri[r->server->pathlen] == '\0')) 
    {
        /* skip all leading /'s (e.g. http://localhost///foo) 
         * so we are looking at only the relative path.
         */
        char *path = r->uri + r->server->pathlen;
        while (*path == '/') {
            ++path;
        }
        if (apr_filepath_merge(&r->filename, conf->ap_document_root, path,
                               APR_FILEPATH_TRUENAME
                             | APR_FILEPATH_SECUREROOT, r->pool)
                    != APR_SUCCESS) {
            return HTTP_FORBIDDEN;
        }
        r->canonical_filename = r->filename;
    }
    else {
        /*
         * Make sure that we do not mess up the translation by adding two
         * /'s in a row.  This happens under windows when the document
         * root ends with a /
         */
        /* skip all leading /'s (e.g. http://localhost///foo) 
         * so we are looking at only the relative path.
         */
        char *path = r->uri;
        while (*path == '/') {
            ++path;
        }
        if (apr_filepath_merge(&r->filename, conf->ap_document_root, path,
                               APR_FILEPATH_TRUENAME
                             | APR_FILEPATH_SECUREROOT, r->pool)
                    != APR_SUCCESS) {
            return HTTP_FORBIDDEN;
        }
        r->canonical_filename = r->filename;
    }

    return OK;
}

/*****************************************************************
 *
 * Test the filesystem name through directory_walk and file_walk
 */
static int core_map_to_storage(request_rec *r)
{
    int access_status;

    if ((access_status = ap_directory_walk(r))) {
        return access_status;
    }

    if ((access_status = ap_file_walk(r))) {
        return access_status;
    }

    return OK;
}


static int do_nothing(request_rec *r) { return OK; }


static int core_override_type(request_rec *r)
{
    core_dir_config *conf =
        (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &core_module);

    /* Check for overrides with ForceType / SetHandler
     */
    if (conf->mime_type && strcmp(conf->mime_type, "none"))
        ap_set_content_type(r, (char*) conf->mime_type);

    if (conf->handler && strcmp(conf->handler, "none"))
        r->handler = conf->handler;

    /* Deal with the poor soul who is trying to force path_info to be
     * accepted within the core_handler, where they will let the subreq
     * address its contents.  This is toggled by the user in the very
     * beginning of the fixup phase, so modules should override the user's
     * discretion in their own module fixup phase.  It is tristate, if
     * the user doesn't specify, the result is 2 (which the module may
     * interpret to its own customary behavior.)  It won't be touched
     * if the value is no longer undefined (2), so any module changing
     * the value prior to the fixup phase OVERRIDES the user's choice.
     */
    if ((r->used_path_info == AP_REQ_DEFAULT_PATH_INFO)
        && (conf->accept_path_info != 3)) {
        r->used_path_info = conf->accept_path_info;
    }

    return OK;
}



static int default_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *e;
    core_dir_config *d;
    int errstatus;
    apr_file_t *fd = NULL;
    apr_status_t status;
    /* XXX if/when somebody writes a content-md5 filter we either need to
     *     remove this support or coordinate when to use the filter vs.
     *     when to use this code
     *     The current choice of when to compute the md5 here matches the 1.3
     *     support fairly closely (unlike 1.3, we don't handle computing md5
     *     when the charset is translated).
     */
    int bld_content_md5;

    d = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &core_module);
    bld_content_md5 = (d->content_md5 & 1)
                      && r->output_filters->frec->ftype != AP_FTYPE_RESOURCE;

    ap_allow_standard_methods(r, MERGE_ALLOW, M_GET, M_OPTIONS, M_POST, -1);

    /* If filters intend to consume the request body, they must
     * register an InputFilter to slurp the contents of the POST
     * data from the POST input stream.  It no longer exists when
     * the output filters are invoked by the default handler.
     */
    if ((errstatus = ap_discard_request_body(r)) != OK) {
        return errstatus;
    }

    if (r->method_number == M_GET || r->method_number == M_POST) {
        if (r->finfo.filetype == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "File does not exist: %s", r->filename);
            return HTTP_NOT_FOUND;
        }

        /* Don't try to serve a dir.  Some OSs do weird things with
         * raw I/O on a dir.
         */
        if (r->finfo.filetype == APR_DIR) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Attempt to serve directory: %s", r->filename);
            return HTTP_NOT_FOUND;
        }

        if ((r->used_path_info != AP_REQ_ACCEPT_PATH_INFO) &&
            r->path_info && *r->path_info)
        {
            /* default to reject */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "File does not exist: %s",
                          apr_pstrcat(r->pool, r->filename, r->path_info, NULL));
            return HTTP_NOT_FOUND;
        }

        /* We understood the (non-GET) method, but it might not be legal for
           this particular resource. Check to see if the 'deliver_script'
           flag is set. If so, then we go ahead and deliver the file since
           it isn't really content (only GET normally returns content).

           Note: based on logic further above, the only possible non-GET
           method at this point is POST. In the future, we should enable
           script delivery for all methods.  */
        if (r->method_number != M_GET) {
            core_request_config *req_cfg;

            req_cfg = ap_get_module_config(r->request_config, &core_module);
            if (!req_cfg->deliver_script) {
                /* The flag hasn't been set for this request. Punt. */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "This resource does not accept the %s method.",
                              r->method);
                return HTTP_METHOD_NOT_ALLOWED;
            }
        }


        if ((status = apr_file_open(&fd, r->filename, APR_READ | APR_BINARY
#if APR_HAS_SENDFILE
                            | ((d->enable_sendfile == ENABLE_SENDFILE_OFF) 
                                                ? 0 : APR_SENDFILE_ENABLED)
#endif
                                    , 0, r->pool)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                          "file permissions deny server access: %s", r->filename);
            return HTTP_FORBIDDEN;
        }

        ap_update_mtime(r, r->finfo.mtime);
        ap_set_last_modified(r);
        ap_set_etag(r);
        apr_table_setn(r->headers_out, "Accept-Ranges", "bytes");
        ap_set_content_length(r, r->finfo.size);
        if ((errstatus = ap_meets_conditions(r)) != OK) {
            apr_file_close(fd);
            return errstatus;
        }

        if (bld_content_md5) {
            apr_table_setn(r->headers_out, "Content-MD5",
                           ap_md5digest(r->pool, fd));
        }

        bb = apr_brigade_create(r->pool, c->bucket_alloc);
#if APR_HAS_SENDFILE && APR_HAS_LARGE_FILES
        if ((d->enable_sendfile != ENABLE_SENDFILE_OFF) &&
            (r->finfo.size > AP_MAX_SENDFILE)) {
            /* APR_HAS_LARGE_FILES issue; must split into mutiple buckets,
             * no greater than MAX(apr_size_t), and more granular than that
             * in case the brigade code/filters attempt to read it directly.
             */
            apr_off_t fsize = r->finfo.size;
            e = apr_bucket_file_create(fd, 0, AP_MAX_SENDFILE, r->pool,
                                       c->bucket_alloc);
            while (fsize > AP_MAX_SENDFILE) {
                apr_bucket *ce;
                apr_bucket_copy(e, &ce);
                APR_BRIGADE_INSERT_TAIL(bb, ce);
                e->start += AP_MAX_SENDFILE;
                fsize -= AP_MAX_SENDFILE;
            }
            e->length = (apr_size_t)fsize; /* Resize just the last bucket */
        }
        else
#endif
            e = apr_bucket_file_create(fd, 0, (apr_size_t)r->finfo.size,
                                       r->pool, c->bucket_alloc);

#if APR_HAS_MMAP
        if (d->enable_mmap == ENABLE_MMAP_OFF) {
            (void)apr_bucket_file_enable_mmap(e, 0);
        }
#endif
        APR_BRIGADE_INSERT_TAIL(bb, e);
        e = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);

        return ap_pass_brigade(r->output_filters, bb);
    }
    else {              /* unusual method (not GET or POST) */
        if (r->method_number == M_INVALID) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid method in request %s", r->the_request);
            return HTTP_NOT_IMPLEMENTED;
        }

        if (r->method_number == M_OPTIONS) {
            return ap_send_http_options(r);
        }
        return HTTP_METHOD_NOT_ALLOWED;
    }
}

typedef struct net_time_filter_ctx {
    apr_socket_t *csd;
    int           first_line;
} net_time_filter_ctx_t;
static int net_time_filter(ap_filter_t *f, apr_bucket_brigade *b,
                           ap_input_mode_t mode, apr_read_type_e block,
                           apr_off_t readbytes)
{
    net_time_filter_ctx_t *ctx = f->ctx;
    int keptalive = f->c->keepalive == AP_CONN_KEEPALIVE;

    if (!ctx) {
        f->ctx = ctx = apr_palloc(f->r->pool, sizeof(*ctx));
        ctx->first_line = 1;
        ctx->csd = ap_get_module_config(f->c->conn_config, &core_module);        
    }

    if (mode != AP_MODE_INIT && mode != AP_MODE_EATCRLF) {
        if (ctx->first_line) {
            apr_socket_timeout_set(ctx->csd, 
                                   keptalive
                                      ? f->c->base_server->keep_alive_timeout
                                      : f->c->base_server->timeout);
            ctx->first_line = 0;
        }
        else {
            if (keptalive) {
                apr_socket_timeout_set(ctx->csd, f->c->base_server->timeout);
            }
        }
    }
    return ap_get_brigade(f->next, b, mode, block, readbytes);
}

/**
 * Remove all zero length buckets from the brigade.
 */
#define BRIGADE_NORMALIZE(b) \
do { \
    apr_bucket *e = APR_BRIGADE_FIRST(b); \
    do {  \
        if (e->length == 0 && !APR_BUCKET_IS_METADATA(e)) { \
            apr_bucket *d; \
            d = APR_BUCKET_NEXT(e); \
            apr_bucket_delete(e); \
            e = d; \
        } \
        e = APR_BUCKET_NEXT(e); \
    } while (!APR_BRIGADE_EMPTY(b) && (e != APR_BRIGADE_SENTINEL(b))); \
} while (0)

static int core_input_filter(ap_filter_t *f, apr_bucket_brigade *b,
                             ap_input_mode_t mode, apr_read_type_e block,
                             apr_off_t readbytes)
{
    apr_bucket *e;
    apr_status_t rv;
    core_net_rec *net = f->ctx;
    core_ctx_t *ctx = net->in_ctx;
    const char *str;
    apr_size_t len;

    if (mode == AP_MODE_INIT) {
        /*
         * this mode is for filters that might need to 'initialize'
         * a connection before reading request data from a client.
         * NNTP over SSL for example needs to handshake before the
         * server sends the welcome message.
         * such filters would have changed the mode before this point
         * is reached.  however, protocol modules such as NNTP should
         * not need to know anything about SSL.  given the example, if
         * SSL is not in the filter chain, AP_MODE_INIT is a noop.
         */
        return APR_SUCCESS;
    }

    if (!ctx)
    {
        ctx = apr_pcalloc(f->c->pool, sizeof(*ctx));
        ctx->b = apr_brigade_create(f->c->pool, f->c->bucket_alloc);

        /* seed the brigade with the client socket. */
        e = apr_bucket_socket_create(net->client_socket, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->b, e);
        net->in_ctx = ctx;
    }
    else if (APR_BRIGADE_EMPTY(ctx->b)) {
        return APR_EOF;
    }

    /* ### This is bad. */
    BRIGADE_NORMALIZE(ctx->b);

    /* check for empty brigade again *AFTER* BRIGADE_NORMALIZE()
     * If we have lost our socket bucket (see above), we are EOF.
     *
     * Ideally, this should be returning SUCCESS with EOS bucket, but
     * some higher-up APIs (spec. read_request_line via ap_rgetline)
     * want an error code. */
    if (APR_BRIGADE_EMPTY(ctx->b)) {
        return APR_EOF;
    }

    if (mode == AP_MODE_GETLINE) {
        /* we are reading a single LF line, e.g. the HTTP headers */
        rv = apr_brigade_split_line(b, ctx->b, block, HUGE_STRING_LEN);
        /* We should treat EAGAIN here the same as we do for EOF (brigade is
         * empty).  We do this by returning whatever we have read.  This may
         * or may not be bogus, but is consistent (for now) with EOF logic.
         */
        if (APR_STATUS_IS_EAGAIN(rv)) {
            rv = APR_SUCCESS;
        }
        return rv;
    }

    /* ### AP_MODE_PEEK is a horrific name for this mode because we also
     * eat any CRLFs that we see.  That's not the obvious intention of
     * this mode.  Determine whether anyone actually uses this or not. */
    if (mode == AP_MODE_EATCRLF) {
        apr_bucket *e;
        const char *c;

        /* The purpose of this loop is to ignore any CRLF (or LF) at the end
         * of a request.  Many browsers send extra lines at the end of POST
         * requests.  We use the PEEK method to determine if there is more
         * data on the socket, so that we know if we should delay sending the
         * end of one request until we have served the second request in a
         * pipelined situation.  We don't want to actually delay sending a
         * response if the server finds a CRLF (or LF), becuause that doesn't
         * mean that there is another request, just a blank line.
         */
        while (1) {
            if (APR_BRIGADE_EMPTY(ctx->b))
                return APR_EOF;

            e = APR_BRIGADE_FIRST(ctx->b);

            rv = apr_bucket_read(e, &str, &len, APR_NONBLOCK_READ);

            if (rv != APR_SUCCESS)
                return rv;

            c = str;
            while (c < str + len) {
                if (*c == APR_ASCII_LF)
                    c++;
                else if (*c == APR_ASCII_CR && *(c + 1) == APR_ASCII_LF)
                    c += 2;
                else
                    return APR_SUCCESS;
            }

            /* If we reach here, we were a bucket just full of CRLFs, so
             * just toss the bucket. */
            /* FIXME: Is this the right thing to do in the core? */
            apr_bucket_delete(e);
        }
        return APR_SUCCESS;
    }

    /* If mode is EXHAUSTIVE, we want to just read everything until the end
     * of the brigade, which in this case means the end of the socket.
     * To do this, we attach the brigade that has currently been setaside to
     * the brigade that was passed down, and send that brigade back.
     *
     * NOTE:  This is VERY dangerous to use, and should only be done with
     * extreme caution.  However, the Perchild MPM needs this feature
     * if it is ever going to work correctly again.  With this, the Perchild
     * MPM can easily request the socket and all data that has been read,
     * which means that it can pass it to the correct child process.
     */
    if (mode == AP_MODE_EXHAUSTIVE) {
        apr_bucket *e;

        /* Tack on any buckets that were set aside. */
        APR_BRIGADE_CONCAT(b, ctx->b);

        /* Since we've just added all potential buckets (which will most
         * likely simply be the socket bucket) we know this is the end,
         * so tack on an EOS too. */
        /* We have read until the brigade was empty, so we know that we
         * must be EOS. */
        e = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);
        return APR_SUCCESS;
    }

    /* read up to the amount they specified. */
    if (mode == AP_MODE_READBYTES || mode == AP_MODE_SPECULATIVE) {
        apr_bucket *e;
        apr_bucket_brigade *newbb;

        AP_DEBUG_ASSERT(readbytes > 0);

        e = APR_BRIGADE_FIRST(ctx->b);
        rv = apr_bucket_read(e, &str, &len, block);

        if (APR_STATUS_IS_EAGAIN(rv)) {
            return APR_SUCCESS;
        }
        else if (rv != APR_SUCCESS) {
            return rv;
        }
        else if (block == APR_BLOCK_READ && len == 0) {
            /* We wanted to read some bytes in blocking mode.  We read
             * 0 bytes.  Hence, we now assume we are EOS.
             *
             * When we are in normal mode, return an EOS bucket to the
             * caller.
             * When we are in speculative mode, leave ctx->b empty, so
             * that the next call returns an EOS bucket.
             */
            apr_bucket_delete(e);

            if (mode == AP_MODE_READBYTES) {
                e = apr_bucket_eos_create(f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(b, e);
            }
            return APR_SUCCESS;
        }

        /* We can only return at most what we read. */
        if (len < readbytes) {
            readbytes = len;
        }

        rv = apr_brigade_partition(ctx->b, readbytes, &e);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        /* Must do split before CONCAT */
        newbb = apr_brigade_split(ctx->b, e);

        if (mode == AP_MODE_READBYTES) {
            APR_BRIGADE_CONCAT(b, ctx->b);
        }
        else if (mode == AP_MODE_SPECULATIVE) {
            apr_bucket *copy_bucket;
            APR_BRIGADE_FOREACH(e, ctx->b) {
                rv = apr_bucket_copy(e, &copy_bucket);
                if (rv != APR_SUCCESS) {
                    return rv;
                }
                APR_BRIGADE_INSERT_TAIL(b, copy_bucket);
            }
        }

        /* Take what was originally there and place it back on ctx->b */
        APR_BRIGADE_CONCAT(ctx->b, newbb);
    }
    return APR_SUCCESS;
}

/* Default filter.  This filter should almost always be used.  Its only job
 * is to send the headers if they haven't already been sent, and then send
 * the actual data.
 */
#define MAX_IOVEC_TO_WRITE 16

/* Optional function coming from mod_logio, used for logging of output
 * traffic
 */
static APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *logio_add_bytes_out;

static apr_status_t core_output_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
    apr_status_t rv;
    apr_bucket_brigade *more;
    conn_rec *c = f->c;
    core_net_rec *net = f->ctx;
    core_output_filter_ctx_t *ctx = net->out_ctx;
    apr_read_type_e eblock = APR_NONBLOCK_READ;
    apr_pool_t *input_pool = b->p;

    if (ctx == NULL) {
        ctx = apr_pcalloc(c->pool, sizeof(*ctx));
        net->out_ctx = ctx;
    }

    /* If we have a saved brigade, concatenate the new brigade to it */
    if (ctx->b) {
        APR_BRIGADE_CONCAT(ctx->b, b);
        b = ctx->b;
        ctx->b = NULL;
    }

    /* Perform multiple passes over the brigade, sending batches of output
       to the connection. */
    while (b && !APR_BRIGADE_EMPTY(b)) {
        apr_size_t nbytes = 0;
        apr_bucket *last_e = NULL; /* initialized for debugging */
        apr_bucket *e;

        /* one group of iovecs per pass over the brigade */
        apr_size_t nvec = 0;
        apr_size_t nvec_trailers = 0;
        struct iovec vec[MAX_IOVEC_TO_WRITE];
        struct iovec vec_trailers[MAX_IOVEC_TO_WRITE];

        /* one file per pass over the brigade */
        apr_file_t *fd = NULL;
        apr_size_t flen = 0;
        apr_off_t foffset = 0;

        /* keep track of buckets that we've concatenated
         * to avoid small writes
         */
        apr_bucket *last_merged_bucket = NULL;

        /* tail of brigade if we need another pass */
        more = NULL;

        /* Iterate over the brigade: collect iovecs and/or a file */
        APR_BRIGADE_FOREACH(e, b) {
            /* keep track of the last bucket processed */
            last_e = e;
            if (APR_BUCKET_IS_EOS(e)) {
                break;
            }
            if (APR_BUCKET_IS_FLUSH(e)) {
                more = apr_brigade_split(b, APR_BUCKET_NEXT(e));
                break;
            }

            /* It doesn't make any sense to use sendfile for a file bucket
             * that represents 10 bytes.
             */
            else if (APR_BUCKET_IS_FILE(e)
                     && (e->length >= AP_MIN_SENDFILE_BYTES)) {
                apr_bucket_file *a = e->data;

                /* We can't handle more than one file bucket at a time
                 * so we split here and send the file we have already
                 * found.
                 */
                if (fd) {
                    more = apr_brigade_split(b, e);
                    break;
                }

                fd = a->fd;
                flen = e->length;
                foffset = e->start;
            }
            else {
                const char *str;
                apr_size_t n;

                rv = apr_bucket_read(e, &str, &n, eblock);
                if (APR_STATUS_IS_EAGAIN(rv)) {
                    /* send what we have so far since we shouldn't expect more
                     * output for a while...  next time we read, block
                     */
                    more = apr_brigade_split(b, e);
                    eblock = APR_BLOCK_READ;
                    break;
                }
                eblock = APR_NONBLOCK_READ;
                if (n) {
                    if (!fd) {
                        if (nvec == MAX_IOVEC_TO_WRITE) {
                            /* woah! too many. buffer them up, for use later. */
                            apr_bucket *temp, *next;
                            apr_bucket_brigade *temp_brig;

                            if (nbytes >= AP_MIN_BYTES_TO_WRITE) {
                                /* We have enough data in the iovec
                                 * to justify doing a writev
                                 */
                                more = apr_brigade_split(b, e);
                                break;
                            }

                            /* Create a temporary brigade as a means
                             * of concatenating a bunch of buckets together
                             */
                            if (last_merged_bucket) {
                                /* If we've concatenated together small
                                 * buckets already in a previous pass,
                                 * the initial buckets in this brigade
                                 * are heap buckets that may have extra
                                 * space left in them (because they
                                 * were created by apr_brigade_write()).
                                 * We can take advantage of this by
                                 * building the new temp brigade out of
                                 * these buckets, so that the content
                                 * in them doesn't have to be copied again.
                                 */
                                apr_bucket_brigade *bb;
                                bb = apr_brigade_split(b,
                                         APR_BUCKET_NEXT(last_merged_bucket));
                                temp_brig = b;
                                b = bb;
                            }
                            else {
                                temp_brig = apr_brigade_create(f->c->pool,
                                                           f->c->bucket_alloc);
                            }

                            temp = APR_BRIGADE_FIRST(b);
                            while (temp != e) {
                                apr_bucket *d;
                                rv = apr_bucket_read(temp, &str, &n, APR_BLOCK_READ);
                                apr_brigade_write(temp_brig, NULL, NULL, str, n);
                                d = temp;
                                temp = APR_BUCKET_NEXT(temp);
                                apr_bucket_delete(d);
                            }

                            nvec = 0;
                            nbytes = 0;
                            temp = APR_BRIGADE_FIRST(temp_brig);
                            APR_BUCKET_REMOVE(temp);
                            APR_BRIGADE_INSERT_HEAD(b, temp);
                            apr_bucket_read(temp, &str, &n, APR_BLOCK_READ);
                            vec[nvec].iov_base = (char*) str;
                            vec[nvec].iov_len = n;
                            nvec++;

                            /* Just in case the temporary brigade has
                             * multiple buckets, recover the rest of
                             * them and put them in the brigade that
                             * we're sending.
                             */
                            for (next = APR_BRIGADE_FIRST(temp_brig);
                                 next != APR_BRIGADE_SENTINEL(temp_brig);
                                 next = APR_BRIGADE_FIRST(temp_brig)) {
                                APR_BUCKET_REMOVE(next);
                                APR_BUCKET_INSERT_AFTER(temp, next);
                                temp = next;
                                apr_bucket_read(next, &str, &n,
                                                APR_BLOCK_READ);
                                vec[nvec].iov_base = (char*) str;
                                vec[nvec].iov_len = n;
                                nvec++;
                            }

                            apr_brigade_destroy(temp_brig);

                            last_merged_bucket = temp;
                            e = temp;
                            last_e = e;
                        }
                        else {
                            vec[nvec].iov_base = (char*) str;
                            vec[nvec].iov_len = n;
                            nvec++;
                        }
                    }
                    else {
                        /* The bucket is a trailer to a file bucket */

                        if (nvec_trailers == MAX_IOVEC_TO_WRITE) {
                            /* woah! too many. stop now. */
                            more = apr_brigade_split(b, e);
                            break;
                        }

                        vec_trailers[nvec_trailers].iov_base = (char*) str;
                        vec_trailers[nvec_trailers].iov_len = n;
                        nvec_trailers++;
                    }

                    nbytes += n;
                }
            }
        }


        /* Completed iterating over the brigades, now determine if we want
         * to buffer the brigade or send the brigade out on the network.
         *
         * Save if we haven't accumulated enough bytes to send, and:
         *
         *   1) we didn't see a file, we don't have more passes over the
         *      brigade to perform,  AND we didn't stop at a FLUSH bucket.
         *      (IOW, we will save plain old bytes such as HTTP headers)
         * or
         *   2) we hit the EOS and have a keep-alive connection
         *      (IOW, this response is a bit more complex, but we save it
         *       with the hope of concatenating with another response)
         */
        if (nbytes + flen < AP_MIN_BYTES_TO_WRITE
            && ((!fd && !more && !APR_BUCKET_IS_FLUSH(last_e))
                || (APR_BUCKET_IS_EOS(last_e)
                    && c->keepalive == AP_CONN_KEEPALIVE))) {

            /* NEVER save an EOS in here.  If we are saving a brigade with
             * an EOS bucket, then we are doing keepalive connections, and
             * we want to process to second request fully.
             */
            if (APR_BUCKET_IS_EOS(last_e)) {
                apr_bucket *bucket;
                int file_bucket_saved = 0;
                apr_bucket_delete(last_e);
                for (bucket = APR_BRIGADE_FIRST(b);
                     bucket != APR_BRIGADE_SENTINEL(b);
                     bucket = APR_BUCKET_NEXT(bucket)) {

                    /* Do a read on each bucket to pull in the
                     * data from pipe and socket buckets, so
                     * that we don't leave their file descriptors
                     * open indefinitely.  Do the same for file
                     * buckets, with one exception: allow the
                     * first file bucket in the brigade to remain
                     * a file bucket, so that we don't end up
                     * doing an mmap+memcpy every time a client
                     * requests a <8KB file over a keepalive
                     * connection.
                     */
                    if (APR_BUCKET_IS_FILE(bucket) && !file_bucket_saved) {
                        file_bucket_saved = 1;
                    }
                    else {
                        const char *buf;
                        apr_size_t len = 0;
                        rv = apr_bucket_read(bucket, &buf, &len,
                                             APR_BLOCK_READ);
                        if (rv != APR_SUCCESS) {
                            ap_log_error(APLOG_MARK, APLOG_ERR, rv,
                                         c->base_server, "core_output_filter:"
                                         " Error reading from bucket.");
                            return HTTP_INTERNAL_SERVER_ERROR;
                        }
                    }
                }
            }
            if (!ctx->deferred_write_pool) {
                apr_pool_create(&ctx->deferred_write_pool, c->pool);
            }
            ap_save_brigade(f, &ctx->b, &b, ctx->deferred_write_pool);

            return APR_SUCCESS;
        }

        if (fd) {
            apr_hdtr_t hdtr;
            apr_size_t bytes_sent;

#if APR_HAS_SENDFILE
            apr_int32_t flags = 0;
#endif

            memset(&hdtr, '\0', sizeof(hdtr));
            if (nvec) {
                hdtr.numheaders = nvec;
                hdtr.headers = vec;
            }

            if (nvec_trailers) {
                hdtr.numtrailers = nvec_trailers;
                hdtr.trailers = vec_trailers;
            }

#if APR_HAS_SENDFILE
            if (apr_file_flags_get(fd) & APR_SENDFILE_ENABLED) {

                if (c->keepalive == AP_CONN_CLOSE && APR_BUCKET_IS_EOS(last_e)) {
                    /* Prepare the socket to be reused */
                    flags |= APR_SENDFILE_DISCONNECT_SOCKET;
                }

                rv = sendfile_it_all(net,      /* the network information   */
                                     fd,       /* the file to send          */
                                     &hdtr,    /* header and trailer iovecs */
                                     foffset,  /* offset in the file to begin
                                                  sending from              */
                                     flen,     /* length of file            */
                                     nbytes + flen, /* total length including
                                                       headers              */
                                     &bytes_sent,   /* how many bytes were
                                                       sent                 */
                                     flags);   /* apr_sendfile flags        */

                if (logio_add_bytes_out && bytes_sent > 0)
                    logio_add_bytes_out(c, bytes_sent);
            }
            else
#endif
            {
                rv = emulate_sendfile(net, fd, &hdtr, foffset, flen,
                                      &bytes_sent);

                if (logio_add_bytes_out && bytes_sent > 0)
                    logio_add_bytes_out(c, bytes_sent);
            }

            fd = NULL;
        }
        else {
            apr_size_t bytes_sent;

            rv = writev_it_all(net->client_socket,
                               vec, nvec,
                               nbytes, &bytes_sent);

            if (logio_add_bytes_out && bytes_sent > 0)
                logio_add_bytes_out(c, bytes_sent);
        }

        apr_brigade_destroy(b);
        
        /* drive cleanups for resources which were set aside 
         * this may occur before or after termination of the request which
         * created the resource
         */
        if (ctx->deferred_write_pool) {
            if (more && more->p == ctx->deferred_write_pool) {
                /* "more" belongs to the deferred_write_pool,
                 * which is about to be cleared.
                 */
                if (APR_BRIGADE_EMPTY(more)) {
                    more = NULL;
                }
                else {
                    /* uh oh... change more's lifetime 
                     * to the input brigade's lifetime 
                     */
                    apr_bucket_brigade *tmp_more = more;
                    more = NULL;
                    ap_save_brigade(f, &more, &tmp_more, input_pool);
                }
            }
            apr_pool_clear(ctx->deferred_write_pool);  
        }

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_INFO, rv, c->base_server,
                         "core_output_filter: writing data to the network");

            if (more)
                apr_brigade_destroy(more);

            /* No need to check for SUCCESS, we did that above. */
            if (!APR_STATUS_IS_EAGAIN(rv)) {
                c->aborted = 1;
            }

            /* The client has aborted, but the request was successful. We
             * will report success, and leave it to the access and error
             * logs to note that the connection was aborted.
             */
            return APR_SUCCESS;
        }

        b = more;
        more = NULL;
    }  /* end while () */

    return APR_SUCCESS;
}

static int core_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    logio_add_bytes_out = APR_RETRIEVE_OPTIONAL_FN(ap_logio_add_bytes_out);
    ident_lookup = APR_RETRIEVE_OPTIONAL_FN(ap_ident_lookup);

    ap_set_version(pconf);
    ap_setup_make_content_type(pconf);
    return OK;
}

static void core_insert_filter(request_rec *r)
{
    core_dir_config *conf = (core_dir_config *)
                            ap_get_module_config(r->per_dir_config,
                                                 &core_module);
    const char *filter, *filters = conf->output_filters;

    if (filters) {
        while (*filters && (filter = ap_getword(r->pool, &filters, ';'))) {
            ap_add_output_filter(filter, NULL, r, r->connection);
        }
    }

    filters = conf->input_filters;
    if (filters) {
        while (*filters && (filter = ap_getword(r->pool, &filters, ';'))) {
            ap_add_input_filter(filter, NULL, r, r->connection);
        }
    }
}

static apr_size_t num_request_notes = AP_NUM_STD_NOTES;

static apr_status_t reset_request_notes(void *dummy)
{
    num_request_notes = AP_NUM_STD_NOTES;
    return APR_SUCCESS;
}

AP_DECLARE(apr_size_t) ap_register_request_note(void)
{
    apr_pool_cleanup_register(apr_hook_global_pool, NULL, reset_request_notes,
                              apr_pool_cleanup_null);
    return num_request_notes++;
}

AP_DECLARE(void **) ap_get_request_note(request_rec *r, apr_size_t note_num)
{
    core_request_config *req_cfg;

    if (note_num >= num_request_notes) {
        return NULL;
    }

    req_cfg = (core_request_config *)
        ap_get_module_config(r->request_config, &core_module);

    if (!req_cfg) {
        return NULL;
    }

    return &(req_cfg->notes[note_num]);
}

static int core_create_req(request_rec *r)
{
    /* Alloc the config struct and the array of request notes in
     * a single block for efficiency
     */
    core_request_config *req_cfg;

    req_cfg = apr_pcalloc(r->pool, sizeof(core_request_config) +
                          sizeof(void *) * num_request_notes);
    req_cfg->notes = (void **)((char *)req_cfg + sizeof(core_request_config));

    /* ### temporarily enable script delivery as the default */
    req_cfg->deliver_script = 1;

    if (r->main) {
        core_request_config *main_req_cfg = (core_request_config *)
            ap_get_module_config(r->main->request_config, &core_module);
        req_cfg->bb = main_req_cfg->bb;
    }
    else {
        req_cfg->bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        if (!r->prev) {
            ap_add_input_filter_handle(ap_net_time_filter_handle,
                                       NULL, r, r->connection);
        }
    }

    ap_set_module_config(r->request_config, &core_module, req_cfg);

    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

    return OK;
}

static int core_create_proxy_req(request_rec *r, request_rec *pr)
{
    return core_create_req(pr);
}

static conn_rec *core_create_conn(apr_pool_t *ptrans, server_rec *server,
                                  apr_socket_t *csd, long id, void *sbh,
                                  apr_bucket_alloc_t *alloc)
{
    apr_status_t rv;
    conn_rec *c = (conn_rec *) apr_pcalloc(ptrans, sizeof(conn_rec));

    c->sbh = sbh;
    (void)ap_update_child_status(c->sbh, SERVER_BUSY_READ, (request_rec *)NULL);

    /* Got a connection structure, so initialize what fields we can
     * (the rest are zeroed out by pcalloc).
     */
    c->conn_config = ap_create_conn_config(ptrans);
    c->notes = apr_table_make(ptrans, 5);

    c->pool = ptrans;
    if ((rv = apr_socket_addr_get(&c->local_addr, APR_LOCAL, csd))
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, server,
                     "apr_socket_addr_get(APR_LOCAL)");
        apr_socket_close(csd);
        return NULL;
    }

    apr_sockaddr_ip_get(&c->local_ip, c->local_addr);
    if ((rv = apr_socket_addr_get(&c->remote_addr, APR_REMOTE, csd))
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, server,
                     "apr_socket_addr_get(APR_REMOTE)");
        apr_socket_close(csd);
        return NULL;
    }

    apr_sockaddr_ip_get(&c->remote_ip, c->remote_addr);
    c->base_server = server;

    c->id = id;
    c->bucket_alloc = alloc;

    return c;
}

static int core_pre_connection(conn_rec *c, void *csd)
{
    core_net_rec *net = apr_palloc(c->pool, sizeof(*net));

#ifdef AP_MPM_DISABLE_NAGLE_ACCEPTED_SOCK
    /* BillS says perhaps this should be moved to the MPMs. Some OSes
     * allow listening socket attributes to be inherited by the
     * accept sockets which means this call only needs to be made
     * once on the listener
     */
    ap_sock_disable_nagle(csd);
#endif
    net->c = c;
    net->in_ctx = NULL;
    net->out_ctx = NULL;
    net->client_socket = csd;

    ap_set_module_config(net->c->conn_config, &core_module, csd);
    ap_add_input_filter_handle(ap_core_input_filter_handle, net, NULL, net->c);
    ap_add_output_filter_handle(ap_core_output_filter_handle, net, NULL, net->c);
    return DONE;
}

static void register_hooks(apr_pool_t *p)
{
    /* create_connection and install_transport_filters are
     * hooks that should always be APR_HOOK_REALLY_LAST to give other
     * modules the opportunity to install alternate network transports
     * and stop other functions from being run.
     */
    ap_hook_create_connection(core_create_conn, NULL, NULL,
                              APR_HOOK_REALLY_LAST);
    ap_hook_pre_connection(core_pre_connection, NULL, NULL,
                           APR_HOOK_REALLY_LAST);

    ap_hook_post_config(core_post_config,NULL,NULL,APR_HOOK_REALLY_FIRST);
    ap_hook_translate_name(ap_core_translate,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_map_to_storage(core_map_to_storage,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_open_logs(ap_open_logs,NULL,NULL,APR_HOOK_REALLY_FIRST);
    ap_hook_handler(default_handler,NULL,NULL,APR_HOOK_REALLY_LAST);
    /* FIXME: I suspect we can eliminate the need for these do_nothings - Ben */
    ap_hook_type_checker(do_nothing,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_fixups(core_override_type,NULL,NULL,APR_HOOK_REALLY_FIRST);
    ap_hook_access_checker(do_nothing,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_create_request(core_create_req, NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(proxy, create_req, core_create_proxy_req, NULL, NULL,
                      APR_HOOK_MIDDLE);
    ap_hook_pre_mpm(ap_create_scoreboard, NULL, NULL, APR_HOOK_MIDDLE);

    /* register the core's insert_filter hook and register core-provided
     * filters
     */
    ap_hook_insert_filter(core_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);

    ap_core_input_filter_handle =
        ap_register_input_filter("CORE_IN", core_input_filter,
                                 NULL, AP_FTYPE_NETWORK);
    ap_net_time_filter_handle =
        ap_register_input_filter("NET_TIME", net_time_filter,
                                 NULL, AP_FTYPE_PROTOCOL);
    ap_content_length_filter_handle =
        ap_register_output_filter("CONTENT_LENGTH", ap_content_length_filter,
                                  NULL, AP_FTYPE_PROTOCOL);
    ap_core_output_filter_handle =
        ap_register_output_filter("CORE", core_output_filter,
                                  NULL, AP_FTYPE_NETWORK);
    ap_subreq_core_filter_handle =
        ap_register_output_filter("SUBREQ_CORE", ap_sub_req_output_filter,
                                  NULL, AP_FTYPE_CONTENT_SET);
    ap_old_write_func =
        ap_register_output_filter("OLD_WRITE", ap_old_write_filter,
                                  NULL, AP_FTYPE_RESOURCE - 10);
}

AP_DECLARE_DATA module core_module = {
    STANDARD20_MODULE_STUFF,
    create_core_dir_config,       /* create per-directory config structure */
    merge_core_dir_configs,       /* merge per-directory config structures */
    create_core_server_config,    /* create per-server config structure */
    merge_core_server_configs,    /* merge per-server config structures */
    core_cmds,                    /* command apr_table_t */
    register_hooks                /* register hooks */
};

