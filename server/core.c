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
#include "util_mutex.h"
#include "mpm_common.h"
#include "scoreboard.h"
#include "mod_core.h"
#include "mod_proxy.h"
#include "ap_listen.h"

#include "mod_so.h" /* for ap_find_loaded_module_symbol */

#if defined(RLIMIT_CPU) || defined (RLIMIT_DATA) || defined (RLIMIT_VMEM) || defined(RLIMIT_AS) || defined (RLIMIT_NPROC)
#include "unixd.h"
#endif

/* LimitRequestBody handling */
#define AP_LIMIT_REQ_BODY_UNSET         ((apr_off_t) -1)
#define AP_DEFAULT_LIMIT_REQ_BODY       ((apr_off_t) 0)

/* LimitXMLRequestBody handling */
#define AP_LIMIT_UNSET                  ((long) -1)
#define AP_DEFAULT_LIMIT_XML_BODY       ((size_t)1000000)

#define AP_MIN_SENDFILE_BYTES           (256)

/* maximum include nesting level */
#ifndef AP_MAX_INCLUDE_DEPTH
#define AP_MAX_INCLUDE_DEPTH            (128)
#endif

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
 * The core module also defines handlers, etc., to handle just enough
 * to allow a server with the core module ONLY to actually serve documents.
 *
 * This file could almost be mod_core.c, except for the stuff which affects
 * the http_conf_globals.
 */

/* Handles for core filters */
AP_DECLARE_DATA ap_filter_rec_t *ap_subreq_core_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_core_output_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_content_length_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_core_input_filter_handle;

/* magic pointer for ErrorDocument xxx "default" */
static char errordocument_default;

static void *create_core_dir_config(apr_pool_t *a, char *dir)
{
    core_dir_config *conf;

    conf = (core_dir_config *)apr_pcalloc(a, sizeof(core_dir_config));

    /* conf->r and conf->d[_*] are initialized by dirsection() or left NULL */

    conf->opts = dir ? OPT_UNSET : OPT_UNSET|OPT_ALL;
    conf->opts_add = conf->opts_remove = OPT_NONE;
    conf->override = dir ? OR_UNSET : OR_UNSET|OR_ALL;
    conf->override_opts = OPT_UNSET | OPT_ALL | OPT_SYM_OWNER | OPT_MULTI;

    conf->content_md5 = 2;
    conf->accept_path_info = 3;

    conf->use_canonical_name = USE_CANONICAL_NAME_UNSET;
    conf->use_canonical_phys_port = USE_CANONICAL_PHYS_PORT_UNSET;

    conf->hostname_lookups = HOSTNAME_LOOKUP_UNSET;

#ifdef RLIMIT_CPU
    conf->limit_cpu = NULL;
#endif
#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS)
    conf->limit_mem = NULL;
#endif
#ifdef RLIMIT_NPROC
    conf->limit_nproc = NULL;
#endif

    conf->limit_req_body = AP_LIMIT_REQ_BODY_UNSET;
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
    conf = (core_dir_config *)apr_pmemdup(a, base, sizeof(core_dir_config));

    conf->d = new->d;
    conf->d_is_fnmatch = new->d_is_fnmatch;
    conf->d_components = new->d_components;
    conf->r = new->r;
    conf->condition = new->condition;

    if (new->opts & OPT_UNSET) {
        /* there was no explicit setting of new->opts, so we merge
         * preserve the invariant (opts_add & opts_remove) == 0
         */
        conf->opts_add = (conf->opts_add & ~new->opts_remove) | new->opts_add;
        conf->opts_remove = (conf->opts_remove & ~new->opts_add)
                            | new->opts_remove;
        conf->opts = (conf->opts & ~conf->opts_remove) | conf->opts_add;

        /* If Includes was enabled with exec in the base config, but
         * was enabled without exec in the new config, then disable
         * exec in the merged set. */
        if (((base->opts & (OPT_INCLUDES|OPT_INC_WITH_EXEC))
             == (OPT_INCLUDES|OPT_INC_WITH_EXEC))
            && ((new->opts & (OPT_INCLUDES|OPT_INC_WITH_EXEC))
                == OPT_INCLUDES)) {
            conf->opts &= ~OPT_INC_WITH_EXEC;
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

    if (!(new->override_opts & OPT_UNSET)) {
        conf->override_opts = new->override_opts;
    }

    if (conf->response_code_strings == NULL) {
        conf->response_code_strings = new->response_code_strings;
    }
    else if (new->response_code_strings != NULL) {
        /* If we merge, the merge-result must have it's own array
         */
        conf->response_code_strings = apr_pmemdup(a,
            base->response_code_strings,
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

    if (new->use_canonical_phys_port != USE_CANONICAL_PHYS_PORT_UNSET) {
        conf->use_canonical_phys_port = new->use_canonical_phys_port;
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

    if (new->limit_req_body != AP_LIMIT_REQ_BODY_UNSET) {
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
            (conf->etag_remove & (~ new->etag_add)) | new->etag_remove;
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

#if APR_HAS_SO_ACCEPTFILTER
#ifndef ACCEPT_FILTER_NAME
#define ACCEPT_FILTER_NAME "httpready"
#ifdef __FreeBSD_version
#if __FreeBSD_version < 411000 /* httpready broken before 4.1.1 */
#undef ACCEPT_FILTER_NAME
#define ACCEPT_FILTER_NAME "dataready"
#endif
#endif
#endif
#endif

static void *create_core_server_config(apr_pool_t *a, server_rec *s)
{
    core_server_config *conf;
    int is_virtual = s->is_virtual;

    conf = (core_server_config *)apr_pcalloc(a, sizeof(core_server_config));

    /* global-default / global-only settings */

    if (!is_virtual) {
        conf->ap_document_root = DOCUMENT_LOCATION;
        conf->access_name = DEFAULT_ACCESS_FNAME;

        /* A mapping only makes sense in the global context */
        conf->accf_map = apr_table_make(a, 5);
#if APR_HAS_SO_ACCEPTFILTER
        apr_table_setn(conf->accf_map, "http", ACCEPT_FILTER_NAME);
        apr_table_setn(conf->accf_map, "https", "dataready");
#else
        apr_table_setn(conf->accf_map, "http", "data");
        apr_table_setn(conf->accf_map, "https", "data");
#endif
    }
    /* pcalloc'ed - we have NULL's/0's
    else ** is_virtual ** {
        conf->ap_document_root = NULL;
        conf->access_name = NULL;
        conf->accf_map = NULL;
    }
     */

    /* initialization, no special case for global context */

    conf->sec_dir = apr_array_make(a, 40, sizeof(ap_conf_vector_t *));
    conf->sec_url = apr_array_make(a, 40, sizeof(ap_conf_vector_t *));

    /* pcalloc'ed - we have NULL's/0's
    conf->gprof_dir = NULL;

    ** recursion stopper; 0 == unset
    conf->redirect_limit = 0;
    conf->subreq_limit = 0;

    conf->protocol = NULL;
     */

    conf->trace_enable = AP_TRACE_UNSET;

    return (void *)conf;
}

static void *merge_core_server_configs(apr_pool_t *p, void *basev, void *virtv)
{
    core_server_config *base = (core_server_config *)basev;
    core_server_config *virt = (core_server_config *)virtv;
    core_server_config *conf = (core_server_config *)
                               apr_pmemdup(p, base, sizeof(core_server_config));

    if (virt->ap_document_root)
        conf->ap_document_root = virt->ap_document_root;

    if (virt->access_name)
        conf->access_name = virt->access_name;

    /* XXX optimize to keep base->sec_ pointers if virt->sec_ array is empty */
    conf->sec_dir = apr_array_append(p, base->sec_dir, virt->sec_dir);
    conf->sec_url = apr_array_append(p, base->sec_url, virt->sec_url);

    if (virt->redirect_limit)
        conf->redirect_limit = virt->redirect_limit;

    if (virt->subreq_limit)
        conf->subreq_limit = virt->subreq_limit;

    if (virt->trace_enable != AP_TRACE_UNSET)
        conf->trace_enable = virt->trace_enable;

    /* no action for virt->accf_map, not allowed per-vhost */

    if (virt->protocol)
        conf->protocol = virt->protocol;

    if (virt->gprof_dir)
        conf->gprof_dir = virt->gprof_dir;

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

/*
 * Optional function coming from mod_authn_core, used for
 * retrieving the type of autorization
 */
static APR_OPTIONAL_FN_TYPE(authn_ap_auth_type) *authn_ap_auth_type;

AP_DECLARE(const char *) ap_auth_type(request_rec *r)
{
    if (authn_ap_auth_type) {
        return authn_ap_auth_type(r);
    }
    return NULL;
}

/*
 * Optional function coming from mod_authn_core, used for
 * retrieving the authorization realm
 */
static APR_OPTIONAL_FN_TYPE(authn_ap_auth_name) *authn_ap_auth_name;

AP_DECLARE(const char *) ap_auth_name(request_rec *r)
{
    if (authn_ap_auth_name) {
        return authn_ap_auth_name(r);
    }
    return NULL;
}

/*
 * Optional function coming from mod_access_compat, used to determine how
   access control interacts with authentication/authorization
 */
static APR_OPTIONAL_FN_TYPE(access_compat_ap_satisfies) *access_compat_ap_satisfies;

AP_DECLARE(int) ap_satisfies(request_rec *r)
{
    if (access_compat_ap_satisfies) {
        return access_compat_ap_satisfies(r);
    }
    return SATISFY_NOSPEC;
}

AP_DECLARE(const char *) ap_document_root(request_rec *r) /* Don't use this! */
{
    core_server_config *conf;

    conf = (core_server_config *)ap_get_module_config(r->server->module_config,
                                                      &core_module);

    return conf->ap_document_root;
}

/* Should probably just get rid of this... the only code that cares is
 * part of the core anyway (and in fact, it isn't publicised to other
 * modules).
 */

char *ap_response_code_string(request_rec *r, int error_index)
{
    core_dir_config *dirconf;
    core_request_config *reqconf;

    /* check for string registered via ap_custom_response() first */
    reqconf = (core_request_config *)ap_get_module_config(r->request_config,
                                                          &core_module);
    if (reqconf->response_code_strings != NULL &&
        reqconf->response_code_strings[error_index] != NULL) {
        return reqconf->response_code_strings[error_index];
    }

    /* check for string specified via ErrorDocument */
    dirconf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                      &core_module);

    if (dirconf->response_code_strings == NULL) {
        return NULL;
    }

    if (dirconf->response_code_strings[error_index] == &errordocument_default) {
        return NULL;
    }

    return dirconf->response_code_strings[error_index];
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
    int ignored_str_is_ip;

    if (!str_is_ip) { /* caller doesn't want to know */
        str_is_ip = &ignored_str_is_ip;
    }
    *str_is_ip = 0;

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
            *str_is_ip = 1;
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
 * name" as supplied by a possible Host: header or full URI.
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
    const char *retval;

    d = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &core_module);

    switch (d->use_canonical_name) {
        case USE_CANONICAL_NAME_ON:
            retval = r->server->server_hostname;
            break;
        case USE_CANONICAL_NAME_DNS:
            if (conn->local_host == NULL) {
                if (apr_getnameinfo(&conn->local_host,
                                conn->local_addr, 0) != APR_SUCCESS)
                    conn->local_host = apr_pstrdup(conn->pool,
                                               r->server->server_hostname);
                else {
                    ap_str_tolower(conn->local_host);
                }
            }
            retval = conn->local_host;
            break;
        case USE_CANONICAL_NAME_OFF:
        case USE_CANONICAL_NAME_UNSET:
            retval = r->hostname ? r->hostname : r->server->server_hostname;
            break;
        default:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                         "ap_get_server_name: Invalid UCN Option somehow");
            retval = "localhost";
            break;
    }
    return retval;
}

/*
 * Get the current server name from the request for the purposes
 * of using in a URL.  If the server name is an IPv6 literal
 * address, it will be returned in URL format (e.g., "[fe80::1]").
 */
AP_DECLARE(const char *) ap_get_server_name_for_url(request_rec *r)
{
    const char *plain_server_name = ap_get_server_name(r);

#if APR_HAVE_IPV6
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

    switch (d->use_canonical_name) {
        case USE_CANONICAL_NAME_OFF:
        case USE_CANONICAL_NAME_DNS:
        case USE_CANONICAL_NAME_UNSET:
            if (d->use_canonical_phys_port == USE_CANONICAL_PHYS_PORT_ON)
                port = r->parsed_uri.port_str ? r->parsed_uri.port :
                       r->connection->local_addr->port ? r->connection->local_addr->port :
                       r->server->port ? r->server->port :
                       ap_default_port(r);
            else /* USE_CANONICAL_PHYS_PORT_OFF or USE_CANONICAL_PHYS_PORT_UNSET */
                port = r->parsed_uri.port_str ? r->parsed_uri.port :
                       r->server->port ? r->server->port :
                       ap_default_port(r);
            break;
        case USE_CANONICAL_NAME_ON:
            /* With UseCanonicalName on (and in all versions prior to 1.3)
             * Apache will use the hostname and port specified in the
             * ServerName directive to construct a canonical name for the
             * server. (If no port was specified in the ServerName
             * directive, Apache uses the port supplied by the client if
             * any is supplied, and finally the default port for the protocol
             * used.
             */
            if (d->use_canonical_phys_port == USE_CANONICAL_PHYS_PORT_ON)
                port = r->server->port ? r->server->port :
                       r->connection->local_addr->port ? r->connection->local_addr->port :
                       ap_default_port(r);
            else /* USE_CANONICAL_PHYS_PORT_OFF or USE_CANONICAL_PHYS_PORT_UNSET */
                port = r->server->port ? r->server->port :
                       ap_default_port(r);
            break;
        default:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                         "ap_get_server_port: Invalid UCN Option somehow");
            port = ap_default_port(r);
            break;
    }

    return port;
}

AP_DECLARE(char *) ap_construct_url(apr_pool_t *p, const char *uri,
                                    request_rec *r)
{
    unsigned port = ap_get_server_port(r);
    const char *host = ap_get_server_name_for_url(r);

    if (ap_is_default_port(port, r)) {
        return apr_pstrcat(p, ap_http_scheme(r), "://", host, uri, NULL);
    }

    return apr_psprintf(p, "%s://%s:%u%s", ap_http_scheme(r), host, port, uri);
}

AP_DECLARE(apr_off_t) ap_get_limit_req_body(const request_rec *r)
{
    core_dir_config *d =
      (core_dir_config *)ap_get_module_config(r->per_dir_config, &core_module);

    if (d->limit_req_body == AP_LIMIT_REQ_BODY_UNSET) {
        return AP_DEFAULT_LIMIT_REQ_BODY;
    }

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

    if ((forbidden & (NOT_IN_LIMIT | NOT_IN_DIR_LOC_FILE))
        && cmd->limited != -1) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, gt,
                           " cannot occur within <Limit> or <LimitExcept> "
                           "section", NULL);
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

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    if (err != NULL) {
        return err;
    }

    conf->access_name = apr_pstrdup(cmd->pool, arg);
    return NULL;
}


static const char *set_define(cmd_parms *cmd, void *dummy,
                                   const char *optarg)
{
    char **newv;

    const char *err = ap_check_cmd_context(cmd,
                                           GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    newv = (char **)apr_array_push(ap_server_config_defines);
    *newv = apr_pstrdup(cmd->pool, optarg);

    return NULL;
}

#ifdef GPROF
static const char *set_gprof_dir(cmd_parms *cmd, void *dummy, const char *arg)
{
    void *sconf = cmd->server->module_config;
    core_server_config *conf = ap_get_module_config(sconf, &core_module);

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
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

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    if (err != NULL) {
        return err;
    }

    /* When ap_document_root_check is false; skip all the stuff below */
    if (!ap_document_root_check) {
       conf->ap_document_root = arg;
       return NULL;
    }

    /* Make it absolute, relative to ServerRoot */
    arg = ap_server_root_relative(cmd->pool, arg);
    if (arg == NULL) {
        return "DocumentRoot must be a directory";
    }

    /* TODO: ap_configtestonly */
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
    core_request_config *conf =
        ap_get_module_config(r->request_config, &core_module);
    int idx;

    if (conf->response_code_strings == NULL) {
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

        if (strcmp(msg, "default") == 0) {
            /* special case: ErrorDocument 404 default restores the
             * canned server error response
             */
            conf->response_code_strings[index_number] = &errordocument_default;
        }
        else {
            /* hack. Prefix a " if it is a msg; as that is what
             * http_protocol.c relies on to distinguish between
             * a msg and a (local) path.
             */
            conf->response_code_strings[index_number] = (what == MSG) ?
                    apr_pstrcat(cmd->pool, "\"",msg,NULL) :
                    apr_pstrdup(cmd->pool, msg);
        }
    }

    return NULL;
}

static const char *set_allow_opts(cmd_parms *cmd, allow_options_t *opts,
                                  const char *l)
{
    allow_options_t opt;
    int first = 1;

    char *w, *p = (char *) l;
    char *tok_state;

    while ((w = apr_strtok(p, ",", &tok_state)) != NULL) {

        if (first) {
            p = NULL;
            *opts = OPT_NONE;
            first = 0;
        }

        if (!strcasecmp(w, "Indexes")) {
            opt = OPT_INDEXES;
        }
        else if (!strcasecmp(w, "Includes")) {
            /* If Includes is permitted, both Includes and
             * IncludesNOEXEC may be changed. */
            opt = (OPT_INCLUDES | OPT_INC_WITH_EXEC);
        }
        else if (!strcasecmp(w, "IncludesNOEXEC")) {
            opt = OPT_INCLUDES;
        }
        else if (!strcasecmp(w, "FollowSymLinks")) {
            opt = OPT_SYM_LINKS;
        }
        else if (!strcasecmp(w, "SymLinksIfOwnerMatch")) {
            opt = OPT_SYM_OWNER;
        }
        else if (!strcasecmp(w, "ExecCGI")) {
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

        *opts |= opt;
    }

    (*opts) &= (~OPT_UNSET);

    return NULL;
}

static const char *set_override(cmd_parms *cmd, void *d_, const char *l)
{
    core_dir_config *d = d_;
    char *w;
    char *k, *v;

    /* Throw a warning if we're in <Location> or <Files> */
    if (ap_check_cmd_context(cmd, NOT_IN_LOCATION | NOT_IN_FILES)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                     "Useless use of AllowOverride in line %d of %s.",
                     cmd->directive->line_num, cmd->directive->filename);
    }

    d->override = OR_NONE;
    while (l[0]) {
        w = ap_getword_conf(cmd->pool, &l);

        k = w;
        v = strchr(k, '=');
        if (v) {
                *v++ = '\0';
        }

        if (!strcasecmp(w, "Limit")) {
            d->override |= OR_LIMIT;
        }
        else if (!strcasecmp(k, "Options")) {
            d->override |= OR_OPTIONS;
            if (v)
                set_allow_opts(cmd, &(d->override_opts), v);
            else
                d->override_opts = OPT_ALL;
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
            opt = (OPT_INCLUDES | OPT_INC_WITH_EXEC);
        }
        else if (!strcasecmp(w, "IncludesNOEXEC")) {
            opt = OPT_INCLUDES;
        }
        else if (!strcasecmp(w, "FollowSymLinks")) {
            opt = OPT_SYM_LINKS;
        }
        else if (!strcasecmp(w, "SymLinksIfOwnerMatch")) {
            opt = OPT_SYM_OWNER;
        }
        else if (!strcasecmp(w, "ExecCGI")) {
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

        if ( (cmd->override_opts & opt) != opt ) {
            return apr_pstrcat(cmd->pool, "Option ", w, " not allowed here", NULL);
        }
        else if (action == '-') {
            /* we ensure the invariant (d->opts_add & d->opts_remove) == 0 */
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

static const char *set_default_type(cmd_parms *cmd, void *d_,
                                   const char *arg)
{
    if ((strcasecmp(arg, "off") != 0) && (strcasecmp(arg, "none") != 0)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
              "Ignoring deprecated use of DefaultType in line %d of %s.",
                     cmd->directive->line_num, cmd->directive->filename);
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


/*
 * Report a missing-'>' syntax error.
 */
static char *unclosed_directive(cmd_parms *cmd)
{
    return apr_pstrcat(cmd->pool, cmd->cmd->name,
                       "> directive missing closing '>'", NULL);
}

/*
 * Report a missing args in '<Foo >' syntax error.
 */
static char *missing_container_arg(cmd_parms *cmd)
{
    return apr_pstrcat(cmd->pool, cmd->cmd->name,
                       "> directive requires additional arguments", NULL);
}

AP_CORE_DECLARE_NONSTD(const char *) ap_limit_section(cmd_parms *cmd,
                                                      void *dummy,
                                                      const char *arg)
{
    const char *endp = ap_strrchr_c(arg, '>');
    const char *limited_methods;
    void *tog = cmd->cmd->cmd_data;
    apr_int64_t limited = 0;
    apr_int64_t old_limited = cmd->limited;
    const char *errmsg;

    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    limited_methods = apr_pstrndup(cmd->pool, arg, endp - arg);

    if (!limited_methods[0]) {
        return missing_container_arg(cmd);
    }

    while (limited_methods[0]) {
        char *method = ap_getword_conf(cmd->pool, &limited_methods);
        int methnum;

        /* check for builtin or module registered method number */
        methnum = ap_method_number_of(method);

        if (methnum == M_TRACE && !tog) {
            return "TRACE cannot be controlled by <Limit>, see TraceEnable";
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
    limited = tog ? ~limited : limited;

    if (!(old_limited & limited)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive excludes all methods", NULL);
    }
    else if ((old_limited & limited) == old_limited) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive specifies methods already excluded",
                           NULL);
    }

    cmd->limited &= limited;

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, cmd->context);

    cmd->limited = old_limited;

    return errmsg;
}

/* XXX: Bogus - need to do this differently (at least OS2/Netware suffer
 * the same problem!!!
 * We use this in <DirectoryMatch> and <FilesMatch>, to ensure that
 * people don't get bitten by wrong-cased regex matches
 */

#ifdef WIN32
#define USE_ICASE AP_REG_ICASE
#else
#define USE_ICASE 0
#endif

static const char *dirsection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    ap_conf_vector_t *new_dir_conf = ap_create_per_dir_config(cmd->pool);
    ap_regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp - arg);

    if (!arg[0]) {
        return missing_container_arg(cmd);
    }

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
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED|USE_ICASE);
        if (!r) {
            return "Regex could not be compiled";
        }
    }
    else if (thiscmd->cmd_data) { /* <DirectoryMatch> */
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED|USE_ICASE);
        if (!r) {
            return "Regex could not be compiled";
        }
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
    ap_regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;
    ap_conf_vector_t *new_url_conf = ap_create_per_dir_config(cmd->pool);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp - arg);

    if (!arg[0]) {
        return missing_container_arg(cmd);
    }

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    cmd->override = OR_ALL|ACCESS_CONF;

    if (thiscmd->cmd_data) { /* <LocationMatch> */
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED);
        if (!r) {
            return "Regex could not be compiled";
        }
    }
    else if (!strcmp(cmd->path, "~")) {
        cmd->path = ap_getword_conf(cmd->pool, &arg);
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED);
        if (!r) {
            return "Regex could not be compiled";
        }
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
    ap_regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;
    core_dir_config *c = mconfig;
    ap_conf_vector_t *new_file_conf = ap_create_per_dir_config(cmd->pool);
    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_LOCATION | NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp - arg);

    if (!arg[0]) {
        return missing_container_arg(cmd);
    }

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    /* Only if not an .htaccess file */
    if (!old_path) {
        cmd->override = OR_ALL|ACCESS_CONF;
    }

    if (thiscmd->cmd_data) { /* <FilesMatch> */
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED|USE_ICASE);
        if (!r) {
            return "Regex could not be compiled";
        }
    }
    else if (!strcmp(cmd->path, "~")) {
        cmd->path = ap_getword_conf(cmd->pool, &arg);
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED|USE_ICASE);
        if (!r) {
            return "Regex could not be compiled";
        }
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
static const char *ifsection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    const command_rec *thiscmd = cmd->cmd;
    core_dir_config *c = mconfig;
    ap_conf_vector_t *new_file_conf = ap_create_per_dir_config(cmd->pool);
    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_LOCATION | NOT_IN_LIMIT);
    const char *condition;
    int expr_err = 0;

    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return unclosed_directive(cmd);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp - arg);

    if (!arg[0]) {
        return missing_container_arg(cmd);
    }

    condition = ap_getword_conf(cmd->pool, &arg);
    /* Only if not an .htaccess file */
    if (!old_path) {
        cmd->override = OR_ALL|ACCESS_CONF;
    }

    /* initialize our config and fetch it */
    conf = ap_set_config_vectors(cmd->server, new_file_conf, cmd->path,
                                 &core_module, cmd->pool);

    conf->condition = ap_expr_parse(cmd->pool, condition, &expr_err);
    if (expr_err) {
        return "Cannot parse condition clause";
    }

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_file_conf);
    if (errmsg != NULL)
        return errmsg;

    conf->d = cmd->path;
    conf->d_is_fnmatch = 0;
    conf->r = NULL;

    ap_add_file_conf(c, new_file_conf);

    if (*arg != '\0') {
        return apr_pstrcat(cmd->pool, "Multiple ", thiscmd->name,
                           "> arguments not supported.", NULL);
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

    if (!arg[0]) {
        return missing_container_arg(cmd);
    }

    found = ap_find_linked_module(arg);

    /* search prelinked stuff */
    if (!found) {
        ap_module_symbol_t *current = ap_prelinked_module_symbols;

        for (; current->name; ++current) {
            if (!strcmp(current->name, arg)) {
                found = current->modp;
                break;
            }
        }
    }

    /* search dynamic stuff */
    if (!found) {
        APR_OPTIONAL_FN_TYPE(ap_find_loaded_module_symbol) *check_symbol =
            APR_RETRIEVE_OPTIONAL_FN(ap_find_loaded_module_symbol);

        if (check_symbol) {
            found = check_symbol(cmd->server, arg);
        }
    }

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

    if (!arg[0]) {
        return missing_container_arg(cmd);
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

    if (!arg[0]) {
        return missing_container_arg(cmd);
    }

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

static const char *set_accf_map(cmd_parms *cmd, void *dummy,
                                const char *iproto, const char* iaccf)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    core_server_config *conf = ap_get_module_config(cmd->server->module_config,
                                                    &core_module);
    char* proto;
    char* accf;
    if (err != NULL) {
        return err;
    }

    proto = apr_pstrdup(cmd->pool, iproto);
    ap_str_tolower(proto);
    accf = apr_pstrdup(cmd->pool, iaccf);
    ap_str_tolower(accf);
    apr_table_setn(conf->accf_map, proto, accf);

    return NULL;
}

AP_DECLARE(const char*) ap_get_server_protocol(server_rec* s)
{
    core_server_config *conf = ap_get_module_config(s->module_config,
                                                    &core_module);
    return conf->protocol;
}

AP_DECLARE(void) ap_set_server_protocol(server_rec* s, const char* proto)
{
    core_server_config *conf = ap_get_module_config(s->module_config,
                                                    &core_module);
    conf->protocol = proto;
}

static const char *set_protocol(cmd_parms *cmd, void *dummy,
                                const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    core_server_config *conf = ap_get_module_config(cmd->server->module_config,
                                                    &core_module);
    char* proto;

    if (err != NULL) {
        return err;
    }

    proto = apr_pstrdup(cmd->pool, arg);
    ap_str_tolower(proto);
    conf->protocol = proto;

    return NULL;
}

static const char *set_server_string_slot(cmd_parms *cmd, void *dummy,
                                          const char *arg)
{
    /* This one's pretty generic... */

    int offset = (int)(long)cmd->info;
    char *struct_ptr = (char *)cmd->server;

    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE);
    if (err != NULL) {
        return err;
    }

    *(const char **)(struct_ptr + offset) = arg;
    return NULL;
}

/*
 * The ServerName directive takes one argument with format
 * [scheme://]fully-qualified-domain-name[:port], for instance
 * ServerName www.example.com
 * ServerName www.example.com:80
 * ServerName https://www.example.com:443
 */

static const char *server_hostname_port(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    const char *portstr, *part;
    char *scheme;
    int port;

    if (err != NULL) {
        return err;
    }

    part = ap_strstr_c(arg, "://");

    if (part) {
      scheme = apr_pstrndup(cmd->pool, arg, part - arg);
      ap_str_tolower(scheme);
      cmd->server->server_scheme = (const char *)scheme;
      part += 3;
    } else {
      part = arg;
    }

    portstr = ap_strchr_c(part, ':');
    if (portstr) {
        cmd->server->server_hostname = apr_pstrndup(cmd->pool, part,
                                                    portstr - part);
        portstr++;
        port = atoi(portstr);
        if (port <= 0 || port >= 65536) { /* 65536 == 1<<16 */
            return apr_pstrcat(cmd->temp_pool, "The port number \"", arg,
                          "\" is outside the appropriate range "
                          "(i.e., 1..65535).", NULL);
        }
    }
    else {
        cmd->server->server_hostname = apr_pstrdup(cmd->pool, part);
        port = 0;
    }

    cmd->server->port = port;
    return NULL;
}

static const char *set_signature_flag(cmd_parms *cmd, void *d_,
                                      const char *arg)
{
    core_dir_config *d = d_;

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
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);

    if (err != NULL) {
        return err;
    }

    cmd->server->timeout = apr_time_from_sec(atoi(arg));
    return NULL;
}

static const char *set_allow2f(cmd_parms *cmd, void *d_, int arg)
{
    core_dir_config *d = d_;

    d->allow_encoded_slashes = arg != 0;
    return NULL;
}

static const char *set_hostname_lookups(cmd_parms *cmd, void *d_,
                                        const char *arg)
{
    core_dir_config *d = d_;

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
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);

    if (err != NULL) {
        return err;
    }

    cmd->server->path = arg;
    cmd->server->pathlen = (int)strlen(arg);
    return NULL;
}

static const char *set_content_md5(cmd_parms *cmd, void *d_, int arg)
{
    core_dir_config *d = d_;

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

static const char *set_use_canonical_phys_port(cmd_parms *cmd, void *d_,
                                          const char *arg)
{
    core_dir_config *d = d_;

    if (strcasecmp(arg, "on") == 0) {
        d->use_canonical_phys_port = USE_CANONICAL_PHYS_PORT_ON;
    }
    else if (strcasecmp(arg, "off") == 0) {
        d->use_canonical_phys_port = USE_CANONICAL_PHYS_PORT_OFF;
    }
    else {
        return "parameter must be 'on' or 'off'";
    }

    return NULL;
}


static const char *include_config (cmd_parms *cmd, void *dummy,
                                   const char *name)
{
    ap_directive_t *conftree = NULL;
    const char* conffile, *error;
    unsigned *recursion;
    void *data;

    apr_pool_userdata_get(&data, "ap_include_sentinel", cmd->pool);
    if (data) {
        recursion = data;
    }
    else {
        data = recursion = apr_palloc(cmd->pool, sizeof(*recursion));
        *recursion = 0;
        apr_pool_userdata_setn(data, "ap_include_sentinel", NULL, cmd->pool);
    }

    if (++*recursion > AP_MAX_INCLUDE_DEPTH) {
        *recursion = 0;
        return apr_psprintf(cmd->pool, "Exceeded maximum include depth of %u. "
                            "You have probably a recursion somewhere.",
                            AP_MAX_INCLUDE_DEPTH);
    }

    conffile = ap_server_root_relative(cmd->pool, name);
    if (!conffile) {
        *recursion = 0;
        return apr_pstrcat(cmd->pool, "Invalid Include path ",
                           name, NULL);
    }

    error = ap_process_resource_config(cmd->server, conffile,
                                       &conftree, cmd->pool, cmd->temp_pool);
    if (error) {
        *recursion = 0;
        return error;
    }

    *(ap_directive_t **)dummy = conftree;

    /* recursion level done */
    if (*recursion) {
        --*recursion;
    }

    return NULL;
}

static const char *set_loglevel(cmd_parms *cmd, void *dummy, const char *arg)
{
    char *str;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
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
                           ap_get_server_banner(),
                           " Server at <a href=\"",
                           ap_is_url(r->server->server_admin) ? "" : "mailto:",
                           ap_escape_html(r->pool, r->server->server_admin),
                           "\">",
                           ap_escape_html(r->pool, ap_get_server_name(r)),
                           "</a> Port ", sport,
                           "</address>\n", NULL);
    }

    return apr_pstrcat(r->pool, prefix, "<address>", ap_get_server_banner(),
                       " Server at ",
                       ap_escape_html(r->pool, ap_get_server_name(r)),
                       " Port ", sport,
                       "</address>\n", NULL);
}

/*
 * Handle a request to include the server's OS platform in the Server
 * response header field (the ServerTokens directive).  Unfortunately
 * this requires a new global in order to communicate the setting back to
 * http_main so it can insert the information in the right place in the
 * string.
 */

static char *server_banner = NULL;
static int banner_locked = 0;
static const char *server_description = NULL;

enum server_token_type {
    SrvTk_MAJOR,         /* eg: Apache/2 */
    SrvTk_MINOR,         /* eg. Apache/2.0 */
    SrvTk_MINIMAL,       /* eg: Apache/2.0.41 */
    SrvTk_OS,            /* eg: Apache/2.0.41 (UNIX) */
    SrvTk_FULL,          /* eg: Apache/2.0.41 (UNIX) PHP/4.2.2 FooBar/1.2b */
    SrvTk_PRODUCT_ONLY  /* eg: Apache */
};
static enum server_token_type ap_server_tokens = SrvTk_FULL;

static apr_status_t reset_banner(void *dummy)
{
    banner_locked = 0;
    ap_server_tokens = SrvTk_FULL;
    server_banner = NULL;
    server_description = NULL;
    return APR_SUCCESS;
}

AP_DECLARE(void) ap_get_server_revision(ap_version_t *version)
{
    version->major = AP_SERVER_MAJORVERSION_NUMBER;
    version->minor = AP_SERVER_MINORVERSION_NUMBER;
    version->patch = AP_SERVER_PATCHLEVEL_NUMBER;
    version->add_string = AP_SERVER_ADD_STRING;
}

AP_DECLARE(const char *) ap_get_server_description(void)
{
    return server_description ? server_description :
        AP_SERVER_BASEVERSION " (" PLATFORM ")";
}

AP_DECLARE(const char *) ap_get_server_banner(void)
{
    return server_banner ? server_banner : AP_SERVER_BASEVERSION;
}

AP_DECLARE(void) ap_add_version_component(apr_pool_t *pconf, const char *component)
{
    if (! banner_locked) {
        /*
         * If the version string is null, register our cleanup to reset the
         * pointer on pool destruction. We also know that, if NULL,
         * we are adding the original SERVER_BASEVERSION string.
         */
        if (server_banner == NULL) {
            apr_pool_cleanup_register(pconf, NULL, reset_banner,
                                      apr_pool_cleanup_null);
            server_banner = apr_pstrdup(pconf, component);
        }
        else {
            /*
             * Tack the given component identifier to the end of
             * the existing string.
             */
            server_banner = apr_pstrcat(pconf, server_banner, " ",
                                        component, NULL);
        }
    }
    server_description = apr_pstrcat(pconf, server_description, " ",
                                     component, NULL);
}

/*
 * This routine adds the real server base identity to the banner string,
 * and then locks out changes until the next reconfig.
 */
static void set_banner(apr_pool_t *pconf)
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
     * Lock the server_banner string if we're not displaying
     * the full set of tokens
     */
    if (ap_server_tokens != SrvTk_FULL) {
        banner_locked++;
    }
    server_description = AP_SERVER_BASEVERSION " (" PLATFORM ")";
}

static const char *set_serv_tokens(cmd_parms *cmd, void *dummy,
                                   const char *arg1, const char *arg2)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    if (!strcasecmp(arg1, "OS")) {
        ap_server_tokens = SrvTk_OS;
    }
    else if (!strcasecmp(arg1, "Min") || !strcasecmp(arg1, "Minimal")) {
        ap_server_tokens = SrvTk_MINIMAL;
    }
    else if (!strcasecmp(arg1, "Major")) {
        ap_server_tokens = SrvTk_MAJOR;
    }
    else if (!strcasecmp(arg1, "Minor") ) {
        ap_server_tokens = SrvTk_MINOR;
    }
    else if (!strcasecmp(arg1, "Prod") || !strcasecmp(arg1, "ProductOnly")) {
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
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    int lim;

    if (err != NULL) {
        return err;
    }

    lim = atoi(arg);
    if (lim < 0) {
        return apr_pstrcat(cmd->temp_pool, "LimitRequestLine \"", arg,
                           "\" must be a non-negative integer", NULL);
    }

    cmd->server->limit_req_line = lim;
    return NULL;
}

static const char *set_limit_req_fieldsize(cmd_parms *cmd, void *dummy,
                                           const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    int lim;

    if (err != NULL) {
        return err;
    }

    lim = atoi(arg);
    if (lim < 0) {
        return apr_pstrcat(cmd->temp_pool, "LimitRequestFieldsize \"", arg,
                          "\" must be a non-negative integer",
                          NULL);
    }

    cmd->server->limit_req_fieldsize = lim;
    return NULL;
}

static const char *set_limit_req_fields(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
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
    char *errp;

    if (APR_SUCCESS != apr_strtoff(&conf->limit_req_body, arg, &errp, 10)) {
        return "LimitRequestBody argument is not parsable.";
    }
    if (*errp || conf->limit_req_body < 0) {
        return "LimitRequestBody requires a non-negative integer.";
    }

    return NULL;
}

static const char *set_limit_xml_req_body(cmd_parms *cmd, void *conf_,
                                          const char *arg)
{
    core_dir_config *conf = conf_;

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

    ap_unixd_set_rlimit(cmd, &conf->limit_cpu, arg, arg2, RLIMIT_CPU);
    return NULL;
}
#endif

#if defined (RLIMIT_DATA) || defined (RLIMIT_VMEM) || defined(RLIMIT_AS)
static const char *set_limit_mem(cmd_parms *cmd, void *conf_,
                                 const char *arg, const char * arg2)
{
    core_dir_config *conf = conf_;

#if defined(RLIMIT_AS)
    ap_unixd_set_rlimit(cmd, &conf->limit_mem, arg, arg2 ,RLIMIT_AS);
#elif defined(RLIMIT_DATA)
    ap_unixd_set_rlimit(cmd, &conf->limit_mem, arg, arg2, RLIMIT_DATA);
#elif defined(RLIMIT_VMEM)
    ap_unixd_set_rlimit(cmd, &conf->limit_mem, arg, arg2, RLIMIT_VMEM);
#endif

    return NULL;
}
#endif

#ifdef RLIMIT_NPROC
static const char *set_limit_nproc(cmd_parms *cmd, void *conf_,
                                   const char *arg, const char * arg2)
{
    core_dir_config *conf = conf_;

    ap_unixd_set_rlimit(cmd, &conf->limit_nproc, arg, arg2, RLIMIT_NPROC);
    return NULL;
}
#endif

static const char *set_recursion_limit(cmd_parms *cmd, void *dummy,
                                       const char *arg1, const char *arg2)
{
    core_server_config *conf = ap_get_module_config(cmd->server->module_config,
                                                    &core_module);
    int limit = atoi(arg1);

    if (limit <= 0) {
        return "The recursion limit must be greater than zero.";
    }
    if (limit < 4) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                     "Limiting internal redirects to very low numbers may "
                     "cause normal requests to fail.");
    }

    conf->redirect_limit = limit;

    if (arg2) {
        limit = atoi(arg2);

        if (limit <= 0) {
            return "The recursion limit must be greater than zero.";
        }
        if (limit < 4) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                         "Limiting the subrequest depth to a very low level may"
                         " cause normal requests to fail.");
        }
    }

    conf->subreq_limit = limit;

    return NULL;
}

static void log_backtrace(const request_rec *r)
{
    const request_rec *top = r;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "r->uri = %s", r->uri ? r->uri : "(unexpectedly NULL)");

    while (top && (top->prev || top->main)) {
        if (top->prev) {
            top = top->prev;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "redirected from r->uri = %s",
                          top->uri ? top->uri : "(unexpectedly NULL)");
        }

        if (!top->prev && top->main) {
            top = top->main;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "subrequested from r->uri = %s",
                          top->uri ? top->uri : "(unexpectedly NULL)");
        }
    }
}

/*
 * check whether redirect limit is reached
 */
AP_DECLARE(int) ap_is_recursion_limit_exceeded(const request_rec *r)
{
    core_server_config *conf = ap_get_module_config(r->server->module_config,
                                                    &core_module);
    const request_rec *top = r;
    int redirects = 0, subreqs = 0;
    int rlimit = conf->redirect_limit
                 ? conf->redirect_limit
                 : AP_DEFAULT_MAX_INTERNAL_REDIRECTS;
    int slimit = conf->subreq_limit
                 ? conf->subreq_limit
                 : AP_DEFAULT_MAX_SUBREQ_DEPTH;


    while (top->prev || top->main) {
        if (top->prev) {
            if (++redirects >= rlimit) {
                /* uuh, too much. */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Request exceeded the limit of %d internal "
                              "redirects due to probable configuration error. "
                              "Use 'LimitInternalRecursion' to increase the "
                              "limit if necessary. Use 'LogLevel debug' to get "
                              "a backtrace.", rlimit);

                /* post backtrace */
                log_backtrace(r);

                /* return failure */
                return 1;
            }

            top = top->prev;
        }

        if (!top->prev && top->main) {
            if (++subreqs >= slimit) {
                /* uuh, too much. */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Request exceeded the limit of %d subrequest "
                              "nesting levels due to probable configuration "
                              "error. Use 'LimitInternalRecursion' to increase "
                              "the limit if necessary. Use 'LogLevel debug' to "
                              "get a backtrace.", slimit);

                /* post backtrace */
                log_backtrace(r);

                /* return failure */
                return 1;
            }

            top = top->main;
        }
    }

    /* recursion state: ok */
    return 0;
}

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
        /* find last entry */
        if (old) {
            while (old->next) {
                old = old->next;
            }
        }
    }

    while (*arg &&
           (filter_name = ap_getword(cmd->pool, &arg, ';')) &&
           strcmp(filter_name, "")) {
        new = apr_pcalloc(cmd->pool, sizeof(ap_filter_rec_t));
        new->name = filter_name;

        /* We found something, so let's append it.  */
        if (old) {
            old->next = new;
        }
        else {
            apr_hash_set(conf->ct_output_filters, arg2,
                         APR_HASH_KEY_STRING, new);
        }
        old = new;
    }

    if (!new) {
        return "invalid filter name";
    }

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
    const char *ctype;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                   &core_module);

    /* We can't do anything with no content-type or if we don't have a
     * filter configured.
     */
    if (!r->content_type || !conf->ct_output_filters) {
        return;
    }

    /* remove c-t decoration */
    ctype = ap_field_noparam(r->pool, r->content_type);
    if (ctype) {
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

static const char *set_trace_enable(cmd_parms *cmd, void *dummy,
                                    const char *arg1)
{
    core_server_config *conf = ap_get_module_config(cmd->server->module_config,
                                                    &core_module);

    if (strcasecmp(arg1, "on") == 0) {
        conf->trace_enable = AP_TRACE_ENABLE;
    }
    else if (strcasecmp(arg1, "off") == 0) {
        conf->trace_enable = AP_TRACE_DISABLE;
    }
    else if (strcasecmp(arg1, "extended") == 0) {
        conf->trace_enable = AP_TRACE_EXTENDED;
    }
    else {
        return "TraceEnable must be one of 'on', 'off', or 'extended'";
    }

    return NULL;
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
AP_INIT_RAW_ARGS("<Limit", ap_limit_section, NULL, OR_LIMIT | OR_AUTHCFG,
  "Container for authentication directives when accessed using specified HTTP "
  "methods"),
AP_INIT_RAW_ARGS("<LimitExcept", ap_limit_section, (void*)1,
                 OR_LIMIT | OR_AUTHCFG,
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
#ifdef GPROF
AP_INIT_TAKE1("GprofDir", set_gprof_dir, NULL, RSRC_CONF,
  "Directory to plop gmon.out files"),
#endif
AP_INIT_TAKE1("AddDefaultCharset", set_add_default_charset, NULL, OR_FILEINFO,
  "The name of the default charset to add to any Content-Type without one or 'Off' to disable"),
AP_INIT_TAKE1("AcceptPathInfo", set_accept_path_info, NULL, OR_FILEINFO,
  "Set to on or off for PATH_INFO to be accepted by handlers, or default for the per-handler preference"),
AP_INIT_TAKE1("Define", set_define, NULL, RSRC_CONF,
              "Define the existance of a variable.  Same as passing -D to the command line."),
AP_INIT_RAW_ARGS("<If", ifsection, NULL, OR_ALL,
  "Container for directives to be conditionally applied"),

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
AP_INIT_TAKE1("DefaultType", set_default_type, NULL, OR_FILEINFO,
  "the default media type for otherwise untyped files (DEPRECATED)"),
AP_INIT_RAW_ARGS("FileETag", set_etag_bits, NULL, OR_FILEINFO,
  "Specify components used to construct a file's ETag"),
AP_INIT_TAKE1("EnableMMAP", set_enable_mmap, NULL, OR_FILEINFO,
  "Controls whether memory-mapping may be used to read files"),
AP_INIT_TAKE1("EnableSendfile", set_enable_sendfile, NULL, OR_FILEINFO,
  "Controls whether sendfile may be used to transmit files"),

/* Old server config file commands */

AP_INIT_TAKE1("Protocol", set_protocol, NULL, RSRC_CONF,
  "Set the Protocol for httpd to use."),
AP_INIT_TAKE2("AcceptFilter", set_accf_map, NULL, RSRC_CONF,
  "Set the Accept Filter to use for a protocol"),
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
AP_INIT_TAKE1("UseCanonicalPhysicalPort", set_use_canonical_phys_port, NULL,
  RSRC_CONF|ACCESS_CONF,
  "Whether to use the physical Port when constructing URLs"),
/* TODO: RlimitFoo should all be part of mod_cgi, not in the core */
/* TODO: ListenBacklog in MPM */
AP_INIT_TAKE1("Include", include_config, NULL,
  (RSRC_CONF | ACCESS_CONF | EXEC_ON_READ),
  "Name of the config file to be included"),
AP_INIT_TAKE1("LogLevel", set_loglevel, NULL, RSRC_CONF,
  "Level of verbosity in error logging"),
AP_INIT_TAKE1("NameVirtualHost", ap_set_name_virtual_host, NULL, RSRC_CONF,
  "A numeric IP address:port, or the name of a host"),
AP_INIT_TAKE12("ServerTokens", set_serv_tokens, NULL, RSRC_CONF,
  "Determine tokens displayed in the Server: header - Min(imal), "
  "Major, Minor, Prod, OS or Full"),
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
AP_INIT_RAW_ARGS("Mutex", ap_set_mutex, NULL, RSRC_CONF,
                 "mutex (or \"default\") and mechanism"),

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

/* internal recursion stopper */
AP_INIT_TAKE12("LimitInternalRecursion", set_recursion_limit, NULL, RSRC_CONF,
              "maximum recursion depth of internal redirects and subrequests"),

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
 * pay attention to.
 * XXX These are not for all platforms, and even some Unix MPMs might not want
 * some directives.
 */
AP_INIT_TAKE1("PidFile",  ap_mpm_set_pidfile, NULL, RSRC_CONF,
              "A file for logging the server process ID"),
AP_INIT_TAKE1("ScoreBoardFile", ap_mpm_set_scoreboard, NULL, RSRC_CONF,
              "A file for Apache to maintain runtime process management information"),
AP_INIT_TAKE1("MaxRequestsPerChild", ap_mpm_set_max_requests, NULL, RSRC_CONF,
              "Maximum number of requests a particular child serves before dying."),
AP_INIT_TAKE1("CoreDumpDirectory", ap_mpm_set_coredumpdir, NULL, RSRC_CONF,
              "The location of the directory Apache changes to before dumping core"),
AP_INIT_TAKE1("MaxMemFree", ap_mpm_set_max_mem_free, NULL, RSRC_CONF,
              "Maximum number of 1k blocks a particular childs allocator may hold."),
AP_INIT_TAKE1("ThreadStackSize", ap_mpm_set_thread_stacksize, NULL, RSRC_CONF,
              "Size in bytes of stack used by threads handling client connections"),
#if AP_ENABLE_EXCEPTION_HOOK
AP_INIT_TAKE1("EnableExceptionHook", ap_mpm_set_exception_hook, NULL, RSRC_CONF,
              "Controls whether exception hook may be called after a crash"),
#endif
AP_INIT_TAKE1("TraceEnable", set_trace_enable, NULL, RSRC_CONF,
              "'on' (default), 'off' or 'extended' to trace request body content"),
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
    apr_status_t rv;

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
        if ((rv = apr_filepath_merge(&r->filename, conf->ap_document_root, path,
                                     APR_FILEPATH_TRUENAME
                                   | APR_FILEPATH_SECUREROOT, r->pool))
                    != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                         "Cannot map %s to file", r->the_request);
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
        if ((rv = apr_filepath_merge(&r->filename, conf->ap_document_root, path,
                                     APR_FILEPATH_TRUENAME
                                   | APR_FILEPATH_SECUREROOT, r->pool))
                    != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                         "Cannot map %s to file", r->the_request);
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
        if (bld_content_md5) {
            apr_table_setn(r->headers_out, "Content-MD5",
                           ap_md5digest(r->pool, fd));
        }

        bb = apr_brigade_create(r->pool, c->bucket_alloc);

        if ((errstatus = ap_meets_conditions(r)) != OK) {
            apr_file_close(fd);
            r->status = errstatus;
        }
        else {
            e = apr_brigade_insert_file(bb, fd, 0, r->finfo.size, r->pool);

#if APR_HAS_MMAP
            if (d->enable_mmap == ENABLE_MMAP_OFF) {
                (void)apr_bucket_file_enable_mmap(e, 0);
            }
#endif
        }

        e = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);

        status = ap_pass_brigade(r->output_filters, bb);
        if (status == APR_SUCCESS
            || r->status != HTTP_OK
            || c->aborted) {
            return OK;
        }
        else {
            /* no way to know what type of error occurred */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                          "default_handler: ap_pass_brigade returned %i",
                          status);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else {              /* unusual method (not GET or POST) */
        if (r->method_number == M_INVALID) {
            /* See if this looks like an undecrypted SSL handshake attempt.
             * It's safe to look a couple bytes into the_request if it exists, as it's
             * always allocated at least MIN_LINE_ALLOC (80) bytes.
             */
            if (r->the_request
                && r->the_request[0] == 0x16                                
                && (r->the_request[1] == 0x2 || r->the_request[1] == 0x3)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Invalid method in request %s - possible attempt to establish SSL connection on non-SSL port", r->the_request);
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Invalid method in request %s", r->the_request);
            }
            return HTTP_NOT_IMPLEMENTED;
        }

        if (r->method_number == M_OPTIONS) {
            return ap_send_http_options(r);
        }
        return HTTP_METHOD_NOT_ALLOWED;
    }
}

/* Optional function coming from mod_logio, used for logging of output
 * traffic
 */
APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *ap__logio_add_bytes_out;
APR_OPTIONAL_FN_TYPE(authz_some_auth_required) *ap__authz_ap_some_auth_required;

/* Insist that at least one module will undertake to provide system
 * security by dropping startup privileges.
 */
static int sys_privileges = 0;
AP_DECLARE(int) ap_sys_privileges_handlers(int inc)
{
    sys_privileges += inc;
    return sys_privileges;
}
static int core_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap__logio_add_bytes_out = APR_RETRIEVE_OPTIONAL_FN(ap_logio_add_bytes_out);
    ident_lookup = APR_RETRIEVE_OPTIONAL_FN(ap_ident_lookup);
    ap__authz_ap_some_auth_required = APR_RETRIEVE_OPTIONAL_FN(authz_some_auth_required);
    authn_ap_auth_type = APR_RETRIEVE_OPTIONAL_FN(authn_ap_auth_type);
    authn_ap_auth_name = APR_RETRIEVE_OPTIONAL_FN(authn_ap_auth_name);
    access_compat_ap_satisfies = APR_RETRIEVE_OPTIONAL_FN(access_compat_ap_satisfies);

    set_banner(pconf);
    ap_setup_make_content_type(pconf);
    ap_setup_auth_internal(ptemp);
    if (!sys_privileges) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL,
                     "Server MUST relinquish startup privileges before "
                     "accepting connections.  Please ensure mod_unixd "
                     "or other system security module is loaded.");
        return !OK;
    }
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
    }

    ap_set_module_config(r->request_config, &core_module, req_cfg);

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

    c->cs = (conn_state_t *)apr_pcalloc(ptrans, sizeof(conn_state_t));
    APR_RING_INIT(&(c->cs->timeout_list), conn_state_t, timeout_list);
    c->cs->expiration_time = 0;
    c->cs->state = CONN_STATE_CHECK_REQUEST_LINE_READABLE;
    c->cs->c = c;
    c->cs->p = ptrans;
    c->cs->bucket_alloc = alloc;
    c->clogging_input_filters = 0;

    return c;
}

static int core_pre_connection(conn_rec *c, void *csd)
{
    core_net_rec *net = apr_palloc(c->pool, sizeof(*net));
    apr_status_t rv;

    /* The Nagle algorithm says that we should delay sending partial
     * packets in hopes of getting more data.  We don't want to do
     * this; we are not telnet.  There are bad interactions between
     * persistent connections and Nagle's algorithm that have very severe
     * performance penalties.  (Failing to disable Nagle is not much of a
     * problem with simple HTTP.)
     */
    rv = apr_socket_opt_set(csd, APR_TCP_NODELAY, 1);
    if (rv != APR_SUCCESS && rv != APR_ENOTIMPL) {
        /* expected cause is that the client disconnected already,
         * hence the debug level
         */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c,
                      "apr_socket_opt_set(APR_TCP_NODELAY)");
    }

    /* The core filter requires the timeout mode to be set, which
     * incidentally sets the socket to be nonblocking.  If this
     * is not initialized correctly, Linux - for example - will
     * be initially blocking, while Solaris will be non blocking
     * and any initial read will fail.
     */
    rv = apr_socket_timeout_set(csd, c->base_server->timeout);
    if (rv != APR_SUCCESS) {
        /* expected cause is that the client disconnected already */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c,
                      "apr_socket_timeout_set");
    }

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
    ap_hook_child_init(ap_logs_child_init,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_handler(default_handler,NULL,NULL,APR_HOOK_REALLY_LAST);
    /* FIXME: I suspect we can eliminate the need for these do_nothings - Ben */
    ap_hook_type_checker(do_nothing,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_fixups(core_override_type,NULL,NULL,APR_HOOK_REALLY_FIRST);
    ap_hook_create_request(core_create_req, NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(proxy, create_req, core_create_proxy_req, NULL, NULL,
                      APR_HOOK_MIDDLE);
    ap_hook_pre_mpm(ap_create_scoreboard, NULL, NULL, APR_HOOK_MIDDLE);

    /* register the core's insert_filter hook and register core-provided
     * filters
     */
    ap_hook_insert_filter(core_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);

    ap_core_input_filter_handle =
        ap_register_input_filter("CORE_IN", ap_core_input_filter,
                                 NULL, AP_FTYPE_NETWORK);
    ap_content_length_filter_handle =
        ap_register_output_filter("CONTENT_LENGTH", ap_content_length_filter,
                                  NULL, AP_FTYPE_PROTOCOL);
    ap_core_output_filter_handle =
        ap_register_output_filter("CORE", ap_core_output_filter,
                                  NULL, AP_FTYPE_NETWORK);
    ap_subreq_core_filter_handle =
        ap_register_output_filter("SUBREQ_CORE", ap_sub_req_output_filter,
                                  NULL, AP_FTYPE_CONTENT_SET);
    ap_old_write_func =
        ap_register_output_filter("OLD_WRITE", ap_old_write_filter,
                                  NULL, AP_FTYPE_RESOURCE - 10);
}

AP_DECLARE_DATA module core_module = {
    MPM20_MODULE_STUFF,
    AP_PLATFORM_REWRITE_ARGS_HOOK, /* hook to run before apache parses args */
    create_core_dir_config,       /* create per-directory config structure */
    merge_core_dir_configs,       /* merge per-directory config structures */
    create_core_server_config,    /* create per-server config structure */
    merge_core_server_configs,    /* merge per-server config structures */
    core_cmds,                    /* command apr_table_t */
    register_hooks                /* register hooks */
};

