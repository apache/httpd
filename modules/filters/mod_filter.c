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

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"
#include "util_filter.h"
#include "ap_expr.h"

module AP_MODULE_DECLARE_DATA filter_module;

/**
 * @brief is a filter provider, as defined and implemented by mod_filter.
 *
 * The struct is a linked list, with dispatch criteria
 * defined for each filter.  The provider implementation itself is a
 * (2.0-compatible) ap_filter_rec_t* frec.
 */
struct ap_filter_provider_t {
    ap_expr_info_t *expr;
    const char **types;

    /** The filter that implements this provider */
    ap_filter_rec_t *frec;

    /** The next provider in the list */
    ap_filter_provider_t *next;
};

/** we need provider_ctx to save ctx values set by providers in filter_init */
typedef struct provider_ctx provider_ctx;
struct provider_ctx {
    ap_filter_provider_t *provider;
    void *ctx;
    provider_ctx *next;
};
typedef struct {
    ap_out_filter_func func;
    void *fctx;
    provider_ctx *init_ctx;
} harness_ctx;

typedef struct mod_filter_chain {
    const char *fname;
    struct mod_filter_chain *next;
} mod_filter_chain;

typedef struct {
    apr_hash_t *live_filters;
    mod_filter_chain *chain;
} mod_filter_cfg;

typedef struct {
    const char* range ;
} mod_filter_ctx ;


static void filter_trace(conn_rec *c, int debug, const char *fname,
                         apr_bucket_brigade *bb)
{
    apr_bucket *b;

    switch (debug) {
    case 0:        /* normal, operational use */
        return;
    case 1:        /* mod_diagnostics level */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(01375) "%s", fname);
        for (b = APR_BRIGADE_FIRST(bb);
             b != APR_BRIGADE_SENTINEL(bb);
             b = APR_BUCKET_NEXT(b)) {

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(01376)
                          "%s: type: %s, length: %" APR_SIZE_T_FMT,
                          fname, b->type->name ? b->type->name : "(unknown)",
                          b->length);
        }
        break;
    }
}

static int filter_init(ap_filter_t *f)
{
    ap_filter_provider_t *p;
    provider_ctx *pctx;
    int err;
    ap_filter_rec_t *filter = f->frec;

    harness_ctx *fctx = apr_pcalloc(f->r->pool, sizeof(harness_ctx));
    for (p = filter->providers; p; p = p->next) {
        if (p->frec->filter_init_func == filter_init) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, APLOGNO(01377)
                          "Chaining of FilterProviders not supported");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        else if (p->frec->filter_init_func) {
            f->ctx = NULL;
            if ((err = p->frec->filter_init_func(f)) != OK) {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, APLOGNO(01378)
                              "filter_init for %s failed", p->frec->name);
                return err;   /* if anyone errors out here, so do we */
            }
            if (f->ctx != NULL) {
                /* the filter init function set a ctx - we need to record it */
                pctx = apr_pcalloc(f->r->pool, sizeof(provider_ctx));
                pctx->provider = p;
                pctx->ctx = f->ctx;
                pctx->next = fctx->init_ctx;
                fctx->init_ctx = pctx;
            }
        }
    }
    f->ctx = fctx;
    return OK;
}

static int filter_lookup(ap_filter_t *f, ap_filter_rec_t *filter)
{
    ap_filter_provider_t *provider;
    int match = 0;
    const char *err = NULL;
    request_rec *r = f->r;
    harness_ctx *ctx = f->ctx;
    provider_ctx *pctx;
#ifndef NO_PROTOCOL
    unsigned int proto_flags;
    mod_filter_ctx *rctx = ap_get_module_config(r->request_config,
                                                &filter_module);
#endif

    /* Check registered providers in order */
    for (provider = filter->providers; provider; provider = provider->next) {
        if (provider->expr) {
            match = ap_expr_exec(r, provider->expr, &err);
            if (err) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01379)
                              "Error evaluating filter dispatch condition: %s",
                              err);
                match = 0;
            }
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                          "Expression condition for '%s' %s",
                          provider->frec->name,
                          match ? "matched" : "did not match");
        }
        else if (r->content_type) {
            const char **type = provider->types;
            size_t len = strcspn(r->content_type, "; \t");
            AP_DEBUG_ASSERT(type != NULL);
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                          "Content-Type '%s' ...", r->content_type);
            while (*type) {
                /* Handle 'content-type;charset=...' correctly */
                if (strncmp(*type, r->content_type, len) == 0
                    && (*type)[len] == '\0') {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                                  "... matched '%s'", *type);
                    match = 1;
                    break;
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                                  "... did not match '%s'", *type);
                }
                type++;
            }
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                          "Content-Type condition for '%s' %s",
                          provider->frec->name,
                          match ? "matched" : "did not match");
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                          "Content-Type condition for '%s' did not match: "
                          "no Content-Type", provider->frec->name);
        }

        if (match) {
            /* condition matches this provider */
#ifndef NO_PROTOCOL
            /* check protocol
             *
             * FIXME:
             * This is a quick hack and almost certainly buggy.
             * The idea is that by putting this in mod_filter, we relieve
             * filter implementations of the burden of fixing up HTTP headers
             * for cases that are routinely affected by filters.
             *
             * Default is ALWAYS to do nothing, so as not to tread on the
             * toes of filters which want to do it themselves.
             *
             */
            proto_flags = provider->frec->proto_flags;

            /* some specific things can't happen in a proxy */
            if (r->proxyreq) {
                if (proto_flags & AP_FILTER_PROTO_NO_PROXY) {
                    /* can't use this provider; try next */
                    continue;
                }

                if (proto_flags & AP_FILTER_PROTO_TRANSFORM) {
                    const char *str = apr_table_get(r->headers_out,
                                                    "Cache-Control");
                    if (str) {
                        if (ap_strcasestr(str, "no-transform")) {
                            /* can't use this provider; try next */
                            continue;
                        }
                    }
                    apr_table_addn(r->headers_out, "Warning",
                                   apr_psprintf(r->pool,
                                                "214 %s Transformation applied",
                                                r->hostname));
                }
            }

            /* things that are invalidated if the filter transforms content */
            if (proto_flags & AP_FILTER_PROTO_CHANGE) {
                apr_table_unset(r->headers_out, "Content-MD5");
                apr_table_unset(r->headers_out, "ETag");
                if (proto_flags & AP_FILTER_PROTO_CHANGE_LENGTH) {
                    apr_table_unset(r->headers_out, "Content-Length");
                }
            }

            /* no-cache is for a filter that has different effect per-hit */
            if (proto_flags & AP_FILTER_PROTO_NO_CACHE) {
                apr_table_unset(r->headers_out, "Last-Modified");
                apr_table_addn(r->headers_out, "Cache-Control", "no-cache");
            }

            if (proto_flags & AP_FILTER_PROTO_NO_BYTERANGE) {
                apr_table_setn(r->headers_out, "Accept-Ranges", "none");
            }
            else if (rctx && rctx->range) {
                /* restore range header we saved earlier */
                apr_table_setn(r->headers_in, "Range", rctx->range);
                rctx->range = NULL;
            }
#endif
            for (pctx = ctx->init_ctx; pctx; pctx = pctx->next) {
                if (pctx->provider == provider) {
                    ctx->fctx = pctx->ctx ;
                }
            }
            ctx->func = provider->frec->filter_func.out_func;
            return 1;
        }
    }

    /* No provider matched */
    return 0;
}

static apr_status_t filter_harness(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_status_t ret;
#ifndef NO_PROTOCOL
    const char *cachecontrol;
#endif
    harness_ctx *ctx = f->ctx;
    ap_filter_rec_t *filter = f->frec;

    if (f->r->status != 200
        && !apr_table_get(f->r->subprocess_env, "filter-errordocs")) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    filter_trace(f->c, filter->debug, f->frec->name, bb);

    /* look up a handler function if we haven't already set it */
    if (!ctx->func) {
#ifndef NO_PROTOCOL
        if (f->r->proxyreq) {
            if (filter->proto_flags & AP_FILTER_PROTO_NO_PROXY) {
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, bb);
            }

            if (filter->proto_flags & AP_FILTER_PROTO_TRANSFORM) {
                cachecontrol = apr_table_get(f->r->headers_out,
                                             "Cache-Control");
                if (cachecontrol) {
                    if (ap_strcasestr(cachecontrol, "no-transform")) {
                        ap_remove_output_filter(f);
                        return ap_pass_brigade(f->next, bb);
                    }
                }
            }
        }
#endif
        if (!filter_lookup(f, filter)) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }
        AP_DEBUG_ASSERT(ctx->func != NULL);
    }

    /* call the content filter with its own context, then restore our
     * context
     */
    f->ctx = ctx->fctx;
    ret = ctx->func(f, bb);
    ctx->fctx = f->ctx;
    f->ctx = ctx;

    return ret;
}

#ifndef NO_PROTOCOL
static const char *filter_protocol(cmd_parms *cmd, void *CFG, const char *fname,
                                   const char *pname, const char *proto)
{
    static const char *sep = ";, \t";
    char *arg;
    char *tok = 0;
    unsigned int flags = 0;
    mod_filter_cfg *cfg = CFG;
    ap_filter_provider_t *provider = NULL;
    ap_filter_rec_t *filter = apr_hash_get(cfg->live_filters, fname,
                                           APR_HASH_KEY_STRING);

    if (!filter) {
        return "FilterProtocol: No such filter";
    }

    /* Fixup the args: it's really pname that's optional */
    if (proto == NULL) {
        proto = pname;
        pname = NULL;
    }
    else {
        /* Find provider */
        for (provider = filter->providers; provider; provider = provider->next){
            if (!strcasecmp(provider->frec->name, pname)) {
                break;
            }
        }
        if (!provider) {
            return "FilterProtocol: No such provider for this filter";
        }
    }

    /* Now set flags from our args */
    for (arg = apr_strtok(apr_pstrdup(cmd->temp_pool, proto), sep, &tok);
         arg; arg = apr_strtok(NULL, sep, &tok)) {

        if (!strcasecmp(arg, "change=yes")) {
            flags |= AP_FILTER_PROTO_CHANGE | AP_FILTER_PROTO_CHANGE_LENGTH;
        }
        if (!strcasecmp(arg, "change=no")) {
            flags &= ~(AP_FILTER_PROTO_CHANGE | AP_FILTER_PROTO_CHANGE_LENGTH);
        }
        else if (!strcasecmp(arg, "change=1:1")) {
            flags |= AP_FILTER_PROTO_CHANGE;
        }
        else if (!strcasecmp(arg, "byteranges=no")) {
            flags |= AP_FILTER_PROTO_NO_BYTERANGE;
        }
        else if (!strcasecmp(arg, "proxy=no")) {
            flags |= AP_FILTER_PROTO_NO_PROXY;
        }
        else if (!strcasecmp(arg, "proxy=transform")) {
            flags |= AP_FILTER_PROTO_TRANSFORM;
        }
        else if (!strcasecmp(arg, "cache=no")) {
            flags |= AP_FILTER_PROTO_NO_CACHE;
        }
    }

    if (pname) {
        provider->frec->proto_flags = flags;
    }
    else {
        filter->proto_flags = flags;
    }

    return NULL;
}
#endif

static const char *filter_declare(cmd_parms *cmd, void *CFG, const char *fname,
                                  const char *place)
{
    mod_filter_cfg *cfg = (mod_filter_cfg *)CFG;
    ap_filter_rec_t *filter;

    filter = apr_pcalloc(cmd->pool, sizeof(ap_filter_rec_t));
    apr_hash_set(cfg->live_filters, fname, APR_HASH_KEY_STRING, filter);

    filter->name = fname;
    filter->filter_init_func = filter_init;
    filter->filter_func.out_func = filter_harness;
    filter->ftype = AP_FTYPE_RESOURCE;
    filter->next = NULL;

    if (place) {
        if (!strcasecmp(place, "CONTENT_SET")) {
            filter->ftype = AP_FTYPE_CONTENT_SET;
        }
        else if (!strcasecmp(place, "PROTOCOL")) {
            filter->ftype = AP_FTYPE_PROTOCOL;
        }
        else if (!strcasecmp(place, "CONNECTION")) {
            filter->ftype = AP_FTYPE_CONNECTION;
        }
        else if (!strcasecmp(place, "NETWORK")) {
            filter->ftype = AP_FTYPE_NETWORK;
        }
    }

    return NULL;
}

static const char *add_filter(cmd_parms *cmd, void *CFG,
                              const char *fname, const char *pname,
                              const char *expr, const char **types)
{
    mod_filter_cfg *cfg = CFG;
    ap_filter_provider_t *provider;
    const char *c;
    ap_filter_rec_t* frec;
    ap_filter_rec_t* provider_frec;
    ap_expr_info_t *node;
    const char *err = NULL;

    /* fname has been declared with DeclareFilter, so we can look it up */
    frec = apr_hash_get(cfg->live_filters, fname, APR_HASH_KEY_STRING);

    /* or if provider is mod_filter itself, we can also look it up */
    if (!frec) {
        c = filter_declare(cmd, CFG, fname, NULL);
        if ( c ) {
            return c;
        }
        frec = apr_hash_get(cfg->live_filters, fname, APR_HASH_KEY_STRING);
    }

    if (!frec) {
        return apr_psprintf(cmd->pool, "Undeclared smart filter %s", fname);
    }

    /* if provider has been registered, we can look it up */
    provider_frec = ap_get_output_filter_handle(pname);
    if (!provider_frec) {
        return apr_psprintf(cmd->pool, "Unknown filter provider %s", pname);
    }
    provider = apr_palloc(cmd->pool, sizeof(ap_filter_provider_t));
    if (expr) {
        node = ap_expr_parse_cmd(cmd, expr, 0, &err, NULL);
        if (err) {
            return apr_pstrcat(cmd->pool,
                               "Error parsing FilterProvider expression:", err,
                               NULL);
        }
        provider->expr = node;
        provider->types = NULL;
    }
    else {
        provider->types = types;
        provider->expr = NULL;
    }
    provider->frec = provider_frec;
    provider->next = frec->providers;
    frec->providers = provider;
    return NULL;
}

static const char *filter_provider(cmd_parms *cmd, void *CFG,
                                   const char *fname, const char *pname,
                                   const char *expr)
{
    return add_filter(cmd, CFG, fname, pname, expr, NULL);
}

static const char *filter_chain(cmd_parms *cmd, void *CFG, const char *arg)
{
    mod_filter_chain *p;
    mod_filter_chain *q;
    mod_filter_cfg *cfg = CFG;

    switch (arg[0]) {
    case '+':        /* add to end of chain */
        p = apr_pcalloc(cmd->pool, sizeof(mod_filter_chain));
        p->fname = arg+1;
        if (cfg->chain) {
            for (q = cfg->chain; q->next; q = q->next);
            q->next = p;
        }
        else {
            cfg->chain = p;
        }
        break;

    case '@':        /* add to start of chain */
        p = apr_palloc(cmd->pool, sizeof(mod_filter_chain));
        p->fname = arg+1;
        p->next = cfg->chain;
        cfg->chain = p;
        break;

    case '-':        /* remove from chain */
        if (cfg->chain) {
            if (strcasecmp(cfg->chain->fname, arg+1)) {
                for (p = cfg->chain; p->next; p = p->next) {
                    if (!strcasecmp(p->next->fname, arg+1)) {
                        p->next = p->next->next;
                    }
                }
            }
            else {
                cfg->chain = cfg->chain->next;
            }
        }
        break;

    case '!':        /* Empty the chain */
                     /** IG: Add a NULL provider to the beginning so that
                      *  we can ensure that we'll empty everything before
                      *  this when doing config merges later */
        p = apr_pcalloc(cmd->pool, sizeof(mod_filter_chain));
        p->fname = NULL;
        cfg->chain = p;
        break;

    case '=':        /* initialise chain with this arg */
                     /** IG: Prepend a NULL provider to the beginning as above */
        p = apr_pcalloc(cmd->pool, sizeof(mod_filter_chain));
        p->fname = NULL;
        p->next = apr_pcalloc(cmd->pool, sizeof(mod_filter_chain));
        p->next->fname = arg+1;
        cfg->chain = p;
        break;

    default:        /* add to end */
        p = apr_pcalloc(cmd->pool, sizeof(mod_filter_chain));
        p->fname = arg;
        if (cfg->chain) {
            for (q = cfg->chain; q->next; q = q->next);
            q->next = p;
        }
        else {
            cfg->chain = p;
        }
        break;
    }

    return NULL;
}

static const char *filter_bytype1(cmd_parms *cmd, void *CFG,
                                  const char *pname, const char **types)
{
    const char *rv;
    const char *fname;
    int seen_name = 0;
    mod_filter_cfg *cfg = CFG;

    /* construct fname from name */
    fname = apr_pstrcat(cmd->pool, "BYTYPE:", pname, NULL);

    /* check whether this is already registered, in which case
     * it's already in the filter chain
     */
    if (apr_hash_get(cfg->live_filters, fname, APR_HASH_KEY_STRING)) {
        seen_name = 1;
    }

    rv = add_filter(cmd, CFG, fname, pname, NULL, types);

    /* If it's the first time through, add to filterchain */
    if (rv == NULL && !seen_name) {
        rv = filter_chain(cmd, CFG, fname);
    }
    return rv;
}

static const char *filter_bytype(cmd_parms *cmd, void *CFG,
                                 int argc, char *const argv[])
{
    /* back compatibility, need to parse multiple components in filter name */
    char *pname;
    char *strtok_state = NULL;
    char *name;
    const char **types;
    const char *rv = NULL;
    if (argc < 2)
        return "AddOutputFilterByType requires at least two arguments";
    name = apr_pstrdup(cmd->temp_pool, argv[0]);
    types = apr_palloc(cmd->pool, argc * sizeof(char *));
    memcpy(types, &argv[1], (argc - 1) * sizeof(char *));
    types[argc-1] = NULL;
    for (pname = apr_strtok(name, ";", &strtok_state);
         pname != NULL && rv == NULL;
         pname = apr_strtok(NULL, ";", &strtok_state)) {
        rv = filter_bytype1(cmd, CFG, pname, types);
    }
    return rv;
}

static const char *filter_debug(cmd_parms *cmd, void *CFG, const char *fname,
                                const char *level)
{
    mod_filter_cfg *cfg = CFG;
    ap_filter_rec_t *frec = apr_hash_get(cfg->live_filters, fname,
                                         APR_HASH_KEY_STRING);
    if (!frec) {
        return apr_psprintf(cmd->pool, "Undeclared smart filter %s", fname);
    }
    frec->debug = atoi(level);

    return NULL;
}

static void filter_insert(request_rec *r)
{
    mod_filter_chain *p;
    ap_filter_rec_t *filter;
    mod_filter_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                               &filter_module);
#ifndef NO_PROTOCOL
    int ranges = 1;
    mod_filter_ctx *ctx = apr_pcalloc(r->pool, sizeof(mod_filter_ctx));
    ap_set_module_config(r->request_config, &filter_module, ctx);
#endif

    /** IG: Now that we've merged to the final config, go one last time
     *  through the chain, and prune out the NULL filters */

    for (p = cfg->chain; p; p = p->next) {
        if (p->fname == NULL)
            cfg->chain = p->next;
    }

    for (p = cfg->chain; p; p = p->next) {
        filter = apr_hash_get(cfg->live_filters, p->fname, APR_HASH_KEY_STRING);
        if (filter == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01380)
                          "Unknown filter %s not added", p->fname);
            continue;
        }
        ap_add_output_filter_handle(filter, NULL, r, r->connection);
#ifndef NO_PROTOCOL
        if (ranges && (filter->proto_flags
                       & (AP_FILTER_PROTO_NO_BYTERANGE
                          | AP_FILTER_PROTO_CHANGE_LENGTH))) {
            ctx->range = apr_table_get(r->headers_in, "Range");
            apr_table_unset(r->headers_in, "Range");
            ranges = 0;
        }
#endif
    }

    return;
}

static void filter_hooks(apr_pool_t *pool)
{
    ap_hook_insert_filter(filter_insert, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *filter_config(apr_pool_t *pool, char *x)
{
    mod_filter_cfg *cfg = apr_palloc(pool, sizeof(mod_filter_cfg));
    cfg->live_filters = apr_hash_make(pool);
    cfg->chain = NULL;
    return cfg;
}

static void *filter_merge(apr_pool_t *pool, void *BASE, void *ADD)
{
    mod_filter_cfg *base = BASE;
    mod_filter_cfg *add = ADD;
    mod_filter_chain *savelink = 0;
    mod_filter_chain *newlink;
    mod_filter_chain *p;
    mod_filter_cfg *conf = apr_palloc(pool, sizeof(mod_filter_cfg));

    conf->live_filters = apr_hash_overlay(pool, add->live_filters,
                                          base->live_filters);
    if (base->chain && add->chain) {
        for (p = base->chain; p; p = p->next) {
            newlink = apr_pmemdup(pool, p, sizeof(mod_filter_chain));
            if (newlink->fname == NULL) {
                conf->chain = savelink = newlink;
            }
            else if (savelink) {
                savelink->next = newlink;
                savelink = newlink;
            }
            else {
                conf->chain = savelink = newlink;
            }
        }

        for (p = add->chain; p; p = p->next) {
            newlink = apr_pmemdup(pool, p, sizeof(mod_filter_chain));
            /** Filter out merged chain resets */
            if (newlink->fname == NULL) {
                conf->chain = savelink = newlink;
            }
            else if (savelink) {
                savelink->next = newlink;
                savelink = newlink;
            }
            else {
                conf->chain = savelink = newlink;
            }
        }
    }
    else if (add->chain) {
        conf->chain = add->chain;
    }
    else {
        conf->chain = base->chain;
    }

    return conf;
}

static const command_rec filter_cmds[] = {
    AP_INIT_TAKE12("FilterDeclare", filter_declare, NULL, OR_OPTIONS,
        "filter-name [filter-type]"),
    AP_INIT_TAKE3("FilterProvider", filter_provider, NULL, OR_OPTIONS,
        "filter-name provider-name match-expression"),
    AP_INIT_ITERATE("FilterChain", filter_chain, NULL, OR_OPTIONS,
        "list of filter names with optional [+-=!@]"),
    AP_INIT_TAKE2("FilterTrace", filter_debug, NULL, RSRC_CONF | ACCESS_CONF,
        "filter-name debug-level"),
    AP_INIT_TAKE_ARGV("AddOutputFilterByType", filter_bytype, NULL, OR_FILEINFO,
        "output filter name followed by one or more content-types"),
#ifndef NO_PROTOCOL
    AP_INIT_TAKE23("FilterProtocol", filter_protocol, NULL, OR_OPTIONS,
        "filter-name [provider-name] protocol-args"),
#endif
    { NULL }
};

AP_DECLARE_MODULE(filter) = {
    STANDARD20_MODULE_STUFF,
    filter_config,
    filter_merge,
    NULL,
    NULL,
    filter_cmds,
    filter_hooks
};
