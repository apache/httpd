/* Copyright (C) 2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Originally by Nick Kew <nick@webthing.com>
 *
 * At the time of writing, this is designed primarily for use with
 * httpd 2.2, but is also back-compatible with 2.0.  It is likely
 * that the 2.0 and 2.2 versions may diverge in future, as additional
 * capabilities for 2.2 are added, including updates to util_filter.
 */

#include <ctype.h>
#include <string.h>

/* apache */
#include "apr_strings.h"
#include "apr_hash.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "util_filter.h"

#ifndef NO_PROTOCOL
#define PROTO_CHANGE 0x1
#define PROTO_CHANGE_LENGTH 0x2
#define PROTO_NO_BYTERANGE 0x4
#define PROTO_NO_PROXY 0x8
#define PROTO_NO_CACHE 0x10
#define PROTO_TRANSFORM 0x20
#endif

module AP_MODULE_DECLARE_DATA filter_module ;

typedef apr_status_t (*filter_func_t)(ap_filter_t*, apr_bucket_brigade*) ;

typedef struct {
    const char* name ;
    filter_func_t func ;
    void* fctx ;
} harness_ctx ;

typedef struct mod_filter_provider {
    enum {
        STRING_MATCH,
        STRING_CONTAINS,
        REGEX_MATCH,
        INT_EQ,
        INT_LT,
        INT_GT,
        DEFINED
    } match_type ;
    int not ;        /* negation on match_type */
    union {
        const char* c ;
        regex_t* r ;
        int i ;
    } match ;
    ap_filter_rec_t* frec ;
    struct mod_filter_provider* next ;
#ifndef NO_PROTOCOL
    unsigned int proto_flags ;
#endif
} mod_filter_provider ;

typedef struct {
    ap_filter_rec_t frec ;
    enum {
        HANDLER,
        REQUEST_HEADERS,
        RESPONSE_HEADERS,
        SUBPROCESS_ENV,
        CONTENT_TYPE
    } dispatch ;
    const char* value ;
    mod_filter_provider* providers ;
    int debug ;
#ifndef NO_PROTOCOL
    unsigned int proto_flags ;
    const char* range ;
#endif
} mod_filter_rec ;

typedef struct mod_filter_chain {
    const char* fname ;
    struct mod_filter_chain* next ;
} mod_filter_chain ;

typedef struct {
    apr_hash_t* live_filters ;
    mod_filter_chain* chain ;
} mod_filter_cfg ;

static const char* filter_bucket_type(apr_bucket* b)
{
    static struct {
        const void* fn ;
        const char* desc ;
    } types[] = {
        { &apr_bucket_type_heap, "HEAP" } ,
        { &apr_bucket_type_transient, "TRANSIENT" } ,
        { &apr_bucket_type_immortal, "IMMORTAL" } ,
        { &apr_bucket_type_pool, "POOL" } ,
        { &apr_bucket_type_eos, "EOS" } ,
        { &apr_bucket_type_flush, "FLUSH" } ,
        { &apr_bucket_type_file, "FILE" } ,
#if APR_HAS_MMAP
        { &apr_bucket_type_mmap, "MMAP" } ,
#endif
        { &apr_bucket_type_pipe, "PIPE" } ,
        { &apr_bucket_type_socket, "SOCKET" } ,
        { NULL, NULL }
    } ;
    int i = 0 ;
    do {
        if ( b->type == types[i].fn ) {
            return types[i].desc ;
        }
    } while ( types[++i].fn != NULL ) ;
    return "(error)" ;
}
static void filter_trace(apr_pool_t* pool, int debug, const char* fname,
                         apr_bucket_brigade* bb)
{
    apr_bucket* b ;
    const char* type ;
    switch ( debug ) {
        case 0:        /* normal, operational use */
            return ;
        case 1:        /* mod_diagnostics level */
            ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, pool, fname);
            for ( b = APR_BRIGADE_FIRST(bb) ;
                  b != APR_BRIGADE_SENTINEL(bb) ;
                  b = APR_BUCKET_NEXT(b) ) {
                type = filter_bucket_type(b) ;
                ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, pool, "   %s: %s %d",
                              fname, filter_bucket_type(b), b->length);
            }
            break ;
    }
}

static int filter_init(ap_filter_t* f)
{
    mod_filter_provider* p ;
    int err = OK ;
    harness_ctx* ctx = f->ctx ;
    mod_filter_cfg* cfg
        = ap_get_module_config(f->r->per_dir_config, &filter_module);
    mod_filter_rec* filter
        = apr_hash_get(cfg->live_filters, ctx->name, APR_HASH_KEY_STRING) ;
    for ( p = filter->providers ; p ; p = p->next ) {
        if ( p->frec->filter_init_func ) {
            if ( err =  p->frec->filter_init_func(f), err != OK ) {
                break ;        /* if anyone errors out here, so do we */
            }
        }
    }
    return err ;
}
static filter_func_t filter_lookup(request_rec* r, mod_filter_rec* filter)
{
    mod_filter_provider* provider ;
    const char* str ;
    char* str1 ;
    int match ;
    unsigned int proto_flags ;

    /* Check registered providers in order */
    for ( provider = filter->providers; provider; provider = provider->next) {
        match = 1 ;
        switch ( filter->dispatch ) {
            case REQUEST_HEADERS:
                str = apr_table_get(r->headers_in, filter->value) ;
                break ;
            case RESPONSE_HEADERS:
                str = apr_table_get(r->headers_out, filter->value) ;
                break ;
            case SUBPROCESS_ENV:
                str = apr_table_get(r->subprocess_env, filter->value) ;
                break ;
            case CONTENT_TYPE:
                str = r->content_type ;
                break ;
            case HANDLER:
                str = r->handler ;
                break ;
        }
        /* treat nulls so we don't have to check every strcmp individually
         * Not sure if there's anything better to do with them
         */
        if ( str == NULL ) {
            if ( provider->match_type == DEFINED ) {
                if ( provider->match.c != NULL ) {
                    match = 0 ;
                }
            }
        } else if ( provider->match.c == NULL ) {
            match = 0 ;
        } else {
            /* Now we have no nulls, so we can do string and regexp matching */
            switch ( provider->match_type ) {
                case STRING_MATCH:
                    if ( strcasecmp(str, provider->match.c) ) {
                        match = 0 ;
                    }
                    break ;
                case STRING_CONTAINS:
                    str1 = apr_pstrdup(r->pool, str) ;
                    ap_str_tolower(str1) ;
                    if ( !strstr(str1, provider->match.c) ) {
                        match = 0 ;
                    }
                    break ;
                case REGEX_MATCH:
                    if ( ap_regexec(provider->match.r, str, 0, NULL, 0)
                        == REG_NOMATCH ) {
                    match = 0 ;
                    }
                    break ;
                case INT_EQ:
                    if ( atoi(str) != provider->match.i ) {
                        match = 0 ;
                    }
                    break ;
                case INT_LT:
                    if ( atoi(str) < provider->match.i ) {
                        match = 0 ;
                    }
                    break ;
                case INT_GT:
                    if ( atoi(str) > provider->match.i ) {
                        match = 0 ;
                    }
                    break ;
                case DEFINED:        /* we already handled this:-) */
                    break ;
            }
        }
        if ( match != provider->not ) {
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
            proto_flags = filter->proto_flags | provider->proto_flags ;

            /* some specific things can't happen in a proxy */
            if ( r->proxyreq ) {
                if ( proto_flags & PROTO_NO_PROXY ) {
                    /* can't use this provider; try next */
                    continue ;
                }
                if ( proto_flags & PROTO_TRANSFORM ) {
                    str = apr_table_get(r->headers_out, "Cache-Control") ;
                    if ( str ) {
                        str1 = apr_pstrdup(r->pool, str) ;
                        ap_str_tolower(str1) ;
                        if ( strstr(str1, "no-transform") ) {
                            /* can't use this provider; try next */
                            continue ;
                        }
                    }
                    apr_table_addn(r->headers_out, "Warning", apr_psprintf(
                      r->pool, "214 %s Transformation applied", r->hostname) ) ;
                }
            }
            /* things that are invalidated if the filter transforms content */
            if ( proto_flags & PROTO_CHANGE ) {
                apr_table_unset(r->headers_out, "Content-MD5") ;
                apr_table_unset(r->headers_out, "ETag") ;
                if ( proto_flags & PROTO_CHANGE_LENGTH ) {
                    apr_table_unset(r->headers_out, "Content-Length") ;
                }
            }
            /* no-cache is for a filter that has different effect per-hit */
            if ( proto_flags & PROTO_NO_CACHE ) {
                apr_table_unset(r->headers_out, "Last-Modified") ;
                apr_table_addn(r->headers_out, "Cache-Control", "no-cache") ;
            }
            if ( proto_flags & PROTO_NO_BYTERANGE ) {
                apr_table_unset(r->headers_out, "Accept-Ranges") ;
            } else if ( filter->range ) {
                apr_table_setn(r->headers_in, "Range", filter->range) ;
            }
#endif
            return provider->frec->filter_func.out_func ;
        }
    }
    /* No provider matched */
    return NULL ;
}
static apr_status_t filter_harness(ap_filter_t* f, apr_bucket_brigade* bb)
{

    apr_status_t ret ;
    const char* cachecontrol ;
    char* str ;
    harness_ctx* ctx = f->ctx ;
    mod_filter_rec* filter = (mod_filter_rec*)f->frec ;

    if ( f->r->status != 200 ) {
        ap_remove_output_filter(f) ;
        return ap_pass_brigade(f->next, bb) ;
    }
    filter_trace(f->c->pool, filter->debug, ctx->name, bb) ;

/* look up a handler function if we haven't already set it */
    if ( ! ctx->func ) {

#ifndef NO_PROTOCOL
        if ( f->r->proxyreq ) {
            if ( filter->proto_flags & PROTO_NO_PROXY ) {
                ap_remove_output_filter(f) ;
                return ap_pass_brigade(f->next, bb) ;
            }
            if ( filter->proto_flags & PROTO_TRANSFORM ) {
                cachecontrol = apr_table_get(f->r->headers_out, "Cache-Control") ;
                if ( cachecontrol ) {
                    str = apr_pstrdup(f->r->pool,  cachecontrol) ;
                    ap_str_tolower(str) ;
                    if ( strstr(str, "no-transform") ) {
                        ap_remove_output_filter(f) ;
                        return ap_pass_brigade(f->next, bb) ;
                    }
                }
            }
        }
#endif
        ctx->func = filter_lookup(f->r, filter) ;
        if ( ! ctx->func ) {
            ap_remove_output_filter(f) ;
            return ap_pass_brigade(f->next, bb) ;
        }
    }

    /* call the content filter with its own context, then restore our context */
    f->ctx = ctx->fctx ;
    ret = ctx->func(f, bb) ;
    ctx->fctx = f->ctx ;
    f->ctx = ctx ;
    return ret ;
}

#ifndef NO_PROTOCOL
static const char* filter_protocol(cmd_parms* cmd, void* CFG,
        const char* fname, const char* pname, const char* proto)
{

    static const char* sep = " ;,	" ;
    char* arg ;
    char* tok = 0 ;
    unsigned int flags = 0 ;
    mod_filter_cfg* cfg = CFG ;
    mod_filter_provider* provider = NULL ;
    mod_filter_rec* filter
        = apr_hash_get(cfg->live_filters, fname, APR_HASH_KEY_STRING) ;

    if ( !provider ) {
        return "FilterProtocol: No such filter" ;
    }

    /* Fixup the args: it's really pname that's optional */
    if ( proto == NULL ) {
        proto = pname ;
        pname = NULL ;
    } else {
        /* Find provider */
        for ( provider = filter->providers; provider; provider = provider->next ) {
            if ( !strcasecmp(provider->frec->name, pname) )
                break ;
        }
        if ( !provider ) {
            return "FilterProtocol: No such provider for this filter" ;
        }
    }
    /* Now set flags from our args */
    for ( arg = apr_strtok(apr_pstrdup(cmd->pool, proto), sep, &tok) ;
        arg ; arg = apr_strtok(NULL, sep, &tok) ) {
        if ( !strcasecmp(arg, "change=yes") ) {
            flags != PROTO_CHANGE | PROTO_CHANGE_LENGTH ;
        } else if ( !strcasecmp(arg, "change=1:1") ) {
            flags |= PROTO_CHANGE ;
        } else if ( !strcasecmp(arg, "byteranges=no") ) {
            flags |= PROTO_NO_BYTERANGE ;
        } else if ( !strcasecmp(arg, "proxy=no") ) {
            flags |= PROTO_NO_PROXY ;
        } else if ( !strcasecmp(arg, "proxy=transform") ) {
            flags |= PROTO_TRANSFORM ;
        } else if ( !strcasecmp(arg, "cache=no") ) {
            flags |= PROTO_NO_CACHE ;
        }
    }
    if ( pname ) {
        provider->proto_flags = flags ;
    } else {
        filter->proto_flags = flags ;
    }
    return NULL ;
}
#endif

static const char* filter_declare(cmd_parms* cmd, void* CFG,
        const char* fname, const char* condition, const char* place)
{

    const char* eq ;
    char* tmpname = "" ;

    mod_filter_cfg* cfg = (mod_filter_cfg*)CFG ;
    mod_filter_rec* filter ;

    filter = apr_pcalloc(cmd->pool, sizeof(mod_filter_rec)) ;
    apr_hash_set(cfg->live_filters, fname, APR_HASH_KEY_STRING, filter) ;

    filter->frec.name = fname ;
    filter->frec.filter_init_func = filter_init ;
    filter->frec.filter_func.out_func = filter_harness ;
    filter->frec.ftype = AP_FTYPE_RESOURCE ;
    filter->frec.next = NULL ;

    /* determine what this filter will dispatch on */
    eq = strchr(condition, '=') ;
    if ( eq ) {
        tmpname = apr_pstrdup(cmd->pool, eq+1) ;
        if ( !strncasecmp(condition, "env=", 4) ) {
            filter->dispatch = SUBPROCESS_ENV ;
        } else if ( !strncasecmp(condition, "req=", 4) ) {
            filter->dispatch = REQUEST_HEADERS ;
        } else if ( !strncasecmp(condition, "resp=", 5) ) {
            filter->dispatch = RESPONSE_HEADERS ;
        } else {
            return "FilterCondition: unrecognised dispatch table" ;
        }
    } else {
        if ( !strcasecmp(condition, "handler") ) {
            filter->dispatch = HANDLER ;
        } else {
            filter->dispatch = RESPONSE_HEADERS ;
            tmpname = apr_pstrdup(cmd->pool, condition) ;
            ap_str_tolower(tmpname) ;
        }
    }
    if ( ( filter->dispatch == RESPONSE_HEADERS )
        && !strcmp(tmpname, "content-type") ) {
        filter->dispatch = CONTENT_TYPE ;
    }
    filter->value = tmpname ;

    if ( place ) {
        if ( !strcasecmp(place, "CONTENT_SET") ) {
            filter->frec.ftype = AP_FTYPE_CONTENT_SET ;
        } else if ( !strcasecmp(place, "PROTOCOL") ) {
            filter->frec.ftype = AP_FTYPE_PROTOCOL ;
        } else if ( !strcasecmp(place, "CONNECTION") ) {
            filter->frec.ftype = AP_FTYPE_CONNECTION ;
        } else if ( !strcasecmp(place, "NETWORK") ) {
            filter->frec.ftype = AP_FTYPE_NETWORK ;
        }
    }

    return NULL ;
}

static const char* filter_provider(cmd_parms* cmd, void* CFG,
        const char* fname, const char* pname, const char* match)
{
    int flags ;
    mod_filter_provider* provider ;
    const char* rxend ;
    const char* c ;
    char* str ;

    /* fname has been declared with DeclareFilter, so we can look it up */
    mod_filter_cfg* cfg = CFG ;
    mod_filter_rec* frec = apr_hash_get(cfg->live_filters, fname, APR_HASH_KEY_STRING) ;
    /* provider has been registered, so we can look it up */
    ap_filter_rec_t* provider_frec = ap_get_output_filter_handle(pname) ;
    if ( ! frec ) {
        return apr_psprintf(cmd->pool, "Undeclared smart filter %s", fname) ;
    } else if ( !provider_frec ) {
        return apr_psprintf(cmd->pool, "Unknown filter provider %s", pname) ;
    } else {
        provider = apr_palloc(cmd->pool, sizeof(mod_filter_provider) ) ;
        if ( match[0] == '!' ) {
            provider->not = 1 ;
            ++match ;
        }
        switch ( match[0] ) {
            case '<':
                provider->match_type = INT_LT ;
                provider->match.i = atoi(match+1) ;
                break ;
            case '>':
                provider->match_type = INT_GT ;
                provider->match.i = atoi(match+1) ;
                break ;
            case '=':
                provider->match_type = INT_EQ ;
                provider->match.i = atoi(match+1) ;
                break ;
            case '/':
                provider->match_type = REGEX_MATCH ;
                rxend = strchr(match+1, '/') ;
                if ( !rxend ) {
                      return "Bad regexp syntax" ;
                }
                flags = REG_NOSUB ;        /* we're not mod_rewrite:-) */
                for ( c = rxend+1; *c; ++c ) {
                    switch (*c) {
                        case 'i': flags |= REG_ICASE ; break ;
                        case 'x': flags |= REG_EXTENDED ; break ;
                    }
                }
                provider->match.r = ap_pregcomp(cmd->pool,
                apr_pstrndup(cmd->pool, match+1, rxend-match-1), flags) ;
                break ;
            case '*':
                provider->match_type = DEFINED ;
                provider->match.i = -1 ;
                break ;
            case '$':
                provider->match_type = STRING_CONTAINS ;
                str = apr_pstrdup(cmd->pool, match+1) ;
                ap_str_tolower(str) ;
                provider->match.c = str ;
                break ;
            default:
                provider->match_type = STRING_MATCH ;
                provider->match.c = apr_pstrdup(cmd->pool, match) ;
                break ;
        }
        provider->frec = provider_frec ;
        provider->next = frec->providers ;
        frec->providers = provider ;
    }
    return NULL ;
}
static const char* filter_chain(cmd_parms* cmd, void* CFG, const char* arg)
{
    mod_filter_chain* p ;
    mod_filter_chain* q ;
    mod_filter_cfg* cfg = CFG ;

    switch (arg[0]) {
        case '+':        /* add to end of chain */
            p = apr_pcalloc(cmd->pool, sizeof(mod_filter_chain)) ;
            p->fname = arg+1 ;
            if ( cfg->chain ) {
                for ( q = cfg->chain ; q->next ; q = q->next ) ;
                q->next = p ;
            } else {
                cfg->chain = p ;
            }
            break ;
        case '@':        /* add to start of chain */
            p = apr_palloc(cmd->pool, sizeof(mod_filter_chain)) ;
            p->fname = arg+1 ;
            p->next = cfg->chain ;
            cfg->chain = p ;
            break ;
        case '-':        /* remove from chain */
            if ( cfg->chain ) {
                if ( strcasecmp(cfg->chain->fname, arg+1) ) {
                    for ( p = cfg->chain ; p->next ; p = p->next ) {
                        if ( !strcasecmp(p->next->fname, arg+1) ) {
                            p->next = p->next->next ;
                        }
                    }
                } else {
                    cfg->chain = cfg->chain->next ;
                }
            }
            break ;
        case '!':        /* Empty the chain */
            cfg->chain = NULL ;
            break ;
        case '=':        /* initialise chain with this arg */
            p = apr_pcalloc(cmd->pool, sizeof(mod_filter_chain)) ;
            p->fname = arg+1 ;
            cfg->chain = p ;
            break ;
        default:        /* add to end */
            p = apr_pcalloc(cmd->pool, sizeof(mod_filter_chain)) ;
            p->fname = arg ;
            if ( cfg->chain ) {
                for ( q = cfg->chain ; q->next ; q = q->next ) ;
                q->next = p ;
            } else {
                cfg->chain = p ;
            }
            break ;
    }
    return NULL ;
}
static const char* filter_debug(cmd_parms* cmd, void* CFG,
        const char* fname, const char* level){
    mod_filter_cfg* cfg = CFG ;
    mod_filter_rec* frec = apr_hash_get(cfg->live_filters, fname,
        APR_HASH_KEY_STRING) ;
    frec->debug = atoi(level) ;
    return NULL ;
}

static const command_rec filter_cmds[] = {
    AP_INIT_TAKE23("FilterDeclare", filter_declare, NULL, OR_ALL,
        "filter-name, dispatch-criterion [, filter-type]") ,
    AP_INIT_TAKE3("FilterProvider", filter_provider, NULL, OR_ALL,
        "filter-name, provider-name, dispatch-match") ,
    AP_INIT_ITERATE("FilterChain", filter_chain, NULL, OR_ALL,
        "list of filter names with optional [+-=!@]") ,
    AP_INIT_TAKE2("FilterDebug", filter_debug, NULL, OR_ALL, "Debug level") ,
#ifndef NO_PROTOCOL
    AP_INIT_TAKE23("FilterProtocol", filter_protocol, NULL, OR_ALL,
        "filter-name [provider-name] protocol-args") ,
#endif
    { NULL }
} ;

static int filter_insert(request_rec* r)
{
    mod_filter_chain* p ;
    mod_filter_rec* filter ;
    harness_ctx* fctx ;
    mod_filter_cfg* cfg = ap_get_module_config(r->per_dir_config, &filter_module) ;
#ifndef NO_PROTOCOL
    int ranges = 1 ;
#endif

    for ( p = cfg->chain ; p ; p = p->next ) {
        filter = apr_hash_get(cfg->live_filters, p->fname, APR_HASH_KEY_STRING) ;
        fctx = apr_pcalloc(r->pool, sizeof(harness_ctx)) ;
        fctx->name = p->fname ;
        ap_add_output_filter_handle(&filter->frec, fctx, r, r->connection) ;
#ifndef NO_PROTOCOL
        if ( ranges && (filter->proto_flags & (PROTO_NO_BYTERANGE|PROTO_CHANGE_LENGTH)) ) {
            filter->range = apr_table_get(r->headers_in, "Range") ;
            apr_table_unset(r->headers_in, "Range") ;
            ranges = 0 ;
        }
#endif
    }
    return OK ;
}
static void filter_hooks(apr_pool_t* pool)
{
    ap_hook_insert_filter(filter_insert, NULL, NULL, APR_HOOK_MIDDLE) ;
}

static void* filter_config(apr_pool_t* pool, char* x)
{
    mod_filter_cfg* cfg = apr_palloc(pool, sizeof(mod_filter_cfg) ) ;
    cfg->live_filters = apr_hash_make(pool) ;
    cfg->chain = NULL ;
    return cfg ;
}
static void* filter_merge(apr_pool_t* pool, void* BASE, void* ADD)
{
    mod_filter_cfg* base = BASE ;
    mod_filter_cfg* add = ADD ;
    mod_filter_chain* savelink = 0 ;
    mod_filter_chain* newlink ;
    mod_filter_chain* p ;
    mod_filter_cfg* conf = apr_palloc(pool, sizeof(mod_filter_cfg)) ;

    conf->live_filters
        = apr_hash_overlay(pool, add->live_filters, base->live_filters) ;
    if ( base->chain && add->chain ) {
        for ( p = base->chain ; p ; p = p->next ) {
            newlink = apr_pmemdup(pool, p, sizeof(mod_filter_chain)) ;
            if ( savelink ) {
                savelink->next = newlink ;
                savelink = newlink ;
            } else {
                conf->chain = savelink = newlink ;
            }
        }
        for ( p = add->chain ; p ; p = p->next ) {
            newlink = apr_pmemdup(pool, p, sizeof(mod_filter_chain)) ;
            savelink->next = newlink ;
            savelink = newlink ;
        }
    } else if ( add->chain ) {
        conf->chain = add->chain ;
    } else {
        conf->chain = base->chain ;
    }
    return conf ;
}
module AP_MODULE_DECLARE_DATA filter_module = {
    STANDARD20_MODULE_STUFF,
    filter_config,
    filter_merge,
    NULL,
    NULL,
    filter_cmds,
    filter_hooks
} ;

