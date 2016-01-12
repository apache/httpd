/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stdio.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_hash.h>
#include <apr_time.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2_h2.h"
#include "h2_util.h"
#include "h2_push.h"
#include "h2_request.h"
#include "h2_response.h"
#include "h2_session.h"
#include "h2_stream.h"

/*******************************************************************************
 * link header handling 
 ******************************************************************************/

static const char *policy_str(h2_push_policy policy)
{
    switch (policy) {
        case H2_PUSH_NONE:
            return "none";
        case H2_PUSH_FAST_LOAD:
            return "fast-load";
        case H2_PUSH_HEAD:
            return "head";
        default:
            return "default";
    }
}

typedef struct {
    const h2_request *req;
    apr_pool_t *pool;
    apr_array_header_t *pushes;
    const char *s;
    size_t slen;
    size_t i;
    
    const char *link;
    apr_table_t *params;
    char b[4096];
} link_ctx;

static int attr_char(char c) 
{
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '&':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return 1;
        default:
            return apr_isalnum(c);
    }
}

static int ptoken_char(char c) 
{
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '&':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case '-':
        case '.':
        case '/':
        case ':':
        case '<':
        case '=':
        case '>':
        case '?':
        case '@':
        case '[':
        case ']':
        case '^':
        case '_':
        case '`':
        case '{':
        case '|':
        case '}':
        case '~':
            return 1;
        default:
            return apr_isalnum(c);
    }
}

static int skip_ws(link_ctx *ctx)
{
    char c;
    while (ctx->i < ctx->slen 
           && (((c = ctx->s[ctx->i]) == ' ') || (c == '\t'))) {
        ++ctx->i;
    }
    return (ctx->i < ctx->slen);
}

static int find_chr(link_ctx *ctx, char c, size_t *pidx)
{
    size_t j;
    for (j = ctx->i; j < ctx->slen; ++j) {
        if (ctx->s[j] == c) {
            *pidx = j;
            return 1;
        }
    } 
    return 0;
}

static int read_chr(link_ctx *ctx, char c)
{
    if (ctx->i < ctx->slen && ctx->s[ctx->i] == c) {
        ++ctx->i;
        return 1;
    }
    return 0;
}

static char *mk_str(link_ctx *ctx, size_t end) 
{
    if (ctx->i < end) {
        return apr_pstrndup(ctx->pool, ctx->s + ctx->i, end - ctx->i);
    }
    return "";
}

static int read_qstring(link_ctx *ctx, char **ps)
{
    if (skip_ws(ctx) && read_chr(ctx, '\"')) {
        size_t end;
        if (find_chr(ctx, '\"', &end)) {
            *ps = mk_str(ctx, end);
            ctx->i = end + 1;
            return 1;
        }
    }
    return 0;
}

static int read_ptoken(link_ctx *ctx, char **ps)
{
    if (skip_ws(ctx)) {
        size_t i;
        for (i = ctx->i; i < ctx->slen && ptoken_char(ctx->s[i]); ++i) {
            /* nop */
        }
        if (i > ctx->i) {
            *ps = mk_str(ctx, i);
            ctx->i = i;
            return 1;
        }
    }
    return 0;
}


static int read_link(link_ctx *ctx)
{
    if (skip_ws(ctx) && read_chr(ctx, '<')) {
        size_t end;
        if (find_chr(ctx, '>', &end)) {
            ctx->link = mk_str(ctx, end);
            ctx->i = end + 1;
            return 1;
        }
    }
    return 0;
}

static int read_pname(link_ctx *ctx, char **pname)
{
    if (skip_ws(ctx)) {
        size_t i;
        for (i = ctx->i; i < ctx->slen && attr_char(ctx->s[i]); ++i) {
            /* nop */
        }
        if (i > ctx->i) {
            *pname = mk_str(ctx, i);
            ctx->i = i;
            return 1;
        }
    }
    return 0;
}

static int read_pvalue(link_ctx *ctx, char **pvalue)
{
    if (skip_ws(ctx) && read_chr(ctx, '=')) {
        if (read_qstring(ctx, pvalue) || read_ptoken(ctx, pvalue)) {
            return 1;
        }
    }
    return 0;
}

static int read_param(link_ctx *ctx)
{
    if (skip_ws(ctx) && read_chr(ctx, ';')) {
        char *name, *value = "";
        if (read_pname(ctx, &name)) {
            read_pvalue(ctx, &value); /* value is optional */
            apr_table_setn(ctx->params, name, value);
            return 1;
        }
    }
    return 0;
}

static int read_sep(link_ctx *ctx)
{
    if (skip_ws(ctx) && read_chr(ctx, ',')) {
        return 1;
    }
    return 0;
}

static void init_params(link_ctx *ctx) 
{
    if (!ctx->params) {
        ctx->params = apr_table_make(ctx->pool, 5);
    }
    else {
        apr_table_clear(ctx->params);
    }
}

static int same_authority(const h2_request *req, const apr_uri_t *uri)
{
    if (uri->scheme != NULL && strcmp(uri->scheme, req->scheme)) {
        return 0;
    }
    if (uri->hostinfo != NULL && strcmp(uri->hostinfo, req->authority)) {
        return 0;
    }
    return 1;
}

static int set_header(void *ctx, const char *key, const char *value) 
{
    apr_table_setn(ctx, key, value);
    return 1;
}


static int add_push(link_ctx *ctx)
{
    /* so, we have read a Link header and need to decide
     * if we transform it into a push.
     */
    const char *rel = apr_table_get(ctx->params, "rel");
    if (rel && !strcmp("preload", rel)) {
        apr_uri_t uri;
        if (apr_uri_parse(ctx->pool, ctx->link, &uri) == APR_SUCCESS) {
            if (uri.path && same_authority(ctx->req, &uri)) {
                char *path;
                const char *method;
                apr_table_t *headers;
                h2_request *req;
                h2_push *push;
                
                /* We only want to generate pushes for resources in the
                 * same authority than the original request.
                 * icing: i think that is wise, otherwise we really need to
                 * check that the vhost/server is available and uses the same
                 * TLS (if any) parameters.
                 */
                path = apr_uri_unparse(ctx->pool, &uri, APR_URI_UNP_OMITSITEPART);
                
                push = apr_pcalloc(ctx->pool, sizeof(*push));
                
                switch (ctx->req->push_policy) {
                    case H2_PUSH_HEAD:
                        method = "HEAD";
                        break;
                    default:
                        method = "GET";
                        break;
                }
                headers = apr_table_make(ctx->pool, 5);
                apr_table_do(set_header, headers, ctx->req->headers,
                             "User-Agent",
                             "Cache-Control",
                             "Accept-Language",
                             NULL);
                req = h2_request_createn(0, ctx->pool, ctx->req->config, 
                                         method, ctx->req->scheme,
                                         ctx->req->authority, 
                                         path, headers);
                /* atm, we do not push on pushes */
                h2_request_end_headers(req, ctx->pool, 1, 0);
                push->req = req;
                
                if (!ctx->pushes) {
                    ctx->pushes = apr_array_make(ctx->pool, 5, sizeof(h2_push*));
                }
                APR_ARRAY_PUSH(ctx->pushes, h2_push*) = push;
            }
        }
    }
    return 0;
}

static void inspect_link(link_ctx *ctx, const char *s, size_t slen)
{
    /* RFC 5988 <https://tools.ietf.org/html/rfc5988#section-6.2.1>
      Link           = "Link" ":" #link-value
      link-value     = "<" URI-Reference ">" *( ";" link-param )
      link-param     = ( ( "rel" "=" relation-types )
                     | ( "anchor" "=" <"> URI-Reference <"> )
                     | ( "rev" "=" relation-types )
                     | ( "hreflang" "=" Language-Tag )
                     | ( "media" "=" ( MediaDesc | ( <"> MediaDesc <"> ) ) )
                     | ( "title" "=" quoted-string )
                     | ( "title*" "=" ext-value )
                     | ( "type" "=" ( media-type | quoted-mt ) )
                     | ( link-extension ) )
      link-extension = ( parmname [ "=" ( ptoken | quoted-string ) ] )
                     | ( ext-name-star "=" ext-value )
      ext-name-star  = parmname "*" ; reserved for RFC2231-profiled
                                    ; extensions.  Whitespace NOT
                                    ; allowed in between.
      ptoken         = 1*ptokenchar
      ptokenchar     = "!" | "#" | "$" | "%" | "&" | "'" | "("
                     | ")" | "*" | "+" | "-" | "." | "/" | DIGIT
                     | ":" | "<" | "=" | ">" | "?" | "@" | ALPHA
                     | "[" | "]" | "^" | "_" | "`" | "{" | "|"
                     | "}" | "~"
      media-type     = type-name "/" subtype-name
      quoted-mt      = <"> media-type <">
      relation-types = relation-type
                     | <"> relation-type *( 1*SP relation-type ) <">
      relation-type  = reg-rel-type | ext-rel-type
      reg-rel-type   = LOALPHA *( LOALPHA | DIGIT | "." | "-" )
      ext-rel-type   = URI
      
      and from <https://tools.ietf.org/html/rfc5987>
      parmname      = 1*attr-char
      attr-char     = ALPHA / DIGIT
                       / "!" / "#" / "$" / "&" / "+" / "-" / "."
                       / "^" / "_" / "`" / "|" / "~"
     */

     ctx->s = s;
     ctx->slen = slen;
     ctx->i = 0;
     
     while (read_link(ctx)) {
        init_params(ctx);
        while (read_param(ctx)) {
            /* nop */
        }
        add_push(ctx);
        if (!read_sep(ctx)) {
            break;
        }
     }
}

static int head_iter(void *ctx, const char *key, const char *value) 
{
    if (!apr_strnatcasecmp("link", key)) {
        inspect_link(ctx, value, strlen(value));
    }
    return 1;
}

apr_array_header_t *h2_push_collect(apr_pool_t *p, const h2_request *req, 
                                    const h2_response *res)
{
    if (req && req->push_policy != H2_PUSH_NONE) {
        /* Collect push candidates from the request/response pair.
         * 
         * One source for pushes are "rel=preload" link headers
         * in the response.
         * 
         * TODO: This may be extended in the future by hooks or callbacks
         * where other modules can provide push information directly.
         */
        if (res->headers) {
            link_ctx ctx;
            
            memset(&ctx, 0, sizeof(ctx));
            ctx.req = req;
            ctx.pool = p;
            
            apr_table_do(head_iter, &ctx, res->headers, NULL);
            if (ctx.pushes) {
                apr_table_setn(res->headers, "push-policy", policy_str(req->push_policy));
            }
            return ctx.pushes;
        }
    }
    return NULL;
}

void h2_push_policy_determine(struct h2_request *req, apr_pool_t *p, int push_enabled)
{
    h2_push_policy policy = H2_PUSH_NONE;
    if (push_enabled) {
        const char *val = apr_table_get(req->headers, "accept-push-policy");
        if (val) {
            if (ap_find_token(p, val, "fast-load")) {
                policy = H2_PUSH_FAST_LOAD;
            }
            else if (ap_find_token(p, val, "head")) {
                policy = H2_PUSH_HEAD;
            }
            else if (ap_find_token(p, val, "default")) {
                policy = H2_PUSH_DEFAULT;
            }
            else if (ap_find_token(p, val, "none")) {
                policy = H2_PUSH_NONE;
            }
            else {
                /* nothing known found in this header, go by default */
                policy = H2_PUSH_DEFAULT;
            }
        }
        else {
            policy = H2_PUSH_DEFAULT;
        }
    }
    req->push_policy = policy;
}

/*******************************************************************************
 * push diary 
 ******************************************************************************/
 
struct h2_push_digest {
    union {
        uint32_t hash;
    } val;
};

typedef struct h2_push_diary_entry {
    h2_push_digest digest;
} h2_push_diary_entry;


static uint32_t val_apr_hash(const char *str) 
{
    apr_ssize_t len = strlen(str);
    return apr_hashfunc_default(str, &len);
}

static void calc_apr_hash(h2_push_diary *diary, h2_push_digest *d, h2_push *push) 
{
    unsigned int val;
    
    val = val_apr_hash(push->req->scheme);
    val ^= val_apr_hash(push->req->authority);
    val ^= val_apr_hash(push->req->path);
    
    d->val.hash = val % (diary->N * diary->P);
}

static int cmp_hash(h2_push_digest *d1, h2_push_digest *d2) 
{
    return (d1->val.hash > d2->val.hash)? 1 : ((d1->val.hash == d2->val.hash)? 0 : -1);
}

static uint32_t ceil_power_of_2(uint32_t n)
{
    --n;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return ++n;
}

h2_push_diary *h2_push_diary_create(apr_pool_t *p, uint32_t N, uint32_t P)
{
    h2_push_diary *diary = NULL;
    
    if (N > 0) {
        diary = apr_pcalloc(p, sizeof(*diary));
        
        diary->N           = ceil_power_of_2(N);
        diary->P           = ceil_power_of_2(P? P : ((1<<31)/diary->N));
        diary->entries     = apr_array_make(p, 16, sizeof(void*));
        diary->dtype       = H2_PUSH_DIGEST_APR_HASH;
        diary->dcalc       = calc_apr_hash;
        diary->dcmp        = cmp_hash;
    }
    
    return diary;
}

static int h2_push_diary_find(h2_push_diary *diary, h2_push_digest *d)
{
    if (diary) {
        h2_push_diary_entry *e;
        int i;
        /* search from the end, where the last accessed digests are */
        for (i = diary->entries->nelts-1; i >= 0; --i) {
            e = APR_ARRAY_IDX(diary->entries, i, h2_push_diary_entry*);
            if (!diary->dcmp(&e->digest, d)) {
                return i;
            }
        }
    }
    return -1;
}

static h2_push_diary_entry *move_to_last(h2_push_diary *diary, apr_size_t idx)
{
    h2_push_diary_entry **entries = (h2_push_diary_entry**)diary->entries->elts;
    h2_push_diary_entry *e = entries[idx];
    /* move entry[idx] to the end */
    if (idx < (diary->entries->nelts-1)) {
        memmove(entries+idx, entries+idx+1, sizeof(h2_push_diary_entry *) * diary->entries->nelts-idx-1);
        entries[diary->entries->nelts-1] = e;
    }
    return e;
}

static h2_push_diary_entry *h2_push_diary_append(h2_push_diary *diary, h2_push_digest *digest)
{
    h2_push_diary_entry *e;
    
    if (diary->entries->nelts < diary->N) {
        /* append a new diary entry at the end */
        e = apr_pcalloc(diary->entries->pool, sizeof(*e));
        APR_ARRAY_PUSH(diary->entries, h2_push_diary_entry*) = e;
    }
    else {
        e = move_to_last(diary, 0);
    }
    /* replace content with new digest. keeps memory usage constant once diary is full */
    memcpy(&e->digest, digest, sizeof(*digest));
    return e;
}

apr_array_header_t *h2_push_diary_update(h2_session *session, apr_array_header_t *pushes)
{
    apr_array_header_t *npushes = pushes;
    h2_push_digest d;
    int i, idx;
    
    if (session->push_diary && pushes) {
        npushes = NULL;
        
        for (i = 0; i < pushes->nelts; ++i) {
            h2_push *push;
            
            push = APR_ARRAY_IDX(pushes, i, h2_push*);
            session->push_diary->dcalc(session->push_diary, &d, push);
            idx = h2_push_diary_find(session->push_diary, &d);
            if (idx >= 0) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                              "push_diary_update: already there PUSH %s", push->req->path);
                move_to_last(session->push_diary, idx);
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                              "push_diary_update: adding PUSH %s", push->req->path);
                if (!npushes) {
                    npushes = apr_array_make(pushes->pool, 5, sizeof(h2_push_diary_entry*));
                }
                APR_ARRAY_PUSH(npushes, h2_push*) = push;
                h2_push_diary_append(session->push_diary, &d);
            }
        }
    }
    return npushes;
}
    
apr_array_header_t *h2_push_collect_update(h2_stream *stream, 
                                           const struct h2_request *req, 
                                           const struct h2_response *res)
{
    apr_array_header_t *pushes = h2_push_collect(stream->pool, req, res);
    return h2_push_diary_update(stream->session, pushes);
}

