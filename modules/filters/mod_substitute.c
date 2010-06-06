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
 * mod_substitute.c: Perform content rewriting on the fly
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "apr_general.h"
#include "apr_strings.h"
#include "apr_strmatch.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

static const char substitute_filter_name[] = "SUBSTITUTE";

module AP_MODULE_DECLARE_DATA substitute_module;

typedef struct subst_pattern_t {
    const apr_strmatch_pattern *pattern;
    const ap_regex_t *regexp;
    const char *replacement;
    apr_size_t replen;
    apr_size_t patlen;
    int flatten;
} subst_pattern_t;

typedef struct {
    apr_array_header_t *patterns;
} subst_dir_conf;

typedef struct {
    apr_bucket_brigade *linebb;
    apr_bucket_brigade *linesbb;
    apr_bucket_brigade *passbb;
    apr_bucket_brigade *pattbb;
    apr_pool_t *tpool;
} substitute_module_ctx;

static void *create_substitute_dcfg(apr_pool_t *p, char *d)
{
    subst_dir_conf *dcfg =
    (subst_dir_conf *) apr_pcalloc(p, sizeof(subst_dir_conf));

    dcfg->patterns = apr_array_make(p, 10, sizeof(subst_pattern_t));
    return dcfg;
}

static void *merge_substitute_dcfg(apr_pool_t *p, void *basev, void *overv)
{
    subst_dir_conf *a =
    (subst_dir_conf *) apr_pcalloc(p, sizeof(subst_dir_conf));
    subst_dir_conf *base = (subst_dir_conf *) basev;
    subst_dir_conf *over = (subst_dir_conf *) overv;

    a->patterns = apr_array_append(p, over->patterns,
                                                  base->patterns);
    return a;
}

#define AP_MAX_BUCKETS 1000

#define SEDSCAT(s1, s2, pool, buff, blen, repl) do { \
    if (!s1) {                                       \
        s1 = apr_pstrmemdup(pool, buff, blen);       \
    }                                                \
    else {                                           \
        s2 = apr_pstrmemdup(pool, buff, blen);       \
        s1 = apr_pstrcat(pool, s1, s2, NULL);        \
    }                                                \
    s1 = apr_pstrcat(pool, s1, repl, NULL);          \
} while (0)

#define SEDRMPATBCKT(b, offset, tmp_b, patlen) do {  \
    apr_bucket_split(b, offset);                     \
    tmp_b = APR_BUCKET_NEXT(b);                      \
    apr_bucket_split(tmp_b, patlen);                 \
    b = APR_BUCKET_NEXT(tmp_b);                      \
    apr_bucket_delete(tmp_b);                        \
} while (0)

static void do_pattmatch(ap_filter_t *f, apr_bucket *inb,
                         apr_bucket_brigade *mybb,
                         apr_pool_t *tmp_pool)
{
    int i;
    int force_quick = 0;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];
    apr_size_t bytes;
    apr_size_t len;
    apr_size_t fbytes;
    const char *buff;
    const char *repl;
    char *scratch;
    char *p;
    char *s1;
    char *s2;
    apr_bucket *b;
    apr_bucket *tmp_b;
    apr_pool_t *tpool;

    subst_dir_conf *cfg =
    (subst_dir_conf *) ap_get_module_config(f->r->per_dir_config,
                                             &substitute_module);
    subst_pattern_t *script;

    APR_BRIGADE_INSERT_TAIL(mybb, inb);
    
    script = (subst_pattern_t *) cfg->patterns->elts;
    apr_pool_create(&tpool, tmp_pool);
    scratch = NULL;
    fbytes = 0;
    /*
     * Simple optimization. If we only have one pattern, then
     * we can safely avoid the overhead of flattening
     */
    if (cfg->patterns->nelts == 1) {
       force_quick = 1;
    }
    for (i = 0; i < cfg->patterns->nelts; i++) {
        for (b = APR_BRIGADE_FIRST(mybb);
             b != APR_BRIGADE_SENTINEL(mybb);
             b = APR_BUCKET_NEXT(b)) {
            if (APR_BUCKET_IS_METADATA(b)) {
                /*
                 * we should NEVER see this, because we should never
                 * be passed any, but "handle" it just in case.
                 */
                continue;
            }
            if (apr_bucket_read(b, &buff, &bytes, APR_BLOCK_READ)
                    == APR_SUCCESS) {
                s1 = NULL;
                if (script->pattern) {
                    while ((repl = apr_strmatch(script->pattern, buff, bytes)))
                    {
                        /* get offset into buff for pattern */
                        len = (apr_size_t) (repl - buff);
                        if (script->flatten && !force_quick) {
                            /*
                             * We are flattening the buckets here, meaning
                             * that we don't do the fast bucket splits.
                             * Instead we copy over what the buckets would
                             * contain and use them. This is slow, since we
                             * are constanting allocing space and copying
                             * strings.
                             */
                            SEDSCAT(s1, s2, tmp_pool, buff, len,
                                    script->replacement);
                        }
                        else {
                            /*
                             * We now split off the stuff before the regex
                             * as its own bucket, then isolate the pattern
                             * and delete it.
                             */
                            SEDRMPATBCKT(b, len, tmp_b, script->patlen);
                            /*
                             * Finally, we create a bucket that contains the
                             * replacement...
                             */
                            tmp_b = apr_bucket_transient_create(script->replacement,
                                      script->replen,
                                      f->r->connection->bucket_alloc);
                            /* ... and insert it */
                            APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        }
                        /* now we need to adjust buff for all these changes */
                        len += script->patlen;
                        bytes -= len;
                        buff += len;
                    }
                    if (script->flatten && s1 && !force_quick) {
                        /*
                         * we've finished looking at the bucket, so remove the
                         * old one and add in our new one
                         */
                        s2 = apr_pstrmemdup(tmp_pool, buff, bytes);
                        s1 = apr_pstrcat(tmp_pool, s1, s2, NULL);
                        tmp_b = apr_bucket_transient_create(s1, strlen(s1),
                                            f->r->connection->bucket_alloc);
                        APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        apr_bucket_delete(b);
                        b = tmp_b;
                    }

                }
                else if (script->regexp) {
                    /*
                     * we need a null terminated string here :(. To hopefully
                     * save time and memory, we don't alloc for each run
                     * through, but only if we need to have a larger chunk
                     * to save the string to. So we keep track of how much
                     * we've allocated and only re-alloc when we need it.
                     * NOTE: this screams for a macro.
                     */
                    if (!scratch || (bytes > (fbytes + 1))) {
                        fbytes = bytes + 1;
                        scratch = apr_palloc(tpool, fbytes);
                    }
                    /* reset pointer to the scratch space */
                    p = scratch;
                    memcpy(p, buff, bytes);
                    p[bytes] = '\0';
                    while (!ap_regexec(script->regexp, p,
                                       AP_MAX_REG_MATCH, regm, 0)) {
                        /* first, grab the replacement string */
                        repl = ap_pregsub(tmp_pool, script->replacement, p,
                                          AP_MAX_REG_MATCH, regm);
                        if (script->flatten && !force_quick) {
                            SEDSCAT(s1, s2, tmp_pool, p, regm[0].rm_so, repl);
                        }
                        else {
                            len = (apr_size_t) (regm[0].rm_eo - regm[0].rm_so);
                            SEDRMPATBCKT(b, regm[0].rm_so, tmp_b, len);
                            tmp_b = apr_bucket_transient_create(repl,
                                                                strlen(repl),
                                             f->r->connection->bucket_alloc);
                            APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        }
                        /*
                         * reset to past what we just did. buff now maps to b
                         * again
                         */
                        p += regm[0].rm_eo;
                    }
                    if (script->flatten && s1 && !force_quick) {
                        s1 = apr_pstrcat(tmp_pool, s1, p, NULL);
                        tmp_b = apr_bucket_transient_create(s1, strlen(s1),
                                            f->r->connection->bucket_alloc);
                        APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        apr_bucket_delete(b);
                        b = tmp_b;
                    }

                }
                else {
                    /* huh? */
                    continue;
                }
            }
        }
        script++;
    }

    apr_pool_destroy(tpool);

    return;
}

static apr_status_t substitute_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_size_t bytes;
    apr_size_t len;
    apr_size_t fbytes;
    const char *buff;
    const char *nl = NULL;
    char *bflat;
    apr_bucket *b;
    apr_bucket *tmp_b;
    apr_bucket_brigade *tmp_bb = NULL;
    apr_status_t rv;

    substitute_module_ctx *ctx = f->ctx;
    
    /*
     * First time around? Create the saved bb that we used for each pass
     * through. Note that we can also get here when we explicitly clear ctx,
     * for error handling
     */
    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        /*
         * Create all the temporary brigades we need and reuse them to avoid
         * creating them over and over again from r->pool which would cost a
         * lot of memory in some cases.
         */
        ctx->linebb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        ctx->linesbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        ctx->pattbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        /*
         * Everything to be passed to the next filter goes in
         * here, our pass brigade.
         */
        ctx->passbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        /* Create our temporary pool only once */
        apr_pool_create(&(ctx->tpool), f->r->pool);
        apr_table_unset(f->r->headers_out, "Content-Length");
    }

    /*
     * Shortcircuit processing
     */
    if (APR_BRIGADE_EMPTY(bb))
        return APR_SUCCESS;

    /*
     * Here's the concept:
     *  Read in the data and look for newlines. Once we
     *  find a full "line", add it to our working brigade.
     *  If we've finished reading the brigade and we have
     *  any left over data (not a "full" line), store that
     *  for the next pass.
     *
     * Note: anything stored in ctx->linebb for sure does not have
     * a newline char, so we don't concat that bb with the
     * new bb, since we would spending time searching for the newline
     * in data we know it doesn't exist. So instead, we simply scan
     * our current bb and, if we see a newline, prepend ctx->linebb
     * to the front of it. This makes the code much less straight-
     * forward (otherwise we could APR_BRIGADE_CONCAT(ctx->linebb, bb)
     * and just scan for newlines and not bother with needing to know
     * when ctx->linebb needs to be reset) but also faster. We'll take
     * the speed.
     *
     * Note: apr_brigade_split_line would be nice here, but we
     * really can't use it since we need more control and we want
     * to re-use already read bucket data.
     *
     * See mod_include if still confused :)
     */

    while ((b = APR_BRIGADE_FIRST(bb)) && (b != APR_BRIGADE_SENTINEL(bb))) {
        if (APR_BUCKET_IS_EOS(b)) {
            /*
             * if we see the EOS, then we need to pass along everything we
             * have. But if the ctx->linebb isn't empty, then we need to add
             * that to the end of what we'll be passing.
             */
            if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
                rv = apr_brigade_pflatten(ctx->linebb, &bflat,
                                          &fbytes, ctx->tpool);
                tmp_b = apr_bucket_transient_create(bflat, fbytes,
                                                f->r->connection->bucket_alloc);
                do_pattmatch(f, tmp_b, ctx->pattbb, ctx->tpool);
                APR_BRIGADE_CONCAT(ctx->passbb, ctx->pattbb);
            }
            apr_brigade_cleanup(ctx->linebb);
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
        }
        /*
         * No need to handle FLUSH buckets separately as we call
         * ap_pass_brigade anyway at the end of the loop.
         */
        else if (APR_BUCKET_IS_METADATA(b)) {
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
        }
        else {
            /*
             * We have actual "data" so read in as much as we can and start
             * scanning and splitting from our read buffer
             */
            rv = apr_bucket_read(b, &buff, &bytes, APR_BLOCK_READ);
            if (rv != APR_SUCCESS || bytes == 0) {
                apr_bucket_delete(b);
            }
            else {
                int num = 0;
                while (bytes > 0) {
                    nl = memchr(buff, APR_ASCII_LF, bytes);
                    if (nl) {
                        len = (apr_size_t) (nl - buff) + 1;
                        /* split *after* the newline */
                        apr_bucket_split(b, len);
                        /*
                         * We've likely read more data, so bypass rereading
                         * bucket data and continue scanning through this
                         * buffer
                         */
                        bytes -= len;
                        buff += len;
                        /*
                         * we need b to be updated for future potential
                         * splitting
                         */
                        tmp_b = APR_BUCKET_NEXT(b);
                        APR_BUCKET_REMOVE(b);
                        /*
                         * Hey, we found a newline! Don't forget the old
                         * stuff that needs to be added to the front. So we
                         * add the split bucket to the end, flatten the whole
                         * bb, morph the whole shebang into a bucket which is
                         * then added to the tail of the newline bb.
                         */
                        if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
                            APR_BRIGADE_INSERT_TAIL(ctx->linebb, b);
                            rv = apr_brigade_pflatten(ctx->linebb, &bflat,
                                                      &fbytes, ctx->tpool);
                            b = apr_bucket_transient_create(bflat, fbytes,
                                            f->r->connection->bucket_alloc);
                            apr_brigade_cleanup(ctx->linebb);
                        }
                        do_pattmatch(f, b, ctx->pattbb, ctx->tpool);
                        /*
                         * Count how many buckets we have in ctx->passbb
                         * so far. Yes, this is correct we count ctx->passbb
                         * and not ctx->pattbb as we do not reset num on every
                         * iteration.
                         */
                        for (b = APR_BRIGADE_FIRST(ctx->pattbb);
                             b != APR_BRIGADE_SENTINEL(ctx->pattbb);
                             b = APR_BUCKET_NEXT(b)) {
                            num++;
                        }
                        APR_BRIGADE_CONCAT(ctx->passbb, ctx->pattbb);
                        /*
                         * If the number of buckets in ctx->passbb reaches an
                         * "insane" level, we consume much memory for all the
                         * buckets as such. So lets flush them down the chain
                         * in this case and thus clear ctx->passbb. This frees
                         * the buckets memory for further processing.
                         * Usually this condition should not become true, but
                         * it is a safety measure for edge cases.
                         */
                        if (num > AP_MAX_BUCKETS) {
                            b = apr_bucket_flush_create(
                                                f->r->connection->bucket_alloc);
                            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
                            rv = ap_pass_brigade(f->next, ctx->passbb);
                            apr_brigade_cleanup(ctx->passbb);
                            num = 0;
                            apr_pool_clear(ctx->tpool);
                            if (rv != APR_SUCCESS)
                                return rv;
                        }
                        b = tmp_b;
                    }
                    else {
                        /*
                         * no newline in whatever is left of this buffer so
                         * tuck data away and get next bucket
                         */
                        APR_BUCKET_REMOVE(b);
                        APR_BRIGADE_INSERT_TAIL(ctx->linebb, b);
                        bytes = 0;
                    }
                }
            }
        }
        if (!APR_BRIGADE_EMPTY(ctx->passbb)) {
            rv = ap_pass_brigade(f->next, ctx->passbb);
            apr_brigade_cleanup(ctx->passbb);
            if (rv != APR_SUCCESS) {
                apr_pool_clear(ctx->tpool);
                return rv;
            }
        }
        apr_pool_clear(ctx->tpool);
    }

    /* Anything left we want to save/setaside for the next go-around */
    if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
        /*
         * Provide ap_save_brigade with an existing empty brigade
         * (ctx->linesbb) to avoid creating a new one.
         */
        ap_save_brigade(f, &(ctx->linesbb), &(ctx->linebb), f->r->pool);
        tmp_bb = ctx->linebb;
        ctx->linebb = ctx->linesbb;
        ctx->linesbb = tmp_bb;
    }

    return APR_SUCCESS;
}

static const char *set_pattern(cmd_parms *cmd, void *cfg, const char *line)
{
    char *from = NULL;
    char *to = NULL;
    char *flags = NULL;
    char *ourline;
    char delim;
    subst_pattern_t *nscript;
    int is_pattern = 0;
    int ignore_case = 0;
    int flatten = 1;
    ap_regex_t *r = NULL;

    if (apr_tolower(*line) != 's') {
        return "Bad Substitute format, must be an s/// pattern";
    }
    ourline = apr_pstrdup(cmd->pool, line);
    delim = *++ourline;
    if (delim)
        from = ++ourline;
    if (from) {
        if (*ourline != delim) {
            while (*++ourline && *ourline != delim);
        }
        if (*ourline) {
            *ourline = '\0';
            to = ++ourline;
        }
    }
    if (to) {
        if (*ourline != delim) {
            while (*++ourline && *ourline != delim);
        }
        if (*ourline) {
            *ourline = '\0';
            flags = ++ourline;
        }
    }

    if (!delim || !from || !*from || !to) {
        return "Bad Substitute format, must be a complete s/// pattern";
    }

    if (flags) {
        while (*flags) {
            delim = apr_tolower(*flags);    /* re-use */
            if (delim == 'i')
                ignore_case = 1;
            else if (delim == 'n')
                is_pattern = 1;
            else if (delim == 'f')
                flatten = 1;
            else if (delim == 'q')
                flatten = 0;
            else
                return "Bad Substitute flag, only s///[infq] are supported";
            flags++;
        }
    }

    /* first see if we can compile the regex */
    if (!is_pattern) {
        r = ap_pregcomp(cmd->pool, from, AP_REG_EXTENDED |
                        (ignore_case ? AP_REG_ICASE : 0));
        if (!r)
            return "Substitute could not compile regex";
    }
    nscript = apr_array_push(((subst_dir_conf *) cfg)->patterns);
    /* init the new entries */
    nscript->pattern = NULL;
    nscript->regexp = NULL;
    nscript->replacement = NULL;
    nscript->patlen = 0;

    if (is_pattern) {
        nscript->patlen = strlen(from);
        nscript->pattern = apr_strmatch_precompile(cmd->pool, from, 
                                                   !ignore_case);
    }
    else {
        nscript->regexp = r;
    }

    nscript->replacement = to;
    nscript->replen = strlen(to);
    nscript->flatten = flatten;

    return NULL;
}

#define PROTO_FLAGS AP_FILTER_PROTO_CHANGE|AP_FILTER_PROTO_CHANGE_LENGTH
static void register_hooks(apr_pool_t *pool)
{
    ap_register_output_filter(substitute_filter_name, substitute_filter,
                              NULL, AP_FTYPE_RESOURCE);
}

static const command_rec substitute_cmds[] = {
    AP_INIT_TAKE1("Substitute", set_pattern, NULL, OR_ALL,
                  "Pattern to filter the response content (s/foo/bar/[inf])"),
    {NULL}
};

AP_DECLARE_MODULE(substitute) = {
    STANDARD20_MODULE_STUFF,
    create_substitute_dcfg,     /* dir config creater */
    merge_substitute_dcfg,      /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    substitute_cmds,            /* command table */
    register_hooks              /* register hooks */
};
