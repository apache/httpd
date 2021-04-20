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
#include "http_log.h"
#include "apr_general.h"
#include "apr_strings.h"
#include "apr_strmatch.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "util_varbuf.h"
#include "apr_buckets.h"
#include "http_request.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

/*
 * We want to limit the memory usage in a way that is predictable.
 * Therefore we limit the resulting length of the line.
 * This is the default value.
 */
#define AP_SUBST_MAX_LINE_LENGTH (1024*1024)

static const char substitute_filter_name[] = "SUBSTITUTE";

module AP_MODULE_DECLARE_DATA substitute_module;

typedef struct subst_pattern_t {
    const apr_strmatch_pattern *pattern;
    const ap_regex_t *regexp;
    const char *replacement;
    apr_size_t replen;
    apr_size_t patlen;
    int flatten;
    const char *from;
} subst_pattern_t;

typedef struct {
    apr_array_header_t *patterns;
    apr_size_t max_line_length;
    int max_line_length_set;
    int inherit_before;
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
        (subst_dir_conf *) apr_palloc(p, sizeof(subst_dir_conf));

    dcfg->patterns = apr_array_make(p, 10, sizeof(subst_pattern_t));
    dcfg->max_line_length = AP_SUBST_MAX_LINE_LENGTH;
    dcfg->max_line_length_set = 0;
    dcfg->inherit_before = -1;
    return dcfg;
}

static void *merge_substitute_dcfg(apr_pool_t *p, void *basev, void *overv)
{
    subst_dir_conf *a =
        (subst_dir_conf *) apr_palloc(p, sizeof(subst_dir_conf));
    subst_dir_conf *base = (subst_dir_conf *) basev;
    subst_dir_conf *over = (subst_dir_conf *) overv;

    a->inherit_before = (over->inherit_before != -1)
                            ? over->inherit_before
                            : base->inherit_before;
    /* SubstituteInheritBefore wasn't the default behavior until 2.5.x,
     * and may be re-disabled as desired; the original default behavior
     * was to apply inherited subst patterns after locally scoped patterns.
     * In later 2.2 and 2.4 versions, SubstituteInheritBefore may be toggled
     * 'on' to follow the corrected/expected behavior, without violating POLS.
     */
    if (a->inherit_before == 1) {
        a->patterns = apr_array_append(p, base->patterns,
                                          over->patterns);
    }
    else {
        a->patterns = apr_array_append(p, over->patterns,
                                          base->patterns);
    }
    a->max_line_length = over->max_line_length_set ?
                             over->max_line_length : base->max_line_length;
    a->max_line_length_set = over->max_line_length_set
                           | base->max_line_length_set;
    return a;
}

#define AP_MAX_BUCKETS 1000

#define SEDRMPATBCKT(b, offset, tmp_b, patlen) do {  \
    apr_bucket_split(b, offset);                     \
    tmp_b = APR_BUCKET_NEXT(b);                      \
    apr_bucket_split(tmp_b, patlen);                 \
    b = APR_BUCKET_NEXT(tmp_b);                      \
    apr_bucket_delete(tmp_b);                        \
} while (0)

#define CAP2LINEMAX(n) ((n) < (apr_size_t)200 ? (int)(n) : 200)

static apr_status_t do_pattmatch(ap_filter_t *f, apr_bucket *inb,
                                 apr_bucket_brigade *mybb,
                                 apr_pool_t *pool)
{
    int i;
    int force_quick = 0;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];
    apr_size_t bytes;
    apr_size_t len;
    const char *buff;
    struct ap_varbuf vb;
    apr_bucket *b;
    apr_bucket *tmp_b;

    subst_dir_conf *cfg =
    (subst_dir_conf *) ap_get_module_config(f->r->per_dir_config,
                                             &substitute_module);
    subst_pattern_t *script;

    APR_BRIGADE_INSERT_TAIL(mybb, inb);
    ap_varbuf_init(pool, &vb, 0);

    script = (subst_pattern_t *) cfg->patterns->elts;
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
                int have_match = 0;

                ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, f->r,
                              "Line read (%" APR_SIZE_T_FMT " bytes): %.*s",
                              bytes, CAP2LINEMAX(bytes), buff);
                ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, f->r,
                              "Replacing %s:'%s' by '%s'",
                              script->pattern ? "string" :
                              script->regexp  ? "regex"  :
                                                "unknown",
                              script->from, script->replacement);

                vb.strlen = 0;
                if (script->pattern) {
                    const char *repl;
                    /*
                     * space_left counts how many bytes we have left until the
                     * line length reaches max_line_length.
                     */
                    apr_size_t space_left = cfg->max_line_length;
                    apr_size_t repl_len = strlen(script->replacement);
                    while ((repl = apr_strmatch(script->pattern, buff, bytes)))
                    {
                        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, f->r,
                                      "Matching found, result: '%s'",
                                      script->replacement);
                        have_match = 1;
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
                            if (vb.strlen + len + repl_len > cfg->max_line_length)
                                return APR_ENOMEM;
                            ap_varbuf_strmemcat(&vb, buff, len);
                            ap_varbuf_strmemcat(&vb, script->replacement, repl_len);
                        }
                        else {
                            /*
                             * The string before the match but after the
                             * previous match (if any) has length 'len'.
                             * Check if we still have space for this string and
                             * the replacement string.
                             */
                            if (space_left < len + repl_len)
                                return APR_ENOMEM;
                            space_left -= len + repl_len;
                            /*
                             * We now split off the string before the match
                             * as its own bucket, then isolate the matched
                             * string and delete it.
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
                    if (have_match) {
                        if (script->flatten && !force_quick) {
                            /* XXX: we should check for AP_MAX_BUCKETS here and
                             * XXX: call ap_pass_brigade accordingly
                             */
                            char *copy = ap_varbuf_pdup(pool, &vb, NULL, 0,
                                                        buff, bytes, &len);
                            ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, f->r,
                                          "New line (%" APR_SIZE_T_FMT " bytes): %.*s",
                                          len, CAP2LINEMAX(len), copy);
                            tmp_b = apr_bucket_pool_create(copy, len, pool,
                                                           f->r->connection->bucket_alloc);
                            APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                            apr_bucket_delete(b);
                            b = tmp_b;
                        }
                        else {
                            /*
                             * We want the behaviour to be predictable.
                             * Therefore we try to always error out if the
                             * line length is larger than the limit,
                             * regardless of the content of the line. So,
                             * let's check if the remaining non-matching
                             * string does not exceed the limit.
                             */
                            if (space_left < b->length)
                                return APR_ENOMEM;
                            ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, f->r,
                                          "New line (%" APR_SIZE_T_FMT " bytes): %.*s",
                                          bytes, CAP2LINEMAX(bytes), buff);
                        }
                    }
                }
                else if (script->regexp) {
                    int left = bytes;
                    const char *pos = buff;
                    char *repl;
                    apr_size_t space_left = cfg->max_line_length;
                    while (!ap_regexec_len(script->regexp, pos, left,
                                       AP_MAX_REG_MATCH, regm, 0)) {
                        apr_status_t rv;
                        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, f->r,
                                      "Matching found");
                        have_match = 1;
                        if (script->flatten && !force_quick) {
                            /* check remaining buffer size */
                            /* Note that the last param in ap_varbuf_regsub below
                             * must stay positive. If it gets 0, it would mean
                             * unlimited space available. */
                            if (vb.strlen + regm[0].rm_so >= cfg->max_line_length)
                                return APR_ENOMEM;
                            /* copy bytes before the match */
                            if (regm[0].rm_so > 0)
                                ap_varbuf_strmemcat(&vb, pos, regm[0].rm_so);
                            /* add replacement string, last argument is unsigned! */
                            rv = ap_varbuf_regsub(&vb, script->replacement, pos,
                                                  AP_MAX_REG_MATCH, regm,
                                                  cfg->max_line_length - vb.strlen);
                            if (rv != APR_SUCCESS)
                                return rv;
                            ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, f->r,
                                          "Result: '%s'", vb.buf);
                        }
                        else {
                            apr_size_t repl_len;
                            /* account for string before the match */
                            if (space_left <= regm[0].rm_so)
                                return APR_ENOMEM;
                            space_left -= regm[0].rm_so;
                            rv = ap_pregsub_ex(pool, &repl,
                                               script->replacement, pos,
                                               AP_MAX_REG_MATCH, regm,
                                               space_left);
                            if (rv != APR_SUCCESS)
                                return rv;
                            repl_len = strlen(repl);
                            space_left -= repl_len;
                            len = (apr_size_t) (regm[0].rm_eo - regm[0].rm_so);
                            SEDRMPATBCKT(b, regm[0].rm_so, tmp_b, len);
                            tmp_b = apr_bucket_transient_create(repl, repl_len,
                                                f->r->connection->bucket_alloc);
                            APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                            ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, f->r,
                                          "Result: '%s'", repl);
                        }
                        /*
                         * reset to past what we just did. pos now maps to b
                         * again
                         */
                        pos += regm[0].rm_eo;
                        left -= regm[0].rm_eo;
                    }
                    if (have_match && script->flatten && !force_quick) {
                        char *copy;
                        /* Copy result plus the part after the last match into
                         * a bucket.
                         */
                        copy = ap_varbuf_pdup(pool, &vb, NULL, 0, pos, left,
                                              &len);
                        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, f->r,
                                      "New line (%" APR_SIZE_T_FMT " bytes): %.*s",
                                      len, CAP2LINEMAX(len), copy);
                        tmp_b = apr_bucket_pool_create(copy, len, pool,
                                           f->r->connection->bucket_alloc);
                        APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        apr_bucket_delete(b);
                        b = tmp_b;
                    }
                }
                else {
                    ap_assert(0);
                    continue;
                }
            }
        }
        script++;
    }
    ap_varbuf_free(&vb);
    return APR_SUCCESS;
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
    subst_dir_conf *cfg =
    (subst_dir_conf *) ap_get_module_config(f->r->per_dir_config,
                                             &substitute_module);

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
        apr_pool_tag(ctx->tpool, "substitute_tpool");
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
                if (rv != APR_SUCCESS)
                    goto err;
                if (fbytes > cfg->max_line_length) {
                    rv = APR_ENOMEM;
                    goto err;
                }
                tmp_b = apr_bucket_transient_create(bflat, fbytes,
                                                f->r->connection->bucket_alloc);
                rv = do_pattmatch(f, tmp_b, ctx->pattbb, ctx->tpool);
                if (rv != APR_SUCCESS)
                    goto err;
                APR_BRIGADE_CONCAT(ctx->passbb, ctx->pattbb);
                apr_brigade_cleanup(ctx->linebb);
            }
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
                    nl = memchr(buff, '\n', bytes);
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
                            if (rv != APR_SUCCESS)
                                goto err;
                            if (fbytes > cfg->max_line_length) {
                                /* Avoid pflattening further lines, we will
                                 * abort later on anyway.
                                 */
                                rv = APR_ENOMEM;
                                goto err;
                            }
                            b = apr_bucket_transient_create(bflat, fbytes,
                                            f->r->connection->bucket_alloc);
                            apr_brigade_cleanup(ctx->linebb);
                        }
                        rv = do_pattmatch(f, b, ctx->pattbb, ctx->tpool);
                        if (rv != APR_SUCCESS)
                            goto err;
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
                                goto err;
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
            if (rv != APR_SUCCESS)
                goto err;
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
err:
    if (rv == APR_ENOMEM)
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(01328) "Line too long, URI %s",
                      f->r->uri);
    apr_pool_clear(ctx->tpool);
    return rv;
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
        int flags = AP_REG_NO_DEFAULT
                    | (ap_regcomp_get_default_cflags() & AP_REG_DOLLAR_ENDONLY)
                    | (ignore_case ? AP_REG_ICASE : 0);
        r = ap_pregcomp(cmd->pool, from, flags);
        if (!r)
            return "Substitute could not compile regex";
    }
    nscript = apr_array_push(((subst_dir_conf *) cfg)->patterns);
    /* init the new entries */
    nscript->pattern = NULL;
    nscript->regexp = NULL;
    nscript->replacement = NULL;
    nscript->patlen = 0;
    nscript->from = from;

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

#define KBYTE         1024
#define MBYTE         1048576
#define GBYTE         1073741824

static const char *set_max_line_length(cmd_parms *cmd, void *cfg, const char *arg)
{
    subst_dir_conf *dcfg = (subst_dir_conf *)cfg;
    apr_off_t max;
    char *end;
    apr_status_t rv;

    rv = apr_strtoff(&max, arg, &end, 10);
    if (rv == APR_SUCCESS) {
        if ((*end == 'K' || *end == 'k') && !end[1]) {
            max *= KBYTE;
        }
        else if ((*end == 'M' || *end == 'm') && !end[1]) {
            max *= MBYTE;
        }
        else if ((*end == 'G' || *end == 'g') && !end[1]) {
            max *= GBYTE;
        }
        else if (*end && /* neither empty nor [Bb] */
                 ((*end != 'B' && *end != 'b') || end[1])) {
            rv = APR_EGENERAL;
        }
    }

    if (rv != APR_SUCCESS || max < 0)
    {
        return "SubstituteMaxLineLength must be a non-negative integer optionally "
               "suffixed with 'b', 'k', 'm' or 'g'.";
    }
    dcfg->max_line_length = (apr_size_t)max;
    dcfg->max_line_length_set = 1;
    return NULL;
}

#define PROTO_FLAGS AP_FILTER_PROTO_CHANGE|AP_FILTER_PROTO_CHANGE_LENGTH
static void register_hooks(apr_pool_t *pool)
{
    ap_register_output_filter(substitute_filter_name, substitute_filter,
                              NULL, AP_FTYPE_RESOURCE);
}

static const command_rec substitute_cmds[] = {
    AP_INIT_TAKE1("Substitute", set_pattern, NULL, OR_FILEINFO,
                  "Pattern to filter the response content (s/foo/bar/[inf])"),
    AP_INIT_TAKE1("SubstituteMaxLineLength", set_max_line_length, NULL, OR_FILEINFO,
                  "Maximum line length"),
    AP_INIT_FLAG("SubstituteInheritBefore", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(subst_dir_conf, inherit_before), OR_FILEINFO,
                 "Apply inherited patterns before those of the current context"),
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
