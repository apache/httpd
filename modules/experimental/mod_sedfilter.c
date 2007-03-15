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
 * mod_sedfilter.c: Perform sed-like rewriting on the fly
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

static const char sedFilterName[] = "SEDFILTER";

module AP_MODULE_DECLARE_DATA sedfilter_module;

typedef struct {
    const apr_strmatch_pattern *pattern;
    const ap_regex_t *regexp;
    const char *replacement;
    apr_size_t replen;
    apr_size_t patlen;
    int flatten;
} sed_script;

typedef struct {
    apr_array_header_t *sed_scripts;
} sed_module_dcfg;

typedef struct {
    apr_bucket_brigade *ctxbb;
} sed_module_ctx;

static void *create_sed_dcfg(apr_pool_t *p, char *d)
{
    sed_module_dcfg *dcfg =
    (sed_module_dcfg *) apr_pcalloc(p, sizeof(sed_module_dcfg));

    dcfg->sed_scripts = apr_array_make(p, 10, sizeof(sed_script));
    return dcfg;
}

static void *merge_sed_dcfg(apr_pool_t *p, void *basev, void *overv)
{
    sed_module_dcfg *a =
    (sed_module_dcfg *) apr_pcalloc(p, sizeof(sed_module_dcfg));
    sed_module_dcfg *base = (sed_module_dcfg *) basev;
    sed_module_dcfg *over = (sed_module_dcfg *) overv;

    a->sed_scripts = apr_array_append(p, over->sed_scripts,
                                      base->sed_scripts);
    return a;
}

static apr_bucket_brigade *do_pattmatch(ap_filter_t *f, apr_bucket *inb)
{
    int i;
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
    apr_bucket_brigade *mybb;
    apr_pool_t *tpool;

    sed_module_dcfg *cfg =
    (sed_module_dcfg *) ap_get_module_config(f->r->per_dir_config,
                                             &sedfilter_module);
    sed_script *script;

    mybb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(mybb, inb);
    
    script = (sed_script *) cfg->sed_scripts->elts;
    apr_pool_create(&tpool, f->r->pool);
    scratch = NULL;
    fbytes = 0;
    for (i = 0; i < cfg->sed_scripts->nelts; i++) {
        for (b = APR_BRIGADE_FIRST(mybb);
             b != APR_BRIGADE_SENTINEL(mybb);
             b = APR_BUCKET_NEXT(b)) {
            if (APR_BUCKET_IS_METADATA(b))
                continue;
            if (apr_bucket_read(b, &buff, &bytes, APR_BLOCK_READ) == APR_SUCCESS) {
                s1 = NULL;
                if (script->pattern) {
                    while ((repl = apr_strmatch(script->pattern, buff, bytes))) {
                        /* get offset into buff for pattern */
                        len = (apr_size_t) (repl - buff);
                        if (script->flatten) {
                            /*
                             * We are flattening the buckets here, meaning
                             * that we don't do the fast bucket splits.
                             * Instead we copy over what the buckets would
                             * contain and use them. This is slow, since we
                             * are constanting allocing space and copying
                             * strings.
                             */
                            if (!s1) {
                                s1 = apr_pstrmemdup(f->r->pool, buff, len);
                            }
                            else {
                                s2 = apr_pstrmemdup(f->r->pool, buff, len);
                                s1 = apr_pstrcat(f->r->pool, s1, s2, NULL);
                            }
                            s1 = apr_pstrcat(f->r->pool, s1, script->replacement, NULL);
                        }
                        else {
                            /* and split off the stuff before */
                            apr_bucket_split(b, len);
                            tmp_b = APR_BUCKET_NEXT(b);
                            /* now isolate the pattern and delete it */
                            apr_bucket_split(tmp_b, script->patlen);
                            b = APR_BUCKET_NEXT(tmp_b);
                            apr_bucket_delete(tmp_b);
                            /*
                             * as above, create a bucket that contains the
                             * replacement and insert it
                             */
                            tmp_b = apr_bucket_pool_create(script->replacement, script->replen,
                                f->r->pool, f->r->connection->bucket_alloc);
                            APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        }
                        /* now we need to adjust buff for all these changes */
                        len += script->patlen;
                        bytes -= len;
                        buff += len;
                    }
                    if (script->flatten && s1) {
                        /*
                         * we've finished looking at the bucket, so remove the
                         * old one and add in our new one
                         */
                        s2 = apr_pstrmemdup(f->r->pool, buff, bytes);
                        s1 = apr_pstrcat(f->r->pool, s1, s2, NULL);
                        tmp_b = apr_bucket_pool_create(s1, strlen(s1),
                                f->r->pool, f->r->connection->bucket_alloc);
                        APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        tmp_b = APR_BUCKET_NEXT(b);
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
                    while (!ap_regexec(script->regexp, p, AP_MAX_REG_MATCH, regm, 0)) {
                        /* first, grab the replacement string */
                        repl = ap_pregsub(f->r->pool, script->replacement, p,
                                          AP_MAX_REG_MATCH, regm);
                        if (script->flatten) {
                            if (!s1)
                                s1 = apr_pstrmemdup(f->r->pool, p, regm[0].rm_so);
                            else {
                                s2 = apr_pstrmemdup(f->r->pool, p, regm[0].rm_so);
                                s1 = apr_pstrcat(f->r->pool, s1, s2, NULL);
                            }
                            s1 = apr_pstrcat(f->r->pool, s1, repl, NULL);
                        }
                        else {
                            /* now split off the stuff before the regex */
                            apr_bucket_split(b, regm[0].rm_so);
                            tmp_b = APR_BUCKET_NEXT(b);
                            /* and after */
                            apr_bucket_split(tmp_b, regm[0].rm_eo - regm[0].rm_so);
                            b = APR_BUCKET_NEXT(tmp_b);
                            /*
                             * now that the regex string is isolated into one
                             * bucket, delete it
                             */
                            apr_bucket_delete(tmp_b);
                            /*
                             * now create a bucket that is just our
                             * replacement
                             */
                            tmp_b = apr_bucket_pool_create(repl, strlen(repl), f->r->pool,
                                            f->r->connection->bucket_alloc);
                            APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        }
                        /*
                         * reset to past what we just did. buff now maps to b
                         * again
                         */
                        p += regm[0].rm_eo;
                    }
                    if (script->flatten && s1) {
                        /*
                         * we've finished looking at the bucket, so remove the
                         * old one and add in our new one
                         */
                        s1 = apr_pstrcat(f->r->pool, s1, p, NULL);
                        tmp_b = apr_bucket_pool_create(s1, strlen(s1),
                                f->r->pool, f->r->connection->bucket_alloc);
                        APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                        tmp_b = APR_BUCKET_NEXT(b);
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

    return mybb;
}

static apr_status_t sed_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_size_t bytes;
    apr_size_t len;
    apr_size_t fbytes;
    apr_off_t blen;
    const char *buff;
    const char *nl = NULL;
    char *bflat;
    apr_bucket *b;
    apr_bucket *tmp_b;
    apr_bucket_brigade *passbb;
    apr_bucket_brigade *pattbb;
    apr_bucket_brigade *tmp_ctxbb = NULL;
    apr_status_t rv;

    sed_module_ctx *ctx = f->ctx;
    /*
     * First time around? Create the saved bb that we used for each pass
     * through. Note that we can also get here when we explicitly clear ctx,
     * for error handling
     */
    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->ctxbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        apr_table_unset(f->r->headers_out, "Content-Length");
    }

    /*
     * Everything to be passed to the next filter goes in
     * here, our pass brigade.
     */
    passbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);

    /*
     * Here's the concept:
     *  Read in the data and look for newlines. Once we
     *  find a full "line", add it to our working brigade.
     *  If we've finished reading the brigade and we have
     *  any left over data (not a "full" line), store that
     *  for the next pass.
     *
     * Note: anything stored in ctxbb for sure does not have
     * a newline char, so we don't concat that bb with the
     * new bb, since we would spending time searching for the newline
     * in data we know it doesn't exist. So instead, we simply scan
     * our current bb and, if we see a newline, prepend ctxbb
     * to the front of it. This makes the code much less straight-
     * forward (otherwise we could APR_BRIGADE_CONCAT(ctx->ctxbb, bb)
     * and just scan for newlines and not bother with needing to know
     * when ctx->ctxbb needs to be reset) but also faster. We'll take
     * the speed.
     *
     * Note: apr_brigade_split_line would be nice here, but we
     * really can't use it since we need more control and we want
     * to re-use already read bucket data.
     *
     * See mod_include if still confused :)
     */

    while ((b = APR_BRIGADE_FIRST(bb)) && (b != APR_BRIGADE_SENTINEL(bb))) {
        apr_brigade_length(passbb, 0, &blen);
        if ((blen != -1) && (blen > AP_MIN_BYTES_TO_WRITE)) {
            ap_pass_brigade(f->next, passbb);
            apr_brigade_cleanup(passbb);
        }
        if (APR_BUCKET_IS_EOS(b)) {
            /*
             * if we see the EOS, then we need to pass along everything we
             * have. But if the ctxbb isn't empty, then we need to add that
             * to the end of what we'll be passing.
             */
            if (!APR_BRIGADE_EMPTY(ctx->ctxbb)) {
                rv = apr_brigade_pflatten(ctx->ctxbb, &bflat, &fbytes, f->r->pool);
                tmp_b = apr_bucket_pool_create(bflat, fbytes, f->r->pool,
                                            f->r->connection->bucket_alloc);
                pattbb = do_pattmatch(f, tmp_b);
                APR_BRIGADE_CONCAT(passbb, pattbb);
            }
            apr_brigade_cleanup(ctx->ctxbb);
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(passbb, b);
        }
        else if (APR_BUCKET_IS_METADATA(b)) {
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(passbb, b);
        }
        else {
            /*
             * We have actual "data" so read in as much as we can and start
             * scanning and splitting from our read buffer
             */
            rv = apr_bucket_read(b, &buff, &bytes, APR_BLOCK_READ);
            if (rv != APR_SUCCESS || bytes == 0) {
                APR_BUCKET_REMOVE(b);
            }
            else {
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
                         * add the split bucket to the end, flatten the whole bb,
                         * morph the whole shebang into a bucket which is
                         * then added to the tail of the newline bb.
                         */
                        if (!APR_BRIGADE_EMPTY(ctx->ctxbb)) {
                            APR_BRIGADE_INSERT_TAIL(ctx->ctxbb, b);
                            rv = apr_brigade_pflatten(ctx->ctxbb, &bflat, &fbytes,
                                                      f->r->pool);
                            b = apr_bucket_pool_create(bflat, fbytes, f->r->pool,
                                            f->r->connection->bucket_alloc);
                            apr_brigade_cleanup(ctx->ctxbb);
                        }
                        pattbb = do_pattmatch(f, b);
                        APR_BRIGADE_CONCAT(passbb, pattbb);
                        b = tmp_b;
                    }
                    else {
                        /*
                         * no newline in whatever is left of this buffer so
                         * tuck data away and get next bucket
                         */
                        APR_BUCKET_REMOVE(b);
                        APR_BRIGADE_INSERT_TAIL(ctx->ctxbb, b);
                        bytes = 0;
                    }
                }
            }
        }
    }

    /* Pass it down */
    rv = ap_pass_brigade(f->next, passbb);

    /* Anything left we want to save/setaside for the next go-around */
    if (!APR_BRIGADE_EMPTY(ctx->ctxbb)) {
        ap_save_brigade(f, &tmp_ctxbb, &(ctx->ctxbb), f->r->pool);
        ctx->ctxbb = tmp_ctxbb;
    }

    return rv;
}

static const char *set_sed_script(cmd_parms *cmd, void *cfg,
                                       const char *line)
{
    char *from = NULL;
    char *to = NULL;
    char *flags = NULL;
    char *ourline;
    char delim;
    sed_script *nscript;
    int is_pattern = 0;
    int ignore_case = 0;
    int flatten = 0;
    ap_regex_t *r = NULL;

    if (apr_tolower(*line) != 's') {
        return "Bad Sed format";
    }
    ourline = apr_pstrdup(cmd->pool, line);
    delim = *++ourline;
    if (delim)
        from = ++ourline;
    if (from) {
        while (*++ourline && *ourline != delim);
        if (*ourline) {
            *ourline = '\0';
            to = ++ourline;
        }
    }
    if (to) {
        while (*++ourline && *ourline != delim);
        if (*ourline) {
            *ourline = '\0';
            flags = ++ourline;
        }
    }

    if (!delim || !from || !to) {
        return "Bad Sed format: cannot parse";
    }

    while (*flags) {
        delim = apr_tolower(*flags);    /* re-use */
        if (delim == 'i')
            ignore_case = 1;
        else if (delim == 'n')
            is_pattern = 1;
        else if (delim == 'f')
            flatten = 1;
        else
            return "Bad Sed format: bad flag";
        flags++;
    }

    /* first see if we can compile the regex */
    if (!is_pattern) {
        r = ap_pregcomp(cmd->pool, from, AP_REG_EXTENDED |
                        (ignore_case ? AP_REG_ICASE : 0));
        if (!r)
            return "Could not compile Sed regex";
    }
    nscript = apr_array_push(((sed_module_dcfg *) cfg)->sed_scripts);
    /* init the new entries */
    nscript->pattern = NULL;
    nscript->regexp = NULL;
    nscript->replacement = NULL;
    nscript->patlen = 0;

    if (is_pattern) {
        nscript->patlen = strlen(from);
        nscript->pattern = apr_strmatch_precompile(cmd->pool, from, !ignore_case);
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
    ap_register_output_filter(sedFilterName, sed_filter, NULL,
                              AP_FTYPE_RESOURCE);
}

static const command_rec sed_filter_cmds[] = {
    AP_INIT_TAKE1("Sed", set_sed_script, NULL, OR_ALL,
                  "Define the sed script (s/foo/bar/)"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA sedfilter_module = {
    STANDARD20_MODULE_STUFF,
    create_sed_dcfg,            /* dir config creater */
    merge_sed_dcfg,             /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    sed_filter_cmds,            /* command table */
    register_hooks              /* register hooks */
};
