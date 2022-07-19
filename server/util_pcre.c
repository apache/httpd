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

/* This code is based on pcreposix.c from the PCRE Library distribution,
 * as originally written by Philip Hazel <ph10@cam.ac.uk>, and forked by
 * the Apache HTTP Server project to provide POSIX-style regex function
 * wrappers around underlying PCRE library functions for httpd.
 * 
 * The original source file pcreposix.c is copyright and licensed as follows;

           Copyright (c) 1997-2004 University of Cambridge

-----------------------------------------------------------------------------
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of the University of Cambridge nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
-----------------------------------------------------------------------------
*/

#include "httpd.h"
#include "apr_strings.h"
#include "apr_tables.h"

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include "pcre2.h"
#define PCREn(x) PCRE2_ ## x
#else
#include "pcre.h"
#define PCREn(x) PCRE_ ## x
#endif

/* PCRE_DUPNAMES is only present since version 6.7 of PCRE */
#if !defined(PCRE_DUPNAMES) && !defined(HAVE_PCRE2)
#error PCRE Version 6.7 or later required!
#else

#define APR_WANT_STRFUNC
#include "apr_want.h"

#ifndef POSIX_MALLOC_THRESHOLD
#define POSIX_MALLOC_THRESHOLD (10)
#endif

#ifdef HAVE_PCRE2
/* Reserve 128 bytes for the PCRE2 structs, that is (a bit above):
 *   sizeof(pcre2_general_context) + offsetof(pcre2_match_data, ovector)
 */
#define AP_PCRE_STACKBUF_SIZE \
    APR_ALIGN_DEFAULT(128 + POSIX_MALLOC_THRESHOLD * sizeof(PCRE2_SIZE) * 2)
#else
#define AP_PCRE_STACKBUF_SIZE \
    APR_ALIGN_DEFAULT(POSIX_MALLOC_THRESHOLD * sizeof(int) * 3)
#endif

/* Table of error strings corresponding to POSIX error codes; must be
 * kept in synch with include/ap_regex.h's AP_REG_E* definitions.
 */

static const char *const pstring[] = {
    "",                         /* Dummy for value 0 */
    "internal error",           /* AP_REG_ASSERT */
    "failed to get memory",     /* AP_REG_ESPACE */
    "bad argument",             /* AP_REG_INVARG */
    "match failed"              /* AP_REG_NOMATCH */
};

AP_DECLARE(const char *) ap_pcre_version_string(int which)
{
#ifdef HAVE_PCRE2
    static char buf[80];
#endif
    switch (which) {
    case AP_REG_PCRE_COMPILED:
        return APR_STRINGIFY(PCREn(MAJOR)) "." APR_STRINGIFY(PCREn(MINOR)) " " APR_STRINGIFY(PCREn(DATE));
    case AP_REG_PCRE_LOADED:
#ifdef HAVE_PCRE2
        pcre2_config(PCRE2_CONFIG_VERSION, buf);
        return buf;
#else
        return pcre_version();
#endif
    default:
        return "Unknown";
    }
}

AP_DECLARE(apr_size_t) ap_regerror(int errcode, const ap_regex_t *preg,
                                   char *errbuf, apr_size_t errbuf_size)
{
    const char *message, *addmessage;
    apr_size_t length, addlength;

    message = (errcode >= (int)(sizeof(pstring) / sizeof(char *))) ?
              "unknown error code" : pstring[errcode];
    length = strlen(message) + 1;

    addmessage = " at offset ";
    addlength = (preg != NULL && (int)preg->re_erroffset != -1) ?
                strlen(addmessage) + 6 : 0;

    if (errbuf_size > 0) {
        if (addlength > 0 && errbuf_size >= length + addlength)
            apr_snprintf(errbuf, errbuf_size, "%s%s%-6d", message, addmessage,
                         (int)preg->re_erroffset);
        else
            apr_cpystrn(errbuf, message, errbuf_size);
    }

    return length + addlength;
}




/*************************************************
 *           Free store held by a regex          *
 *************************************************/

AP_DECLARE(void) ap_regfree(ap_regex_t *preg)
{
#ifdef HAVE_PCRE2
    pcre2_code_free(preg->re_pcre);
#else
    (pcre_free)(preg->re_pcre);
#endif
}




/*************************************************
 *            Compile a regular expression       *
 *************************************************/

static int default_cflags = AP_REG_DEFAULT;

AP_DECLARE(int) ap_regcomp_get_default_cflags(void)
{
    return default_cflags;
}

AP_DECLARE(void) ap_regcomp_set_default_cflags(int cflags)
{
    default_cflags = cflags;
}

AP_DECLARE(int) ap_regcomp_default_cflag_by_name(const char *name)
{
    int cflag = 0;

    if (ap_cstr_casecmp(name, "ICASE") == 0) {
        cflag = AP_REG_ICASE;
    }
    else if (ap_cstr_casecmp(name, "DOTALL") == 0) {
        cflag = AP_REG_DOTALL;
    }
    else if (ap_cstr_casecmp(name, "DOLLAR_ENDONLY") == 0) {
        cflag = AP_REG_DOLLAR_ENDONLY;
    }
    else if (ap_cstr_casecmp(name, "EXTENDED") == 0) {
        cflag = AP_REG_EXTENDED;
    }

    return cflag;
}

/*
 * Arguments:
 *  preg        points to a structure for recording the compiled expression
 *  pattern     the pattern to compile
 *  cflags      compilation flags
 *
 * Returns:      0 on success
 *               various non-zero codes on failure
*/
AP_DECLARE(int) ap_regcomp(ap_regex_t * preg, const char *pattern, int cflags)
{
#ifdef HAVE_PCRE2
    uint32_t capcount;
    PCRE2_SIZE erroffset;
#else
    const char *errorptr;
    int erroffset;
#endif
    int errcode = 0;
    int options = PCREn(DUPNAMES);

    if ((cflags & AP_REG_NO_DEFAULT) == 0)
        cflags |= default_cflags;

    if ((cflags & AP_REG_ICASE) != 0)
        options |= PCREn(CASELESS);
    if ((cflags & AP_REG_NEWLINE) != 0)
        options |= PCREn(MULTILINE);
    if ((cflags & AP_REG_DOTALL) != 0)
        options |= PCREn(DOTALL);
    if ((cflags & AP_REG_DOLLAR_ENDONLY) != 0)
        options |= PCREn(DOLLAR_ENDONLY);

#ifdef HAVE_PCRE2
    preg->re_pcre = pcre2_compile((const unsigned char *)pattern,
                                  PCRE2_ZERO_TERMINATED, options, &errcode,
                                  &erroffset, NULL);
#else
    preg->re_pcre = pcre_compile2(pattern, options, &errcode,
                                  &errorptr, &erroffset, NULL);
#endif

    preg->re_erroffset = erroffset;
    if (preg->re_pcre == NULL) {
        /* Internal ERR21 is "failed to get memory" according to pcreapi(3) */
        if (errcode == 21)
            return AP_REG_ESPACE;
        return AP_REG_INVARG;
    }

#ifdef HAVE_PCRE2
    pcre2_pattern_info((const pcre2_code *)preg->re_pcre,
                       PCRE2_INFO_CAPTURECOUNT, &capcount);
    preg->re_nsub = capcount;
#else
    pcre_fullinfo((const pcre *)preg->re_pcre, NULL,
                  PCRE_INFO_CAPTURECOUNT, &(preg->re_nsub));
#endif
    return 0;
}




/*************************************************
 *              Match a regular expression       *
 *************************************************/

/* Unfortunately, PCRE1 requires 3 ints of working space for each captured
 * substring, so we have to get and release working store instead of just using
 * the POSIX structures as was done in earlier releases when PCRE needed only 2
 * ints. However, if the number of possible capturing brackets is small, use a
 * block of store on the stack, to reduce the use of malloc/free. The threshold
 * is in POSIX_MALLOC_THRESHOLD macro that can be changed at configure time.
 * PCRE2 takes an opaque match context and lets us provide the callbacks to
 * manage the memory needed during the match, so we can still use a small stack
 * space that will suffice for the match context struct and a single frame of
 * POSIX_MALLOC_THRESHOLD captures, above that either use a thread local
 * subpool cache (#if AP_HAS_THREAD_LOCAL) or fall back to malloc()/free().
 */

#if AP_HAS_THREAD_LOCAL && !defined(APREG_NO_THREAD_LOCAL)
#define APREG_USE_THREAD_LOCAL 1
#else
#define APREG_USE_THREAD_LOCAL 0
#endif

#ifdef HAVE_PCRE2
typedef PCRE2_SIZE* match_vector_pt;
#else
typedef int*        match_vector_pt;
#endif

#if APREG_USE_THREAD_LOCAL
static AP_THREAD_LOCAL apr_pool_t *thread_pool;
#endif

struct match_data_state {
    /* keep first, struct aligned */
    char buf[AP_PCRE_STACKBUF_SIZE];
    apr_size_t buf_used;

#if APREG_USE_THREAD_LOCAL
    apr_thread_t *thd;
    apr_pool_t *pool;
#endif

#ifdef HAVE_PCRE2
    pcre2_general_context *pcre2_ctx;
    pcre2_match_data* match_data;
#else
    int *match_data;
#endif
};

static void * private_malloc(size_t size, void *ctx)
{
    struct match_data_state *state = ctx;

    if (size <= sizeof(state->buf) - state->buf_used) {
        void *p = state->buf + state->buf_used;
        state->buf_used += APR_ALIGN_DEFAULT(size);
        return p;
    }

#if APREG_USE_THREAD_LOCAL
    if (state->thd) {
        apr_pool_t *pool = state->pool;
        if (pool == NULL) {
            pool = thread_pool;
            if (pool == NULL) {
                apr_pool_create(&pool, apr_thread_pool_get(state->thd));
                thread_pool = pool;
            }
            state->pool = pool;
        }
        return apr_palloc(pool, size);
    }
#endif

    return malloc(size);
}

static void private_free(void *block, void *ctx)
{
    struct match_data_state *state = ctx;
    char *p = block;

    if (p >= state->buf && p < state->buf + sizeof(state->buf)) {
        /* This block allocated from stack buffer. Do nothing. */
        return;
    }

#if APREG_USE_THREAD_LOCAL
    if (state->thd) {
        /* Freed in cleanup_state() eventually. */
        return;
    }
#endif

    free(block);
} 

static APR_INLINE
int setup_state(struct match_data_state *state, apr_uint32_t ncaps)
{
    state->buf_used = 0;

#if APREG_USE_THREAD_LOCAL
    state->thd = ap_thread_current();
    state->pool = NULL;
#endif

#ifdef HAVE_PCRE2
    state->pcre2_ctx = pcre2_general_context_create(private_malloc,
                                                    private_free, state);
    if (!state->pcre2_ctx) { 
        return 0;
    }

    state->match_data = pcre2_match_data_create(ncaps, state->pcre2_ctx);
    if (!state->match_data) {
        pcre2_general_context_free(state->pcre2_ctx);
        return 0;
    }
#else
    if (ncaps) {
        state->match_data = private_malloc(ncaps * sizeof(int) * 3, state);
        if (!state->match_data) {
            return 0;
        }
    }
    else {
        /* Fine with PCRE1 */
        state->match_data = NULL;
    }
#endif

    return 1;
}

static APR_INLINE
void cleanup_state(struct match_data_state *state)
{
#ifdef HAVE_PCRE2
    pcre2_match_data_free(state->match_data);
    pcre2_general_context_free(state->pcre2_ctx);
#else
    if (state->match_data) {
        private_free(state->match_data, state);
    }
#endif

#if APREG_USE_THREAD_LOCAL
    if (state->pool) {
        /* Let the thread's pool allocator recycle or free according
         * to its max_free setting.
         */
        apr_pool_clear(state->pool);
    }
#endif
}

AP_DECLARE(int) ap_regexec(const ap_regex_t *preg, const char *string,
                           apr_size_t nmatch, ap_regmatch_t *pmatch,
                           int eflags)
{
    return ap_regexec_len(preg, string, strlen(string), nmatch, pmatch,
                          eflags);
}

AP_DECLARE(int) ap_regexec_len(const ap_regex_t *preg, const char *buff,
                               apr_size_t len, apr_size_t nmatch,
                               ap_regmatch_t *pmatch, int eflags)
{
    int rc;
    int options = 0;
    struct match_data_state state;
    match_vector_pt ovector = NULL;
    apr_uint32_t ncaps = (apr_uint32_t)preg->re_nsub + 1;

#ifndef HAVE_PCRE2
    /* This is fine if pcre_exec() gets a vector size smaller than the
     * number of capturing groups (it will treat the remaining ones as
     * non-capturing), but if the vector is too small to keep track of
     * the potential backrefs within the pattern, it will temporarily
     * malloc()ate the necessary space anyway. So let's provide a vector
     * of at least PCRE_INFO_BACKREFMAX entries (likely zero, otherwise
     * the vector is most likely cached already anyway).
     * Note that if no captures are to be used by the caller, passing an
     * nmatch of zero (thus forcing all groups to be non-capturing) may
     * allow for some optimizations and/or less recursion (stack usage)
     * with PCRE1, unless backrefs..
     */
    if (ncaps > nmatch) {
        int backrefmax = 0;
        pcre_fullinfo((const pcre *)preg->re_pcre, NULL,
                      PCRE_INFO_BACKREFMAX, &backrefmax);
        if (backrefmax > 0 && (apr_uint32_t)backrefmax >= nmatch) {
            ncaps = (apr_uint32_t)backrefmax + 1;
        }
        else {
            ncaps = nmatch;
        }
    }
#endif

    if (!setup_state(&state, ncaps)) {
        return AP_REG_ESPACE;
    }

    if ((eflags & AP_REG_NOTBOL) != 0)
        options |= PCREn(NOTBOL);
    if ((eflags & AP_REG_NOTEOL) != 0)
        options |= PCREn(NOTEOL);
    if ((eflags & AP_REG_NOTEMPTY) != 0)
        options |= PCREn(NOTEMPTY);
    if ((eflags & AP_REG_ANCHORED) != 0)
        options |= PCREn(ANCHORED);

#ifdef HAVE_PCRE2
    rc = pcre2_match((const pcre2_code *)preg->re_pcre,
                     (const unsigned char *)buff, len, 0, options,
                     state.match_data, NULL);
    ovector = pcre2_get_ovector_pointer(state.match_data);
#else
    ovector = state.match_data;
    rc = pcre_exec((const pcre *)preg->re_pcre, NULL, buff, (int)len,
                   0, options, ovector, ncaps * 3);
#endif

    if (rc >= 0) {
        apr_size_t n = rc, i;
        if (n == 0 || n > nmatch)
            rc = n = nmatch; /* All capture slots were filled in */
        for (i = 0; i < n; i++) {
            pmatch[i].rm_so = ovector[i * 2];
            pmatch[i].rm_eo = ovector[i * 2 + 1];
        }
        for (; i < nmatch; i++)
            pmatch[i].rm_so = pmatch[i].rm_eo = -1;
        cleanup_state(&state);
        return 0;
    }
    else {
        cleanup_state(&state);
#ifdef HAVE_PCRE2
        if (rc <= PCRE2_ERROR_UTF8_ERR1 && rc >= PCRE2_ERROR_UTF8_ERR21)
            return AP_REG_INVARG;
#endif
        switch (rc) {
        case PCREn(ERROR_NOMATCH):
            return AP_REG_NOMATCH;
        case PCREn(ERROR_NULL):
            return AP_REG_INVARG;
        case PCREn(ERROR_BADOPTION):
            return AP_REG_INVARG;
        case PCREn(ERROR_BADMAGIC):
            return AP_REG_INVARG;
        case PCREn(ERROR_NOMEMORY):
            return AP_REG_ESPACE;
#if defined(HAVE_PCRE2) || defined(PCRE_ERROR_MATCHLIMIT)
        case PCREn(ERROR_MATCHLIMIT):
            return AP_REG_ESPACE;
#endif
#if defined(PCRE_ERROR_UNKNOWN_NODE)
        case PCRE_ERROR_UNKNOWN_NODE:
            return AP_REG_ASSERT;
#endif
#if defined(PCRE_ERROR_BADUTF8)
        case PCREn(ERROR_BADUTF8):
            return AP_REG_INVARG;
#endif
#if defined(PCRE_ERROR_BADUTF8_OFFSET)
        case PCREn(ERROR_BADUTF8_OFFSET):
            return AP_REG_INVARG;
#endif
        default:
            return AP_REG_ASSERT;
        }
    }
}

AP_DECLARE(int) ap_regname(const ap_regex_t *preg,
                           apr_array_header_t *names, const char *prefix,
                           int upper)
{
    char *nametable;

#ifdef HAVE_PCRE2
    uint32_t namecount;
    uint32_t nameentrysize;
    uint32_t i;
    pcre2_pattern_info((const pcre2_code *)preg->re_pcre,
                       PCRE2_INFO_NAMECOUNT, &namecount);
    pcre2_pattern_info((const pcre2_code *)preg->re_pcre,
                       PCRE2_INFO_NAMEENTRYSIZE, &nameentrysize);
    pcre2_pattern_info((const pcre2_code *)preg->re_pcre,
                       PCRE2_INFO_NAMETABLE, &nametable);
#else
    int namecount;
    int nameentrysize;
    int i;
    pcre_fullinfo((const pcre *)preg->re_pcre, NULL,
                  PCRE_INFO_NAMECOUNT, &namecount);
    pcre_fullinfo((const pcre *)preg->re_pcre, NULL,
                  PCRE_INFO_NAMEENTRYSIZE, &nameentrysize);
    pcre_fullinfo((const pcre *)preg->re_pcre, NULL,
                  PCRE_INFO_NAMETABLE, &nametable);
#endif

    for (i = 0; i < namecount; i++) {
        const char *offset = nametable + i * nameentrysize;
        int capture = ((offset[0] << 8) + offset[1]);
        while (names->nelts <= capture) {
            apr_array_push(names);
        }
        if (upper || prefix) {
            char *name = ((char **) names->elts)[capture] =
                    prefix ? apr_pstrcat(names->pool, prefix, offset + 2,
                            NULL) :
                            apr_pstrdup(names->pool, offset + 2);
            if (upper) {
                ap_str_toupper(name);
            }
        }
        else {
            ((const char **)names->elts)[capture] = offset + 2;
        }
    }

    return namecount;
}

#endif /* PCRE_DUPNAMES defined */

/* End of pcreposix.c */
