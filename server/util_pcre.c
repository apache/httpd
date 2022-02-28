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
#include "apr_thread_proc.h"

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
    size_t erroffset;
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

/* Unfortunately, PCRE requires 3 ints of working space for each captured
 * substring, so we have to get and release working store instead of just using
 * the POSIX structures as was done in earlier releases when PCRE needed only 2
 * ints. However, if the number of possible capturing brackets is small, use a
 * block of store on the stack, to reduce the use of malloc/free. The threshold
 * is in a macro that can be changed at configure time.
 * Yet more unfortunately, PCRE2 wants an opaque context by providing the API
 * to allocate and free it, so to minimize these calls we maintain one opaque
 * context per thread (in Thread Local Storage, TLS) grown as needed, and while
 * at it we do the same for PCRE1 ints vectors. Note that this requires a fast
 * TLS mechanism to be worth it, which is the case of apr_thread_data_get/set()
 * from/to ap_thread_current() when AP_HAS_THREAD_LOCAL; otherwise we'll do
 * the allocation and freeing for each ap_regexec().
 */

#ifdef HAVE_PCRE2
typedef pcre2_match_data* match_data_pt;
typedef size_t*           match_vector_pt;
#else
typedef int*              match_data_pt;
typedef int*              match_vector_pt;
#endif

static APR_INLINE
match_data_pt alloc_match_data(apr_size_t size,
                               match_vector_pt small_vector)
{
    match_data_pt data;

#ifdef HAVE_PCRE2
    data = pcre2_match_data_create(size, NULL);
#else
    if (size > POSIX_MALLOC_THRESHOLD) {
        data = malloc(size * sizeof(int) * 3);
    }
    else {
        data = small_vector;
    }
#endif

    return data;
}

static APR_INLINE
void free_match_data(match_data_pt data, apr_size_t size)
{
#ifdef HAVE_PCRE2
    pcre2_match_data_free(data);
#else
    if (size > POSIX_MALLOC_THRESHOLD) {
        free(data);
    }
#endif
}

#if AP_HAS_THREAD_LOCAL && !defined(APREG_NO_THREAD_LOCAL)

struct apreg_tls {
    match_data_pt data;
    apr_size_t size;
};

#ifdef HAVE_PCRE2
static apr_status_t apreg_tls_cleanup(void *arg)
{
    struct apreg_tls *tls = arg;
    pcre2_match_data_free(tls->data); /* NULL safe */
    return APR_SUCCESS;
}
#endif

static match_data_pt get_match_data(apr_size_t size,
                                    match_vector_pt small_vector,
                                    int *to_free)
{
    apr_thread_t *current;
    struct apreg_tls *tls = NULL;

    /* Even though AP_HAS_THREAD_LOCAL, we may still be called by a
     * native/non-apr thread, let's fall back to alloc/free in this case.
     */
    current = ap_thread_current();
    if (!current) {
        *to_free = 1;
        return alloc_match_data(size, small_vector);
    }

    apr_thread_data_get((void **)&tls, "apreg", current);
    if (!tls || tls->size < size) {
        apr_pool_t *tp = apr_thread_pool_get(current);
        if (!tls) {
            tls = apr_pcalloc(tp, sizeof(*tls));
#ifdef HAVE_PCRE2
            apr_thread_data_set(tls, "apreg", apreg_tls_cleanup, current);
#else
            apr_thread_data_set(tls, "apreg", NULL, current);
#endif
        }

        tls->size *= 2;
        if (tls->size < size) {
            tls->size = size;
            if (tls->size < POSIX_MALLOC_THRESHOLD) {
                tls->size = POSIX_MALLOC_THRESHOLD;
            }
        }

#ifdef HAVE_PCRE2
        pcre2_match_data_free(tls->data); /* NULL safe */
        tls->data = pcre2_match_data_create(tls->size, NULL);
        if (!tls->data) {
            tls->size = 0;
            return NULL;
        }
#else
        tls->data = apr_palloc(tp, tls->size * sizeof(int) * 3);
#endif
    }

    return tls->data;
}

#else /* AP_HAS_THREAD_LOCAL && !defined(APREG_NO_THREAD_LOCAL) */

static APR_INLINE match_data_pt get_match_data(apr_size_t size,
                                               match_vector_pt small_vector,
                                               int *to_free)
{
    *to_free = 1;
    return alloc_match_data(size, small_vector);
}

#endif /* AP_HAS_THREAD_LOCAL && !defined(APREG_NO_THREAD_LOCAL) */

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
    int options = 0, to_free = 0;
    match_vector_pt ovector = NULL;
    apr_size_t ncaps = (apr_size_t)preg->re_nsub + 1;
#ifdef HAVE_PCRE2
    match_data_pt data = get_match_data(ncaps, NULL, &to_free);
#else
    int small_vector[POSIX_MALLOC_THRESHOLD * 3];
    match_data_pt data = get_match_data(ncaps, small_vector, &to_free);
#endif

    if (!data) {
        return AP_REG_ESPACE;
    }

    if ((eflags & AP_REG_NOTBOL) != 0)
        options |= PCREn(NOTBOL);
    if ((eflags & AP_REG_NOTEOL) != 0)
        options |= PCREn(NOTEOL);

#ifdef HAVE_PCRE2
    rc = pcre2_match((const pcre2_code *)preg->re_pcre,
                     (const unsigned char *)buff, len,
                     0, options, data, NULL);
    ovector = pcre2_get_ovector_pointer(data);
#else
    ovector = data;
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
        if (to_free) {
            free_match_data(data, ncaps);
        }
        return 0;
    }
    else {
        if (to_free) {
            free_match_data(data, ncaps);
        }
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
