/*************************************************
 *      Perl-Compatible Regular Expressions      *
 *************************************************/

/*
This is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language. See
the file Tech.Notes for some information on the internals.

This module is a wrapper that provides a POSIX API to the underlying PCRE
functions.

Written by: Philip Hazel <ph10@cam.ac.uk>

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

    if ((cflags & AP_REG_ICASE) != 0)
        options |= PCREn(CASELESS);
    if ((cflags & AP_REG_NEWLINE) != 0)
        options |= PCREn(MULTILINE);
    if ((cflags & AP_REG_DOTALL) != 0)
        options |= PCREn(DOTALL);

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
 */
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
#ifdef HAVE_PCRE2
    pcre2_match_data *matchdata;
    size_t *ovector;
#else
    int small_ovector[POSIX_MALLOC_THRESHOLD * 3];
    int allocated_ovector = 0;
    int *ovector = NULL;
#endif

    if ((eflags & AP_REG_NOTBOL) != 0)
        options |= PCREn(NOTBOL);
    if ((eflags & AP_REG_NOTEOL) != 0)
        options |= PCREn(NOTEOL);

#ifdef HAVE_PCRE2
    /* TODO: create a generic TLS matchdata buffer of some nmatch limit,
     * e.g. 10 matches, to avoid a malloc-per-call. If it must be alloced,
     * implement a general context using palloc and no free implementation.
     */
    matchdata = pcre2_match_data_create(nmatch, NULL);
    if (matchdata == NULL)
        return AP_REG_ESPACE;
    ovector = pcre2_get_ovector_pointer(matchdata);
    rc = pcre2_match((const pcre2_code *)preg->re_pcre,
                     (const unsigned char *)buff, len,
                     0, options, matchdata, NULL);
#else
    if (nmatch > 0) {
        if (nmatch <= POSIX_MALLOC_THRESHOLD) {
            ovector = &(small_ovector[0]);
        }
        else {
            ovector = (int *)malloc(sizeof(int) * nmatch * 3);
            if (ovector == NULL)
                return AP_REG_ESPACE;
            allocated_ovector = 1;
        }
    }
    rc = pcre_exec((const pcre *)preg->re_pcre, NULL, buff, (int)len,
                   0, options, ovector, nmatch * 3);
#endif

    if (rc == 0)
        rc = nmatch;            /* All captured slots were filled in */

    if (rc >= 0) {
        apr_size_t i;
        apr_size_t nlim = (apr_size_t)rc < nmatch ? (apr_size_t)rc : nmatch;
        for (i = 0; i < nlim; i++) {
            pmatch[i].rm_so = ovector[i * 2];
            pmatch[i].rm_eo = ovector[i * 2 + 1];
        }
        for (; i < nmatch; i++)
            pmatch[i].rm_so = pmatch[i].rm_eo = -1;
    }

#ifdef HAVE_PCRE2
    pcre2_match_data_free(matchdata);
#else
    if (allocated_ovector)
        free(ovector);
#endif

    if (rc >= 0) {
        return 0;
    }
    else {
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
