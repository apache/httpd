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
#include "apr_lib.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "ap_regex.h"
#include "httpd.h"

static apr_status_t rxplus_cleanup(void *preg)
{
    ap_regfree((ap_regex_t *) preg);
    return APR_SUCCESS;
}

AP_DECLARE(ap_rxplus_t*) ap_rxplus_compile(apr_pool_t *pool,
                                           const char *pattern)
{
    /* perl style patterns
     * add support for more as and when wanted
     * substitute: s/rx/subs/
     * match: m/rx/ or just /rx/
     */

    /* allow any nonalnum delimiter as first or second char.
     * If we ever use this with non-string pattern we'll need an extra check
     */
    const char *endp = 0;
    const char *str = pattern;
    const char *rxstr;
    ap_rxplus_t *ret = apr_pcalloc(pool, sizeof(ap_rxplus_t));
    char delim = 0;
    enum { SUBSTITUTE = 's', MATCH = 'm'} action = MATCH;

    if (!apr_isalnum(pattern[0])) {
        delim = *str++;
    }
    else if (pattern[0] == 's' && !apr_isalnum(pattern[1])) {
        action = SUBSTITUTE;
        delim = pattern[1];
        str += 2;
    }
    else if (pattern[0] == 'm' && !apr_isalnum(pattern[1])) {
        delim = pattern[1];
        str += 2;
    }
    /* TODO: support perl's after/before */
    /* FIXME: fix these simplminded delims */

    /* we think there's a delimiter.  Allow for it not to be if unmatched */
    if (delim) {
        endp = ap_strchr_c(str, delim);
    }
    if (!endp) { /* there's no delim or flags */
        if (ap_regcomp(&ret->rx, pattern, 0) == 0) {
            apr_pool_cleanup_register(pool, &ret->rx, rxplus_cleanup,
                                      apr_pool_cleanup_null);
            return ret;
        }
        else {
            return NULL;
        }
    }

    /* We have a delimiter.  Use it to extract the regexp */
    rxstr = apr_pstrmemdup(pool, str, endp-str);

    /* If it's a substitution, we need the replacement string
     * TODO: possible future enhancement - support other parsing
     * in the replacement string.
     */
    if (action == SUBSTITUTE) {
        str = endp+1;
        if (!*str || (endp = ap_strchr_c(str, delim), !endp)) {
            /* missing replacement string is an error */
            return NULL;
        }
        ret->subs = apr_pstrmemdup(pool, str, endp-str);
    }

    /* anything after the current delimiter is flags */
    while (*++endp) {
        switch (*endp) {
        case 'i': ret->flags |= AP_REG_ICASE; break;
        case 'm': ret->flags |= AP_REG_NEWLINE; break;
        case 'n': ret->flags |= AP_REG_NOMEM; break;
        case 'g': ret->flags |= AP_REG_MULTI; break;
        case 's': ret->flags |= AP_REG_DOTALL; break;
        case '^': ret->flags |= AP_REG_NOTBOL; break;
        case '$': ret->flags |= AP_REG_NOTEOL; break;
        default: break; /* we should probably be stricter here */
        }
    }
    if (ap_regcomp(&ret->rx, rxstr, ret->flags) == 0) {
        apr_pool_cleanup_register(pool, &ret->rx, rxplus_cleanup,
                                  apr_pool_cleanup_null);
    }
    else {
        return NULL;
    }
    if (!(ret->flags & AP_REG_NOMEM)) {
        /* count size of memory required, starting at 1 for the whole-match
         * Simpleminded should be fine 'cos regcomp already checked syntax
         */
        ret->nmatch = 1;
        while (*rxstr) {
            switch (*rxstr++) {
            case '\\':  /* next char is escaped - skip it */
                if (*rxstr != 0) {
                    ++rxstr;
                }
                break;
            case '(':   /* unescaped bracket implies memory */
                ++ret->nmatch;
                break;
            default:
                break;
            }
        }
        ret->pmatch = apr_palloc(pool, ret->nmatch*sizeof(ap_regmatch_t));
    }
    return ret;
}

AP_DECLARE(int) ap_rxplus_exec(apr_pool_t *pool, ap_rxplus_t *rx,
                               const char *pattern, char **newpattern)
{
    int ret = 1;
    int startl, oldl, newl, diffsz;
    const char *remainder;
    char *subs;
/* snrf process_regexp from mod_headers */
    if (ap_regexec(&rx->rx, pattern, rx->nmatch, rx->pmatch, rx->flags) != 0) {
        rx->match = NULL;
        return 0; /* no match, nothing to do */
    }
    rx->match = pattern;
    if (rx->subs) {
        *newpattern = ap_pregsub(pool, rx->subs, pattern,
                                 rx->nmatch, rx->pmatch);
        if (!*newpattern) {
            return 0; /* FIXME - should we do more to handle error? */
        }
        startl = rx->pmatch[0].rm_so;
        oldl = rx->pmatch[0].rm_eo - startl;
        newl = strlen(*newpattern);
        diffsz = newl - oldl;
        remainder = pattern + startl + oldl;
        if (rx->flags & AP_REG_MULTI) {
            /* recurse to do any further matches */
            ret += ap_rxplus_exec(pool, rx, remainder, &subs);
            if (ret > 1) {
                /* a further substitution happened */
                diffsz += strlen(subs) - strlen(remainder);
                remainder = subs;
            }
        }
        subs  = apr_palloc(pool, strlen(pattern) + 1 + diffsz);
        memcpy(subs, pattern, startl);
        memcpy(subs+startl, *newpattern, newl);
        strcpy(subs+startl+newl, remainder);
        *newpattern = subs;
    }
    return ret;
}
#ifdef DOXYGEN
AP_DECLARE(int) ap_rxplus_nmatch(ap_rxplus_t *rx)
{
    return (rx->match != NULL) ? rx->nmatch : 0;
}
#endif

/* If this blows up on you, see the notes in the header/apidoc
 * rx->match is a pointer and it's your responsibility to ensure
 * it hasn't gone out-of-scope since the last ap_rxplus_exec
 */
AP_DECLARE(void) ap_rxplus_match(ap_rxplus_t *rx, int n, int *len,
                                 const char **match)
{
    if (n >= 0 && n < ap_rxplus_nmatch(rx)) {
        *match = rx->match + rx->pmatch[n].rm_so;
        *len = rx->pmatch[n].rm_eo - rx->pmatch[n].rm_so;
    }
    else {
        *len = -1;
        *match = NULL;
    }
}
AP_DECLARE(char*) ap_rxplus_pmatch(apr_pool_t *pool, ap_rxplus_t *rx, int n)
{
    int len;
    const char *match;
    ap_rxplus_match(rx, n, &len, &match);
    return apr_pstrndup(pool, match, len);
}
