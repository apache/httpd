/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#define CORE_PRIVATE

#include "mod_cache.h"



/* -------------------------------------------------------------- */

/* return true if the request is conditional */
CACHE_DECLARE(int) ap_cache_request_is_conditional(request_rec *r)
{
    if (apr_table_get(r->headers_in, "If-Match") ||
        apr_table_get(r->headers_in, "If-None-Match") ||
        apr_table_get(r->headers_in, "If-Modified-Since") ||
        apr_table_get(r->headers_in, "If-Unmodified-Since")) {

        return 1;
    }
    return 0;
}


/* remove other filters from filter stack */
CACHE_DECLARE(void) ap_cache_reset_output_filters(request_rec *r)
{
    ap_filter_t *f = r->output_filters;

    while (f) {
        if (!strcasecmp(f->frec->name, "CORE") ||
            !strcasecmp(f->frec->name, "CONTENT_LENGTH") ||
            !strcasecmp(f->frec->name, "HTTP_HEADER")) {
            f = f->next;
            continue;
        }
        else {
            ap_remove_output_filter(f);
            f = f->next;
        }
    }
}

CACHE_DECLARE(const char *)ap_cache_get_cachetype(request_rec *r, 
                                                  cache_server_conf *conf, 
                                                  const char *url)
{
    const char *type = NULL;
    int i;

    /* we can't cache if there's no URL */
    if (!url) return NULL;

    /* loop through all the cacheenable entries */
    for (i = 0; i < conf->cacheenable->nelts; i++) {
        struct cache_enable *ent = 
                                (struct cache_enable *)conf->cacheenable->elts;
        const char *thisurl = ent[i].url;
        const char *thistype = ent[i].type;
        if ((thisurl) && !strncasecmp(thisurl, url, strlen(thisurl))) {
            if (!type) {
                type = thistype;
            }
            else {
                type = apr_pstrcat(r->pool, type, ",", thistype, NULL);
            }
        }
    }

    /* then loop through all the cachedisable entries */
    /* Looking for urls that contain the full cachedisable url and possibly more. */
    /*   This means we are disabling cachedisable url and below... */
    for (i = 0; i < conf->cachedisable->nelts; i++) {
        struct cache_disable *ent = 
                               (struct cache_disable *)conf->cachedisable->elts;
        const char *thisurl = ent[i].url;
        if ((thisurl) && !strncasecmp(thisurl, url, strlen(thisurl))) {
            type = NULL;
        }
    }

    return type;
}


/* do a HTTP/1.1 age calculation */
CACHE_DECLARE(apr_int64_t) ap_cache_current_age(cache_info *info, const apr_time_t age_value,
                                                apr_time_t now)
{
    apr_time_t apparent_age, corrected_received_age, response_delay,
               corrected_initial_age, resident_time, current_age,
               age_value_usec;

    age_value_usec = apr_time_from_sec(age_value);

    /* Perform an HTTP/1.1 age calculation. (RFC2616 13.2.3) */

    apparent_age = MAX(0, info->response_time - info->date);
    corrected_received_age = MAX(apparent_age, age_value_usec);
    response_delay = info->response_time - info->request_time;
    corrected_initial_age = corrected_received_age + response_delay;
    resident_time = now - info->response_time;
    current_age = corrected_initial_age + resident_time;

    return apr_time_sec(current_age);
}

CACHE_DECLARE(int) ap_cache_check_freshness(cache_request_rec *cache, 
                                            request_rec *r)
{
    apr_int64_t age, maxage_req, maxage_cresp, maxage, smaxage, maxstale, minfresh;
    int age_in_errhdr = 0;
    const char *cc_cresp, *cc_ceresp, *cc_req;
    const char *agestr = NULL;
    const char *expstr = NULL;
    char *val;
    apr_time_t age_c = 0;
    cache_info *info = &(cache->handle->cache_obj->info);

    /*
     * We now want to check if our cached data is still fresh. This depends
     * on a few things, in this order:
     *
     * - RFC2616 14.9.4 End to end reload, Cache-Control: no-cache no-cache in
     * either the request or the cached response means that we must
     * revalidate the request unconditionally, overriding any expiration
     * mechanism. It's equivalent to max-age=0,must-revalidate.
     * 
     * - RFC2616 14.32 Pragma: no-cache This is treated the same as
     * Cache-Control: no-cache.
     * 
     * - RFC2616 14.9.3 Cache-Control: max-stale, must-revalidate,
     * proxy-revalidate if the max-stale request header exists, modify the
     * stale calculations below so that an object can be at most <max-stale>
     * seconds stale before we request a revalidation, _UNLESS_ a
     * must-revalidate or proxy-revalidate cached response header exists to
     * stop us doing this.
     * 
     * - RFC2616 14.9.3 Cache-Control: s-maxage the origin server specifies the
     * maximum age an object can be before it is considered stale. This
     * directive has the effect of proxy|must revalidate, which in turn means
     * simple ignore any max-stale setting.
     * 
     * - RFC2616 14.9.4 Cache-Control: max-age this header can appear in both
     * requests and responses. If both are specified, the smaller of the two
     * takes priority.
     * 
     * - RFC2616 14.21 Expires: if this request header exists in the cached
     * entity, and it's value is in the past, it has expired.
     * 
     */
    cc_cresp = apr_table_get(r->headers_out, "Cache-Control");
    cc_ceresp = apr_table_get(r->err_headers_out, "Cache-Control");
    cc_req = apr_table_get(r->headers_in, "Cache-Control");
    
    if ((agestr = apr_table_get(r->headers_out, "Age"))) {
        age_c = apr_atoi64(agestr);
    }
    else if ((agestr = apr_table_get(r->err_headers_out, "Age"))) {
        age_c = apr_atoi64(agestr);
        age_in_errhdr = 1;
    }

    if (!(expstr = apr_table_get(r->err_headers_out, "Expires"))) {
        expstr = apr_table_get(r->headers_out, "Expires");
    }

    /* calculate age of object */
    age = ap_cache_current_age(info, age_c, r->request_time);

    /* extract s-maxage */
    if (cc_cresp && ap_cache_liststr(r->pool, cc_cresp, "s-maxage", &val))
        smaxage = apr_atoi64(val);
    else if (cc_ceresp && ap_cache_liststr(r->pool, cc_ceresp, "s-maxage", &val)) {
        smaxage = apr_atoi64(val);
    }
    else
        smaxage = -1;

    /* extract max-age from request */
    if (cc_req && ap_cache_liststr(r->pool, cc_req, "max-age", &val))
        maxage_req = apr_atoi64(val);
    else
        maxage_req = -1;

    /* extract max-age from response */
    if (cc_cresp && ap_cache_liststr(r->pool, cc_cresp, "max-age", &val))
        maxage_cresp = apr_atoi64(val);
    else if (cc_ceresp && ap_cache_liststr(r->pool, cc_ceresp, "max-age", &val)) {
        maxage_cresp = apr_atoi64(val);
    }
    else
        maxage_cresp = -1;

    /*
     * if both maxage request and response, the smaller one takes priority
     */
    if (-1 == maxage_req)
        maxage = maxage_cresp;
    else if (-1 == maxage_cresp)
        maxage = maxage_req;
    else
        maxage = MIN(maxage_req, maxage_cresp);

    /* extract max-stale */
    if (cc_req && ap_cache_liststr(r->pool, cc_req, "max-stale", &val))
        maxstale = apr_atoi64(val);
    else
        maxstale = 0;

    /* extract min-fresh */
    if (cc_req && ap_cache_liststr(r->pool, cc_req, "min-fresh", &val))
        minfresh = apr_atoi64(val);
    else
        minfresh = 0;

    /* override maxstale if must-revalidate or proxy-revalidate */
    if (maxstale && ((cc_cresp &&
                      ap_cache_liststr(NULL, cc_cresp,
                                       "must-revalidate", NULL)) ||
                     (cc_cresp &&
                      ap_cache_liststr(NULL, cc_cresp,
                                       "proxy-revalidate", NULL)) ||
                     (cc_ceresp &&
                      ap_cache_liststr(NULL, cc_ceresp,
                                       "must-revalidate", NULL)) ||
                     (cc_ceresp &&
                      ap_cache_liststr(NULL, cc_ceresp,
                                       "proxy-revalidate", NULL)))) {
        maxstale = 0;
    }

    /* handle expiration */
    if (((smaxage != -1) && (age < (smaxage - minfresh))) ||
        ((maxage != -1) && (age < (maxage + maxstale - minfresh))) ||
        ((smaxage == -1) && (maxage == -1) &&
         (info->expire != APR_DATE_BAD) &&
         (age < (apr_time_sec(info->expire - info->date) + maxstale - minfresh)))) {
        const char *warn_head;
        apr_table_t *head_ptr;

        warn_head = apr_table_get(r->headers_out, "Warning");
        if (warn_head != NULL) {
            head_ptr = r->headers_out;
        }
        else {
            warn_head = apr_table_get(r->err_headers_out, "Warning");
            head_ptr = r->err_headers_out;
        }

        /* it's fresh darlings... */
        /* set age header on response */
        if (age_in_errhdr) {
            apr_table_set(r->err_headers_out, "Age",
                          apr_psprintf(r->pool, "%lu", (unsigned long)age));
        }
        else {
            apr_table_set(r->headers_out, "Age",
                          apr_psprintf(r->pool, "%lu", (unsigned long)age));
        }

        /* add warning if maxstale overrode freshness calculation */
        if (!(((smaxage != -1) && age < smaxage) ||
              ((maxage != -1) && age < maxage) ||
              (info->expire != APR_DATE_BAD && (info->expire - info->date) > age))) {
            /* make sure we don't stomp on a previous warning */
            if ((warn_head == NULL) ||
                ((warn_head != NULL) && (ap_strstr_c(warn_head, "110") == NULL))) {
                apr_table_merge(head_ptr, "Warning", "110 Response is stale");
            }
        }
        /* 
         * If none of Expires, Cache-Control: max-age, or Cache-Control: 
         * s-maxage appears in the response, and the respose header age 
         * calculated is more than 24 hours add the warning 113 
         */
        if ((maxage_cresp == -1) && (smaxage == -1) &&
            (expstr == NULL) && (age > 86400)) {

            /* Make sure we don't stomp on a previous warning, and don't dup
             * a 113 marning that is already present. Also, make sure to add
             * the new warning to the correct *headers_out location.
             */
            if ((warn_head == NULL) ||
                ((warn_head != NULL) && (ap_strstr_c(warn_head, "113") == NULL))) {
                apr_table_merge(head_ptr, "Warning", "113 Heuristic expiration");
            }
        }
        return 1;    /* Cache object is fresh (enough) */
    }
    return 0;        /* Cache object is stale */
}
/* 
 * list is a comma-separated list of case-insensitive tokens, with
 * optional whitespace around the tokens.
 * The return returns 1 if the token val is found in the list, or 0
 * otherwise.
 */
CACHE_DECLARE(int) ap_cache_liststr(apr_pool_t *p, const char *list,
                                    const char *key, char **val)
{
    apr_size_t key_len;
    const char *next;

    if (!list) {
        return 0;
    }

    key_len = strlen(key);
    next = list;

    for (;;) {

        /* skip whitespace and commas to find the start of the next key */
        while (*next && (apr_isspace(*next) || (*next == ','))) {
            next++;
        }

        if (!*next) {
            return 0;
        }

        if (!strncasecmp(next, key, key_len)) {
            /* this field matches the key (though it might just be
             * a prefix match, so make sure the match is followed
             * by either a space or an equals sign)
             */
            next += key_len;
            if (!*next || (*next == '=') || apr_isspace(*next) ||
                (*next == ',')) {
                /* valid match */
                if (val) {
                    while (*next && (*next != '=') && (*next != ',')) {
                        next++;
                    }
                    if (*next == '=') {
                        next++;
                        while (*next && apr_isspace(*next )) {
                            next++;
                        }
                        if (!*next) {
                            *val = NULL;
                        }
                        else {
                            const char *val_start = next;
                            while (*next && !apr_isspace(*next) &&
                                   (*next != ',')) {
                                next++;
                            }
                            *val = apr_pstrmemdup(p, val_start,
                                                  next - val_start);
                        }
                    }
                }
                return 1;
            }
        }

        /* skip to the next field */
        do {
            next++;
            if (!*next) {
                return 0;
            }
        } while (*next != ',');
    }
}

/* return each comma separated token, one at a time */
CACHE_DECLARE(const char *)ap_cache_tokstr(apr_pool_t *p, const char *list, const char **str)
{
    apr_size_t i;
    const char *s;

    s = ap_strchr_c(list, ',');
    if (s != NULL) {
        i = s - list;
        do
            s++;
        while (apr_isspace(*s))
            ; /* noop */
    }
    else
        i = strlen(list);

    while (i > 0 && apr_isspace(list[i - 1]))
        i--;

    *str = s;
    if (i)
        return apr_pstrndup(p, list, i);
    else
        return NULL;
}

/*
 * Converts apr_time_t expressed as hex digits to 
 * a true apr_time_t.
 */
CACHE_DECLARE(apr_time_t) ap_cache_hex2usec(const char *x)
{
    int i, ch;
    apr_time_t j;
    for (i = 0, j = 0; i < sizeof(j) * 2; i++) {
        ch = x[i];
        j <<= 4;
        if (apr_isdigit(ch))
            j |= ch - '0';
        else if (apr_isupper(ch))
            j |= ch - ('A' - 10);
        else
            j |= ch - ('a' - 10);
    }
    return j;
}

/*
 * Converts apr_time_t to apr_time_t expressed as hex digits.
 */
CACHE_DECLARE(void) ap_cache_usec2hex(apr_time_t j, char *y)
{
    int i, ch;

    for (i = (sizeof(j) * 2)-1; i >= 0; i--) {
        ch = (int)(j & 0xF);
        j >>= 4;
        if (ch >= 10)
            y[i] = ch + ('A' - 10);
        else
            y[i] = ch + '0';
    }
    y[sizeof(j) * 2] = '\0';
}

static void cache_hash(const char *it, char *val, int ndepth, int nlength)
{
    apr_md5_ctx_t context;
    unsigned char digest[16];
    char tmp[22];
    int i, k, d;
    unsigned int x;
    static const char enc_table[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@";

    apr_md5_init(&context);
    apr_md5_update(&context, (const unsigned char *) it, strlen(it));
    apr_md5_final(digest, &context);

    /* encode 128 bits as 22 characters, using a modified uuencoding 
     * the encoding is 3 bytes -> 4 characters* i.e. 128 bits is 
     * 5 x 3 bytes + 1 byte -> 5 * 4 characters + 2 characters
     */
    for (i = 0, k = 0; i < 15; i += 3) {
        x = (digest[i] << 16) | (digest[i + 1] << 8) | digest[i + 2];
        tmp[k++] = enc_table[x >> 18];
        tmp[k++] = enc_table[(x >> 12) & 0x3f];
        tmp[k++] = enc_table[(x >> 6) & 0x3f];
        tmp[k++] = enc_table[x & 0x3f];
    }

    /* one byte left */
    x = digest[15];
    tmp[k++] = enc_table[x >> 2];    /* use up 6 bits */
    tmp[k++] = enc_table[(x << 4) & 0x3f];

    /* now split into directory levels */
    for (i = k = d = 0; d < ndepth; ++d) {
        memcpy(&val[i], &tmp[k], nlength);
        k += nlength;
        val[i + nlength] = '/';
        i += nlength + 1;
    }
    memcpy(&val[i], &tmp[k], 22 - k);
    val[i + 22 - k] = '\0';
}

CACHE_DECLARE(char *)generate_name(apr_pool_t *p, int dirlevels, int dirlength, const char *name)
{
    char hashfile[66];
    cache_hash(name, hashfile, dirlevels, dirlength);
    return apr_pstrdup(p, hashfile);
}

/* Create a new table consisting of those elements from an input
 * headers table that are allowed to be stored in a cache.
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_hdrs_out(apr_pool_t *pool,
                                                        apr_table_t *t)
{
    /* Make a copy of the headers, and remove from
     * the copy any hop-by-hop headers, as defined in Section
     * 13.5.1 of RFC 2616
     */
    apr_table_t *headers_out;
    headers_out = apr_table_copy(pool, t);
    apr_table_unset(headers_out, "Connection");
    apr_table_unset(headers_out, "Keep-Alive");
    apr_table_unset(headers_out, "Proxy-Authenticate");
    apr_table_unset(headers_out, "Proxy-Authorization");
    apr_table_unset(headers_out, "TE");
    apr_table_unset(headers_out, "Trailers");
    apr_table_unset(headers_out, "Transfer-Encoding");
    apr_table_unset(headers_out, "Upgrade");
    return headers_out;
}
