/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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
int ap_cache_request_is_conditional(request_rec *r)
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
void ap_cache_reset_output_filters(request_rec *r)
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

const char *ap_cache_get_cachetype(request_rec *r, 
                                   cache_server_conf *conf, 
                                   const char *url)
{
    const char *type = NULL;
    int i;

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

/*
 * list is a comma-separated list of case-insensitive tokens, with
 * optional whitespace around the tokens.
 * The return returns 1 if the token val is found in the list, or 0
 * otherwise.
 */
int ap_cache_liststr(const char *list, const char *key, char **val)
{
    int len, i;
    char *p;
    char valbuf[HUGE_STRING_LEN];
    valbuf[sizeof(valbuf)-1] = 0; /* safety terminating zero */

    len = strlen(key);

    while (list != NULL) {
        p = strchr((char *) list, ',');
        if (p != NULL) {
            i = p - list;
            do
            p++;
            while (ap_isspace(*p));
        }
        else
            i = strlen(list);

        while (i > 0 && ap_isspace(list[i - 1]))
            i--;
        if (i == len && strncasecmp(list, key, len) == 0) {
            if (val) {
            p = strchr((char *) list, ',');
            while (ap_isspace(*list)) {
                list++;
            }
            if ('=' == list[0])
                list++;
            while (ap_isspace(*list)) {
                list++;
            }
            strncpy(valbuf, list, MIN(p-list, sizeof(valbuf)-1));
            *val = valbuf;
            }
            return 1;
        }
        list = p;
    }
    return 0;
}

/* return each comma separated token, one at a time */
const char *ap_cache_tokstr(apr_pool_t *p, const char *list, const char **str)
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
 * XXX TODO:
 * These functions were lifted from mod_proxy
 * Consider putting them in APR or some other common accessable
 * location.
 */
/*
 * Converts apr_time_t hex digits to a time integer
 */
static apr_time_t ap_cache_hex2msec(const char *x)
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
 * Converts a time integer to apr_time_t hex digits
 */
static void ap_cache_msec2hex(apr_time_t j, char *y)
{
    int i, ch;

    for (i = (sizeof(j) * 2)-1; i >= 0; i--) {
        ch = j & 0xF;
        j >>= 4;
        if (ch >= 10)
            y[i] = ch + ('A' - 10);
        else
            y[i] = ch + '0';
    }
    y[sizeof(j) * 2] = '\0';
}

int mkdir_structure(char *file, const char *root)
{
    
    /* XXX TODO: Use APR to make a root directory. Do some sanity checking... */
    return 0;
}

cache_info * create_cache_el(apr_pool_t *p, cache_handle_t *h, const char *name)
{
    cache_info *info = apr_pcalloc(p, sizeof(cache_info));
    memset(info, '\0', sizeof(cache_info));
    info->name = (char *)name;
    return info;
}

/* These two functions get and put state information into the data 
 * file for an ap_cache_el, this state information will be read 
 * and written transparent to clients of this module 
 */
int file_cache_read_mydata(apr_file_t *fd, cache_info *info, request_rec *r)
{
    apr_status_t rv;
    char urlbuff[1034];
    int urllen = sizeof(urlbuff);
    int offset=0;
    char * temp;

    if(!info->hdrsfile) {
	return APR_NOTFOUND;
    }

    /* read the data from the cache file */
    /* format
     * date SP expire SP count CRLF
     * dates are stored as hex seconds since 1970
     */
    rv = apr_file_gets(&urlbuff[0], urllen, fd);
    if (rv != APR_SUCCESS)
    {
	return rv;
    }

    if ((temp = strchr(&urlbuff[0], '\n')) != NULL) /* trim off new line character */
	*temp = '\0';      /* overlay it with the null terminator */

    if (!apr_date_checkmask(urlbuff, "&&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&&"))
    {
        return APR_EGENERAL;
    }

    info->date = ap_cache_hex2msec(urlbuff + offset);
    offset += (sizeof(info->date)*2) + 1;
    info->expire = ap_cache_hex2msec(urlbuff + offset);
    offset += (sizeof(info->expire)*2) + 1;
    info->version = ap_cache_hex2msec(urlbuff + offset);
    
    /* check that we have the same URL */
    rv = apr_file_gets(&urlbuff[0], urllen, fd);
    if (rv != APR_SUCCESS)
    {
	return rv;
    }

    if ((temp = strchr(&urlbuff[0], '\n')) != NULL) /* trim off new line character */
	*temp = '\0';      /* overlay it with the null terminator */

    if (strncmp(urlbuff, "X-NAME: ", 7) != 0)
    {
	return APR_EGENERAL;
    }
    if (strcmp(urlbuff + 8, info->name) != 0)
    {
        return APR_EGENERAL;
    }
    
    return APR_SUCCESS;
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

static char *generate_name(apr_pool_t *p, cache_handle_t *h, const char *name)
{
    char hashfile[66], *filebase;
    cache_hash(name, hashfile, h->dirlevels, h->dirlength);
    filebase = apr_pstrcat(p, h->root, "/", hashfile, "%s", NULL);
    return filebase;
}
char *header_file(cache_handle_t *h, apr_pool_t *p, const char *name)
{
    return apr_psprintf(p, generate_name(p, h, name), CACHE_HEADER_SUFFIX);
}
char *data_file(cache_handle_t *h, apr_pool_t *p, const char *name)
{
    return apr_psprintf(p, generate_name(p, h, name), CACHE_DATA_SUFFIX);
}
