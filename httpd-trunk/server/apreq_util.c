/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

#include "apreq_util.h"
#include "apreq_error.h"
#include "apr_time.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include <assert.h>

#undef MAX
#undef MIN
#define MIN(a,b) ( (a) < (b) ? (a) : (b) )
#define MAX(a,b) ( (a) > (b) ? (a) : (b) )

/* used for specifying file sizes */

APREQ_DECLARE(apr_int64_t) apreq_atoi64f(const char *s)
{
    apr_int64_t n = 0;
    char *p;
    if (s == NULL)
        return 0;

    n = apr_strtoi64(s, &p, 0);

    if (p == NULL)
        return n;
    while (apr_isspace(*p))
        ++p;

    switch (*p) {
      case 'G': /* fall thru */
      case 'g': return n * 1024*1024*1024;
      case 'M': /* fall thru */
      case 'm': return n * 1024*1024;
      case 'K': /* fall thru */
      case 'k': return n * 1024;
    }

    return n;
}


/* converts date offsets (e.g. "+3M") to seconds */

APREQ_DECLARE(apr_int64_t) apreq_atoi64t(const char *s)
{
    apr_int64_t n = 0;
    char *p;
    if (s == NULL)
        return 0;
    n = apr_strtoi64(s, &p, 0); /* XXX: what about overflow? */

    if (p == NULL)
        return n;
    while (apr_isspace(*p))
        ++p;

    switch (*p) {
      case 'Y': /* fall thru */
      case 'y': return n * 60*60*24*365;
      case 'M': return n * 60*60*24*30;
      case 'D': /* fall thru */
      case 'd': return n * 60*60*24;
      case 'H': /* fall thru */
      case 'h': return n * 60*60;
      case 'm': return n * 60;
      case 's': /* fall thru */
      default:
          return n;
    }
    /* should never get here */
    return -1;
}


APREQ_DECLARE(apr_ssize_t ) apreq_index(const char* hay, apr_size_t hlen,
                                        const char* ndl, apr_size_t nlen,
                                        const apreq_match_t type)
{
    apr_size_t len = hlen;
    const char *end = hay + hlen;
    const char *begin = hay;

    while ( (hay = memchr(hay, ndl[0], len)) ) {
	len = end - hay;

	/* done if matches up to capacity of buffer */
	if ( memcmp(hay, ndl, MIN(nlen, len)) == 0 ) {
            if (type == APREQ_MATCH_FULL && len < nlen)
                hay = NULL;     /* insufficient room for match */
	    break;
        }
        --len;
        ++hay;
    }

    return hay ? hay - begin : -1;
}


static const char c2x_table[] = "0123456789ABCDEF";
static APR_INLINE unsigned char hex2_to_char(const char *what)
{
    register unsigned char digit;

#if !APR_CHARSET_EBCDIC
    digit  = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));
#else /*APR_CHARSET_EBCDIC*/
    char xstr[5];
    xstr[0]='0';
    xstr[1]='x';
    xstr[2]=what[0];
    xstr[3]=what[1];
    xstr[4]='\0';
    digit = apr_xlate_conv_byte(ap_hdrs_from_ascii, 0xFF & strtol(xstr, NULL, 16));
#endif /*APR_CHARSET_EBCDIC*/
    return (digit);
}


/* Unicode notes: "bmp" refers to the 16-bit
 * Unicode Basic Multilingual Plane. Here we're
 * restricting our unicode internals to 16-bit
 * codepoints, to keep the code as simple as possible.
 * This should be sufficient for apreq itself, since
 * we really only need to validate RFC3986-encoded utf8.
 */

/* Converts Windows cp1252 to Unicode. */

static APR_INLINE
apr_uint16_t cp1252_to_bmp(unsigned char c)
{
    /* We only need to deal with iso-8859-1 control chars
     * in the 0x80 - 0x9F range.
     */
    if ((c & 0xE0) != 0x80)
        return c;

    switch (c) {
    case 0x80: return 0x20AC;
    case 0x82: return 0x201A;
    case 0x83: return 0x192;
    case 0x84: return 0x201E;
    case 0x85: return 0x2026;
    case 0x86: return 0x2020;
    case 0x87: return 0x2021;
    case 0x88: return 0x2C6;
    case 0x89: return 0x2030;
    case 0x8A: return 0x160;
    case 0x8B: return 0x2039;
    case 0x8C: return 0x152;
    case 0x8E: return 0x17D;
    case 0x91: return 0x2018;
    case 0x92: return 0x2019;
    case 0x93: return 0x201C;
    case 0x94: return 0x201D;
    case 0x95: return 0x2022;
    case 0x96: return 0x2013;
    case 0x97: return 0x2014;
    case 0x98: return 0x2DC;
    case 0x99: return 0x2122;
    case 0x9A: return 0x161;
    case 0x9B: return 0x203A;
    case 0x9C: return 0x153;
    case 0x9E: return 0x17E;
    case 0x9F: return 0x178;
    }
    return c;
}

/* converts cp1252 to utf8 */
APREQ_DECLARE(apr_size_t) apreq_cp1252_to_utf8(char *dest,
                                               const char *src, apr_size_t slen)
{
    const unsigned char *s = (unsigned const char *)src;
    const unsigned char *end = s + slen;
    unsigned char *d = (unsigned char *)dest;
    apr_uint16_t c;

    while (s < end) {
        c = cp1252_to_bmp(*s++);

        if (c < 0x80) {
            *d++ = c;
        }
        else if (c < 0x800) {
            *d++ = 0xC0 | (c >> 6);
            *d++ = 0x80 | (c & 0x3F);
        }
        else {
            *d++ = 0xE0 | (c >> 12);
            *d++ = 0x80 | ((c >> 6) & 0x3F);
            *d++ = 0x80 | (c & 0x3F);
        }
    }
    *d = 0;
    return d - (unsigned char *)dest;
}


/**
 * Valid utf8 bit patterns: (true utf8 must satisfy a minimality condition)
 *
 * 0aaaaaaa
 * 110bbbba 10aaaaaa                        minimality mask: 0x1E
 * 1110cccc 10cbbbba 10aaaaaa                                0x0F || 0x20
 * 11110ddd 10ddcccc 10cbbbba 10aaaaaa                       0x07 || 0x30
 * 111110ee 10eeeddd 10ddcccc 10cbbbba 10aaaaaa              0x03 || 0x38
 * 1111110f 10ffffee 10eeeddd 10ddcccc 10cbbbba 10aaaaaa     0x01 || 0x3C
 *
 * Charset divination heuristics:
 * 1) presume ascii; if not, then
 * 2) presume utf8; if not, then
 * 3) presume latin1; unless there are control chars, in which case
 * 4) punt to cp1252.
 *
 * Note: in downgrading from 2 to 3, we need to be careful
 * about earlier control characters presumed to be valid utf8.
 */

APREQ_DECLARE(apreq_charset_t) apreq_charset_divine(const char *src,
                                                    apr_size_t slen)

{
    apreq_charset_t rv = APREQ_CHARSET_ASCII;
    register unsigned char trail = 0, saw_cntrl = 0, mask = 0;
    register const unsigned char *s = (const unsigned char *)src;
    const unsigned char *end = s + slen;

    for (; s < end; ++s) {
        if (trail) {
            if ((*s & 0xC0) == 0x80 && (mask == 0 || (mask & *s))) {
                mask = 0;
                --trail;

                if ((*s & 0xE0) == 0x80) {
                    saw_cntrl = 1;
                }
            }
            else {
                trail = 0;
                if (saw_cntrl)
                    return APREQ_CHARSET_CP1252;
                rv = APREQ_CHARSET_LATIN1;
            }
        }
        else if (*s < 0x80) {
            /* do nothing */
        }
        else if (*s < 0xA0) {
            return APREQ_CHARSET_CP1252;
        }
        else if (*s < 0xC0) {
            if (saw_cntrl)
                return APREQ_CHARSET_CP1252;
            rv = APREQ_CHARSET_LATIN1;
        }
        else if (rv == APREQ_CHARSET_LATIN1) {
            /* do nothing */
        }

        /* utf8 cases */

        else if (*s < 0xE0) {
            if (*s & 0x1E) {
                rv = APREQ_CHARSET_UTF8;
                trail = 1;
                mask = 0;
            }
            else if (saw_cntrl)
                return APREQ_CHARSET_CP1252;
            else
                rv = APREQ_CHARSET_LATIN1;
        }
        else if (*s < 0xF0) {
            mask = (*s & 0x0F) ? 0 : 0x20;
            rv = APREQ_CHARSET_UTF8;
            trail = 2;
        }
        else if (*s < 0xF8) {
            mask = (*s & 0x07) ? 0 : 0x30;
            rv = APREQ_CHARSET_UTF8;
            trail = 3;
        }
        else if (*s < 0xFC) {
            mask = (*s & 0x03) ? 0 : 0x38;
            rv = APREQ_CHARSET_UTF8;
            trail = 4;
        }
        else if (*s < 0xFE) {
            mask = (*s & 0x01) ? 0 : 0x3C;
            rv = APREQ_CHARSET_UTF8;
            trail = 5;
        }
        else {
            rv = APREQ_CHARSET_UTF8;
        }
    }

    return trail ? saw_cntrl ?
        APREQ_CHARSET_CP1252 : APREQ_CHARSET_LATIN1 : rv;
}


static APR_INLINE apr_uint16_t hex4_to_bmp(const char *what) {
    register apr_uint16_t digit = 0;

#if !APR_CHARSET_EBCDIC
    digit  = (what[0] >= 'A' ? ((what[0] & 0xDF)-'A') + 10 : (what[0]-'0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xDF)-'A') + 10 : (what[1]-'0'));
    digit *= 16;
    digit += (what[2] >= 'A' ? ((what[2] & 0xDF)-'A') + 10 : (what[2]-'0'));
    digit *= 16;
    digit += (what[3] >= 'A' ? ((what[3] & 0xDF)-'A') + 10 : (what[3]-'0'));

#else /*APR_CHARSET_EBCDIC*/
    char xstr[7];
    xstr[0]='0';
    xstr[1]='x';
    xstr[2]=what[0];
    xstr[3]=what[1];
    xstr[4]=what[2];
    xstr[5]=what[3];
    xstr[6]='\0';
    digit = apr_xlate_conv_byte(ap_hdrs_from_ascii, 0xFFFF & strtol(xstr, NULL, 16));
#endif /*APR_CHARSET_EBCDIC*/
    return (digit);
}


static apr_status_t url_decode(char *dest, apr_size_t *dlen,
                               const char *src, apr_size_t *slen)
{
    register const char *s = src;
    unsigned char *start = (unsigned char *)dest;
    register unsigned char *d = (unsigned char *)dest;
    const char *end = src + *slen;

    for (; s < end; ++d, ++s) {
        switch (*s) {

        case '+':
            *d = ' ';
            break;

        case '%':
	    if (s + 2 < end && apr_isxdigit(s[1]) && apr_isxdigit(s[2]))
            {
                *d = hex2_to_char(s + 1);
                s += 2;
	    }
            else if (s + 5 < end && (s[1] == 'u' || s[1] == 'U') &&
                     apr_isxdigit(s[2]) && apr_isxdigit(s[3]) &&
                     apr_isxdigit(s[4]) && apr_isxdigit(s[5]))
            {
                apr_uint16_t c = hex4_to_bmp(s+2);

                if (c < 0x80) {
                    *d = c;
                }
                else if (c < 0x800) {
                    *d++ = 0xC0 | (c >> 6);
                    *d   = 0x80 | (c & 0x3F);
                }
                else {
                    *d++ = 0xE0 | (c >> 12);
                    *d++ = 0x80 | ((c >> 6) & 0x3F);
                    *d   = 0x80 | (c & 0x3F);
                }
                s += 5;
            }
	    else {
                *dlen = d - start;
                *slen = s - src;
                if (s + 5 < end
                    || (s + 2 < end && !apr_isxdigit(s[2]))
                    || (s + 1 < end && !apr_isxdigit(s[1])
                        && s[1] != 'u' && s[1] != 'U'))
                {
                    *d = 0;
                    return APREQ_ERROR_BADSEQ;
                }

                memmove(d, s, end - s);
                d[end - s] = 0;
                return APR_INCOMPLETE;
	    }
            break;

        default:
            if (*s > 0) {
                *d = *s;
            }
            else {
                *d = 0;
                *dlen = d - start;
                *slen = s - src;
                return APREQ_ERROR_BADCHAR;
            }
        }
    }

    *d = 0;
    *dlen = d - start;
    *slen = s - src;
    return APR_SUCCESS;
}


APREQ_DECLARE(apr_status_t) apreq_decode(char *d, apr_size_t *dlen,
                                         const char *s, apr_size_t slen)
{
    apr_size_t len = 0;
    const char *end = s + slen;

    if (s == (const char *)d) {     /* optimize for src = dest case */
        for ( ; d < end; ++d) {
            if (*d == '%' || *d == '+')
                break;
            else if (*d == 0) {
                *dlen = (const char *)d - s;
                return APREQ_ERROR_BADCHAR;
            }
        }
        len = (const char *)d - s;
        s = (const char *)d;
        slen -= len;
    }

    return url_decode(d, dlen, s, &slen);
}

APREQ_DECLARE(apr_status_t) apreq_decodev(char *d, apr_size_t *dlen,
                                          struct iovec *v, int nelts)
{
    apr_status_t status = APR_SUCCESS;
    int n = 0;

    *dlen = 0;

    while (n < nelts) {
        apr_size_t slen, len;

        slen = v[n].iov_len;
        switch (status = url_decode(d, &len, v[n].iov_base, &slen)) {

        case APR_SUCCESS:
            d += len;
            *dlen += len;
            ++n;
            continue;

        case APR_INCOMPLETE:
            d += len;
            *dlen += len;
            slen = v[n].iov_len - slen;

            if (++n == nelts) {
                return status;
            }
            memcpy(d + slen, v[n].iov_base, v[n].iov_len);
            v[n].iov_len += slen;
            v[n].iov_base = d;
            continue;

        default:
            *dlen += len;
            return status;
        }
    }

    return status;
}


APREQ_DECLARE(apr_size_t) apreq_encode(char *dest, const char *src,
                                       const apr_size_t slen)
{
    char *d = dest;
    const unsigned char *s = (const unsigned char *)src;
    unsigned char c;

    for ( ; s < (const unsigned char *)src + slen; ++s) {
        c = *s;
        if ( c < 0x80 && (apr_isalnum(c)
                          || c == '-' || c == '.'
                          || c == '_' || c == '~') )
            *d++ = c;

        else if ( c == ' ' )
            *d++ = '+';

        else {
#if APR_CHARSET_EBCDIC
            c = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)c);
#endif
            *d++ = '%';
            *d++ = c2x_table[c >> 4];
            *d++ = c2x_table[c & 0xf];
        }
    }
    *d = 0;

    return d - dest;
}

static int is_quoted(const char *p, const apr_size_t len) {
    if (len > 1 && p[0] == '"' && p[len-1] == '"') {
        apr_size_t i;
        int backslash = 0;

        for (i = 1; i < len - 1; i++) {
            if (p[i] == '\\')
                backslash = !backslash;
            else if (p[i] == 0 || (p[i] == '"' && !backslash))
                return 0;
            else
                backslash = 0;
        }

        return !backslash;
    }

    return 0;
}

APREQ_DECLARE(apr_size_t) apreq_quote_once(char *dest, const char *src,
                                           const apr_size_t slen)
{
    if (is_quoted(src, slen)) {
        /* looks like src is already quoted */
        memcpy(dest, src, slen);
        dest[slen] = 0;
        return slen;
    }
    else
        return apreq_quote(dest, src, slen);
}

APREQ_DECLARE(apr_size_t) apreq_quote(char *dest, const char *src,
                                      const apr_size_t slen)
{
    char *d = dest;
    const char *s = src;
    const char *const last = src + slen - 1;

    if (slen == 0) {
        *d = 0;
        return 0;
    }

    *d++ = '"';

    while (s <= last) {
        switch (*s) {
        case 0:
            *d++ = '\\';
            *d++ = '0';
            s++;
            break;

        case '\\':
        case '"':
            *d++ = '\\';

        default:
            *d++ = *s++;
        }
    }

    *d++ = '"';
    *d = 0;

    return d - dest;
}

APREQ_DECLARE(char *) apreq_join(apr_pool_t *p,
                                 const char *sep,
                                 const apr_array_header_t *arr,
                                 apreq_join_t mode)
{
    apr_size_t len, slen;
    char *rv;
    const apreq_value_t **a = (const apreq_value_t **)arr->elts;
    char *d;
    const int n = arr->nelts;
    int j;

    slen = sep ? strlen(sep) : 0;

    if (n == 0)
        return apr_pstrdup(p, "");

    for (j=0, len=0; j < n; ++j)
        len += a[j]->dlen + slen + 1;

    /* Allocated the required space */

    switch (mode) {
    case APREQ_JOIN_ENCODE:
        len += 2 * len;
        break;
    case APREQ_JOIN_QUOTE:
        len = 2 * (len + n);
        break;
    case APREQ_JOIN_AS_IS:
    case APREQ_JOIN_DECODE:
        /* nothing special required, just here to keep noisy compilers happy */
        break;
    }

    rv = apr_palloc(p, len);

    /* Pass two --- copy the argument strings into the result space */

    d = rv;

    switch (mode) {

    case APREQ_JOIN_ENCODE:
        d += apreq_encode(d, a[0]->data, a[0]->dlen);

        for (j = 1; j < n; ++j) {
                memcpy(d, sep, slen);
                d += slen;
                d += apreq_encode(d, a[j]->data, a[j]->dlen);
        }
        break;

    case APREQ_JOIN_DECODE:
        if (apreq_decode(d, &len, a[0]->data, a[0]->dlen))
            return NULL;
        else
            d += len;

        for (j = 1; j < n; ++j) {
            memcpy(d, sep, slen);
            d += slen;

            if (apreq_decode(d, &len, a[j]->data, a[j]->dlen))
                return NULL;
            else
                d += len;
        }
        break;


    case APREQ_JOIN_QUOTE:
        d += apreq_quote_once(d, a[0]->data, a[0]->dlen);

        for (j = 1; j < n; ++j) {
            memcpy(d, sep, slen);
            d += slen;
            d += apreq_quote_once(d, a[j]->data, a[j]->dlen);
        }
        break;


    case APREQ_JOIN_AS_IS:
        memcpy(d,a[0]->data, a[0]->dlen);
        d += a[0]->dlen;

        for (j = 1; j < n ; ++j) {
            memcpy(d, sep, slen);
            d += slen;
            memcpy(d, a[j]->data, a[j]->dlen);
            d += a[j]->dlen;
        }
        break;
    }

    *d = 0;
    return rv;
}

/*
 * This is intentionally not apr_file_writev()
 * note, this is iterative and not recursive
 */
APR_INLINE
static apr_status_t apreq_fwritev(apr_file_t *f, struct iovec *v,
                                  int *nelts, apr_size_t *bytes_written)
{
    apr_size_t len;
    int n;
    apr_status_t s;

    *bytes_written = 0;

    while (1) {
        /* try to write */
        s = apr_file_writev(f, v, *nelts, &len);

        *bytes_written += len;

        if (s != APR_SUCCESS)
            return s;

        /* see how far we've come */
        n = 0;

#ifdef SOLARIS2
# ifdef __GNUC__
        /*
         * iovec.iov_len is a long here
         * which causes a comparison between 
         * signed(long) and unsigned(apr_size_t)
         *
         */
        while (n < *nelts && len >= (apr_size_t)v[n].iov_len)
# else
          /*
           * Sun C however defines this as size_t which is unsigned
           * 
           */
        while (n < *nelts && len >= v[n].iov_len)
# endif /* !__GNUC__ */
#else
          /*
           * Hopefully everything else does this
           * (this was the default for years)
           */
        while (n < *nelts && len >= v[n].iov_len)
#endif
            len -= v[n++].iov_len;

        if (n == *nelts) {
            /* nothing left to write, report success */
            *nelts = 0;
            return APR_SUCCESS;
        }

        /* incomplete write: must shift v */
        v[n].iov_len -= len;
        v[n].iov_base = (char *)(v[n].iov_base) + len;

        if (n > 0) {
            /* we're satisfied for now if we can remove one iovec from
               the "v" array */
            (*nelts) -= n;
            memmove(v, v + n, sizeof(*v) * *nelts);

            return APR_SUCCESS;
        }

        /* we're still in the first iovec - check for endless loop,
           and then try again */
        if (len == 0)
            return APREQ_ERROR_GENERAL;
    }
}




struct cleanup_data {
    const char *fname;
    apr_pool_t *pool;
};

static apr_status_t apreq_file_cleanup(void *d)
{
    struct cleanup_data *data = d;
    return apr_file_remove(data->fname, data->pool);
}

/*
 * The reason we need the above cleanup is because on Windows, APR_DELONCLOSE
 * forces applications to open the file with FILE_SHARED_DELETE
 * set, which is, unfortunately, a property that is preserved
 * across NTFS "hard" links.  This breaks apps that link() the temp
 * file to a permanent location, and subsequently expect to open it
 * before the original tempfile is closed+deleted. In fact, even
 * Apache::Upload does this, so it is a common enough event that the
 * apreq_file_cleanup workaround is necessary.
 */

APREQ_DECLARE(apr_status_t) apreq_file_mktemp(apr_file_t **fp,
                                              apr_pool_t *pool,
                                              const char *path)
{
    apr_status_t rc;
    char *tmpl;
    struct cleanup_data *data;
    apr_int32_t flag;

    if (path == NULL) {
        rc = apr_temp_dir_get(&path, pool);
        if (rc != APR_SUCCESS)
            return rc;
    }
    rc = apr_filepath_merge(&tmpl, path, "apreqXXXXXX",
                            APR_FILEPATH_NOTRELATIVE, pool);

    if (rc != APR_SUCCESS)
        return rc;

    data = apr_palloc(pool, sizeof *data);
    /* cleanups are LIFO, so this one will run just after
       the cleanup set by mktemp */
    apr_pool_cleanup_register(pool, data,
                              apreq_file_cleanup, apreq_file_cleanup);

    /* NO APR_DELONCLOSE! see comment above */
    flag = APR_CREATE | APR_READ | APR_WRITE | APR_EXCL | APR_BINARY;

    rc = apr_file_mktemp(fp, tmpl, flag, pool);

    if (rc == APR_SUCCESS) {
        apr_file_name_get(&data->fname, *fp);
        data->pool = pool;
    }
    else {
        apr_pool_cleanup_kill(pool, data, apreq_file_cleanup);
    }

    return rc;
}


/*
 * is_2616_token() is the verbatim definition from section 2.2
 * in the rfc itself.  We try to optimize it around the
 * expectation that the argument is not a token, which
 * should be the typical usage.
 */

static APR_INLINE
unsigned is_2616_token(const char c) {
    switch (c) {
    case ' ': case ';': case ',': case '"': case '\t':
        /* The chars we are expecting are listed above;
           the chars below are just for completeness. */
    case '?': case '=': case '@': case ':': case '\\': case '/':
    case '(': case ')':
    case '<': case '>':
    case '{': case '}':
    case '[': case ']':
        return 0;
    default:
        if (apr_iscntrl(c))
            return 0;
    }
    return 1;
}

APREQ_DECLARE(apr_status_t)
    apreq_header_attribute(const char *hdr,
                           const char *name, const apr_size_t nlen,
                           const char **val, apr_size_t *vlen)
{
    const char *key, *v;

    /* Must ensure first char isn't '=', so we can safely backstep. */
    while (*hdr == '=')
        ++hdr;

    while ((key = strchr(hdr, '=')) != NULL) {

        v = key + 1;
        --key;

        while (apr_isspace(*key) && key > hdr + nlen)
            --key;

        key -= nlen - 1;

        while (apr_isspace(*v))
            ++v;

        if (*v == '"') {
            ++v;
            *val = v;

        look_for_end_quote:
            switch (*v) {
            case '"':
                break;
            case 0:
                return APREQ_ERROR_BADSEQ;
            case '\\':
                if (v[1] != 0)
                    ++v;
            default:
                ++v;
                goto look_for_end_quote;
            }
        }
        else {
            *val = v;

        look_for_terminator:
            switch (*v) {
            case 0:
            case ' ':
            case ';':
            case ',':
            case '\t':
            case '\r':
            case '\n':
                break;
            default:
                ++v;
                goto look_for_terminator;
            }
        }

        if (key >= hdr && strncasecmp(key, name, nlen) == 0) {
            *vlen = v - *val;
            if (key == hdr || ! is_2616_token(key[-1]))
                return APR_SUCCESS;
        }
        hdr = v;
    }

    return APREQ_ERROR_NOATTR;
}



#define BUCKET_IS_SPOOL(e) ((e)->type == &spool_bucket_type)
#define FILE_BUCKET_LIMIT      ((apr_size_t)-1 - 1)

static
void spool_bucket_destroy(void *data)
{
    apr_bucket_type_file.destroy(data);
}

static
apr_status_t spool_bucket_read(apr_bucket *e, const char **str,
                                   apr_size_t *len, apr_read_type_e block)
{
    return apr_bucket_type_file.read(e, str, len, block);
}

static
apr_status_t spool_bucket_setaside(apr_bucket *data, apr_pool_t *reqpool)
{
    return apr_bucket_type_file.setaside(data, reqpool);
}

static
apr_status_t spool_bucket_split(apr_bucket *a, apr_size_t point)
{
    apr_status_t rv = apr_bucket_shared_split(a, point);
    a->type = &apr_bucket_type_file;
    return rv;
}

static
apr_status_t spool_bucket_copy(apr_bucket *e, apr_bucket **c)
{
    apr_status_t rv = apr_bucket_shared_copy(e, c);
    (*c)->type = &apr_bucket_type_file;
    return rv;
}

static const apr_bucket_type_t spool_bucket_type = {
    "APREQ_SPOOL", 5, APR_BUCKET_DATA,
    spool_bucket_destroy,
    spool_bucket_read,
    spool_bucket_setaside,
    spool_bucket_split,
    spool_bucket_copy,
};

APREQ_DECLARE(apr_file_t *)apreq_brigade_spoolfile(apr_bucket_brigade *bb)
{
    apr_bucket *last;

    last = APR_BRIGADE_LAST(bb);
    if (BUCKET_IS_SPOOL(last))
        return ((apr_bucket_file *)last->data)->fd;

    return NULL;
}

APREQ_DECLARE(apr_status_t) apreq_brigade_concat(apr_pool_t *pool,
                                                 const char *temp_dir,
                                                 apr_size_t heap_limit,
                                                 apr_bucket_brigade *out,
                                                 apr_bucket_brigade *in)
{
    apr_status_t s;
    apr_bucket_file *f;
    apr_off_t wlen;
    apr_file_t *file;
    apr_off_t in_len, out_len;
    apr_bucket *last_in, *last_out;

    last_out = APR_BRIGADE_LAST(out);

    if (APR_BUCKET_IS_EOS(last_out))
        return APR_EOF;

    s = apr_brigade_length(out, 0, &out_len);
    if (s != APR_SUCCESS)
        return s;

    /* This cast, when out_len = -1, is intentional */
    if ((apr_uint64_t)out_len < heap_limit) {

        s = apr_brigade_length(in, 0, &in_len);
        if (s != APR_SUCCESS)
            return s;

        /* This cast, when in_len = -1, is intentional */
        if ((apr_uint64_t)in_len < heap_limit - (apr_uint64_t)out_len) {
            APR_BRIGADE_CONCAT(out, in);
            return APR_SUCCESS;
        }
    }

    if (!BUCKET_IS_SPOOL(last_out)) {

        s = apreq_file_mktemp(&file, pool, temp_dir);
        if (s != APR_SUCCESS)
            return s;

        s = apreq_brigade_fwrite(file, &wlen, out);

        if (s != APR_SUCCESS)
            return s;

        last_out = apr_bucket_file_create(file, wlen, 0,
                                          out->p, out->bucket_alloc);
        last_out->type = &spool_bucket_type;
        APR_BRIGADE_INSERT_TAIL(out, last_out);
        f = last_out->data;
    }
    else {
        f = last_out->data;
        /* Need to seek here, just in case our spool bucket
         * was read from between apreq_brigade_concat calls.
         */
        wlen = last_out->start + last_out->length;
        s = apr_file_seek(f->fd, APR_SET, &wlen);
        if (s != APR_SUCCESS)
            return s;
    }

    if (in == out)
        return APR_SUCCESS;

    last_in = APR_BRIGADE_LAST(in);

    if (APR_BUCKET_IS_EOS(last_in))
        APR_BUCKET_REMOVE(last_in);

    s = apreq_brigade_fwrite(f->fd, &wlen, in);

    if (s == APR_SUCCESS) {

        /* We have to deal with the possibility that the new
         * data may be too large to be represented by a single
         * temp_file bucket.
         */

        while ((apr_uint64_t)wlen > FILE_BUCKET_LIMIT - last_out->length) {
            apr_bucket *e;

            apr_bucket_copy(last_out, &e);
            e->length = 0;
            e->start = last_out->start + FILE_BUCKET_LIMIT;
            wlen -= FILE_BUCKET_LIMIT - last_out->length;
            last_out->length = FILE_BUCKET_LIMIT;

            /* Copying makes the bucket types exactly the
             * opposite of what we need here.
             */
            last_out->type = &apr_bucket_type_file;
            e->type = &spool_bucket_type;

            APR_BRIGADE_INSERT_TAIL(out, e);
            last_out = e;
        }

        last_out->length += wlen;

        if (APR_BUCKET_IS_EOS(last_in))
            APR_BRIGADE_INSERT_TAIL(out, last_in);

    }
    else if (APR_BUCKET_IS_EOS(last_in))
        APR_BRIGADE_INSERT_TAIL(in, last_in);

    apr_brigade_cleanup(in);
    return s;
}

APREQ_DECLARE(apr_status_t) apreq_brigade_fwrite(apr_file_t *f,
                                                 apr_off_t *wlen,
                                                 apr_bucket_brigade *bb)
{
    struct iovec v[APREQ_DEFAULT_NELTS];
    apr_status_t s;
    apr_bucket *e, *first;
    int n = 0;
    apr_bucket_brigade *tmp = bb;
    *wlen = 0;

    if (BUCKET_IS_SPOOL(APR_BRIGADE_LAST(bb))) {
        tmp = apr_brigade_create(bb->p, bb->bucket_alloc);

        s = apreq_brigade_copy(tmp, bb);
        if (s != APR_SUCCESS)
            return s;
    }

    for (e = APR_BRIGADE_FIRST(tmp); e != APR_BRIGADE_SENTINEL(tmp);
         e = APR_BUCKET_NEXT(e))
    {
        apr_size_t len;
        if (n == APREQ_DEFAULT_NELTS) {
            s = apreq_fwritev(f, v, &n, &len);
            if (s != APR_SUCCESS)
                return s;

            if (tmp != bb) {
                while ((first = APR_BRIGADE_FIRST(tmp)) != e)
                    apr_bucket_delete(first);
            }

            *wlen += len;
        }
        s = apr_bucket_read(e, (const char **)&(v[n].iov_base),
                            &len, APR_BLOCK_READ);
        if (s != APR_SUCCESS)
            return s;

        v[n++].iov_len = len;
    }

    while (n > 0) {
        apr_size_t len;
        s = apreq_fwritev(f, v, &n, &len);
        if (s != APR_SUCCESS)
            return s;
        *wlen += len;

        if (tmp != bb) {
            while ((first = APR_BRIGADE_FIRST(tmp)) != e)
                apr_bucket_delete(first);
        }
    }
    return APR_SUCCESS;
}
