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

#include "apreq_cookie.h"
#include "apreq_error.h"
#include "apreq_util.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_date.h"


#define RFC      1
#define NETSCAPE 0

#define ADD_COOKIE(j,c) apreq_value_table_add(&c->v, j)

APREQ_DECLARE(void) apreq_cookie_expires(apreq_cookie_t *c,
                                         const char *time_str)
{
    if (time_str == NULL) {
        c->max_age = -1;
        return;
    }

    if (!strcasecmp(time_str, "now"))
        c->max_age = 0;
    else {
        c->max_age = apr_date_parse_rfc(time_str);
        if (c->max_age == APR_DATE_BAD)
            c->max_age = apr_time_from_sec(apreq_atoi64t(time_str));
        else
            c->max_age -= apr_time_now();
    }
}

static apr_status_t apreq_cookie_attr(apr_pool_t *p,
                                      apreq_cookie_t *c,
                                      const char *attr,
                                      apr_size_t alen,
                                      const char *val,
                                      apr_size_t vlen)
{
    if (alen < 2)
        return APR_EBADARG;

    if ( attr[0] ==  '-' || attr[0] == '$' ) {
        ++attr;
        --alen;
    }

    switch (apr_tolower(*attr)) {

    case 'n': /* name is not an attr */
        return APR_ENOTIMPL;

    case 'v': /* version; value is not an attr */
        if (alen == 5 && strncasecmp(attr,"value", 5) == 0)
            return APR_ENOTIMPL;

        while (!apr_isdigit(*val)) {
            if (vlen == 0)
                return APREQ_ERROR_BADSEQ;
            ++val;
            --vlen;
        }
        apreq_cookie_version_set(c, *val - '0');
        return APR_SUCCESS;

    case 'e': case 'm': /* expires, max-age */
        apreq_cookie_expires(c, val);
        return APR_SUCCESS;

    case 'd':
        c->domain = apr_pstrmemdup(p,val,vlen);
        return APR_SUCCESS;

    case 'p':
        if (alen != 4)
            break;
        if (!strncasecmp("port", attr, 4)) {
            c->port = apr_pstrmemdup(p,val,vlen);
            return APR_SUCCESS;
        }
        else if (!strncasecmp("path", attr, 4)) {
            c->path = apr_pstrmemdup(p,val,vlen);
            return APR_SUCCESS;
        }
        break;

    case 'c':
        if (!strncasecmp("commentURL", attr, 10)) {
            c->commentURL = apr_pstrmemdup(p,val,vlen);
            return APR_SUCCESS;
        }
        else if (!strncasecmp("comment", attr, 7)) {
            c->comment = apr_pstrmemdup(p,val,vlen);
            return APR_SUCCESS;
        }
        break;

    case 's':
        if (vlen > 0 && *val != '0' && strncasecmp("off",val,vlen))
            apreq_cookie_secure_on(c);
        else
            apreq_cookie_secure_off(c);
        return APR_SUCCESS;

    case 'h': /* httponly */
        if (vlen > 0 && *val != '0' && strncasecmp("off",val,vlen))
            apreq_cookie_httponly_on(c);
        else
            apreq_cookie_httponly_off(c);
        return APR_SUCCESS;

    };

    return APR_ENOTIMPL;
}

APREQ_DECLARE(apreq_cookie_t *) apreq_cookie_make(apr_pool_t *p,
                                                  const char *name,
                                                  const apr_size_t nlen,
                                                  const char *value,
                                                  const apr_size_t vlen)
{
    apreq_cookie_t *c;
    apreq_value_t *v;

    c = apr_palloc(p, nlen + vlen + 1 + sizeof *c);

    if (c == NULL)
        return NULL;

    *(const apreq_value_t **)&v = &c->v;

    if (vlen > 0 && value != NULL)
        memcpy(v->data, value, vlen);
    v->data[vlen] = 0;
    v->dlen = vlen;
    v->name = v->data + vlen + 1;
    if (nlen && name != NULL)
        memcpy(v->name, name, nlen);
    v->name[nlen] = 0;
    v->nlen = nlen;

    c->path = NULL;
    c->domain = NULL;
    c->port = NULL;
    c->comment = NULL;
    c->commentURL = NULL;
    c->max_age = -1;    /* session cookie is the default */
    c->flags = 0;


    return c;
}

static APR_INLINE
apr_status_t get_pair(apr_pool_t *p, const char **data,
                      const char **n, apr_size_t *nlen,
                      const char **v, apr_size_t *vlen, unsigned unquote)
{
    const char *hdr, *key, *val;
    int nlen_set = 0;
    hdr = *data;

    while (apr_isspace(*hdr) || *hdr == '=')
        ++hdr;

    key = hdr;
    *n = hdr;

 scan_name:

    switch (*hdr) {

    case 0:
    case ';':
    case ',':
        if (!nlen_set)
            *nlen = hdr - key;
        *v = hdr;
        *vlen = 0;
        *data = hdr;
        return *nlen ? APREQ_ERROR_NOTOKEN : APREQ_ERROR_BADCHAR;

    case '=':
        if (!nlen_set) {
            *nlen = hdr - key;
            nlen_set = 1;
        }
        break;

    case ' ':
    case '\t':
    case '\r':
    case '\n':
        if (!nlen_set) {
            *nlen = hdr - key;
            nlen_set = 1;
        }
        /* fall thru */

    default:
        ++hdr;
        goto scan_name;
    }

    val = hdr + 1;

    while (apr_isspace(*val))
        ++val;

    if (*val == '"') {
        unsigned saw_backslash = 0;
        for (*v = (unquote) ? ++val : val++; *val; ++val) {
            switch (*val) {
            case '"':
                *data = val + 1;

                if (!unquote) {
                    *vlen = (val - *v) + 1;
                }
                else if (!saw_backslash) {
                    *vlen = val - *v;
                }
                else {
                    char *dest = apr_palloc(p, val - *v), *d = dest;
                    const char *s = *v;
                    while (s < val) {
                        if (*s == '\\')
                            ++s;
                        *d++ = *s++;
                    }

                    *vlen = d - dest;
                    *v = dest;
                }

                return APR_SUCCESS;
            case '\\':
                saw_backslash = 1;
                if (val[1] != 0)
                    ++val;
            default:
                break;
            }
        }
        /* bad sequence: no terminating quote found */
        *data = val;
        return APREQ_ERROR_BADSEQ;
    }
    else {
        /* value is not wrapped in quotes */
        for (*v = val; *val; ++val) {
            switch (*val) {
            case ';':
            case ',':
            case ' ':
            case '\t':
            case '\r':
            case '\n':
                *data = val;
                *vlen = val - *v;
                return APR_SUCCESS;
            default:
                break;
            }
        }
    }

    *data = val;
    *vlen = val - *v;

    return APR_SUCCESS;
}



APREQ_DECLARE(apr_status_t)apreq_parse_cookie_header(apr_pool_t *p,
                                                     apr_table_t *j,
                                                     const char *hdr)
{
    apreq_cookie_t *c;
    unsigned version;
    apr_status_t rv = APR_SUCCESS;

 parse_cookie_header:

    c = NULL;
    version = NETSCAPE;

    while (apr_isspace(*hdr))
        ++hdr;


    if (*hdr == '$' && strncasecmp(hdr, "$Version", 8) == 0) {
        /* XXX cheat: assume "$Version" => RFC Cookie header */
        version = RFC;
    skip_version_string:
        switch (*hdr++) {
        case 0:
            return rv;
        case ',':
            goto parse_cookie_header;
        case ';':
            break;
        default:
            goto skip_version_string;
        }
    }

    for (;;) {
        apr_status_t status;
        const char *name, *value;
        apr_size_t nlen, vlen;

        while (*hdr == ';' || apr_isspace(*hdr))
            ++hdr;

        switch (*hdr) {

        case 0:
            /* this is the normal exit point */
            if (c != NULL) {
                ADD_COOKIE(j, c);
            }
            return rv;

        case ',':
            ++hdr;
            if (c != NULL) {
                ADD_COOKIE(j, c);
            }
            goto parse_cookie_header;

        case '$':
            ++hdr;
            if (c == NULL) {
                rv = APREQ_ERROR_BADCHAR;
                goto parse_cookie_error;
            }
            else if (version == NETSCAPE) {
                rv = APREQ_ERROR_MISMATCH;
            }

            status = get_pair(p, &hdr, &name, &nlen, &value, &vlen, 1);
            if (status != APR_SUCCESS) {
                rv = status;
                goto parse_cookie_error;
            }

            status = apreq_cookie_attr(p, c, name, nlen, value, vlen);

            switch (status) {

            case APR_ENOTIMPL:
                rv = APREQ_ERROR_BADATTR;
                /* fall thru */

            case APR_SUCCESS:
                break;

            default:
                rv = status;
                goto parse_cookie_error;
            }

            break;

        default:
            if (c != NULL) {
                ADD_COOKIE(j, c);
            }

            status = get_pair(p, &hdr, &name, &nlen, &value, &vlen, 0);

            if (status != APR_SUCCESS) {
                c = NULL;
                rv = status;
                goto parse_cookie_error;
            }

            c = apreq_cookie_make(p, name, nlen, value, vlen);
            apreq_cookie_tainted_on(c);
            if (version != NETSCAPE)
                apreq_cookie_version_set(c, version);
        }
    }

 parse_cookie_error:

    switch (*hdr) {

    case 0:
        return rv;

    case ',':
    case ';':
        if (c != NULL)
            ADD_COOKIE(j, c);
        ++hdr;
        goto parse_cookie_header;

    default:
        ++hdr;
        goto parse_cookie_error;
    }

    /* not reached */
    return rv;
}


APREQ_DECLARE(int) apreq_cookie_serialize(const apreq_cookie_t *c,
                                          char *buf, apr_size_t len)
{
    /*  The format string must be large enough to accomodate all
     *  of the cookie attributes.  The current attributes sum to
     *  ~90 characters (w/ 6-8 padding chars per attr), so anything
     *  over 100 should be fine.
     */

    unsigned version = apreq_cookie_version(c);
    char format[128] = "%s=%s";
    char *f = format + strlen(format);

    /* XXX protocol enforcement (for debugging, anyway) ??? */

    if (c->v.name == NULL)
        return -1;

#define NULL2EMPTY(attr) (attr ? attr : "")


    if (version == NETSCAPE) {
        char expires[APR_RFC822_DATE_LEN] = {0};

#define ADD_NS_ATTR(name) do {                  \
    if (c->name != NULL)                        \
        strcpy(f, "; " #name "=%s");            \
    else                                        \
        strcpy(f, "%0.s");                      \
    f += strlen(f);                             \
} while (0)

        ADD_NS_ATTR(path);
        ADD_NS_ATTR(domain);

        if (c->max_age != -1) {
            strcpy(f, "; expires=%s");
            apr_rfc822_date(expires, c->max_age + apr_time_now());
            expires[7] = '-';
            expires[11] = '-';
        }
        else
            strcpy(f, "");

        f += strlen(f);

        if (apreq_cookie_is_secure(c))
            strcpy(f, "; secure");

        f += strlen(f);

        if (apreq_cookie_is_httponly(c))
            strcpy(f, "; HttpOnly");

        return apr_snprintf(buf, len, format, c->v.name, c->v.data,
           NULL2EMPTY(c->path), NULL2EMPTY(c->domain), expires);
    }

    /* c->version == RFC */

    strcpy(f,"; Version=%u");
    f += strlen(f);

/* ensure RFC attributes are always quoted */
#define ADD_RFC_ATTR(name) do {                 \
    if (c->name != NULL)                        \
        if (*c->name == '"')                    \
            strcpy(f, "; " #name "=%s");        \
        else                                    \
            strcpy(f, "; " #name "=\"%s\"");    \
    else                                        \
        strcpy(f, "%0.s");                      \
    f += strlen (f);                            \
} while (0)

    ADD_RFC_ATTR(path);
    ADD_RFC_ATTR(domain);
    ADD_RFC_ATTR(port);
    ADD_RFC_ATTR(comment);
    ADD_RFC_ATTR(commentURL);

    strcpy(f, c->max_age != -1 ? "; max-age=%" APR_TIME_T_FMT : "");

    f += strlen(f);

    if (apreq_cookie_is_secure(c))
        strcpy(f, "; secure");

    f += strlen(f);

    if (apreq_cookie_is_httponly(c))
        strcpy(f, "; HttpOnly");

    return apr_snprintf(buf, len, format, c->v.name, c->v.data, version,
                        NULL2EMPTY(c->path), NULL2EMPTY(c->domain),
                        NULL2EMPTY(c->port), NULL2EMPTY(c->comment),
                        NULL2EMPTY(c->commentURL), apr_time_sec(c->max_age));
}


APREQ_DECLARE(char*) apreq_cookie_as_string(const apreq_cookie_t *c,
                                            apr_pool_t *p)
{
    int n = apreq_cookie_serialize(c, NULL, 0);
    char *s = apr_palloc(p, n + 1);
    apreq_cookie_serialize(c, s, n + 1);
    return s;
}

