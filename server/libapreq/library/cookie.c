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

#include "apr_strings.h"
#include "apreq_cookie.h"
#include "apreq_error.h"
#include "apreq_module.h"
#include "apreq_util.h"
#include "at.h"

static const char nscookies[] = "a=1; foo=bar; fl=left; fr=right;bad; "
                                "ns=foo=1&bar=2,frl=right-left; "
                                "flr=left-right; fll=left-left; "
                                "good_one=1;=;bad";

static const char rfccookies[] = "$Version=1; first=a;$domain=quux;second=be,"
                                 "$Version=1;third=cie";

static apr_table_t *jar, *jar2;
static apr_pool_t *p;

static void jar_make(dAT)
{
    jar = apr_table_make(p, APREQ_DEFAULT_NELTS);
    AT_not_null(jar);
    AT_int_eq(apreq_parse_cookie_header(p, jar, nscookies), APREQ_ERROR_NOTOKEN);
    jar2 = apr_table_make(p, APREQ_DEFAULT_NELTS);
    AT_not_null(jar2);
    AT_int_eq(apreq_parse_cookie_header(p, jar2, rfccookies), APR_SUCCESS);
}

static void jar_get_rfc(dAT)
{
    const char *val;
    AT_not_null(val = apr_table_get(jar2, "first"));
    AT_str_eq(val, "a");
    AT_not_null(val = apr_table_get(jar2, "second"));
    AT_str_eq(val, "be");
    AT_not_null(val = apr_table_get(jar2, "third"));
    AT_str_eq(val, "cie");
}

static void jar_get_ns(dAT)
{

    AT_str_eq(apr_table_get(jar, "a"), "1");

    /* ignore wacky cookies that don't have an '=' sign */
    AT_is_null(apr_table_get(jar, "bad"));

    /* accept wacky cookies that contain multiple '=' */
    AT_str_eq(apr_table_get(jar, "ns"), "foo=1&bar=2");

    AT_str_eq(apr_table_get(jar,"foo"), "bar");
    AT_str_eq(apr_table_get(jar,"fl"),  "left");
    AT_str_eq(apr_table_get(jar,"fr"),  "right");
    AT_str_eq(apr_table_get(jar,"frl"), "right-left");
    AT_str_eq(apr_table_get(jar,"flr"), "left-right");
    AT_str_eq(apr_table_get(jar,"fll"), "left-left");
    AT_is_null(apr_table_get(jar,""));
}


static void netscape_cookie(dAT)
{
    char expires[APR_RFC822_DATE_LEN];
    char *val;
    apreq_cookie_t *c;

    *(const char **)&val = apr_table_get(jar, "foo");
    AT_not_null(val);

    c = apreq_value_to_cookie(val);

    AT_str_eq(c->v.data, "bar");
    AT_int_eq(apreq_cookie_version(c), 0);
    AT_str_eq(apreq_cookie_as_string(c, p), "foo=bar");

    c->domain = apr_pstrdup(p, "example.com");
    AT_str_eq(apreq_cookie_as_string(c, p), "foo=bar; domain=example.com");

    c->path = apr_pstrdup(p, "/quux");
    AT_str_eq(apreq_cookie_as_string(c, p),
              "foo=bar; path=/quux; domain=example.com");

    apreq_cookie_expires(c, "+1y");
    apr_rfc822_date(expires, apr_time_now()
                             + apr_time_from_sec(apreq_atoi64t("+1y")));
    expires[7] = '-';
    expires[11] = '-';
    val = apr_pstrcat(p, "foo=bar; path=/quux; domain=example.com; expires=",
                      expires, NULL);

    AT_str_eq(apreq_cookie_as_string(c, p), val);
}


static void rfc_cookie(dAT)
{
    apreq_cookie_t *c = apreq_cookie_make(p,"rfc",3,"out",3);
    const char *expected;
    long expires;

    AT_str_eq(c->v.data, "out");

    apreq_cookie_version_set(c, 1);
    AT_int_eq(apreq_cookie_version(c), 1);
    AT_str_eq(apreq_cookie_as_string(c,p),"rfc=out; Version=1");

    c->domain = apr_pstrdup(p, "example.com");

#ifndef WIN32

    AT_str_eq(apreq_cookie_as_string(c,p),
              "rfc=out; Version=1; domain=\"example.com\"");
    c->path = apr_pstrdup(p, "/quux");
    AT_str_eq(apreq_cookie_as_string(c,p),
              "rfc=out; Version=1; path=\"/quux\"; domain=\"example.com\"");

    apreq_cookie_expires(c, "+3m");
    expires = apreq_atoi64t("+3m");
    expected = apr_psprintf(p, "rfc=out; Version=1; path=\"/quux\"; "
                       "domain=\"example.com\"; max-age=%ld",
                       expires);
    AT_str_eq(apreq_cookie_as_string(c,p), expected);

#else

    expected = "rfc=out; Version=1; domain=\"example.com\"";
    AT_str_eq(apreq_cookie_as_string(c,p), expected);

    c->path = apr_pstrdup(p, "/quux");
    expected = "rfc=out; Version=1; path=\"/quux\"; domain=\"example.com\"";
    AT_str_eq(apreq_cookie_as_string(c,p), expected);

    apreq_cookie_expires(c, "+3m");
    expires = apreq_atoi64t("+3m");
    expected = apr_psprintf(p, "rfc=out; Version=1; path=\"/quux\"; "
                           "domain=\"example.com\"; max-age=%ld",
                           expires);
    AT_str_eq(apreq_cookie_as_string(c,p), expected);

#endif

}


#define dT(func, plan) #func, func, plan


int main(int argc, char *argv[])
{
    unsigned i, plan = 0;
    dAT;
    at_test_t test_list [] = {
        { dT(jar_make, 4) },
        { dT(jar_get_rfc, 6), "1 3 5" },
        { dT(jar_get_ns, 10) },
        { dT(netscape_cookie, 7) },
        { dT(rfc_cookie, 6) },
    };

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&p, NULL);

    AT = at_create(p, 0, at_report_stdout_make(p));

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        plan += test_list[i].plan;

    AT_begin(plan);

    for (i = 0; i < sizeof(test_list) / sizeof(at_test_t);  ++i)
        AT_run(&test_list[i]);

    AT_end();

    return 0;
}
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

    hdr = *data;

    while (apr_isspace(*hdr) || *hdr == '=')
        ++hdr;

    key = strchr(hdr, '=');

    if (key == NULL)
        return APREQ_ERROR_NOTOKEN;

    val = key + 1;

    do --key;
    while (key > hdr && apr_isspace(*key));

    *n = key;

    while (key >= hdr && !apr_isspace(*key))
        --key;

    *nlen = *n - key;
    *n = key + 1;

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

 parse_cookie_header:

    c = NULL;
    version = NETSCAPE;

    while (apr_isspace(*hdr))
        ++hdr;


    if (*hdr == '$') {
        /* XXX cheat: assume "$..." => "$Version" => RFC Cookie header */
        version = RFC;
    skip_version_string:
        switch (*hdr++) {
        case 0:
            return APR_SUCCESS;
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
            return APR_SUCCESS;

        case ',':
            ++hdr;
            if (c != NULL) {
                ADD_COOKIE(j, c);
            }
            goto parse_cookie_header;

        case '$':
            if (c == NULL) {
                return APREQ_ERROR_BADCHAR;
            }
            else if (version == NETSCAPE) {
                return APREQ_ERROR_MISMATCH;
            }

            ++hdr;
            status = get_pair(p, &hdr, &name, &nlen, &value, &vlen, 1);
            if (status != APR_SUCCESS)
                return status;

            status = apreq_cookie_attr(p, c, name, nlen, value, vlen);

            switch (status) {
            case APR_ENOTIMPL:
                /* XXX: skip unrecognized attr?  Not really correct,
                   but for now, just fall through */

            case APR_SUCCESS:
                break;
            default:
                return status;
            }

            break;

        default:
            if (c != NULL) {
                ADD_COOKIE(j, c);
            }

            status = get_pair(p, &hdr, &name, &nlen, &value, &vlen, 0);

            if (status != APR_SUCCESS)
                return status;

            c = apreq_cookie_make(p, name, nlen, value, vlen);
            apreq_cookie_tainted_on(c);
            if (version != NETSCAPE)
                apreq_cookie_version_set(c, version);
        }
    }

    /* NOT REACHED */
    return APREQ_ERROR_GENERAL;
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

