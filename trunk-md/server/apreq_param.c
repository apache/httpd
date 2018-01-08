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

#include "apreq_param.h"
#include "apreq_error.h"
#include "apreq_util.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define MAX_LEN         (1024 * 1024)
#define MAX_BRIGADE_LEN (1024 * 256)
#define MAX_READ_AHEAD  (1024 * 64)


APREQ_DECLARE(apreq_param_t *) apreq_param_make(apr_pool_t *p,
                                                const char *name,
                                                const apr_size_t nlen,
                                                const char *val,
                                                const apr_size_t vlen)
{
    apreq_param_t *param;
    apreq_value_t *v;

    param = apr_palloc(p, nlen + vlen + 1 + sizeof *param);

    if (param == NULL)
        return NULL;

    param->info = NULL;
    param->upload = NULL;
    param->flags = 0;

    *(const apreq_value_t **)&v = &param->v;

    if (vlen && val != NULL)
        memcpy(v->data, val, vlen);
    v->data[vlen] = 0;
    v->dlen = vlen;

    v->name = v->data + vlen + 1;
    if (nlen && name != NULL)
        memcpy(v->name, name, nlen);
    v->name[nlen] = 0;
    v->nlen = nlen;

    return param;
}

APREQ_DECLARE(apr_status_t) apreq_param_decode(apreq_param_t **param,
                                               apr_pool_t *pool,
                                               const char *word,
                                               apr_size_t nlen,
                                               apr_size_t vlen)
{
    apr_status_t status;
    apreq_value_t *v;
    apreq_param_t *p;
    apreq_charset_t charset;

    if (nlen == 0) {
        *param = NULL;
        return APR_EBADARG;
    }

    p = apr_palloc(pool, nlen + vlen + 1 + sizeof *p);
    p->info = NULL;
    p->upload = NULL;
    p->flags = 0;
    *(const apreq_value_t **)&v = &p->v;

    if (vlen > 0) {
        status = apreq_decode(v->data, &v->dlen, word + nlen + 1, vlen);
        if (status != APR_SUCCESS) {
            *param = NULL;
            return status;
        }
        charset = apreq_charset_divine(v->data, v->dlen);
    }
    else {
        v->data[0] = 0;
        v->dlen = 0;
        charset = APREQ_CHARSET_ASCII;
    }
    v->name = v->data + vlen + 1;

    status = apreq_decode(v->name, &v->nlen, word, nlen);
    if (status != APR_SUCCESS) {
        *param = NULL;
        return status;
    }

    switch (apreq_charset_divine(v->name, v->nlen)) {
    case APREQ_CHARSET_UTF8:
        if (charset == APREQ_CHARSET_ASCII)
            charset = APREQ_CHARSET_UTF8;
    case APREQ_CHARSET_ASCII:
        break;

    case APREQ_CHARSET_LATIN1:
        if (charset != APREQ_CHARSET_CP1252)
            charset = APREQ_CHARSET_LATIN1;
        break;
    case APREQ_CHARSET_CP1252:
        charset = APREQ_CHARSET_CP1252;
    }

    apreq_param_charset_set(p, charset);
    *param = p;

    return APR_SUCCESS;
}


APREQ_DECLARE(char *) apreq_param_encode(apr_pool_t *pool,
                                         const apreq_param_t *param)
{
    apr_size_t dlen;
    char *data;
    data = apr_palloc(pool, 3 * (param->v.nlen + param->v.dlen) + 2);
    dlen = apreq_encode(data, param->v.name, param->v.nlen);
    data[dlen++] = '=';
    dlen += apreq_encode(data + dlen, param->v.data, param->v.dlen);

    return data;
}

APREQ_DECLARE(apr_status_t) apreq_parse_query_string(apr_pool_t *pool,
                                                     apr_table_t *t,
                                                     const char *qs)
{
    const char *start = qs;
    apr_size_t nlen = 0;

    for (;;++qs) {
        switch (*qs) {

        case '=':
            if (nlen == 0) {
                nlen = qs - start;
            }
            break;

        case '&':
        case ';':
        case 0:
            if (qs > start) {
                apr_size_t vlen = 0;
                apreq_param_t *param;
                apr_status_t s;
                if (nlen == 0)
                    nlen = qs - start;
                else
                    vlen = qs - start - nlen - 1;

                s = apreq_param_decode(&param, pool, start, nlen, vlen);
                if (s != APR_SUCCESS)
                    return s;

                apreq_param_tainted_on(param);
                apreq_value_table_add(&param->v, t);
            }

            if (*qs == 0)
                return APR_SUCCESS;

            nlen = 0;
            start = qs + 1;
        }
    }
    /* not reached */
    return APR_INCOMPLETE;
}




static int param_push(void *data, const char *key, const char *val)
{
    apr_array_header_t *arr = data;
    *(apreq_param_t **)apr_array_push(arr) =
        apreq_value_to_param(val);
    return 1;   /* keep going */
}


APREQ_DECLARE(apr_array_header_t *) apreq_params_as_array(apr_pool_t *p,
                                                          const apr_table_t *t,
                                                          const char *key)
{
    apr_array_header_t *arr;

    arr = apr_array_make(p, apr_table_elts(t)->nelts,
                         sizeof(apreq_param_t *));

    apr_table_do(param_push, arr, t, key, NULL);
    return arr;
}

APREQ_DECLARE(const char *) apreq_params_as_string(apr_pool_t *p,
                                                   const apr_table_t *t,
                                                   const char *key,
                                                   apreq_join_t mode)
{
    apr_array_header_t *arr = apreq_params_as_array(p, t, key);
    apreq_param_t **elt = (apreq_param_t **)arr->elts;
    apreq_param_t **const end = elt + arr->nelts;
    if (arr->nelts == 0)
        return apr_pstrdup(p, "");

    while (elt < end) {
        *(const apreq_value_t **)elt = &(**elt).v;
        ++elt;
    }
    return apreq_join(p, ", ", arr, mode);
}



static int upload_push(void *data, const char *key, const char *val)
{
    apr_table_t *t = data;
    apreq_param_t *p = apreq_value_to_param(val);

    if (p->upload != NULL)
        apreq_value_table_add(&p->v, t);
    return 1;   /* keep going */
}


APREQ_DECLARE(const apr_table_t *) apreq_uploads(const apr_table_t *body,
                                                 apr_pool_t *pool)
{
    apr_table_t *t = apr_table_make(pool, APREQ_DEFAULT_NELTS);
    apr_table_do(upload_push, t, body, NULL);
    return t;
}

static int upload_set(void *data, const char *key, const char *val)
{
    const apreq_param_t **q = data;
    apreq_param_t *p = apreq_value_to_param(val);

    if (p->upload != NULL) {
        *q = p;
        return 0; /* upload found, stop */
    }
    else
        return 1; /* keep searching */
}


APREQ_DECLARE(const apreq_param_t *) apreq_upload(const apr_table_t *body,
                                                  const char *name)
{
    apreq_param_t *param = NULL;
    apr_table_do(upload_set, &param, body, name, NULL);
    return param;
}
