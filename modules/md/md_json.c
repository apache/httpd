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
 
#include <assert.h>
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include "md_json.h"
#include "md_log.h"
#include "md_http.h"
#include "md_util.h"

/* jansson thinks everyone compiles with the platform's cc in its fullest capabilities
 * when undefining their INLINEs, we get static, unused functions, arg 
 */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunreachable-code"
#endif
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif

#include <jansson_config.h>
#undef  JSON_INLINE
#define JSON_INLINE 
#include <jansson.h>

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

struct md_json_t {
    apr_pool_t *p;
    json_t *j;
};

/**************************************************************************************************/
/* lifecycle */

static apr_status_t json_pool_cleanup(void *data)
{
    md_json_t *json = data;
    if (json) {
        md_json_destroy(json);
    }
    return APR_SUCCESS;
}

static md_json_t *json_create(apr_pool_t *pool, json_t *j)
{
    md_json_t *json;
    
    if (!j) {
        apr_abortfunc_t abfn = apr_pool_abort_get(pool);
        if (abfn) {
            abfn(APR_ENOMEM);
        }
        assert(j != NULL); /* failsafe in case abort is unset */
    }
    json = apr_pcalloc(pool, sizeof(*json));
    json->p = pool;
    json->j = j;
    apr_pool_cleanup_register(pool, json, json_pool_cleanup, apr_pool_cleanup_null);
        
    return json;
}

md_json_t *md_json_create(apr_pool_t *pool)
{
    return json_create(pool, json_object());
}

md_json_t *md_json_create_s(apr_pool_t *pool, const char *s)
{
    return json_create(pool, json_string(s));
}

void md_json_destroy(md_json_t *json)
{
    if (json && json->j) {
        assert(json->j->refcount > 0);
        json_decref(json->j);
        json->j = NULL;
    }
}

md_json_t *md_json_copy(apr_pool_t *pool, md_json_t *json)
{
    return json_create(pool, json_copy(json->j));
}

md_json_t *md_json_clone(apr_pool_t *pool, md_json_t *json)
{
    return json_create(pool, json_deep_copy(json->j));
}

/**************************************************************************************************/
/* selectors */


static json_t *jselect(md_json_t *json, va_list ap)
{
    json_t *j;
    const char *key;
    
    j = json->j;
    key = va_arg(ap, char *);
    while (key && j) {
        j = json_object_get(j, key);
        key = va_arg(ap, char *);
    }
    return j;
}

static json_t *jselect_parent(const char **child_key, int create, md_json_t *json, va_list ap)
{
    const char *key, *next;
    json_t *j, *jn;
    
    *child_key = NULL;
    j = json->j;
    key = va_arg(ap, char *);
    while (key && j) {
        next = va_arg(ap, char *);
        if (next) {
            jn = json_object_get(j, key);
            if (!jn && create) {
                jn = json_object();
                json_object_set_new(j, key, jn);
            }
            j = jn;
        }
        else {
            *child_key = key;
        }
        key = next;
    }
    return j;
}

static apr_status_t jselect_add(json_t *val, md_json_t *json, va_list ap)
{
    const char *key;
    json_t *j, *aj;
    
    j = jselect_parent(&key, 1, json, ap);
    
    if (!j || !json_is_object(j)) {
        json_decref(val);
        return APR_EINVAL;
    }
    
    aj = json_object_get(j, key);
    if (!aj) {
        aj = json_array();
        json_object_set_new(j, key, aj);
    }
    
    if (!json_is_array(aj)) {
        json_decref(val);
        return APR_EINVAL;
    }

    json_array_append(aj, val);
    return APR_SUCCESS;
}

static apr_status_t jselect_set(json_t *val, md_json_t *json, va_list ap)
{
    const char *key;
    json_t *j;
    
    j = jselect_parent(&key, 1, json, ap);
    
    if (!j) {
        json_decref(val);
        return APR_EINVAL;
    }
    
    if (key) {
        if (!json_is_object(j)) {
            json_decref(val);
            return APR_EINVAL;
        }
        json_object_set(j, key, val);
    }
    else {
        /* replace */
        if (json->j) {
            json_decref(json->j);
        }
        json_incref(val);
        json->j = val;
    }
    return APR_SUCCESS;
}

static apr_status_t jselect_set_new(json_t *val, md_json_t *json, va_list ap)
{
    const char *key;
    json_t *j;
    
    j = jselect_parent(&key, 1, json, ap);
    
    if (!j) {
        json_decref(val);
        return APR_EINVAL;
    }
    
    if (key) {
        if (!json_is_object(j)) {
            json_decref(val);
            return APR_EINVAL;
        }
        json_object_set_new(j, key, val);
    }
    else {
        /* replace */
        if (json->j) {
            json_decref(json->j);
        }
        json->j = val;
    }
    return APR_SUCCESS;
}

int md_json_has_key(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);

    return j != NULL;
}

/**************************************************************************************************/
/* booleans */

int md_json_getb(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);

    return j? json_is_true(j) : 0;
}

apr_status_t md_json_setb(int value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = jselect_set_new(json_boolean(value), json, ap);
    va_end(ap);
    return rv;
}

/**************************************************************************************************/
/* numbers */

double md_json_getn(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);
    return (j && json_is_number(j))? json_number_value(j) : 0.0;
}

apr_status_t md_json_setn(double value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = jselect_set_new(json_real(value), json, ap);
    va_end(ap);
    return rv;
}

/**************************************************************************************************/
/* longs */

long md_json_getl(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);
    return (long)((j && json_is_number(j))? json_integer_value(j) : 0L);
}

apr_status_t md_json_setl(long value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = jselect_set_new(json_integer(value), json, ap);
    va_end(ap);
    return rv;
}

/**************************************************************************************************/
/* strings */

const char *md_json_gets(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);

    return (j && json_is_string(j))? json_string_value(j) : NULL;
}

const char *md_json_dups(apr_pool_t *p, md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);

    return (j && json_is_string(j))? apr_pstrdup(p, json_string_value(j)) : NULL;
}

apr_status_t md_json_sets(const char *value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = jselect_set_new(json_string(value), json, ap);
    va_end(ap);
    return rv;
}

/**************************************************************************************************/
/* json itself */

md_json_t *md_json_getj(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);
    
    if (j) {
        if (j == json->j) {
            return json;
        }
        json_incref(j);
        return json_create(json->p, j);
    }
    return NULL;
}

apr_status_t md_json_setj(md_json_t *value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    const char *key;
    json_t *j;
    
    if (value) {
        va_start(ap, json);
        rv = jselect_set(value->j, json, ap);
        va_end(ap);
    }
    else {
        va_start(ap, json);
        j = jselect_parent(&key, 1, json, ap);
        va_end(ap);
        
        if (key && j && !json_is_object(j)) {
            json_object_del(j, key);
            rv = APR_SUCCESS;
        }
        else {
            rv = APR_EINVAL;
        }
    }
    return rv;
}

apr_status_t md_json_addj(md_json_t *value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = jselect_add(value->j, json, ap);
    va_end(ap);
    return rv;
}


/**************************************************************************************************/
/* arrays / objects */

apr_status_t md_json_clr(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);

    if (j && json_is_object(j)) {
        json_object_clear(j);
    }
    else if (j && json_is_array(j)) {
        json_array_clear(j);
    }
    return APR_SUCCESS;
}

apr_status_t md_json_del(md_json_t *json, ...)
{
    const char *key;
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect_parent(&key, 0, json, ap);
    va_end(ap);
    
    if (key && j && json_is_object(j)) {
        json_object_del(j, key);
    }
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* object strings */

apr_status_t md_json_gets_dict(apr_table_t *dict, md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);

    if (j && json_is_object(j)) {
        const char *key;
        json_t *val;
        
        json_object_foreach(j, key, val) {
            if (json_is_string(val)) {
                apr_table_set(dict, key, json_string_value(val));
            }
        }
        return APR_SUCCESS;
    }
    return APR_ENOENT;
}

static int object_set(void *data, const char *key, const char *val)
{
    json_t *j = data, *nj = json_string(val);
    json_object_set(j, key, nj);
    json_decref(nj);
    return 1;
}
 
apr_status_t md_json_sets_dict(apr_table_t *dict, md_json_t *json, ...)
{
    json_t *nj, *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);
    
    if (!j || !json_is_object(j)) {
        const char *key;
        
        va_start(ap, json);
        j = jselect_parent(&key, 1, json, ap);
        va_end(ap);
        
        if (!key || !j || !json_is_object(j)) {
            return APR_EINVAL;
        }
        nj = json_object();
        json_object_set_new(j, key, nj);
        j = nj; 
    }
    
    apr_table_do(object_set, j, dict, NULL);
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* conversions */

apr_status_t md_json_pass_to(void *value, md_json_t *json, apr_pool_t *p, void *baton)
{
    (void)p;
    (void)baton;
    return md_json_setj(value, json, NULL);
}

apr_status_t md_json_pass_from(void **pvalue, md_json_t *json, apr_pool_t *p, void *baton)
{
    (void)p;
    (void)baton;
    *pvalue = json;
    return APR_SUCCESS;
}

apr_status_t md_json_clone_to(void *value, md_json_t *json, apr_pool_t *p, void *baton)
{
    (void)baton;
    return md_json_setj(md_json_clone(p, value), json, NULL);
}

apr_status_t md_json_clone_from(void **pvalue, md_json_t *json, apr_pool_t *p, void *baton)
{
    (void)baton;
    *pvalue = md_json_clone(p, json);
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* array generic */

apr_status_t md_json_geta(apr_array_header_t *a, md_json_from_cb *cb, void *baton,
                          md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    apr_status_t rv = APR_SUCCESS;
    size_t index;
    json_t *val;
    md_json_t wrap;
    void *element;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);
    
    if (!j || !json_is_array(j)) {
        return APR_ENOENT;
    }
        
    wrap.p = a->pool;
    json_array_foreach(j, index, val) {
        wrap.j = val;
        if (APR_SUCCESS == (rv = cb(&element, &wrap, wrap.p, baton))) {
            if (element) {
                APR_ARRAY_PUSH(a, void*) = element;
            }
        }
        else if (APR_ENOENT == rv) {
            rv = APR_SUCCESS;
        }
        else {
            break;
        }
    }
    return rv;
}

apr_status_t md_json_seta(apr_array_header_t *a, md_json_to_cb *cb, void *baton, 
                          md_json_t *json, ...)
{
    json_t *j, *nj;
    md_json_t wrap;
    apr_status_t rv = APR_SUCCESS;
    va_list ap;
    int i;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);
    
    if (!j || !json_is_array(j)) {
        const char *key;
        
        va_start(ap, json);
        j = jselect_parent(&key, 1, json, ap);
        va_end(ap);
        
        if (!key || !j || !json_is_object(j)) {
            return APR_EINVAL;
        }
        nj = json_array();
        json_object_set_new(j, key, nj);
        j = nj; 
    }
    
    json_array_clear(j);
    wrap.p = json->p;
    for (i = 0; i < a->nelts; ++i) {
        if (!cb) {
            return APR_EINVAL;
        }    
        wrap.j = json_string("");
        if (APR_SUCCESS == (rv = cb(APR_ARRAY_IDX(a, i, void*), &wrap, json->p, baton))) {
            json_array_append_new(j, wrap.j);
        }
    }
    return rv;
}

int md_json_itera(md_json_itera_cb *cb, void *baton, md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    size_t index;
    json_t *val;
    md_json_t wrap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);
    
    if (!j || !json_is_array(j)) {
        return 0;
    }
        
    wrap.p = json->p;
    json_array_foreach(j, index, val) {
        wrap.j = val;
        if (!cb(baton, index, &wrap)) {
            return 0;
        }
    }
    return 1;
}

/**************************************************************************************************/
/* array strings */

apr_status_t md_json_getsa(apr_array_header_t *a, md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);

    if (j && json_is_array(j)) {
        size_t index;
        json_t *val;
        
        json_array_foreach(j, index, val) {
            if (json_is_string(val)) {
                APR_ARRAY_PUSH(a, const char *) = json_string_value(val);
            }
        }
        return APR_SUCCESS;
    }
    return APR_ENOENT;
}

apr_status_t md_json_dupsa(apr_array_header_t *a, apr_pool_t *p, md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);

    if (j && json_is_array(j)) {
        size_t index;
        json_t *val;
        
        json_array_foreach(j, index, val) {
            if (json_is_string(val)) {
                APR_ARRAY_PUSH(a, const char *) = apr_pstrdup(p, json_string_value(val));
            }
        }
        return APR_SUCCESS;
    }
    return APR_ENOENT;
}

apr_status_t md_json_setsa(apr_array_header_t *a, md_json_t *json, ...)
{
    json_t *nj, *j;
    va_list ap;
    int i;
    
    va_start(ap, json);
    j = jselect(json, ap);
    va_end(ap);
    
    if (!j || !json_is_array(j)) {
        const char *key;
        
        va_start(ap, json);
        j = jselect_parent(&key, 1, json, ap);
        va_end(ap);
        
        if (!key || !j || !json_is_object(j)) {
            return APR_EINVAL;
        }
        nj = json_array();
        json_object_set_new(j, key, nj);
        j = nj; 
    }
    
    json_array_clear(j);
    for (i = 0; i < a->nelts; ++i) {
        json_array_append_new(j, json_string(APR_ARRAY_IDX(a, i, const char*)));
    }
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* formatting, parsing */

typedef struct {
    md_json_t *json;
    md_json_fmt_t fmt;
    const char *fname;
    apr_file_t *f;
} j_write_ctx;

/* Convert from md_json_fmt_t to the Jansson json_dumpX flags. */
static size_t fmt_to_flags(md_json_fmt_t fmt)
{
    /* NOTE: JSON_PRESERVE_ORDER is off by default before Jansson 2.8. It
     * doesn't have any semantic effect on the protocol, but it does let the
     * md_json_writeX unit tests run deterministically. */
    return JSON_PRESERVE_ORDER |
           ((fmt == MD_JSON_FMT_COMPACT) ? JSON_COMPACT : JSON_INDENT(2)); 
}

static int dump_cb(const char *buffer, size_t len, void *baton)
{
    apr_bucket_brigade *bb = baton;
    apr_status_t rv;
    
    rv = apr_brigade_write(bb, NULL, NULL, buffer, len);
    return (rv == APR_SUCCESS)? 0 : -1;
}

apr_status_t md_json_writeb(md_json_t *json, md_json_fmt_t fmt, apr_bucket_brigade *bb)
{
    int rv = json_dump_callback(json->j, dump_cb, bb, fmt_to_flags(fmt));
    return rv? APR_EGENERAL : APR_SUCCESS;
}

static int chunk_cb(const char *buffer, size_t len, void *baton)
{
    apr_array_header_t *chunks = baton;
    char *chunk = apr_pcalloc(chunks->pool, len+1);
    
    memcpy(chunk, buffer, len);
    APR_ARRAY_PUSH(chunks, const char *) = chunk;
    return 0;
}

const char *md_json_writep(md_json_t *json, apr_pool_t *p, md_json_fmt_t fmt)
{
    apr_array_header_t *chunks;
    int rv;

    chunks = apr_array_make(p, 10, sizeof(char *));
    rv = json_dump_callback(json->j, chunk_cb, chunks, fmt_to_flags(fmt));

    if (rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p,
                      "md_json_writep failed to dump JSON");
        return NULL;
    }

    switch (chunks->nelts) {
        case 0:
            return "";
        case 1:
            return APR_ARRAY_IDX(chunks, 0, const char *);
        default:
            return apr_array_pstrcat(p, chunks, 0);
    }
}

apr_status_t md_json_writef(md_json_t *json, apr_pool_t *p, md_json_fmt_t fmt, apr_file_t *f)
{
    apr_status_t rv;
    const char *s;
    
    s = md_json_writep(json, p, fmt);

    if (s) {
        rv = apr_file_write_full(f, s, strlen(s), NULL);
    }
    else {
        rv = APR_EINVAL;
    }

    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, json->p, "md_json_writef");
    }
    return rv;
}

apr_status_t md_json_fcreatex(md_json_t *json, apr_pool_t *p, md_json_fmt_t fmt, 
                              const char *fpath, apr_fileperms_t perms)
{
    apr_status_t rv;
    apr_file_t *f;
    
    rv = md_util_fcreatex(&f, fpath, perms, p);
    if (APR_SUCCESS == rv) {
        rv = md_json_writef(json, p, fmt, f);
        apr_file_close(f);
    }
    return rv;
}

static apr_status_t write_json(void *baton, apr_file_t *f, apr_pool_t *p)
{
    j_write_ctx *ctx = baton;
    apr_status_t rv = md_json_writef(ctx->json, p, ctx->fmt, f);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "freplace json in %s", ctx->fname);
    }
    return rv;
}

apr_status_t md_json_freplace(md_json_t *json, apr_pool_t *p, md_json_fmt_t fmt, 
                              const char *fpath, apr_fileperms_t perms)
{
    j_write_ctx ctx;
    ctx.json = json;
    ctx.fmt = fmt;
    ctx.fname = fpath;
    return md_util_freplace(fpath, perms, p, write_json, &ctx);
}

apr_status_t md_json_readd(md_json_t **pjson, apr_pool_t *pool, const char *data, size_t data_len)
{
    json_error_t error;
    json_t *j;
    
    j = json_loadb(data, data_len, 0, &error);
    if (!j) {
        return APR_EINVAL;
    }
    *pjson = json_create(pool, j);
    return APR_SUCCESS;
}

static size_t load_cb(void *data, size_t max_len, void *baton)
{
    apr_bucket_brigade *body = baton;
    size_t blen, read_len = 0;
    const char *bdata;
    char *dest = data;
    apr_bucket *b;
    apr_status_t rv;
    
    while (body && !APR_BRIGADE_EMPTY(body) && max_len > 0) {
        b = APR_BRIGADE_FIRST(body);
        if (APR_BUCKET_IS_METADATA(b)) {
            if (APR_BUCKET_IS_EOS(b)) {
                body = NULL;
            }
        }
        else {
            rv = apr_bucket_read(b, &bdata, &blen, APR_BLOCK_READ);
            if (rv == APR_SUCCESS) {
                if (blen > max_len) {
                    apr_bucket_split(b, max_len);
                    blen = max_len;
                }
                memcpy(dest, bdata, blen);
                read_len += blen;
                max_len -= blen;
                dest += blen;
            }
            else {
                body = NULL;
                if (!APR_STATUS_IS_EOF(rv)) {
                    /* everything beside EOF is an error */
                    read_len = (size_t)-1;
                }
            }
        }
        APR_BUCKET_REMOVE(b);
        apr_bucket_delete(b);
    }
    
    return read_len;
}

apr_status_t md_json_readb(md_json_t **pjson, apr_pool_t *pool, apr_bucket_brigade *bb)
{
    json_error_t error;
    json_t *j;
    
    j = json_load_callback(load_cb, bb, 0, &error);
    if (!j) {
        return APR_EINVAL;
    }
    *pjson = json_create(pool, j);
    return APR_SUCCESS;
}

static size_t load_file_cb(void *data, size_t max_len, void *baton)
{
    apr_file_t *f = baton;
    apr_size_t len = max_len;
    apr_status_t rv;
    
    rv = apr_file_read(f, data, &len);
    if (APR_SUCCESS == rv) {
        return len;
    }
    else if (APR_EOF == rv) {
        return 0;
    }
    return (size_t)-1;
}

apr_status_t md_json_readf(md_json_t **pjson, apr_pool_t *p, const char *fpath)
{
    apr_file_t *f;
    json_t *j;
    apr_status_t rv;
    json_error_t error;
    
    rv = apr_file_open(&f, fpath, APR_FOPEN_READ, 0, p);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    j = json_load_callback(load_file_cb, f, 0, &error);
    if (j) {
        *pjson = json_create(p, j);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p,
                      "failed to load JSON file %s: %s (line %d:%d)",
                      fpath, error.text, error.line, error.column);
    }

    apr_file_close(f);
    return (j && *pjson) ? APR_SUCCESS : APR_EINVAL;
}

/**************************************************************************************************/
/* http get */

apr_status_t md_json_read_http(md_json_t **pjson, apr_pool_t *pool, const md_http_response_t *res)
{
    apr_status_t rv = APR_ENOENT;
    if (res->rv == APR_SUCCESS) {
        const char *ctype = apr_table_get(res->headers, "content-type");
        if (ctype && res->body && (strstr(ctype, "/json") || strstr(ctype, "+json"))) {
            rv = md_json_readb(pjson, pool, res->body);
        }
    }
    return rv;
}

typedef struct {
    apr_status_t rv;
    apr_pool_t *pool;
    md_json_t *json;
} resp_data;

static apr_status_t json_resp_cb(const md_http_response_t *res)
{
    resp_data *resp = res->req->baton;
    return md_json_read_http(&resp->json, resp->pool, res);
}

apr_status_t md_json_http_get(md_json_t **pjson, apr_pool_t *pool,
                              struct md_http_t *http, const char *url)
{
    long req_id;
    apr_status_t rv;
    resp_data resp;
    
    memset(&resp, 0, sizeof(resp));
    resp.pool = pool;
    
    rv = md_http_GET(http, url, NULL, json_resp_cb, &resp, &req_id);
    
    if (rv == APR_SUCCESS) {
        md_http_await(http, req_id);
        *pjson = resp.json;
        return resp.rv;
    }
    *pjson = NULL;
    return rv;
}

