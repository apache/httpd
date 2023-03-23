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
#include <apr_encode.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>

#include <rustls.h>

#include "tls_cert.h"
#include "tls_util.h"

extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);


apr_status_t tls_cert_load_pem(
    apr_pool_t *p, const tls_cert_spec_t *cert, tls_cert_pem_t **ppem)
{
    apr_status_t rv;
    const char *fpath;
    tls_cert_pem_t *cpem;

    ap_assert(cert->cert_file);
    cpem = apr_pcalloc(p, sizeof(*cpem));
    fpath = ap_server_root_relative(p, cert->cert_file);
    if (NULL == fpath) {
        rv = APR_ENOENT; goto cleanup;
    }
    rv = tls_util_file_load(p, fpath, 0, 100*1024, &cpem->cert_pem);
    if (APR_SUCCESS != rv) goto cleanup;

    if (cert->pkey_file) {
        fpath = ap_server_root_relative(p, cert->pkey_file);
        if (NULL == fpath) {
            rv = APR_ENOENT; goto cleanup;
        }
        rv = tls_util_file_load(p, fpath, 0, 100*1024, &cpem->pkey_pem);
        if (APR_SUCCESS != rv) goto cleanup;
    }
    else {
        cpem->pkey_pem = cpem->cert_pem;
    }
cleanup:
    *ppem = (APR_SUCCESS == rv)? cpem : NULL;
    return rv;
}

#define PEM_IN_CHUNK    48      /* PEM demands at most 64 chars per line */

static apr_status_t tls_der_to_pem(
    const char **ppem, apr_pool_t *p,
    const unsigned char *der_data, apr_size_t der_len,
    const char *header, const char *footer)
{
    apr_status_t rv = APR_SUCCESS;
    char *pem = NULL, *s;
    apr_size_t b64_len, n, hd_len, ft_len;
    apr_ssize_t in_len, i;

    if (der_len > INT_MAX) {
        rv = APR_ENOMEM;
        goto cleanup;
    }
    in_len = (apr_ssize_t)der_len;
    rv = apr_encode_base64(NULL, (const char*)der_data, in_len, APR_ENCODE_NONE, &b64_len);
    if (APR_SUCCESS != rv) goto cleanup;
    if (b64_len > INT_MAX) {
        rv = APR_ENOMEM;
        goto cleanup;
    }
    hd_len = header? strlen(header) : 0;
    ft_len = footer? strlen(footer) : 0;
    s = pem = apr_pcalloc(p,
        + b64_len + (der_len/PEM_IN_CHUNK) + 1 /* \n per chunk */
        + hd_len +1 + ft_len + 1 /* adding \n */
        + 1); /* NUL-terminated */
    if (header) {
        strcpy(s, header);
        s += hd_len;
        *s++ = '\n';
    }
    for (i = 0; in_len > 0; i += PEM_IN_CHUNK, in_len -= PEM_IN_CHUNK) {
        rv = apr_encode_base64(s,
            (const char*)der_data + i, in_len > PEM_IN_CHUNK? PEM_IN_CHUNK : in_len,
            APR_ENCODE_NONE, &n);
        s += n;
        *s++ = '\n';
    }
    if (footer) {
        strcpy(s, footer);
        s += ft_len;
        *s++ = '\n';
    }
cleanup:
    *ppem = (APR_SUCCESS == rv)? pem : NULL;
    return rv;
}

#define PEM_CERT_HD     "-----BEGIN CERTIFICATE-----"
#define PEM_CERT_FT     "-----END CERTIFICATE-----"

apr_status_t tls_cert_to_pem(const char **ppem, apr_pool_t *p, const rustls_certificate *cert)
{
    const unsigned char* der_data;
    size_t der_len;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;
    const char *pem = NULL;

    rr = rustls_certificate_get_der(cert, &der_data, &der_len);
    if (RUSTLS_RESULT_OK != rr) goto cleanup;
    rv = tls_der_to_pem(&pem, p, der_data, der_len, PEM_CERT_HD, PEM_CERT_FT);
cleanup:
    if (RUSTLS_RESULT_OK != rr) {
        rv = tls_util_rustls_error(p, rr, NULL);
    }
    *ppem = (APR_SUCCESS == rv)? pem : NULL;
    return rv;
}

static void nullify_key_pem(tls_cert_pem_t *pems)
{
    if (pems->pkey_pem.len) {
        memset((void*)pems->pkey_pem.data, 0, pems->pkey_pem.len);
    }
}

static apr_status_t make_certified_key(
    apr_pool_t *p, const char *name,
    const tls_data_t *cert_pem, const tls_data_t *pkey_pem,
    const rustls_certified_key **pckey)
{
    const rustls_certified_key *ckey = NULL;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;

    rr = rustls_certified_key_build(
        cert_pem->data, cert_pem->len,
        pkey_pem->data, pkey_pem->len,
        &ckey);

    if (RUSTLS_RESULT_OK != rr) {
        const char *err_descr;
        rv = tls_util_rustls_error(p, rr, &err_descr);
        ap_log_perror(APLOG_MARK, APLOG_ERR, rv, p, APLOGNO(10363)
                     "Failed to load certified key %s: [%d] %s",
                     name, (int)rr, err_descr);
    }
    if (APR_SUCCESS == rv) {
        *pckey = ckey;
    }
    else if (ckey) {
        rustls_certified_key_free(ckey);
    }
    return rv;
}

apr_status_t tls_cert_load_cert_key(
    apr_pool_t *p, const tls_cert_spec_t *spec,
    const char **pcert_pem, const rustls_certified_key **pckey)
{
    apr_status_t rv = APR_SUCCESS;

    if (spec->cert_file) {
        tls_cert_pem_t *pems;

        rv = tls_cert_load_pem(p, spec, &pems);
        if (APR_SUCCESS != rv) goto cleanup;
        if (pcert_pem) *pcert_pem = tls_data_to_str(p, &pems->cert_pem);
        rv = make_certified_key(p, spec->cert_file, &pems->cert_pem, &pems->pkey_pem, pckey);
        /* dont want them hanging around in memory unnecessarily. */
        nullify_key_pem(pems);
    }
    else if (spec->cert_pem) {
        tls_data_t pkey_pem, pem;
        pem = tls_data_from_str(spec->cert_pem);
        if (spec->pkey_pem) {
            pkey_pem = tls_data_from_str(spec->pkey_pem);
        }
        else {
            pkey_pem = pem;
        }
        if (pcert_pem) *pcert_pem = spec->cert_pem;
        rv = make_certified_key(p, "memory", &pem, &pkey_pem, pckey);
        /* pems provided from outside are responsibility of the caller */
    }
    else {
        rv = APR_ENOENT; goto cleanup;
    }
cleanup:
    return rv;
}

typedef struct {
    const char *id;
    const char *cert_pem;
    server_rec *server;
    const rustls_certified_key *certified_key;
} tls_cert_reg_entry_t;

static int reg_entry_cleanup(void *ctx, const void *key, apr_ssize_t klen, const void *val)
{
    tls_cert_reg_entry_t *entry = (tls_cert_reg_entry_t*)val;
    (void)ctx; (void)key; (void)klen;
    if (entry->certified_key) {
        rustls_certified_key_free(entry->certified_key);
        entry->certified_key = NULL;
    }
    return 1;
}

static apr_status_t reg_cleanup(void *data)
{
    tls_cert_reg_t *reg = data;
    if (reg->id2entry) {
        apr_hash_do(reg_entry_cleanup, reg, reg->id2entry);
        apr_hash_clear(reg->id2entry);
        if (reg->key2entry) apr_hash_clear(reg->key2entry);
    }
    return APR_SUCCESS;
}

tls_cert_reg_t *tls_cert_reg_make(apr_pool_t *p)
{
    tls_cert_reg_t *reg;

    reg = apr_pcalloc(p, sizeof(*reg));
    reg->pool = p;
    reg->id2entry = apr_hash_make(p);
    reg->key2entry = apr_hash_make(p);
    apr_pool_cleanup_register(p, reg, reg_cleanup, apr_pool_cleanup_null);
    return reg;
}

apr_size_t tls_cert_reg_count(tls_cert_reg_t *reg)
{
    return apr_hash_count(reg->id2entry);
}

static const char *cert_spec_to_id(const tls_cert_spec_t *spec)
{
    if (spec->cert_file) return spec->cert_file;
    if (spec->cert_pem) return spec->cert_pem;
    return NULL;
}

apr_status_t tls_cert_reg_get_certified_key(
    tls_cert_reg_t *reg, server_rec *s, const tls_cert_spec_t *spec,
    const rustls_certified_key **pckey)
{
    apr_status_t rv = APR_SUCCESS;
    const char *id;
    tls_cert_reg_entry_t *entry;

    id = cert_spec_to_id(spec);
    assert(id);
    entry = apr_hash_get(reg->id2entry, id, APR_HASH_KEY_STRING);
    if (!entry) {
        const rustls_certified_key *certified_key;
        const char *cert_pem;
        rv = tls_cert_load_cert_key(reg->pool, spec, &cert_pem, &certified_key);
        if (APR_SUCCESS != rv) goto cleanup;
        entry = apr_pcalloc(reg->pool, sizeof(*entry));
        entry->id = apr_pstrdup(reg->pool, id);
        entry->cert_pem = cert_pem;
        entry->server = s;
        entry->certified_key = certified_key;
        apr_hash_set(reg->id2entry, entry->id, APR_HASH_KEY_STRING, entry);
        /* associates the pointer value */
        apr_hash_set(reg->key2entry, &entry->certified_key, sizeof(entry->certified_key), entry);
    }

cleanup:
    if (APR_SUCCESS == rv) {
        *pckey = entry->certified_key;
    }
    else {
        *pckey = NULL;
    }
    return rv;
}

typedef struct {
    void *userdata;
    tls_cert_reg_visitor *visitor;
} reg_visit_ctx_t;

static int reg_visit(void *vctx, const void *key, apr_ssize_t klen, const void *val)
{
    reg_visit_ctx_t *ctx = vctx;
    tls_cert_reg_entry_t *entry = (tls_cert_reg_entry_t*)val;

    (void)key; (void)klen;
    return ctx->visitor(ctx->userdata, entry->server, entry->id, entry->cert_pem, entry->certified_key);
}

void tls_cert_reg_do(
    tls_cert_reg_visitor *visitor, void *userdata, tls_cert_reg_t *reg)
{
    reg_visit_ctx_t ctx;
    ctx.visitor = visitor;
    ctx.userdata = userdata;
    apr_hash_do(reg_visit, &ctx, reg->id2entry);
}

const char *tls_cert_reg_get_id(tls_cert_reg_t *reg, const rustls_certified_key *certified_key)
{
    tls_cert_reg_entry_t *entry;

    entry = apr_hash_get(reg->key2entry, &certified_key, sizeof(certified_key));
    return entry? entry->id : NULL;
}

apr_status_t tls_cert_load_root_store(
    apr_pool_t *p, const char *store_file, rustls_root_cert_store **pstore)
{
    const char *fpath;
    tls_data_t pem;
    rustls_root_cert_store *store = NULL;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_pool_t *ptemp = NULL;
    apr_status_t rv;

    ap_assert(store_file);

    rv = apr_pool_create(&ptemp, p);
    if (APR_SUCCESS != rv) goto cleanup;
    apr_pool_tag(ptemp, "tls_load_root_cert_store");
    fpath = ap_server_root_relative(ptemp, store_file);
    if (NULL == fpath) {
        rv = APR_ENOENT; goto cleanup;
    }
    /* we use this for client auth CAs. 1MB seems large enough. */
    rv = tls_util_file_load(ptemp, fpath, 0, 1024*1024, &pem);
    if (APR_SUCCESS != rv) goto cleanup;

    store = rustls_root_cert_store_new();
    rr = rustls_root_cert_store_add_pem(store, pem.data, pem.len, 1);
    if (RUSTLS_RESULT_OK != rr) goto cleanup;

cleanup:
    if (RUSTLS_RESULT_OK != rr) {
        const char *err_descr;
        rv = tls_util_rustls_error(p, rr, &err_descr);
        ap_log_perror(APLOG_MARK, APLOG_ERR, rv, p, APLOGNO(10364)
                     "Failed to load root store %s: [%d] %s",
                     store_file, (int)rr, err_descr);
    }
    if (APR_SUCCESS == rv) {
        *pstore = store;
    }
    else {
        *pstore = NULL;
        if (store) rustls_root_cert_store_free(store);
    }
    if (ptemp) apr_pool_destroy(ptemp);
    return rv;
}

typedef struct {
    const char *id;
    rustls_root_cert_store *store;
} tls_cert_root_stores_entry_t;

static int stores_entry_cleanup(void *ctx, const void *key, apr_ssize_t klen, const void *val)
{
    tls_cert_root_stores_entry_t *entry = (tls_cert_root_stores_entry_t*)val;
    (void)ctx; (void)key; (void)klen;
    if (entry->store) {
        rustls_root_cert_store_free(entry->store);
        entry->store = NULL;
    }
    return 1;
}

static apr_status_t stores_cleanup(void *data)
{
    tls_cert_root_stores_t *stores = data;
    tls_cert_root_stores_clear(stores);
    return APR_SUCCESS;
}

tls_cert_root_stores_t *tls_cert_root_stores_make(apr_pool_t *p)
{
    tls_cert_root_stores_t *stores;

    stores = apr_pcalloc(p, sizeof(*stores));
    stores->pool = p;
    stores->file2store = apr_hash_make(p);
    apr_pool_cleanup_register(p, stores, stores_cleanup, apr_pool_cleanup_null);
    return stores;
}

void tls_cert_root_stores_clear(tls_cert_root_stores_t *stores)
{
    if (stores->file2store) {
        apr_hash_do(stores_entry_cleanup, stores, stores->file2store);
        apr_hash_clear(stores->file2store);
    }
}

apr_status_t tls_cert_root_stores_get(
    tls_cert_root_stores_t *stores,
    const char *store_file,
    rustls_root_cert_store **pstore)
{
    apr_status_t rv = APR_SUCCESS;
    tls_cert_root_stores_entry_t *entry;

    entry = apr_hash_get(stores->file2store, store_file, APR_HASH_KEY_STRING);
    if (!entry) {
        rustls_root_cert_store *store;
        rv = tls_cert_load_root_store(stores->pool, store_file, &store);
        if (APR_SUCCESS != rv) goto cleanup;
        entry = apr_pcalloc(stores->pool, sizeof(*entry));
        entry->id = apr_pstrdup(stores->pool, store_file);
        entry->store = store;
        apr_hash_set(stores->file2store, entry->id, APR_HASH_KEY_STRING, entry);
    }

cleanup:
    if (APR_SUCCESS == rv) {
        *pstore = entry->store;
    }
    else {
        *pstore = NULL;
    }
    return rv;
}

typedef struct {
    const char *id;
    const rustls_client_cert_verifier *client_verifier;
    const rustls_client_cert_verifier_optional *client_verifier_opt;
} tls_cert_verifiers_entry_t;

static int verifiers_entry_cleanup(void *ctx, const void *key, apr_ssize_t klen, const void *val)
{
    tls_cert_verifiers_entry_t *entry = (tls_cert_verifiers_entry_t*)val;
    (void)ctx; (void)key; (void)klen;
    if (entry->client_verifier) {
        rustls_client_cert_verifier_free(entry->client_verifier);
        entry->client_verifier = NULL;
    }
    if (entry->client_verifier_opt) {
        rustls_client_cert_verifier_optional_free(entry->client_verifier_opt);
        entry->client_verifier_opt = NULL;
    }
    return 1;
}

static apr_status_t verifiers_cleanup(void *data)
{
    tls_cert_verifiers_t *verifiers = data;
    tls_cert_verifiers_clear(verifiers);
    return APR_SUCCESS;
}

tls_cert_verifiers_t *tls_cert_verifiers_make(
    apr_pool_t *p, tls_cert_root_stores_t *stores)
{
    tls_cert_verifiers_t *verifiers;

    verifiers = apr_pcalloc(p, sizeof(*verifiers));
    verifiers->pool = p;
    verifiers->stores = stores;
    verifiers->file2verifier = apr_hash_make(p);
    apr_pool_cleanup_register(p, verifiers, verifiers_cleanup, apr_pool_cleanup_null);
    return verifiers;
}

void tls_cert_verifiers_clear(tls_cert_verifiers_t *verifiers)
{
    if (verifiers->file2verifier) {
        apr_hash_do(verifiers_entry_cleanup, verifiers, verifiers->file2verifier);
        apr_hash_clear(verifiers->file2verifier);
    }
}

static tls_cert_verifiers_entry_t * verifiers_get_or_make_entry(
    tls_cert_verifiers_t *verifiers,
    const char *store_file)
{
    tls_cert_verifiers_entry_t *entry;

    entry = apr_hash_get(verifiers->file2verifier, store_file, APR_HASH_KEY_STRING);
    if (!entry) {
        entry = apr_pcalloc(verifiers->pool, sizeof(*entry));
        entry->id = apr_pstrdup(verifiers->pool, store_file);
        apr_hash_set(verifiers->file2verifier, entry->id, APR_HASH_KEY_STRING, entry);
    }
    return entry;
}

apr_status_t tls_cert_client_verifiers_get(
    tls_cert_verifiers_t *verifiers,
    const char *store_file,
    const rustls_client_cert_verifier **pverifier)
{
    apr_status_t rv = APR_SUCCESS;
    tls_cert_verifiers_entry_t *entry;

    entry = verifiers_get_or_make_entry(verifiers, store_file);
    if (!entry->client_verifier) {
        rustls_root_cert_store *store;
        rv = tls_cert_root_stores_get(verifiers->stores, store_file, &store);
        if (APR_SUCCESS != rv) goto cleanup;
        entry->client_verifier = rustls_client_cert_verifier_new(store);
    }

cleanup:
    if (APR_SUCCESS == rv) {
        *pverifier = entry->client_verifier;
    }
    else {
        *pverifier = NULL;
    }
    return rv;
}

apr_status_t tls_cert_client_verifiers_get_optional(
    tls_cert_verifiers_t *verifiers,
    const char *store_file,
    const rustls_client_cert_verifier_optional **pverifier)
{
    apr_status_t rv = APR_SUCCESS;
    tls_cert_verifiers_entry_t *entry;

    entry = verifiers_get_or_make_entry(verifiers, store_file);
    if (!entry->client_verifier_opt) {
        rustls_root_cert_store *store;
        rv = tls_cert_root_stores_get(verifiers->stores, store_file, &store);
        if (APR_SUCCESS != rv) goto cleanup;
        entry->client_verifier_opt = rustls_client_cert_verifier_optional_new(store);
    }

cleanup:
    if (APR_SUCCESS == rv) {
        *pverifier = entry->client_verifier_opt;
    }
    else {
        *pverifier = NULL;
    }
    return rv;
}
