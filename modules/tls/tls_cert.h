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
#ifndef tls_cert_h
#define tls_cert_h

#include "tls_util.h"

/**
 * The PEM data of a certificate and its key.
 */
typedef struct {
    tls_data_t cert_pem;
    tls_data_t pkey_pem;
} tls_cert_pem_t;

/**
 * Specify a certificate via files or PEM data.
 */
typedef struct {
    const char *cert_file; /* file path, relative to ap_root */
    const char *pkey_file; /* file path, relative to ap_root */
    const char *cert_pem;  /* NUL-terminated PEM string */
    const char *pkey_pem;  /* NUL-terminated PEM string */
} tls_cert_spec_t;

/**
 * Load the PEM data for a certificate file and key file as given in `cert`.
 */
apr_status_t tls_cert_load_pem(
    apr_pool_t *p, const tls_cert_spec_t *cert, tls_cert_pem_t **ppem);

apr_status_t tls_cert_to_pem(const char **ppem, apr_pool_t *p, const rustls_certificate *cert);

/**
 * Load a rustls certified key from a certificate specification.
 * The returned `rustls_certified_key` is owned by the caller.
 * @param p the memory pool to use
 * @param spec the specification for the certificate (file or PEM data)
 * @param cert_pem return the PEM data used for loading the certificates, optional
 * @param pckey the loaded certified key on return
 */
apr_status_t tls_cert_load_cert_key(
    apr_pool_t *p, const tls_cert_spec_t *spec,
    const char **pcert_pem, const rustls_certified_key **pckey);

/**
 * A registry of rustls_certified_key* by identifier.
 */
typedef struct tls_cert_reg_t tls_cert_reg_t;
struct  tls_cert_reg_t{
    apr_pool_t *pool;
    apr_hash_t *id2entry;
    apr_hash_t *key2entry;
};

/**
 * Create a new registry with lifetime based on the memory pool.
 * The registry will take care of its memory and allocated keys when
 * the pool is destroyed.
 */
tls_cert_reg_t *tls_cert_reg_make(apr_pool_t *p);

/**
 * Return the number of certified keys in the registry.
 */
apr_size_t tls_cert_reg_count(tls_cert_reg_t *reg);

/**
 * Get a the `rustls_certified_key` identified by `spec` from the registry.
 * This will load the key the first time it is requested.
 * The returned `rustls_certified_key` is owned by the registry.
 * @param reg the certified key registry
 * @param s the server_rec this is loaded into, useful for error logging
 * @param spec the specification of the certified key
 * @param pckey the certified key instance on return
 */
apr_status_t tls_cert_reg_get_certified_key(
    tls_cert_reg_t *reg, server_rec *s, const tls_cert_spec_t *spec, const rustls_certified_key **pckey);

/**
 * Visit all certified keys in the registry.
 * The callback may return 0 to abort the iteration.
 * @param userdata supplied by the visit invocation
 * @param s the server_rec the certified was load into first
 * @param id internal identifier of the certified key
 * @param cert_pem the PEM data of the certificate and its chain
 * @param certified_key the key instance itself
 */
typedef int tls_cert_reg_visitor(
    void *userdata, server_rec *s,
    const char *id, const char *cert_pem, const rustls_certified_key *certified_key);

/**
 * Visit all certified_key entries in the registry.
 * @param visitor callback invoked on each entry until it returns 0.
 * @param userdata passed to callback
 * @param reg the registry to iterate over
 */
void tls_cert_reg_do(
    tls_cert_reg_visitor *visitor, void *userdata, tls_cert_reg_t *reg);

/**
 * Get the identity assigned to a loaded, certified key. Returns NULL, if the
 * key is not part of the registry. The returned bytes are owned by the registry
 * entry.
 * @param reg the registry to look in.
 * @param certified_key the key to get the identifier for
 */
const char *tls_cert_reg_get_id(tls_cert_reg_t *reg, const rustls_certified_key *certified_key);

/**
 * Load all root certificates from a PEM file into a rustls_root_cert_store.
 * @param p the memory pool to use
 * @param store_file the (server relative) path of the PEM file
 * @param pstore the loaded root store on success
 */
apr_status_t tls_cert_load_root_store(
    apr_pool_t *p, const char *store_file, rustls_root_cert_store **pstore);

typedef struct tls_cert_root_stores_t tls_cert_root_stores_t;
struct tls_cert_root_stores_t {
    apr_pool_t *pool;
    apr_hash_t *file2store;
};

/**
 * Create a new root stores registry with lifetime based on the memory pool.
 * The registry will take care of its memory and allocated stores when
 * the pool is destroyed.
 */
tls_cert_root_stores_t *tls_cert_root_stores_make(apr_pool_t *p);

/**
 * Clear the root stores registry, freeing all stores.
 */
void tls_cert_root_stores_clear(tls_cert_root_stores_t *stores);

/**
 * Load all root certificates from a PEM file into a rustls_root_cert_store.
 * @param p the memory pool to use
 * @param store_file the (server relative) path of the PEM file
 * @param pstore the loaded root store on success
 */
apr_status_t tls_cert_root_stores_get(
    tls_cert_root_stores_t *stores,
    const char *store_file,
    rustls_root_cert_store **pstore);

typedef struct tls_cert_verifiers_t tls_cert_verifiers_t;
struct tls_cert_verifiers_t {
    apr_pool_t *pool;
    tls_cert_root_stores_t *stores;
    apr_hash_t *file2verifier;
};

/**
 * Create a new registry for certificate verifiers with lifetime based on the memory pool.
 * The registry will take care of its memory and allocated verifiers when
 * the pool is destroyed.
 * @param p the memory pool to use
 * @param stores the store registry for lookups
 */
tls_cert_verifiers_t *tls_cert_verifiers_make(
    apr_pool_t *p, tls_cert_root_stores_t *stores);

/**
 * Clear the verifiers registry, freeing all verifiers.
 */
void tls_cert_verifiers_clear(
    tls_cert_verifiers_t *verifiers);

/**
 * Get the mandatory client certificate verifier for the
 * root certificate store in `store_file`. Will create
 * the verifier if not already known.
 * @param verifiers the registry of certificate verifiers
 * @param store_file the (server relative) path of the PEM file with certificates
 * @param pverifiers the verifier on success
 */
apr_status_t tls_cert_client_verifiers_get(
    tls_cert_verifiers_t *verifiers,
    const char *store_file,
    const rustls_client_cert_verifier **pverifier);

/**
 * Get the optional client certificate verifier for the
 * root certificate store in `store_file`. Will create
 * the verifier if not already known.
 * @param verifiers the registry of certificate verifiers
 * @param store_file the (server relative) path of the PEM file with certificates
 * @param pverifiers the verifier on success
 */
apr_status_t tls_cert_client_verifiers_get_optional(
    tls_cert_verifiers_t *verifiers,
    const char *store_file,
    const rustls_client_cert_verifier_optional **pverifier);

#endif /* tls_cert_h */