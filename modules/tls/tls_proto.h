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
#ifndef tls_proto_h
#define tls_proto_h

#include "tls_util.h"


#define TLS_VERSION_1_2   0x0303
#define TLS_VERSION_1_3   0x0304

/**
 * Specification of a TLS cipher by name, possible alias and its 16 bit value
 * as assigned by IANA.
 */
typedef struct {
    apr_uint16_t id;      /* IANA 16-bit assigned value as used on the wire */
    const char *name;     /* IANA given name of the cipher */
    const char *alias;    /* Optional, commonly known alternate name */
} tls_cipher_t;

/**
 * TLS protocol related definitions constructed
 * by querying crustls lib.
 */
typedef struct tls_proto_conf_t tls_proto_conf_t;
struct tls_proto_conf_t {
    apr_array_header_t *supported_versions; /* supported protocol versions (apr_uint16_t) */
    apr_hash_t *known_ciphers_by_name; /* hash by name of known tls_cipher_t* */
    apr_hash_t *known_ciphers_by_id; /* hash by id of known tls_cipher_t* */
    apr_hash_t *rustls_ciphers_by_id; /* hash by id of rustls rustls_supported_ciphersuite* */
    apr_array_header_t *supported_cipher_ids; /* cipher ids (apr_uint16_t) supported by rustls */
    const rustls_root_cert_store *native_roots;
};

/**
 * Create and populate the protocol configuration.
 */
tls_proto_conf_t *tls_proto_init(apr_pool_t *p, server_rec *s);

/**
 * Called during pre-config phase to start initialization
 * of the tls protocol configuration.
 */
apr_status_t tls_proto_pre_config(apr_pool_t *pool, apr_pool_t *ptemp);

/**
 * Called during post-config phase to conclude the initialization
 * of the tls protocol configuration.
 */
apr_status_t tls_proto_post_config(apr_pool_t *p, apr_pool_t *ptemp, server_rec *s);

/**
 * Get the TLS protocol identifier (as used on the wire) for the TLS
 * protocol of the given name. Returns 0 if protocol is unknown.
 */
apr_uint16_t tls_proto_get_version_by_name(tls_proto_conf_t *conf, const char *name);

/**
 * Get the name of the protocol version identified by its identifier. This
 * will return the name from the protocol configuration or, if unknown, create
 * the string `TLSv0x%04x` from the 16bit identifier.
 */
const char *tls_proto_get_version_name(
    tls_proto_conf_t *conf, apr_uint16_t id, apr_pool_t *pool);

/**
 * Create an array of the given TLS protocol version identifier `min_version`
 * and all supported new ones. The array carries apr_uint16_t values.
 */
apr_array_header_t *tls_proto_create_versions_plus(
    tls_proto_conf_t *conf, apr_uint16_t min_version, apr_pool_t *pool);

/**
 * Get a TLS cipher spec by name/alias.
 */
apr_status_t tls_proto_get_cipher_by_name(
    tls_proto_conf_t *conf, const char *name, apr_uint16_t *pcipher);

/**
 * Return != 0 iff the cipher is supported by the rustls library.
 */
int tls_proto_is_cipher_supported(tls_proto_conf_t *conf, apr_uint16_t cipher);

/**
 * Get the name of a TLS cipher for the IANA assigned 16bit value. This will
 * return the name in the protocol configuration, if the cipher is known, and
 * create the string `TLS_CIPHER_0x%04x` for the 16bit cipher value.
 */
const char *tls_proto_get_cipher_name(
    tls_proto_conf_t *conf, apr_uint16_t cipher, apr_pool_t *pool);

/**
 * Get the concatenated names with ':' as separator of all TLS cipher identifiers
 * as given in `ciphers`.
 * @param conf the TLS protocol configuration
 * @param ciphers the 16bit values of the TLS ciphers
 * @param pool to use for allocation the string.
 */
const char *tls_proto_get_cipher_names(
    tls_proto_conf_t *conf, const apr_array_header_t *ciphers, apr_pool_t *pool);

/**
 * Convert an array of TLS cipher 16bit identifiers into the `rustls_supported_ciphersuite`
 * instances that can be passed to crustls in session configurations.
 * Any cipher identifier not supported by rustls we be silently omitted.
 */
apr_array_header_t *tls_proto_get_rustls_suites(
    tls_proto_conf_t *conf, const apr_array_header_t *ids, apr_pool_t *pool);

#endif /* tls_proto_h */
