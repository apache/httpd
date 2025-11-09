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
 
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_buckets.h>

#include "md_crypt.h"
#include "md_json.h"
#include "md_jws.h"
#include "md_log.h"
#include "md_util.h"

apr_status_t md_jws_get_jwk(md_json_t **pjwk, apr_pool_t *p, struct md_pkey_t *pkey)
{
    md_json_t *jwk;

    if (!pkey) return APR_EINVAL;

    jwk = md_json_create(p);
    md_json_sets(md_pkey_get_rsa_e64(pkey, p), jwk, "e", NULL);
    md_json_sets("RSA", jwk, "kty", NULL);
    md_json_sets(md_pkey_get_rsa_n64(pkey, p), jwk, "n", NULL);
    *pjwk = jwk;
    return APR_SUCCESS;
}

apr_status_t md_jws_sign(md_json_t **pmsg, apr_pool_t *p,
                         md_data_t *payload, md_json_t *prot_fields,
                         struct md_pkey_t *pkey, const char *key_id)
{
    md_json_t *msg, *jprotected, *jwk;
    const char *prot64, *pay64, *sign64, *sign, *prot;
    md_data_t data;
    apr_status_t rv;

    msg = md_json_create(p);
    jprotected = md_json_clone(p, prot_fields);
    md_json_sets("RS256", jprotected, "alg", NULL);
    if (key_id) {
        md_json_sets(key_id, jprotected, "kid", NULL);
    }
    else {
        rv = md_jws_get_jwk(&jwk, p, pkey);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "get jwk");
            goto cleanup;
        }
        md_json_setj(jwk, jprotected, "jwk", NULL);
    }

    prot = md_json_writep(jprotected, p, MD_JSON_FMT_COMPACT);
    if (!prot) {
        rv = APR_EINVAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "serialize protected");
        goto cleanup;
    }

    md_data_init(&data, prot, strlen(prot));
    prot64 = md_util_base64url_encode(&data, p);
    md_json_sets(prot64, msg, "protected", NULL);

    pay64 = md_util_base64url_encode(payload, p);
    md_json_sets(pay64, msg, "payload", NULL);
    sign = apr_psprintf(p, "%s.%s", prot64, pay64);

    rv = md_crypt_sign64(&sign64, pkey, p, sign, strlen(sign));
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "jwk signed message");
        goto cleanup;
    }
    md_json_sets(sign64, msg, "signature", NULL);

cleanup:
    *pmsg = (APR_SUCCESS == rv)? msg : NULL;
    return rv;
}

apr_status_t md_jws_pkey_thumb(const char **pthumb, apr_pool_t *p, struct md_pkey_t *pkey)
{
    const char *e64, *n64, *s;
    md_data_t data;
    apr_status_t rv;
    
    e64 = md_pkey_get_rsa_e64(pkey, p);
    n64 = md_pkey_get_rsa_n64(pkey, p);
    if (!e64 || !n64) {
        return APR_EINVAL;
    }

    /* whitespace and order is relevant, since we hand out a digest of this */
    s = apr_psprintf(p, "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}", e64, n64);
    md_data_init_str(&data, s);
    rv = md_crypt_sha256_digest64(pthumb, p, &data);
    return rv;
}

apr_status_t md_jws_hmac(md_json_t **pmsg, apr_pool_t *p,
                         md_data_t *payload, md_json_t *prot_fields,
                         const md_data_t *hmac_key)
{
    md_json_t *msg, *jprotected;
    const char *prot64, *pay64, *mac64, *sign, *prot;
    md_data_t data;
    apr_status_t rv;

    msg = md_json_create(p);
    jprotected = md_json_clone(p, prot_fields);
    md_json_sets("HS256", jprotected, "alg", NULL);
    prot = md_json_writep(jprotected, p, MD_JSON_FMT_COMPACT);
    if (!prot) {
        rv = APR_EINVAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "serialize protected");
        goto cleanup;
    }

    md_data_init(&data, prot, strlen(prot));
    prot64 = md_util_base64url_encode(&data, p);
    md_json_sets(prot64, msg, "protected", NULL);

    pay64 = md_util_base64url_encode(payload, p);
    md_json_sets(pay64, msg, "payload", NULL);
    sign = apr_psprintf(p, "%s.%s", prot64, pay64);

    rv = md_crypt_hmac64(&mac64, hmac_key, p, sign, strlen(sign));
    if (APR_SUCCESS != rv) {
        goto cleanup;
    }
    md_json_sets(mac64, msg, "signature", NULL);

cleanup:
    *pmsg = (APR_SUCCESS == rv)? msg : NULL;
    return rv;
}
