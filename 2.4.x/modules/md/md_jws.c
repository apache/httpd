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

static int header_set(void *data, const char *key, const char *val)
{
    md_json_sets(val, (md_json_t *)data, key, NULL);
    return 1;
}

apr_status_t md_jws_sign(md_json_t **pmsg, apr_pool_t *p,
                         const char *payload, size_t len, 
                         struct apr_table_t *protected, 
                         struct md_pkey_t *pkey, const char *key_id)
{
    md_json_t *msg, *jprotected;
    const char *prot64, *pay64, *sign64, *sign, *prot;
    apr_status_t rv = APR_SUCCESS;

    *pmsg = NULL;
    
    msg = md_json_create(p);

    jprotected = md_json_create(p);
    md_json_sets("RS256", jprotected, "alg", NULL);
    if (key_id) {
        md_json_sets(key_id, jprotected, "kid", NULL);
    }
    else {
        md_json_sets(md_pkey_get_rsa_e64(pkey, p), jprotected, "jwk", "e", NULL);
        md_json_sets("RSA", jprotected, "jwk", "kty", NULL);
        md_json_sets(md_pkey_get_rsa_n64(pkey, p), jprotected, "jwk", "n", NULL);
    }
    apr_table_do(header_set, jprotected, protected, NULL);
    prot = md_json_writep(jprotected, p, MD_JSON_FMT_COMPACT);
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, p, "protected: %s",
                  prot ? prot : "<failed to serialize!>");

    if (!prot) {
        rv = APR_EINVAL;
    }
    
    if (rv == APR_SUCCESS) {
        prot64 = md_util_base64url_encode(prot, strlen(prot), p);
        md_json_sets(prot64, msg, "protected", NULL);
        pay64 = md_util_base64url_encode(payload, len, p);

        md_json_sets(pay64, msg, "payload", NULL);
        sign = apr_psprintf(p, "%s.%s", prot64, pay64);

        rv = md_crypt_sign64(&sign64, pkey, p, sign, strlen(sign));
    }

    if (rv == APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, p, 
                      "jws pay64=%s\nprot64=%s\nsign64=%s", pay64, prot64, sign64);
        
        md_json_sets(sign64, msg, "signature", NULL);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "jwk signed message");
    } 
    
    *pmsg = (APR_SUCCESS == rv)? msg : NULL;
    return rv;
}

apr_status_t md_jws_pkey_thumb(const char **pthumb, apr_pool_t *p, struct md_pkey_t *pkey)
{
    const char *e64, *n64, *s;
    apr_status_t rv;
    
    e64 = md_pkey_get_rsa_e64(pkey, p);
    n64 = md_pkey_get_rsa_n64(pkey, p);
    if (!e64 || !n64) {
        return APR_EINVAL;
    }

    /* whitespace and order is relevant, since we hand out a digest of this */
    s = apr_psprintf(p, "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}", e64, n64);
    rv = md_crypt_sha256_digest64(pthumb, p, s, strlen(s));
    return rv;
}
