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
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_hash.h>
#include <apr_uri.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "md_result.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"

#include "md_tailscale.h"

typedef struct {
    apr_pool_t *pool;
    md_proto_driver_t *driver;
    const char *unix_socket_path;
    md_t *md;
    apr_array_header_t *chain;
    md_pkey_t *pkey;
} ts_ctx_t;

static apr_status_t ts_init(md_proto_driver_t *d, md_result_t *result)
{
    ts_ctx_t *ts_ctx;
    apr_uri_t uri;
    const char *ca_url;
    apr_status_t rv = APR_SUCCESS;

    md_result_set(result, APR_SUCCESS, NULL);
    ts_ctx = apr_pcalloc(d->p, sizeof(*ts_ctx));
    ts_ctx->pool = d->p;
    ts_ctx->driver = d;
    ts_ctx->chain = apr_array_make(d->p, 5, sizeof(md_cert_t *));

    ca_url = (d->md->ca_urls && !apr_is_empty_array(d->md->ca_urls))?
                APR_ARRAY_IDX(d->md->ca_urls, 0, const char*) : NULL;
    if (!ca_url) {
        ca_url = MD_TAILSCALE_DEF_URL;
    }
    rv = apr_uri_parse(d->p, ca_url, &uri);
    if (APR_SUCCESS != rv) {
        md_result_printf(result, rv, "error parsing CA URL `%s`", ca_url);
        goto leave;
    }
    if (uri.scheme && uri.scheme[0] && strcmp("file", uri.scheme)) {
        rv = APR_ENOTIMPL;
        md_result_printf(result, rv, "non `file` URLs not supported, CA URL is `%s`",
                         ca_url);
        goto leave;
    }
    if (uri.hostname && uri.hostname[0] && strcmp("localhost", uri.hostname)) {
        rv = APR_ENOTIMPL;
        md_result_printf(result, rv, "non `localhost` URLs not supported, CA URL is `%s`",
                         ca_url);
        goto leave;
    }
    ts_ctx->unix_socket_path = uri.path;
    d->baton = ts_ctx;

leave:
    return rv;
}

static apr_status_t ts_preload_init(md_proto_driver_t *d, md_result_t *result)
{
    return ts_init(d, result);
}

static apr_status_t ts_preload(md_proto_driver_t *d,
                               md_store_group_t load_group, md_result_t *result)
{
    apr_status_t rv;
    md_t *md;
    md_credentials_t *creds;
    md_pkey_spec_t *pkspec;
    apr_array_header_t *all_creds;
    const char *name;
    int i;

    name = d->md->name;
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, "%s: preload start", name);
    /* Load data from MD_SG_STAGING and save it into "load_group".
     */
    if (APR_SUCCESS != (rv = md_load(d->store, MD_SG_STAGING, name, &md, d->p))) {
        md_result_set(result, rv, "loading staged md.json");
        goto leave;
    }

     /* tailscale generates one cert+key with key specification being whatever
      * it chooses. Use the NULL spec here.
      */
    all_creds = apr_array_make(d->p, 5, sizeof(md_credentials_t*));
    pkspec = NULL;
    if (APR_SUCCESS != (rv = md_creds_load(d->store, MD_SG_STAGING, name, pkspec, &creds, d->p))) {
        md_result_printf(result, rv, "loading staged credentials");
        goto leave;
    }
    if (!creds->chain) {
        rv = APR_ENOENT;
        md_result_printf(result, rv, "no certificate in staged credentials");
        goto leave;
    }
    if (APR_SUCCESS != (rv = md_check_cert_and_pkey(creds->chain, creds->pkey))) {
        md_result_printf(result, rv, "certificate and private key do not match in staged credentials");
        goto leave;
    }
    APR_ARRAY_PUSH(all_creds, md_credentials_t*) = creds;

    md_result_activity_setn(result, "purging store tmp space");
    rv = md_store_purge(d->store, d->p, load_group, name);
    if (APR_SUCCESS != rv) {
        md_result_set(result, rv, NULL);
        goto leave;
    }

    md_result_activity_setn(result, "saving staged md/privkey/pubcert");
    if (APR_SUCCESS != (rv = md_save(d->store, d->p, load_group, md, 1))) {
        md_result_set(result, rv, "writing md.json");
        goto leave;
    }

    for (i = 0; i < all_creds->nelts; ++i) {
        creds = APR_ARRAY_IDX(all_creds, i, md_credentials_t*);
        if (APR_SUCCESS != (rv = md_creds_save(d->store, d->p, load_group, name, creds, 1))) {
            md_result_printf(result, rv, "writing credentials #%d", i);
            goto leave;
        }
    }

    md_result_set(result, APR_SUCCESS, "saved staged data successfully");

leave:
    md_result_log(result, MD_LOG_DEBUG);
    return rv;
}

static apr_status_t rv_of_response(const md_http_response_t *res)
{
    switch (res->status) {
        case 200:
            return APR_SUCCESS;
        case 400:
            return APR_EINVAL;
        case 401: /* sectigo returns this instead of 403 */
        case 403:
            return APR_EACCES;
        case 404:
            return APR_ENOENT;
        default:
            return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

static apr_status_t on_get_cert(const md_http_response_t *res, void *baton)
{
    ts_ctx_t *ts_ctx = baton;
    apr_status_t rv;

    rv = rv_of_response(res);
    if (APR_SUCCESS != rv) goto leave;
    apr_array_clear(ts_ctx->chain);
    rv = md_cert_chain_read_http(ts_ctx->chain, ts_ctx->pool, res);
    if (APR_SUCCESS != rv) goto leave;

leave:
    return rv;
}

static apr_status_t on_get_key(const md_http_response_t *res, void *baton)
{
    ts_ctx_t *ts_ctx = baton;
    apr_status_t rv;

    rv = rv_of_response(res);
    if (APR_SUCCESS != rv) goto leave;
    rv = md_pkey_read_http(&ts_ctx->pkey, ts_ctx->pool, res);
    if (APR_SUCCESS != rv) goto leave;

leave:
    return rv;
}

static apr_status_t ts_renew(md_proto_driver_t *d, md_result_t *result)
{
    const char *name, *domain, *url;
    apr_status_t rv = APR_ENOENT;
    ts_ctx_t *ts_ctx = d->baton;
    md_http_t *http;
    const md_pubcert_t *pubcert;
    md_cert_t *old_cert, *new_cert;
    int reset_staging = d->reset;

    /* "renewing" the certificate from tailscale. Since tailscale has its
     * own ideas on when to do this, we can only inspect the certificate
     * it gives us and see if it is different from the current one we have.
     * (if we have any. first time, lacking a cert, any it gives us is
     *  considered as 'renewed'.)
     */
    name = d->md->name;
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, "%s: renewing cert", name);

    /* When not explicitly told to reset, we check the existing data. If
     * it is incomplete or old, we trigger the reset for a clean start. */
    if (!reset_staging) {
        md_result_activity_setn(result, "Checking staging area");
        rv = md_load(d->store, MD_SG_STAGING, d->md->name, &ts_ctx->md, d->p);
        if (APR_SUCCESS == rv) {
            /* So, we have a copy in staging, but is it a recent or an old one? */
            if (md_is_newer(d->store, MD_SG_DOMAINS, MD_SG_STAGING, d->md->name, d->p)) {
                reset_staging = 1;
            }
        }
        else if (APR_STATUS_IS_ENOENT(rv)) {
            reset_staging = 1;
            rv = APR_SUCCESS;
        }
    }

    if (reset_staging) {
        md_result_activity_setn(result, "Resetting staging area");
        /* reset the staging area for this domain */
        rv = md_store_purge(d->store, d->p, MD_SG_STAGING, d->md->name);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, d->p,
                      "%s: reset staging area", d->md->name);
        if (APR_SUCCESS != rv && !APR_STATUS_IS_ENOENT(rv)) {
            md_result_printf(result, rv, "resetting staging area");
            goto leave;
        }
        rv = APR_SUCCESS;
        ts_ctx->md = NULL;
    }

    if (!ts_ctx->md || !md_array_str_eq(ts_ctx->md->ca_urls, d->md->ca_urls, 1)) {
        md_result_activity_printf(result, "Resetting staging for %s", d->md->name);
        /* re-initialize staging */
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, "%s: setup staging", d->md->name);
        md_store_purge(d->store, d->p, MD_SG_STAGING, d->md->name);
        ts_ctx->md = md_copy(d->p, d->md);
        rv = md_save(d->store, d->p, MD_SG_STAGING, ts_ctx->md, 0);
        if (APR_SUCCESS != rv) {
            md_result_printf(result, rv, "Saving MD information in staging area.");
            md_result_log(result, MD_LOG_ERR);
            goto leave;
        }
    }

    if (!ts_ctx->unix_socket_path) {
        rv = APR_ENOTIMPL;
        md_result_set(result, rv, "only unix sockets are supported for tailscale connections");
        goto leave;
    }

    rv = md_util_is_unix_socket(ts_ctx->unix_socket_path, d->p);
    if (APR_SUCCESS != rv) {
        md_result_printf(result, rv, "tailscale socket not available, may not be up: %s",
                         ts_ctx->unix_socket_path);
        goto leave;
    }

    rv = md_http_create(&http, d->p,
                        apr_psprintf(d->p, "Apache mod_md/%s", MOD_MD_VERSION),
                        NULL);
    if (APR_SUCCESS != rv) {
        md_result_set(result, rv, "creating http context");
        goto leave;
    }
    md_http_set_unix_socket_path(http, ts_ctx->unix_socket_path);

    domain = (d->md->domains->nelts > 0)?
              APR_ARRAY_IDX(d->md->domains, 0, const char*) : NULL;
    if (!domain) {
        rv = APR_EINVAL;
        md_result_set(result, rv, "no domain names available");
    }

    url = apr_psprintf(d->p, "http://localhost/localapi/v0/cert/%s?type=crt",
                       domain);
    rv = md_http_GET_perform(http, url, NULL, on_get_cert, ts_ctx);
    if (APR_SUCCESS != rv) {
        md_result_set(result, rv, "retrieving certificate from tailscale");
        goto leave;
    }
    if (ts_ctx->chain->nelts <= 0) {
        rv = APR_ENOENT;
        md_result_set(result, rv, "tailscale returned no certificates");
        goto leave;
    }

    /* Got the key and the chain, is it new? */
    rv = md_reg_get_pubcert(&pubcert, d->reg,d->md, 0, d->p);
    if (APR_SUCCESS == rv) {
        old_cert = APR_ARRAY_IDX(pubcert->certs, 0, md_cert_t*);
        new_cert = APR_ARRAY_IDX(ts_ctx->chain, 0, md_cert_t*);
        if (md_certs_are_equal(old_cert, new_cert)) {
            /* tailscale has not renewed the certificate, yet */
            rv = APR_ENOENT;
            md_result_set(result, rv, "tailscale has not renewed the certificate yet");
            /* let's check this daily */
            md_result_delay_set(result, apr_time_now() + apr_time_from_sec(MD_SECS_PER_DAY));
            goto leave;
        }
    }

    /* We have a new certificate (or had none before).
     * Get the key and store both in STAGING.
     */
    url = apr_psprintf(d->p, "http://localhost/localapi/v0/cert/%s?type=key",
                       domain);
    rv = md_http_GET_perform(http, url, NULL, on_get_key, ts_ctx);
    if (APR_SUCCESS != rv) {
        md_result_set(result, rv, "retrieving key from tailscale");
        goto leave;
    }

    rv = md_pkey_save(d->store, d->p, MD_SG_STAGING, name, NULL, ts_ctx->pkey, 1);
    if (APR_SUCCESS != rv) {
        md_result_set(result, rv, "saving private key");
        goto leave;
    }

    rv = md_pubcert_save(d->store, d->p, MD_SG_STAGING, name,
                         NULL, ts_ctx->chain, 1);
    if (APR_SUCCESS != rv) {
        md_result_printf(result, rv, "saving new certificate chain.");
        goto leave;
    }

    md_result_set(result, APR_SUCCESS,
        "A new tailscale certificate has been retrieved successfully and can "
        "be used. A graceful server restart is recommended.");

leave:
    md_result_log(result, MD_LOG_DEBUG);
    return rv;
}

static apr_status_t ts_complete_md(md_t *md, apr_pool_t *p)
{
    (void)p;
    if (!md->ca_urls) {
        md->ca_urls = apr_array_make(p, 3, sizeof(const char *));
        APR_ARRAY_PUSH(md->ca_urls, const char*) = MD_TAILSCALE_DEF_URL;
    }
    return APR_SUCCESS;
}


static md_proto_t TAILSCALE_PROTO = {
    MD_PROTO_TAILSCALE, ts_init, ts_renew,
    ts_preload_init, ts_preload, ts_complete_md,
};

apr_status_t md_tailscale_protos_add(apr_hash_t *protos, apr_pool_t *p)
{
    (void)p;
    apr_hash_set(protos, MD_PROTO_TAILSCALE, sizeof(MD_PROTO_TAILSCALE)-1, &TAILSCALE_PROTO);
    return APR_SUCCESS;
}
