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
#include <apr_uri.h>
#include <apr_tables.h>
#include <apr_time.h>
#include <apr_date.h>

#include "md_json.h"
#include "md.h"
#include "md_crypt.h"
#include "md_log.h"
#include "md_store.h"
#include "md_util.h"


int md_contains(const md_t *md, const char *domain, int case_sensitive)
{
    if (md_array_str_index(md->domains, domain, 0, case_sensitive) >= 0) {
        return 1;
    }
    return md_dns_domains_match(md->domains, domain);
}

const char *md_common_name(const md_t *md1, const md_t *md2)
{
    int i;
    
    if (md1 == NULL || md1->domains == NULL
        || md2 == NULL || md2->domains == NULL) {
        return NULL;
    }
    
    for (i = 0; i < md1->domains->nelts; ++i) {
        const char *name1 = APR_ARRAY_IDX(md1->domains, i, const char*);
        if (md_contains(md2, name1, 0)) {
            return name1;
        }
    }
    return NULL;
}

int md_domains_overlap(const md_t *md1, const md_t *md2)
{
    return md_common_name(md1, md2) != NULL;
}

apr_size_t md_common_name_count(const md_t *md1, const md_t *md2)
{
    int i;
    apr_size_t hits;
    
    if (md1 == NULL || md1->domains == NULL
        || md2 == NULL || md2->domains == NULL) {
        return 0;
    }
    
    hits = 0;
    for (i = 0; i < md1->domains->nelts; ++i) {
        const char *name1 = APR_ARRAY_IDX(md1->domains, i, const char*);
        if (md_contains(md2, name1, 0)) {
            ++hits;
        }
    }
    return hits;
}

int md_is_covered_by_alt_names(const md_t *md, const struct apr_array_header_t* alt_names)
{
    const char *name;
    int i;
    
    if (alt_names) {
        for (i = 0; i < md->domains->nelts; ++i) {
            name = APR_ARRAY_IDX(md->domains, i, const char *);
            if (!md_dns_domains_match(alt_names, name)) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

md_t *md_create_empty(apr_pool_t *p)
{
    md_t *md = apr_pcalloc(p, sizeof(*md));
    if (md) {
        md->domains = apr_array_make(p, 5, sizeof(const char *));
        md->contacts = apr_array_make(p, 5, sizeof(const char *));
        md->renew_mode = MD_RENEW_DEFAULT;
        md->require_https = MD_REQUIRE_UNSET;
        md->must_staple = -1;
        md->transitive = -1;
        md->acme_tls_1_domains = apr_array_make(p, 5, sizeof(const char *));
        md->stapling = -1;
        md->defn_name = "unknown";
        md->defn_line_number = 0;
    }
    return md;
}

int md_equal_domains(const md_t *md1, const md_t *md2, int case_sensitive)
{
    int i;
    if (md1->domains->nelts == md2->domains->nelts) {
        for (i = 0; i < md1->domains->nelts; ++i) {
            const char *name1 = APR_ARRAY_IDX(md1->domains, i, const char*);
            if (!md_contains(md2, name1, case_sensitive)) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

int md_contains_domains(const md_t *md1, const md_t *md2)
{
    int i;
    if (md1->domains->nelts >= md2->domains->nelts) {
        for (i = 0; i < md2->domains->nelts; ++i) {
            const char *name2 = APR_ARRAY_IDX(md2->domains, i, const char*);
            if (!md_contains(md1, name2, 0)) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

md_t *md_get_by_name(struct apr_array_header_t *mds, const char *name)
{
    int i;
    for (i = 0; i < mds->nelts; ++i) {
        md_t *md = APR_ARRAY_IDX(mds, i, md_t *);
        if (!strcmp(name, md->name)) {
            return md;
        }
    }
    return NULL;
}

md_t *md_get_by_domain(struct apr_array_header_t *mds, const char *domain)
{
    int i;
    for (i = 0; i < mds->nelts; ++i) {
        md_t *md = APR_ARRAY_IDX(mds, i, md_t *);
        if (md_contains(md, domain, 0)) {
            return md;
        }
    }
    return NULL;
}

md_t *md_get_by_dns_overlap(struct apr_array_header_t *mds, const md_t *md)
{
    int i;
    for (i = 0; i < mds->nelts; ++i) {
        md_t *o = APR_ARRAY_IDX(mds, i, md_t *);
        if (strcmp(o->name, md->name) && md_common_name(o, md)) {
            return o;
        }
    }
    return NULL;
}

int md_cert_count(const md_t *md)
{
    /* cert are defined as a list of static files or a list of private key specs */
    if (md->cert_files && md->cert_files->nelts) {
        return md->cert_files->nelts;
    }
    return md_pkeys_spec_count(md->pks);
}

md_t *md_create(apr_pool_t *p, apr_array_header_t *domains)
{
    md_t *md;
    
    md = md_create_empty(p);
    md->domains = md_array_str_compact(p, domains, 0);
    md->name = APR_ARRAY_IDX(md->domains, 0, const char *);
    
    return md;
}

/**************************************************************************************************/
/* lifetime */

md_t *md_copy(apr_pool_t *p, const md_t *src)
{
    md_t *md;
    
    md = apr_pcalloc(p, sizeof(*md));
    if (md) {
        memcpy(md, src, sizeof(*md));
        md->domains = apr_array_copy(p, src->domains);
        md->contacts = apr_array_copy(p, src->contacts);
        if (src->ca_challenges) {
            md->ca_challenges = apr_array_copy(p, src->ca_challenges);
        }
        md->acme_tls_1_domains = apr_array_copy(p, src->acme_tls_1_domains);
        md->pks = md_pkeys_spec_clone(p, src->pks);
    }    
    return md;   
}

md_t *md_clone(apr_pool_t *p, const md_t *src)
{
    md_t *md;
    
    md = apr_pcalloc(p, sizeof(*md));
    if (md) {
        md->state = src->state;
        md->name = apr_pstrdup(p, src->name);
        md->require_https = src->require_https;
        md->must_staple = src->must_staple;
        md->renew_mode = src->renew_mode;
        md->domains = md_array_str_compact(p, src->domains, 0);
        md->pks = md_pkeys_spec_clone(p, src->pks);
        md->renew_window = src->renew_window;
        md->warn_window = src->warn_window;
        md->contacts = md_array_str_clone(p, src->contacts);
        if (src->ca_proto) md->ca_proto = apr_pstrdup(p, src->ca_proto);
        if (src->ca_urls) {
            md->ca_urls = md_array_str_clone(p, src->ca_urls);
        }
        if (src->ca_effective) md->ca_effective = apr_pstrdup(p, src->ca_effective);
        if (src->ca_account) md->ca_account = apr_pstrdup(p, src->ca_account);
        if (src->ca_agreement) md->ca_agreement = apr_pstrdup(p, src->ca_agreement);
        if (src->defn_name) md->defn_name = apr_pstrdup(p, src->defn_name);
        md->defn_line_number = src->defn_line_number;
        if (src->ca_challenges) {
            md->ca_challenges = md_array_str_clone(p, src->ca_challenges);
        }
        md->acme_tls_1_domains = md_array_str_compact(p, src->acme_tls_1_domains, 0);
        md->stapling = src->stapling;
        if (src->dns01_cmd) md->dns01_cmd = apr_pstrdup(p, src->dns01_cmd);
        if (src->cert_files) md->cert_files = md_array_str_clone(p, src->cert_files);
        if (src->pkey_files) md->pkey_files = md_array_str_clone(p, src->pkey_files);
    }    
    return md;   
}

/**************************************************************************************************/
/* format conversion */

md_json_t *md_to_json(const md_t *md, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        apr_array_header_t *domains = md_array_str_compact(p, md->domains, 0);
        md_json_sets(md->name, json, MD_KEY_NAME, NULL);
        md_json_setsa(domains, json, MD_KEY_DOMAINS, NULL);
        md_json_setsa(md->contacts, json, MD_KEY_CONTACTS, NULL);
        md_json_setl(md->transitive, json, MD_KEY_TRANSITIVE, NULL);
        md_json_sets(md->ca_account, json, MD_KEY_CA, MD_KEY_ACCOUNT, NULL);
        md_json_sets(md->ca_proto, json, MD_KEY_CA, MD_KEY_PROTO, NULL);
        md_json_sets(md->ca_effective, json, MD_KEY_CA, MD_KEY_URL, NULL);
        if (md->ca_urls && !apr_is_empty_array(md->ca_urls)) {
            md_json_setsa(md->ca_urls, json, MD_KEY_CA, MD_KEY_URLS, NULL);
        }
        md_json_sets(md->ca_agreement, json, MD_KEY_CA, MD_KEY_AGREEMENT, NULL);
        if (!md_pkeys_spec_is_empty(md->pks)) {
            md_json_setj(md_pkeys_spec_to_json(md->pks, p), json, MD_KEY_PKEY, NULL);
        }
        md_json_setl(md->state, json, MD_KEY_STATE, NULL);
        if (md->state_descr)
            md_json_sets(md->state_descr, json, MD_KEY_STATE_DESCR, NULL);
        md_json_setl(md->renew_mode, json, MD_KEY_RENEW_MODE, NULL);
        if (md->renew_window)
            md_json_sets(md_timeslice_format(md->renew_window, p), json, MD_KEY_RENEW_WINDOW, NULL);
        if (md->warn_window)
            md_json_sets(md_timeslice_format(md->warn_window, p), json, MD_KEY_WARN_WINDOW, NULL);
        if (md->ca_challenges && md->ca_challenges->nelts > 0) {
            apr_array_header_t *na;
            na = md_array_str_compact(p, md->ca_challenges, 0);
            md_json_setsa(na, json, MD_KEY_CA, MD_KEY_CHALLENGES, NULL);
        }
        switch (md->require_https) {
            case MD_REQUIRE_TEMPORARY:
                md_json_sets(MD_KEY_TEMPORARY, json, MD_KEY_REQUIRE_HTTPS, NULL);
                break;
            case MD_REQUIRE_PERMANENT:
                md_json_sets(MD_KEY_PERMANENT, json, MD_KEY_REQUIRE_HTTPS, NULL);
                break;
            default:
                break;
        }
        md_json_setb(md->must_staple > 0, json, MD_KEY_MUST_STAPLE, NULL);
        md_json_setsa(md->acme_tls_1_domains, json, MD_KEY_PROTO, MD_KEY_ACME_TLS_1, NULL);
        if (md->cert_files) md_json_setsa(md->cert_files, json, MD_KEY_CERT_FILES, NULL);
        if (md->pkey_files) md_json_setsa(md->pkey_files, json, MD_KEY_PKEY_FILES, NULL);
        md_json_setb(md->stapling > 0, json, MD_KEY_STAPLING, NULL);
        if (md->dns01_cmd) md_json_sets(md->dns01_cmd, json, MD_KEY_CMD_DNS01, NULL);
        if (md->ca_eab_kid && strcmp("none", md->ca_eab_kid)) {
            md_json_sets(md->ca_eab_kid, json, MD_KEY_EAB, MD_KEY_KID, NULL);
            if (md->ca_eab_hmac) md_json_sets(md->ca_eab_hmac, json, MD_KEY_EAB, MD_KEY_HMAC, NULL);
        }
        return json;
    }
    return NULL;
}

md_t *md_from_json(md_json_t *json, apr_pool_t *p)
{
    const char *s;
    md_t *md = md_create_empty(p);
    if (md) {
        md->name = md_json_dups(p, json, MD_KEY_NAME, NULL);            
        md_json_dupsa(md->domains, p, json, MD_KEY_DOMAINS, NULL);
        md_json_dupsa(md->contacts, p, json, MD_KEY_CONTACTS, NULL);
        md->ca_account = md_json_dups(p, json, MD_KEY_CA, MD_KEY_ACCOUNT, NULL);
        md->ca_proto = md_json_dups(p, json, MD_KEY_CA, MD_KEY_PROTO, NULL);
        md->ca_effective = md_json_dups(p, json, MD_KEY_CA, MD_KEY_URL, NULL);
        if (md_json_has_key(json, MD_KEY_CA, MD_KEY_URLS, NULL)) {
            md->ca_urls = apr_array_make(p, 5, sizeof(const char*));
            md_json_dupsa(md->ca_urls, p, json, MD_KEY_CA, MD_KEY_URLS, NULL);
        }
        else if (md->ca_effective) {
            /* compat for old format where we had only a single url */
            md->ca_urls = apr_array_make(p, 5, sizeof(const char*));
            APR_ARRAY_PUSH(md->ca_urls, const char*) = md->ca_effective;
        }
        md->ca_agreement = md_json_dups(p, json, MD_KEY_CA, MD_KEY_AGREEMENT, NULL);
        if (md_json_has_key(json, MD_KEY_PKEY, NULL)) {
            md->pks = md_pkeys_spec_from_json(md_json_getj(json, MD_KEY_PKEY, NULL), p);
        }
        md->state = (md_state_t)md_json_getl(json, MD_KEY_STATE, NULL);
        md->state_descr = md_json_dups(p, json, MD_KEY_STATE_DESCR, NULL);
        if (MD_S_EXPIRED_DEPRECATED == md->state) md->state = MD_S_COMPLETE;
        md->renew_mode = (int)md_json_getl(json, MD_KEY_RENEW_MODE, NULL);
        md->domains = md_array_str_compact(p, md->domains, 0);
        md->transitive = (int)md_json_getl(json, MD_KEY_TRANSITIVE, NULL);
        s = md_json_gets(json, MD_KEY_RENEW_WINDOW, NULL);
        md_timeslice_parse(&md->renew_window, p, s, MD_TIME_LIFE_NORM);
        s = md_json_gets(json, MD_KEY_WARN_WINDOW, NULL);
        md_timeslice_parse(&md->warn_window, p, s, MD_TIME_LIFE_NORM);
        if (md_json_has_key(json, MD_KEY_CA, MD_KEY_CHALLENGES, NULL)) {
            md->ca_challenges = apr_array_make(p, 5, sizeof(const char*));
            md_json_dupsa(md->ca_challenges, p, json, MD_KEY_CA, MD_KEY_CHALLENGES, NULL);
        }
        md->require_https = MD_REQUIRE_OFF;
        s = md_json_gets(json, MD_KEY_REQUIRE_HTTPS, NULL);
        if (s && !strcmp(MD_KEY_TEMPORARY, s)) {
            md->require_https = MD_REQUIRE_TEMPORARY;
        }
        else if (s && !strcmp(MD_KEY_PERMANENT, s)) {
            md->require_https = MD_REQUIRE_PERMANENT;
        }
        md->must_staple = (int)md_json_getb(json, MD_KEY_MUST_STAPLE, NULL);
        md_json_dupsa(md->acme_tls_1_domains, p, json, MD_KEY_PROTO, MD_KEY_ACME_TLS_1, NULL);
            
        if (md_json_has_key(json, MD_KEY_CERT_FILES, NULL)) {
            md->cert_files = apr_array_make(p, 3, sizeof(char*));
            md->pkey_files = apr_array_make(p, 3, sizeof(char*));
            md_json_dupsa(md->cert_files, p, json, MD_KEY_CERT_FILES, NULL);
            md_json_dupsa(md->pkey_files, p, json, MD_KEY_PKEY_FILES, NULL);
        }
        md->stapling = (int)md_json_getb(json, MD_KEY_STAPLING, NULL);
        md->dns01_cmd = md_json_dups(p, json, MD_KEY_CMD_DNS01, NULL);
        if (md_json_has_key(json, MD_KEY_EAB, NULL)) {
            md->ca_eab_kid = md_json_dups(p, json, MD_KEY_EAB, MD_KEY_KID, NULL);
            md->ca_eab_hmac = md_json_dups(p, json, MD_KEY_EAB, MD_KEY_HMAC, NULL);
        }
        return md;
    }
    return NULL;
}

md_json_t *md_to_public_json(const md_t *md, apr_pool_t *p)
{
    md_json_t *json = md_to_json(md, p);
    if (md_json_has_key(json, MD_KEY_EAB, MD_KEY_HMAC, NULL)) {
        md_json_sets("***", json, MD_KEY_EAB, MD_KEY_HMAC, NULL);
    }
    return json;
}

typedef struct {
    const char *name;
    const char *url;
} md_ca_t;

#define LE_ACMEv2_PROD      "https://acme-v02.api.letsencrypt.org/directory"
#define LE_ACMEv2_STAGING   "https://acme-staging-v02.api.letsencrypt.org/directory"
#define BUYPASS_ACME        "https://api.buypass.com/acme/directory"
#define BUYPASS_ACME_TEST   "https://api.test4.buypass.no/acme/directory"

static md_ca_t KNOWN_CAs[] = {
    { "LetsEncrypt", LE_ACMEv2_PROD },
    { "LetsEncrypt-Test", LE_ACMEv2_STAGING },
    { "Buypass", BUYPASS_ACME },
    { "Buypass-Test", BUYPASS_ACME_TEST },
};

const char *md_get_ca_name_from_url(apr_pool_t *p, const char *url)
{
    apr_uri_t uri_parsed;
    unsigned int i;

    for (i = 0; i < sizeof(KNOWN_CAs)/sizeof(KNOWN_CAs[0]); ++i) {
        if (!apr_strnatcasecmp(KNOWN_CAs[i].url, url)) {
            return KNOWN_CAs[i].name;
        }
    }
    if (APR_SUCCESS == apr_uri_parse(p, url, &uri_parsed)) {
        return uri_parsed.hostname;
    }
    return apr_pstrdup(p, url);
}

apr_status_t md_get_ca_url_from_name(const char **purl, apr_pool_t *p, const char *name)
{
    const char *err;
    unsigned int i;
    apr_status_t rv = APR_SUCCESS;

    *purl = NULL;
    for (i = 0; i < sizeof(KNOWN_CAs)/sizeof(KNOWN_CAs[0]); ++i) {
        if (!apr_strnatcasecmp(KNOWN_CAs[i].name, name)) {
            *purl = KNOWN_CAs[i].url;
            goto leave;
        }
    }
    *purl = name;
    rv = md_util_abs_uri_check(p, name, &err);
    if (APR_SUCCESS != rv) {
        apr_array_header_t *names;

        names = apr_array_make(p, 10, sizeof(const char*));
        for (i = 0; i < sizeof(KNOWN_CAs)/sizeof(KNOWN_CAs[0]); ++i) {
            APR_ARRAY_PUSH(names, const char *) = KNOWN_CAs[i].name;
        }
        *purl = apr_psprintf(p,
            "The CA name '%s' is not known and it is not a URL either (%s). "
            "Known CA names are: %s.",
            name, err, apr_array_pstrcat(p, names, ' '));
    }
leave:
    return rv;
}
