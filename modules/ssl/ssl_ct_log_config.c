/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_dbd.h"
#include "apr_escape.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_log.h"
#include "http_main.h"

#include "ssl_ct_sct.h"
#include "ssl_ct_log_config.h"
#include "ssl_ct_util.h"

APLOG_USE_MODULE(ssl_ct);

int log_config_readable(apr_pool_t *p, const char *logconfig,
                        const char **msg)
{
    const apr_dbd_driver_t *driver;
    apr_dbd_t *handle;
    apr_status_t rv;
    apr_dbd_results_t *res;
    int rc;

    rv = apr_dbd_get_driver(p, "sqlite3", &driver);
    if (rv != APR_SUCCESS) {
        if (msg) {
            *msg = "SQLite3 driver cannot be loaded";
        }
        return 0;
    }

    rv = apr_dbd_open(driver, p, logconfig, &handle);
    if (rv != APR_SUCCESS) {
        return 0;
    }

    /* is there a cheaper way? */
    res = NULL;
    rc = apr_dbd_select(driver, p, handle, &res,
                        "SELECT * FROM loginfo WHERE id = 0", 0);

    apr_dbd_close(driver, handle);

    if (rc != 0) {
        return 0;
    }

    return 1;
}

static apr_status_t public_key_cleanup(void *data)
{
    EVP_PKEY *pubkey = data;

    EVP_PKEY_free(pubkey);
    return APR_SUCCESS;
}

static apr_status_t read_public_key(apr_pool_t *p, const char *pubkey_fname,
                                    EVP_PKEY **ppkey)
{
    apr_status_t rv;
    EVP_PKEY *pubkey;
    FILE *pubkeyf;

    *ppkey = NULL;

    rv = ctutil_fopen(pubkey_fname, "r", &pubkeyf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                     APLOGNO(02751) "could not open log public key file %s",
                     pubkey_fname);
        return rv;
    }

    pubkey = PEM_read_PUBKEY(pubkeyf, NULL, NULL, NULL);
    if (!pubkey) {
        fclose(pubkeyf);
        rv = APR_EINVAL;
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                     APLOGNO(02752) "PEM_read_PUBKEY() failed to process "
                     "public key file %s",
                     pubkey_fname);
        return rv;
    }

    fclose(pubkeyf);

    *ppkey = pubkey;

    apr_pool_cleanup_register(p, (void *)pubkey, public_key_cleanup,
                              apr_pool_cleanup_null);

    return APR_SUCCESS;
}

static void digest_public_key(EVP_PKEY *pubkey, unsigned char digest[LOG_ID_SIZE])
{
    int len = i2d_PUBKEY(pubkey, NULL);
    unsigned char *val = ap_malloc(len);
    unsigned char *tmp = val;
    SHA256_CTX sha256ctx;

    ap_assert(LOG_ID_SIZE == SHA256_DIGEST_LENGTH);

    i2d_PUBKEY(pubkey, &tmp);
    SHA256_Init(&sha256ctx);
    SHA256_Update(&sha256ctx, (unsigned char *)val, len);
    SHA256_Final(digest, &sha256ctx);
    free(val);
}

static apr_status_t parse_log_url(apr_pool_t *p, const char *lu, apr_uri_t *puri)
{
    apr_status_t rv;
    apr_uri_t uri;

    rv = apr_uri_parse(p, lu, &uri);
    if (rv == APR_SUCCESS) {
        if (!uri.scheme
            || !uri.hostname
            || !uri.path) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         APLOGNO(02753) "Error in log url \"%s\": URL can't be "
                         "parsed or is missing required elements", lu);
            rv = APR_EINVAL;
        }
        if (strcmp(uri.scheme, "http")) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         APLOGNO(02754) "Error in log url \"%s\": Only scheme "
                         "\"http\" (instead of \"%s\") is currently "
                         "accepted",
                         lu, uri.scheme);
            rv = APR_EINVAL;
        }
        if (strcmp(uri.path, "/")) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         APLOGNO(02755) "Error in log url \"%s\": Only path "
                         "\"/\" (instead of \"%s\") is currently accepted",
                         lu, uri.path);
            rv = APR_EINVAL;
        }
    }
    if (rv == APR_SUCCESS) {
        *puri = uri;
    }
    return rv;
}

static apr_status_t parse_time_str(apr_pool_t *p, const char *time_str,
                                   apr_time_t *time)
{
    apr_int64_t val;
    const char *end;

    errno = 0;
    val = apr_strtoi64(time_str, (char **)&end, 10);
    if (errno || *end != '\0') {
        return APR_EINVAL;
    }

    *time = apr_time_from_msec(val);
    return APR_SUCCESS;
}

/* The log_config array should have already been allocated from p. */
apr_status_t save_log_config_entry(apr_array_header_t *log_config,
                                   apr_pool_t *p,
                                   const char *log_id,
                                   const char *pubkey_fname,
                                   const char *distrusted_str,
                                   const char *min_time_str,
                                   const char *max_time_str,
                                   const char *url)
{
    apr_size_t len;
    apr_status_t rv;
    apr_time_t min_time, max_time;
    apr_uri_t uri;
    char *computed_log_id = NULL, *log_id_bin = NULL;
    ct_log_config *newconf, **pnewconf;
    int distrusted;
    EVP_PKEY *public_key;

    if (!distrusted_str) {
        distrusted = DISTRUSTED_UNSET;
    }
    else if (!strcmp(distrusted_str, "1")) {
        distrusted = DISTRUSTED;
    }
    else if (!strcmp(distrusted_str, "0")) {
        distrusted = TRUSTED;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                     APLOGNO(02756) "Trusted status \"%s\" not valid",
                     distrusted_str);
        return APR_EINVAL;
    }

    if (log_id) {
        rv = apr_unescape_hex(NULL, log_id, strlen(log_id), 0, &len);
        if (rv != 0 || len != 32) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         APLOGNO(02757) "Log id \"%s\" not valid", log_id);
            log_id_bin = apr_palloc(p, len);
            apr_unescape_hex(log_id_bin, log_id, strlen(log_id), 0, NULL);
        }
    }

    if (pubkey_fname) {
        rv = read_public_key(p, pubkey_fname, &public_key);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }
    else {
        public_key = NULL;
    }

    if (min_time_str) {
        rv = parse_time_str(p, min_time_str, &min_time);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         APLOGNO(02758) "Invalid min time \"%s\"", min_time_str);
            return rv;
        }
    }
    else {
        min_time = 0;
    }

    if (max_time_str) {
        rv = parse_time_str(p, max_time_str, &max_time);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         APLOGNO(02759) "Invalid max time \"%s\"", max_time_str);
            return rv;
        }
    }
    else {
        max_time = 0;
    }

    if (url) {
        rv = parse_log_url(p, url, &uri);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    newconf = apr_pcalloc(p, sizeof(ct_log_config));
    pnewconf = (ct_log_config **)apr_array_push(log_config);
    *pnewconf = newconf;

    newconf->distrusted = distrusted;
    newconf->public_key = public_key;

    if (newconf->public_key) {
        computed_log_id = apr_palloc(p, LOG_ID_SIZE);
        digest_public_key(newconf->public_key,
                          (unsigned char *)computed_log_id);
    }

    if (computed_log_id && log_id_bin) {
        if (memcmp(computed_log_id, log_id_bin, LOG_ID_SIZE)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         APLOGNO(02760) "Provided log id doesn't match digest "
                         "of public key");
            return APR_EINVAL;
        }
    }

    newconf->log_id = log_id_bin ? log_id_bin : computed_log_id;

    newconf->min_valid_time = min_time;
    newconf->max_valid_time = max_time;

    newconf->url = url;
    if (url) {
        newconf->uri = uri;
        newconf->uri_str = apr_uri_unparse(p, &uri, 0);
    }
    newconf->public_key_pem = pubkey_fname;

    return APR_SUCCESS;
}

apr_status_t read_config_db(apr_pool_t *p, server_rec *s_main,
                            const char *log_config_fname,
                            apr_array_header_t *log_config)
{
    apr_status_t rv;
    const apr_dbd_driver_t *driver;
    apr_dbd_t *handle;
    apr_dbd_results_t *res;
    apr_dbd_row_t *row;
    int rc;

    ap_assert(log_config);

    rv = apr_dbd_get_driver(p, "sqlite3", &driver);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s_main,
                     APLOGNO(02761) "APR SQLite3 driver can't be loaded");
        return rv;
    }

    rv = apr_dbd_open(driver, p, log_config_fname, &handle);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s_main,
                     APLOGNO(02762) "Can't open SQLite3 db %s",
                     log_config_fname);
        return rv;
    }

    res = NULL;
    rc = apr_dbd_select(driver, p, handle, &res,
                        "SELECT * FROM loginfo", 0);

    if (rc != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                     APLOGNO(02763) "SELECT of loginfo records failed");
        apr_dbd_close(driver, handle);
        return APR_EINVAL;
    }

    rc = apr_dbd_num_tuples(driver, res);
    switch (rc) {
    case -1:
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                     APLOGNO(02764) "Unexpected asynchronous result reading %s",
                     log_config_fname);
        apr_dbd_close(driver, handle);
        return APR_EINVAL;
    case 0:
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s_main,
                     APLOGNO(02765) "Log configuration in %s is empty",
                     log_config_fname);
        apr_dbd_close(driver, handle);
        return APR_SUCCESS;
    default:
        /* quiet some lints */
        break;
    }
        
    for (rv = apr_dbd_get_row(driver, p, res, &row, -1);
         rv == APR_SUCCESS;
         rv = apr_dbd_get_row(driver, p, res, &row, -1)) {
        int cur = 0;
        const char *id = apr_dbd_get_entry(driver, row, cur++);
        const char *log_id = apr_dbd_get_entry(driver, row, cur++);
        const char *public_key = apr_dbd_get_entry(driver, row, cur++);
        const char *distrusted = apr_dbd_get_entry(driver, row, cur++);
        const char *min_timestamp = apr_dbd_get_entry(driver, row, cur++);
        const char *max_timestamp = apr_dbd_get_entry(driver, row, cur++);
        const char *url = apr_dbd_get_entry(driver, row, cur++);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s_main, APLOGNO(03036)
                     "Log config: Record %s, log id %s, public key file %s,"
                     " distrusted %s, URL %s, time %s->%s",
                     id,
                     log_id ? log_id : "(unset)",
                     public_key ? public_key : "(unset)",
                     distrusted ? distrusted : "(unset, defaults to trusted)",
                     url ? url : "(unset)",
                     min_timestamp ? min_timestamp : "-INF",
                     max_timestamp ? max_timestamp : "+INF");

        rv = save_log_config_entry(log_config, p, log_id,
                                   public_key, distrusted, 
                                   min_timestamp, max_timestamp, url);
        if (rv != APR_SUCCESS) {
            apr_dbd_close(driver, handle);
            return rv;
        }
    }

    apr_dbd_close(driver, handle);

    return APR_SUCCESS;
}

int log_valid_for_received_sct(const ct_log_config *l, apr_time_t to_check)
{
    if (l->distrusted == DISTRUSTED) {
        return 0;
    }

    if (l->max_valid_time && l->max_valid_time < to_check) {
        return 0;
    }

    if (l->min_valid_time && l->min_valid_time < to_check) {
        return 0;
    }

    return 1;
}

int log_valid_for_sent_sct(const ct_log_config *l)
{
    /* The log could return us an SCT with an older timestamp which
     * is within the trusted time interval for the log, but for
     * simplicity let's just assume that if the log isn't still
     * within a trusted interval we won't send SCTs from the log.
     */
    return log_valid_for_received_sct(l, apr_time_now());
}

int log_configured_for_fetching_sct(const ct_log_config *l)
{
    /* must have a url and a public key configured in order to obtain
     * an SCT from the log
     */
    return l->url != NULL && l->public_key != NULL;
}
