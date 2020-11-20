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

/*
 * Issues
 *
 * + Known low-level code kludges/problems
 *   . proxy: an httpd child process validates SCTs from a server only on the
 *     first time the data is received; but it could fail once due to invalid
 *     timestamp, and not be rechecked later after (potentially) time elapses
 *     and the timestamp is now in a valid range
 *   . server: shouldn't have to read file of server SCTs on every handshake
 *     (shared memory or cached file?)
 *   . split mod_ssl_ct.c into more pieces
 *   . research: Is it possible to send an SCT that is outside of the known
 *     valid interval for the log?
 */

#if defined(WIN32)
#define HAVE_SCT_DAEMON_THREAD
#else
#define HAVE_SCT_DAEMON_CHILD
#endif

#include <limits.h>

#if defined(HAVE_SCT_DAEMON_CHILD)
#include <unistd.h>
#endif

#include "apr_version.h"
#if !APR_VERSION_AT_LEAST(1,5,0)
#error mod_ssl_ct requires APR 1.5.0 or later! (for apr_escape.h)
#endif

#include "apr_escape.h"
#include "apr_global_mutex.h"
#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_thread_rwlock.h"

#include "apr_dbd.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "mpm_common.h"
#include "util_mutex.h"
#include "ap_listen.h"
#include "ap_mpm.h"

#if AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include "mod_proxy.h"
#include "mod_ssl.h"
#include "mod_ssl_openssl.h"

#include "ssl_ct_util.h"
#include "ssl_ct_sct.h"

#include "openssl/x509v3.h"
#include "openssl/ocsp.h"

#if OPENSSL_VERSION_NUMBER < 0x10002003L
#error "mod_ssl_ct requires OpenSSL 1.0.2-beta3 or later"
#endif

#ifdef WIN32
#define DOTEXE ".exe"
#else
#define DOTEXE ""
#endif

#define CLIENT_STATUS_VAR         "SSL_CT_CLIENT_STATUS"
#define PROXY_STATUS_VAR          "SSL_CT_PROXY_STATUS"
#define STATUS_VAR_AWARE_VAL      "peer-aware"
#define STATUS_VAR_UNAWARE_VAL    "peer-unaware"

#define PROXY_SCT_SOURCES_VAR     "SSL_CT_PROXY_SCT_SOURCES"

#define DAEMON_NAME         "SCT maintenance daemon"
#define DAEMON_THREAD_NAME  DAEMON_NAME " thread"
#define SERVICE_THREAD_NAME "service thread"

/** Limit on size of stored SCTs for a certificate (individual SCTs as well
 * as size of all.
 */
#define MAX_SCTS_SIZE 10000

/** Limit on size of log URL list for a certificate
 */
#define MAX_LOGLIST_SIZE 1000

typedef struct ct_server_config {
    apr_array_header_t *db_log_config;
    apr_pool_t *db_log_config_pool;
    apr_array_header_t *static_log_config;
    apr_array_header_t *server_cert_info; /* ct_server_cert_info */
    apr_hash_t *static_cert_sct_dirs;
    const char *sct_storage;
    const char *audit_storage;
    const char *ct_exe;
    const char *log_config_fname;
    apr_time_t max_sct_age;
    int max_sh_sct;
#define PROXY_AWARENESS_UNSET -1
#define PROXY_OBLIVIOUS        1
#define PROXY_AWARE            2 /* default */
#define PROXY_REQUIRE          3
    int proxy_awareness;
} ct_server_config;

typedef struct ct_conn_config {
    int peer_ct_aware;
    int client_handshake;
    int proxy_handshake;
    /* proxy mode only */
    cert_chain *certs;
    int server_cert_has_sct_list;
    void *cert_sct_list;
    apr_size_t cert_sct_list_size;
    int serverhello_has_sct_list;
    void *serverhello_sct_list;
    apr_size_t serverhello_sct_list_size;
    int ocsp_has_sct_list;
    void *ocsp_sct_list;
    apr_size_t ocsp_sct_list_size;
    apr_array_header_t *all_scts; /* array of ct_sct_data */
} ct_conn_config;

typedef struct ct_server_cert_info {
    const char *fingerprint;
    const char *sct_dir;
} ct_server_cert_info;

typedef struct ct_sct_data {
    const void *data;
    apr_uint16_t len;
} ct_sct_data;

typedef struct ct_callback_info {
    server_rec *s;
    conn_rec *c;
    ct_conn_config *conncfg;
} ct_callback_info;

typedef struct ct_cached_server_data {
    apr_status_t validation_result;
} ct_cached_server_data;

/* the log configuration in use -- either db_log_config or static_log_config */
static apr_array_header_t *active_log_config;

module AP_MODULE_DECLARE_DATA ssl_ct_module;

#define SSL_CT_MUTEX_TYPE "ssl-ct-sct-update"

static apr_global_mutex_t *ssl_ct_sct_update;

static int refresh_all_scts(server_rec *s_main, apr_pool_t *p,
                            apr_array_header_t *log_config);

static ct_server_config *copy_ct_server_config(apr_pool_t *p,
                                               ct_server_config *base);

static apr_thread_t *service_thread;

static apr_hash_t *cached_server_data;

static const char *audit_fn_perm, *audit_fn_active;
static apr_file_t *audit_file;
static int audit_file_nonempty;
static apr_thread_mutex_t *audit_file_mutex;
static apr_thread_mutex_t *cached_server_data_mutex;
static apr_thread_rwlock_t *log_config_rwlock;

#ifdef HAVE_SCT_DAEMON_CHILD

/* The APR other-child API doesn't tell us how the daemon exited
 * (SIGSEGV vs. exit(1)).  The other-child maintenance function
 * needs to decide whether to restart the daemon after a failure
 * based on whether or not it exited due to a fatal startup error
 * or something that happened at steady-state.  This exit status
 * is unlikely to collide with exit signals.
 */
#define DAEMON_STARTUP_ERROR 254

static int daemon_start(apr_pool_t *p, server_rec *main_server, apr_proc_t *procnew);
static server_rec *root_server = NULL;
static apr_pool_t *root_pool = NULL;
static pid_t daemon_pid;
static int daemon_should_exit = 0;

#endif /* HAVE_SCT_DAEMON_CHILD */

static apr_pool_t *pdaemon = NULL;

#ifdef HAVE_SCT_DAEMON_THREAD
static apr_thread_t *daemon_thread;
#endif /* HAVE_SCT_DAEMON_THREAD */

static const char *get_cert_fingerprint(apr_pool_t *p, const X509 *x)
{
    const EVP_MD *digest;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    digest = EVP_get_digestbyname("sha256");
    X509_digest(x, digest, md, &n);

    return apr_pescape_hex(p, md, n, 0);
}

/* a server's SCT-related storage on disk:
 *
 *   <rootdir>/<fingerprint>/servercerts.pem
 *                  Concatenation of leaf certificate and any
 *                  configured intermediate certificates
 *
 *   <rootdir>/<fingerprint>/logs  
 *                  List of log URLs, one per line; this is
 *                  used to recognize when a log URL configuration
 *                  change makes our current SCT set invalid
 *
 *   <rootdir>/<fingerprint>/AUTO_hostname_port_uri.sct
 *                  SCT for cert with this fingerprint
 *                  from this log (could be any number
 *                  of these)
 *
 *   <rootdir>/<fingerprint>/<anything>.sct
 *                  (file is optional; could be any number
 *                  of these; should not start with "AUTO_")
 *                  Note that the administrator should store 
 *                  statically maintained SCTs in a different
 *                  directory for the server certificate (specified
 *                  by the CTStaticSCTs directive).  A hypothetical
 *                  external mechanism for maintaining SCTs following
 *                  some other model could store them here for use
 *                  by the server.
 *
 *   <rootdir>/<fingerprint>/collated
 *                  one or more SCTs ready to send
 *                  (this is all that the web server
 *                  processes care about)
 *
 * Additionally, the CTStaticSCTs directive specifies a certificate-
 * specific directory of statically-maintained SCTs to be sent.
 */

#define SERVERCERTS_BASENAME   "servercerts.pem"
#define COLLATED_SCTS_BASENAME "collated"
#define LOGLIST_BASENAME       "logs"
#define LOG_SCT_PREFIX         "AUTO_" /* to distinguish from admin-created .sct
                                        * files
                                        */

static apr_status_t collate_scts(server_rec *s, apr_pool_t *p,
                                 const char *cert_sct_dir,
                                 const char *static_cert_sct_dir,
                                 int max_sh_sct)
{
    /* Read the various .sct files and stick them together in a single file */
    apr_array_header_t *arr;
    apr_status_t rv, tmprv;
    apr_file_t *tmpfile;
    apr_size_t bytes_written;
    apr_uint16_t overall_len = 0;
    char *tmp_collated_fn, *collated_fn;
    const char *cur_sct_file;
    const char * const *elts;
    int i, scts_written = 0, skipped = 0;

    rv = ctutil_path_join(&collated_fn, cert_sct_dir, COLLATED_SCTS_BASENAME, p, s);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    /* Note: We rebuild the file that combines the SCTs every time this
     *       code runs, even if no individual SCTs are new (or at least
     *       re-fetched).
     *       That allows the admin to see the last processing by looking
     *       at the timestamp.
     *       Rechecking even if no SCTs are new allows SCTs which were not
     *       yet valid originally (just submitted to a log) to be used as
     *       soon as practical.
     */
    tmp_collated_fn = apr_pstrcat(p, collated_fn, ".tmp", NULL);

    rv = apr_file_open(&tmpfile, tmp_collated_fn,
                       APR_FOPEN_WRITE|APR_FOPEN_CREATE|APR_FOPEN_TRUNCATE
                       |APR_FOPEN_BINARY|APR_FOPEN_BUFFERED,
                       APR_FPROT_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02683) "can't create %s", tmp_collated_fn);
        return rv;
    }

    /* stick a 0 len (for the list) at the start of the file;
     * we'll have to patch that later
     */
    rv = ctutil_file_write_uint16(s, tmpfile, overall_len);
    if (rv != APR_SUCCESS) {
        apr_file_close(tmpfile);
        return rv;
    }

    arr = NULL; /* Build list from scratch, creating array */
    rv = ctutil_read_dir(p, s, cert_sct_dir, "*.sct", &arr);
    if (rv != APR_SUCCESS) {
        apr_file_close(tmpfile);
        return rv;
    }

    if (static_cert_sct_dir) {
        /* Add in any SCTs that the administrator has configured */
        rv = ctutil_read_dir(p, s, static_cert_sct_dir, "*.sct", &arr);
        if (rv != APR_SUCCESS) {
            apr_file_close(tmpfile);
            return rv;
        }
    }

    elts = (const char * const *)arr->elts;

    for (i = 0; i < arr->nelts; i++) {
        char *scts;
        apr_size_t scts_size_wide;
        apr_uint16_t scts_size;
        sct_fields_t fields;

        cur_sct_file = elts[i];

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03022)
                     "Adding SCT from file %s", cur_sct_file);

        rv = ctutil_read_file(p, s, cur_sct_file, MAX_SCTS_SIZE, &scts,
                              &scts_size_wide);
        if (rv != APR_SUCCESS) {
            break;
        }
        ap_assert(scts_size_wide <= USHRT_MAX);
        scts_size = (apr_uint16_t)scts_size_wide;

        rv = sct_parse(cur_sct_file,
                       s, (const unsigned char *)scts, scts_size, NULL, &fields);
        if (rv != APR_SUCCESS) {
            sct_release(&fields);
            break;
        }

        /* If the SCT has a timestamp in the future, it may have just been
         * created by the log.
         */
        if (fields.time > apr_time_now()) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         APLOGNO(02684) "SCT in file %s has timestamp in future "
                         "(%s), skipping",
                         cur_sct_file, fields.timestr);
            sct_release(&fields);
            continue;
        }

        sct_release(&fields);

        /* Only now do we know that the SCT is valid to send, so
         * see if it has to be skipped by configured limit.
         */
        if (scts_written >= max_sh_sct) {
            skipped++;
            continue;
        }

        overall_len += scts_size + 2; /* include size header */

        rv = ctutil_file_write_uint16(s, tmpfile, (apr_uint16_t)scts_size);
        if (rv != APR_SUCCESS) {
            break;
        }

        rv = apr_file_write_full(tmpfile, scts, scts_size, &bytes_written);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(02685) "can't write %hu bytes to %s",
                         scts_size, tmp_collated_fn);
            break;
        }

        scts_written++;
    }

    if (rv == APR_SUCCESS && skipped) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     APLOGNO(02686) "SCTs sent in ServerHello are limited to "
                     "%d by CTServerHelloSCTLimit (ignoring %d)",
                     max_sh_sct,
                     skipped);
    }

    if (rv == APR_SUCCESS) {
        apr_off_t offset = 0;

        rv = apr_file_seek(tmpfile, APR_SET, &offset);
        if (rv == APR_SUCCESS) {
            rv = ctutil_file_write_uint16(s, tmpfile, overall_len);
        }
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(02687) "could not write the SCT list length "
                         "at the start of the file");
        }
    }

    tmprv = apr_file_close(tmpfile);
    if (tmprv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, tmprv, s,
                     APLOGNO(02688) "error flushing and closing %s",
                     tmp_collated_fn);
        if (rv == APR_SUCCESS) {
            rv = tmprv;
        }
    }

    if (rv == APR_SUCCESS && scts_written) {
        int replacing = ctutil_file_exists(p, collated_fn);

        if (replacing) {
            if ((rv = apr_global_mutex_lock(ssl_ct_sct_update)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             APLOGNO(02689) "global mutex lock failed");
                return rv;
            }
            apr_file_remove(collated_fn, p);
        }
        rv = apr_file_rename(tmp_collated_fn, collated_fn, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         APLOGNO(02690) "couldn't rename %s to %s, no SCTs to "
                         "send for now",
                         tmp_collated_fn, collated_fn);
        }
        if (replacing) {
            if ((tmprv = apr_global_mutex_unlock(ssl_ct_sct_update)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, tmprv, s,
                             APLOGNO(02691) "global mutex unlock failed");
                if (rv == APR_SUCCESS) {
                    rv = tmprv;
                }
            }
        }
    }

    return rv;
}

static const char *url_to_fn(apr_pool_t *p, const apr_uri_t *log_url)
{
    char *fn = apr_psprintf(p, LOG_SCT_PREFIX "%s_%s_%s.sct",
                            log_url->hostname, log_url->port_str, log_url->path);
    char *ch;

    ch = fn;
    while (*ch) {
        switch(*ch) {
        /* chars that shouldn't be used in a filename */
        case ':':
        case '/':
        case '\\':
        case '*':
        case '?':
        case '<':
        case '>':
        case '"':
        case '|':
            *ch = '-';
        }
        ++ch;
    }
    return fn;
}

static apr_status_t submission(server_rec *s, apr_pool_t *p, const char *ct_exe,
                               const ct_log_config *log_cfg,
                               const char *cert_file, const char *sct_fn)
{
    apr_status_t rv;
    const char *args[8];
    int i;

    i = 0;
    args[i++] = ct_exe;
    args[i++] = apr_pstrcat(p, "--ct_server=", log_cfg->url, NULL);
    args[i++] = "--logtostderr=true";
    args[i++] = apr_pstrcat(p, "--ct_server_submission=", cert_file, NULL);
    args[i++] = apr_pstrcat(p, "--ct_server_response_out=", sct_fn, NULL);
    args[i++] = apr_pstrcat(p, "--ct_server_public_key=", log_cfg->public_key_pem, NULL);
    args[i++] = "upload";
    args[i++] = NULL;
    ap_assert(i == sizeof args / sizeof args[0]);

    rv = ctutil_run_to_log(p, s, args, "log client");

    return rv;
}

static apr_status_t fetch_sct(server_rec *s, apr_pool_t *p,
                              const char *cert_file,
                              const char *cert_sct_dir,
                              const ct_log_config *log_cfg,
                              const char *ct_exe, apr_time_t max_sct_age)
{
    apr_status_t rv;
    char *sct_fn;
    apr_finfo_t finfo;
    const char *log_url_basename;

    log_url_basename = url_to_fn(p, &log_cfg->uri);

    rv = ctutil_path_join(&sct_fn, cert_sct_dir, log_url_basename, p, s);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_stat(&finfo, sct_fn, APR_FINFO_MTIME, p);
    if (rv == APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03023)
                     "Found SCT for %s in %s", cert_file, sct_fn);

        if (finfo.mtime + max_sct_age < apr_time_now()) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(02692)
                         "SCT for %s is older than %d seconds, must refresh",
                         cert_file, (int)(apr_time_sec(max_sct_age)));
        }
        else {
            return APR_SUCCESS;
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_INFO,
                     /* no need to print error string for file-not-found err */
                     APR_STATUS_IS_ENOENT(rv) ? 0 : rv,
                     s, APLOGNO(02693)
                     "Did not find SCT for %s in %s, must fetch",
                     cert_file, sct_fn);
    }

    rv = submission(s, p, ct_exe, log_cfg, cert_file, sct_fn);

    return rv;
}

static apr_status_t record_log_urls(server_rec *s, apr_pool_t *p,
                                    const char *listfile, apr_array_header_t *log_config)
{
    apr_file_t *f;
    apr_status_t rv, tmprv;
    ct_log_config **config_elts;
    int i;

    rv = apr_file_open(&f, listfile,
                       APR_FOPEN_WRITE|APR_FOPEN_CREATE|APR_FOPEN_TRUNCATE
                       |APR_FOPEN_BUFFERED,
                       APR_FPROT_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02694) "can't create %s", listfile);
        return rv;
    }

    config_elts  = (ct_log_config **)log_config->elts;

    for (i = 0; i < log_config->nelts; i++) {
        if (!log_configured_for_fetching_sct(config_elts[i])) {
            continue;
        }
        if (!log_valid_for_sent_sct(config_elts[i])) {
            continue;
        }
        rv = apr_file_puts(config_elts[i]->uri_str, f);
        if (rv == APR_SUCCESS) {
            rv = apr_file_puts("\n", f);
        }
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(02695) "error writing to %s", listfile);
            break;
        }
    }

    tmprv = apr_file_close(f);
    if (tmprv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, tmprv, s,
                     APLOGNO(02696) "error flushing and closing %s", listfile);
        if (rv == APR_SUCCESS) {
            rv = tmprv;
        }
    }

    return rv;
}

static int uri_in_config(const char *needle, const apr_array_header_t *haystack)
{
    ct_log_config **elts;
    int i;

    elts = (ct_log_config **)haystack->elts;
    for (i = 0; i < haystack->nelts; i++) {
        if (!log_configured_for_fetching_sct(elts[i])) {
            continue;
        }
        if (!log_valid_for_sent_sct(elts[i])) {
            continue;
        }
        if (!strcmp(needle, elts[i]->uri_str)) {
            return 1;
        }
    }

    return 0;
}

static apr_status_t update_log_list_for_cert(server_rec *s, apr_pool_t *p,
                                             const char *cert_sct_dir,
                                             apr_array_header_t *log_config)
{
    apr_array_header_t *old_urls;
    apr_size_t contents_size;
    apr_status_t rv;
    char *contents, *listfile;

    /* The set of logs can change, and we need to remove SCTs retrieved
     * from logs that we no longer trust.  To track changes we'll use a
     * file in the directory for the server certificate.
     *
     * (When can the set change?  Right now they can only change at [re]start,
     * but in the future we should be able to find the set of trusted logs
     * dynamically.)
     */

    rv = ctutil_path_join(&listfile, cert_sct_dir, LOGLIST_BASENAME, p, s);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if (ctutil_file_exists(p, listfile)) {
        char **elts;
        int i;

        rv = ctutil_read_file(p, s, listfile, MAX_LOGLIST_SIZE, &contents, &contents_size);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        ctutil_buffer_to_array(p, contents, contents_size, &old_urls);

        elts = (char **)old_urls->elts;
        for (i = 0; i < old_urls->nelts; i++) {
            if (!uri_in_config(elts[i], log_config)) {
                char *sct_for_log;
                int exists;
                apr_uri_t uri;

                rv = apr_uri_parse(p, elts[i], &uri);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                                 APLOGNO(02697) "unparsable log URL %s in file "
                                 "%s - ignoring",
                                 elts[i], listfile);
                    /* some garbage in the file? can't map to an auto-maintained SCT,
                     * so just skip it
                     */
                    continue;
                }

                rv = ctutil_path_join(&sct_for_log, cert_sct_dir, url_to_fn(p, &uri), p, s);
                ap_assert(rv == APR_SUCCESS);
                exists = ctutil_file_exists(p, sct_for_log);

                ap_log_error(APLOG_MARK, 
                             exists ? APLOG_NOTICE : APLOG_DEBUG, 0, s,
                             APLOGNO(02698) "Log %s is no longer enabled%s",
                             elts[i],
                             exists ? ", removing SCT" : ", no SCT was present");

                if (exists) {
                    rv = apr_file_remove(sct_for_log, p);
                    if (rv != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                                     APLOGNO(02699) "can't remove SCT %s from "
                                     "previously trusted log %s",
                                     sct_for_log, elts[i]);
                        return rv;
                    }
                }
            }
        }
    }
    else {
        /* can't tell what was trusted before; just remove everything
         * that was created automatically
         */
        apr_array_header_t *arr;
        const char * const *elts;
        int i;

        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     APLOGNO(02700) "List of previous logs doesn't exist (%s), "
                     "removing previously obtained SCTs",
                     listfile);

        arr = NULL; /* Build list from scratch, creating array */
        rv = ctutil_read_dir(p, s, cert_sct_dir, LOG_SCT_PREFIX "*.sct", &arr);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        elts = (const char * const *)arr->elts;
        for (i = 0; i < arr->nelts; i++) {
            const char *cur_sct_file = elts[i];

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03024)
                         "Removing %s", cur_sct_file);

            rv = apr_file_remove(cur_sct_file, p);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                             APLOGNO(02701) "can't remove %s", cur_sct_file);
            }
        }
    }

    if (rv == APR_SUCCESS) {
        rv = record_log_urls(s, p, listfile, log_config);
    }

    return rv;
}

static apr_status_t refresh_scts_for_cert(server_rec *s, apr_pool_t *p,
                                          const char *cert_sct_dir,
                                          const char *static_cert_sct_dir,
                                          apr_array_header_t *log_config,
                                          const char *ct_exe,
                                          apr_time_t max_sct_age,
                                          int max_sh_sct)
{
    apr_status_t rv;
    ct_log_config **config_elts;
    char *cert_fn;
    int i;

    rv = ctutil_path_join(&cert_fn, cert_sct_dir, SERVERCERTS_BASENAME, p, s);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    config_elts  = (ct_log_config **)log_config->elts;

    if (ct_exe) {
        rv = update_log_list_for_cert(s, p, cert_sct_dir, log_config);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        for (i = 0; i < log_config->nelts; i++) {
            if (!log_configured_for_fetching_sct(config_elts[i])) {
                continue;
            }
            if (!log_valid_for_sent_sct(config_elts[i])) {
                continue;
            }
            rv = fetch_sct(s, p, cert_fn,
                           cert_sct_dir,
                           config_elts[i],
                           ct_exe,
                           max_sct_age);
            if (rv != APR_SUCCESS) {
                return rv;
            }
        }
    }
    else {
        /* Log client tool (from certificate-transparency open source project)
         * not configured; we can only use admin-managed SCTs
         */
    }

    rv = collate_scts(s, p, cert_sct_dir, static_cert_sct_dir, max_sh_sct);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    return rv;
}

static void * APR_THREAD_FUNC run_service_thread(apr_thread_t *me, void *data)
{
    server_rec *s = data;
    ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                   &ssl_ct_module);
    int mpmq_s;
    apr_status_t rv;
    int count = 0;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03241)
                 SERVICE_THREAD_NAME " started");

    while (1) {
        if ((rv = ap_mpm_query(AP_MPMQ_MPM_STATE, &mpmq_s)) != APR_SUCCESS) {
            break;
        }
        if (mpmq_s == AP_MPMQ_STOPPING) {
            break;
        }
        apr_sleep(apr_time_from_sec(1));
        if (++count >= 30) {
            count = 0;
            if (sconf->db_log_config) {
                /* Reload log config DB */
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03242)
                             SERVICE_THREAD_NAME " - reloading config");
                ap_assert(apr_thread_rwlock_wrlock(log_config_rwlock) == 0);
                active_log_config = NULL;
                apr_pool_clear(sconf->db_log_config_pool);
                sconf->db_log_config =
                    apr_array_make(sconf->db_log_config_pool, 2,
                                   sizeof(ct_log_config *));
                rv = read_config_db(sconf->db_log_config_pool,
                                    s, sconf->log_config_fname,
                                    sconf->db_log_config);
                ap_assert(apr_thread_rwlock_unlock(log_config_rwlock) == 0);
                if (rv != APR_SUCCESS) {
                    /* specific issue already logged */
                    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                                 APLOGNO(02702) SERVICE_THREAD_NAME " - no "
                                 "active configuration until "
                                 "log config DB is corrected");
                }
                else {
                    active_log_config = sconf->db_log_config;
                }
            }
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(03243)
                 SERVICE_THREAD_NAME " exiting");

    apr_thread_exit(me, APR_SUCCESS);
    return NULL;
}

static apr_status_t wait_for_thread(void *data)
{
    apr_thread_t *thd = data;
    apr_status_t retval;

    apr_thread_join(&retval, thd);
    return APR_SUCCESS;
}

static void sct_daemon_cycle(ct_server_config *sconf, server_rec *s_main,
                             apr_pool_t *ptemp, const char *daemon_name)
{
    apr_status_t rv;

    if (sconf->db_log_config) { /* not using static config */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s_main, APLOGNO(03025)
                     "%s - reloading config", daemon_name);
        apr_pool_clear(sconf->db_log_config_pool);
        active_log_config = NULL;
        sconf->db_log_config =
            apr_array_make(sconf->db_log_config_pool, 2,
                           sizeof(ct_log_config *));
        rv = read_config_db(sconf->db_log_config_pool,
                            s_main, sconf->log_config_fname,
                            sconf->db_log_config);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s_main,
                         APLOGNO(02703) "%s - no active configuration until "
                         "log config DB is corrected", daemon_name);
            return;
        }
        active_log_config = sconf->db_log_config;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s_main, APLOGNO(03026)
                 "%s - refreshing SCTs as needed", daemon_name);
    rv = refresh_all_scts(s_main, ptemp, active_log_config);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s_main,
                     APLOGNO(02704) "%s - SCT refresh failed; will try again "
                     "later",
                     daemon_name);
    }
}

#ifdef HAVE_SCT_DAEMON_CHILD

static void daemon_signal_handler(int sig)
{
    if (sig == SIGHUP) {
        ++daemon_should_exit;
    }
}

#if APR_HAS_OTHER_CHILD
static void daemon_maint(int reason, void *data, apr_wait_t status)
{
    apr_proc_t *proc = data;
    int mpm_state;
    int stopping;

    switch (reason) {
        case APR_OC_REASON_DEATH:
            apr_proc_other_child_unregister(data);
            /* If apache is not terminating or restarting,
             * restart the daemon
             */
            stopping = 1; /* if MPM doesn't support query,
                           * assume we shouldn't restart daemon
                           */
            if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS &&
                mpm_state != AP_MPMQ_STOPPING) {
                stopping = 0;
            }
            if (!stopping) {
                if (status == DAEMON_STARTUP_ERROR) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, ap_server_conf, APLOGNO(02634)
                                 DAEMON_NAME " failed to initialize");
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(02635)
                                 DAEMON_NAME " process died, restarting");
                    daemon_start(root_pool, root_server, proc);
                }
            }
            break;
        case APR_OC_REASON_RESTART:
            /* don't do anything; server is stopping or restarting */
            apr_proc_other_child_unregister(data);
            break;
        case APR_OC_REASON_LOST:
            /* Restart the child cgid daemon process */
            apr_proc_other_child_unregister(data);
            daemon_start(root_pool, root_server, proc);
            break;
        case APR_OC_REASON_UNREGISTER:
            /* we get here when pcgi is cleaned up; pcgi gets cleaned
             * up when pconf gets cleaned up
             */
            kill(proc->pid, SIGHUP); /* send signal to daemon telling it to die */
            break;
    }
}
#endif

static int sct_daemon(server_rec *s_main)
{
    apr_status_t rv;
    apr_pool_t *ptemp;
    ct_server_config *sconf = ap_get_module_config(s_main->module_config,
                                                   &ssl_ct_module);
    int rc;

    /* Ignoring SIGCHLD results in errno ECHILD returned from apr_proc_wait().
     * apr_signal(SIGCHLD, SIG_IGN);
     */
    apr_signal(SIGHUP, daemon_signal_handler);

    /* Close our copy of the listening sockets */
    ap_close_listeners();

    rv = apr_global_mutex_child_init(&ssl_ct_sct_update,
                                     apr_global_mutex_lockfile(ssl_ct_sct_update), pdaemon);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, root_server,
                     APLOGNO(02705) "could not initialize " SSL_CT_MUTEX_TYPE
                     " mutex in " DAEMON_NAME);
        return DAEMON_STARTUP_ERROR;
    }

    if (!geteuid()) {
        /* Fix up permissions of the directories written to by the daemon
         */
        int i;
        apr_array_header_t *subdirs = apr_array_make(pdaemon, 5, sizeof(char *));

        *(const char **)apr_array_push(subdirs) = sconf->sct_storage;
        if (sconf->audit_storage) {
            *(const char **)apr_array_push(subdirs) = sconf->audit_storage;
        }

        rv = ctutil_read_dir(pdaemon, root_server, sconf->sct_storage, "*",
                             &subdirs);
        if (rv == APR_SUCCESS && subdirs->nelts > 0) {
            const char * const *elts = (const char * const *)subdirs->elts;

            for (i = 0; i < subdirs->nelts; i++) {
                if (elts[i] && chown(elts[i], ap_unixd_config.user_id,
                                     ap_unixd_config.group_id) < 0) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, errno, root_server,
                                 APLOGNO(02706) "Couldn't change owner or group of "
                                 "directory %s",
                                 elts[i]);
                    return errno;
                }
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, root_server,
                         APLOGNO(02707) "Did not read any entries from %s (no "
                         "server certificate?)",
                         sconf->sct_storage);
        }
    }

    /* if running as root, switch to configured user/group */
    if ((rc = ap_run_drop_privileges(pdaemon, ap_server_conf)) != 0) {
        return rc;
    }

    /* ptemp - temporary pool for refresh cycles */
    apr_pool_create(&ptemp, pdaemon);
    apr_pool_tag(ptemp, "sct_daemon_refresh");

    while (!daemon_should_exit) {
        sct_daemon_cycle(sconf, s_main, ptemp, DAEMON_NAME);
        apr_sleep(apr_time_from_sec(30)); /* SIGHUP at restart/stop will break out */
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s_main, APLOGNO(03244)
                 DAEMON_NAME " - exiting");

    return 0;
}

static int daemon_start(apr_pool_t *p, server_rec *main_server,
                        apr_proc_t *procnew)
{
    daemon_should_exit = 0; /* clear setting from previous generation */
    if ((daemon_pid = fork()) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
                     APLOGNO(02708) "Couldn't create " DAEMON_NAME " process");
        return DECLINED;
    }
    else if (daemon_pid == 0) {
        if (pdaemon == NULL) {
            apr_pool_create(&pdaemon, p);
            apr_pool_tag(pdaemon, "sct_daemon");
        }
        exit(sct_daemon(main_server) > 0 ? DAEMON_STARTUP_ERROR : -1);
    }
    procnew->pid = daemon_pid;
    procnew->err = procnew->in = procnew->out = NULL;
    apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);
#if APR_HAS_OTHER_CHILD
    apr_proc_other_child_register(procnew, daemon_maint, procnew, NULL, p);
#endif
    return OK;
}
#endif /* HAVE_SCT_DAEMON_CHILD */

#ifdef HAVE_SCT_DAEMON_THREAD
static void *sct_daemon_thread(apr_thread_t *me, void *data)
{
    server_rec *s = data;
    ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                   &ssl_ct_module);
    int mpmq_s;
    apr_pool_t *ptemp;
    apr_status_t rv;
    int count = 0;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03245)
                 DAEMON_THREAD_NAME " started");

    /* ptemp - temporary pool for refresh cycles */
    apr_pool_create(&ptemp, pdaemon);
    apr_pool_tag(ptemp, "sct_daemon_thread");

    while (1) {
        if ((rv = ap_mpm_query(AP_MPMQ_MPM_STATE, &mpmq_s)) != APR_SUCCESS) {
            break;
        }
        if (mpmq_s == AP_MPMQ_STOPPING) {
            break;
        }
        apr_sleep(apr_time_from_sec(1));
        if (++count >= 30) {
            count = 0;
            sct_daemon_cycle(sconf, s, ptemp, DAEMON_THREAD_NAME);
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03246)
                 DAEMON_THREAD_NAME " - exiting");

    apr_thread_exit(me, APR_SUCCESS);
    return NULL;
}

static int daemon_thread_start(apr_pool_t *pconf, server_rec *s_main)
{
    apr_status_t rv;

    apr_pool_create(&pdaemon, pconf);
    apr_pool_tag(pdaemon, "sct_daemon");
    rv = apr_thread_create(&daemon_thread, NULL, sct_daemon_thread, s_main,
                           pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s_main,
                     APLOGNO(02709) "could not create " DAEMON_THREAD_NAME 
                     " in parent");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_pool_pre_cleanup_register(pconf, daemon_thread, wait_for_thread);

    return OK;
}
#endif /* HAVE_SCT_DAEMON_THREAD */

static apr_status_t ssl_ct_mutex_remove(void *data)
{
    apr_global_mutex_destroy(ssl_ct_sct_update);
    ssl_ct_sct_update = NULL;
    return APR_SUCCESS;
}

static int refresh_all_scts(server_rec *s_main, apr_pool_t *p,
                            apr_array_header_t *log_config)
{
    apr_hash_t *already_processed;
    apr_status_t rv = APR_SUCCESS;
    server_rec *s;

    already_processed = apr_hash_make(p);

    s = s_main;
    while (s) {
        ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                       &ssl_ct_module);
        int i;
        const ct_server_cert_info *cert_info_elts;

        if (sconf && sconf->server_cert_info) {
            cert_info_elts =
                (const ct_server_cert_info *)sconf->server_cert_info->elts;
            for (i = 0; i < sconf->server_cert_info->nelts; i++) {
                /* we may have already processed this cert for another
                 * server_rec
                 */
                if (!apr_hash_get(already_processed, cert_info_elts[i].sct_dir,
                                  APR_HASH_KEY_STRING)) {
                    const char *static_cert_sct_dir = 
                        apr_hash_get(sconf->static_cert_sct_dirs,
                                     cert_info_elts[i].fingerprint,
                                     APR_HASH_KEY_STRING);

                    apr_hash_set(already_processed, cert_info_elts[i].sct_dir,
                                 APR_HASH_KEY_STRING, "done");
                    rv = refresh_scts_for_cert(s_main, p,
                                               cert_info_elts[i].sct_dir,
                                               static_cert_sct_dir,
                                               log_config,
                                               sconf->ct_exe,
                                               sconf->max_sct_age,
                                               sconf->max_sh_sct);
                    if (rv != APR_SUCCESS) {
                        return rv;
                    }
                }
            }
        }

        s = s->next;
    }

    return rv;
}

static int num_server_certs(server_rec *s_main)
{
    int num = 0;
    server_rec *s;

    s = s_main;
    while (s) {
        ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                       &ssl_ct_module);

        if (sconf && sconf->server_cert_info) {
            num += sconf->server_cert_info->nelts;
        }
        s = s->next;
    }

    return num;
}

static int ssl_ct_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s_main)
{
    ct_server_config *sconf = ap_get_module_config(s_main->module_config,
                                                   &ssl_ct_module);
    apr_status_t rv;
#ifdef HAVE_SCT_DAEMON_CHILD
    apr_proc_t *procnew = NULL;
    const char *userdata_key = "sct_daemon_init";

    root_server = s_main;
    root_pool = pconf;

    procnew = ap_retained_data_get(userdata_key);
    if (!procnew) {
        procnew = ap_retained_data_create(userdata_key, sizeof(*procnew));
        procnew->pid = -1;
        procnew->err = procnew->in = procnew->out = NULL;
    }
#endif /* HAVE_SCT_DAEMON_CHILD */

    if (num_server_certs(s_main) == 0) {
        /* Theoretically this module could operate in a proxy-only
         * configuration, where httpd does not act as a TLS server but proxy is
         * configured as a TLS client.  That isn't currently implemented.
         */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                     APLOGNO(02710) "No server certificates were found.");
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                     APLOGNO(02711) "mod_ssl_ct only supports configurations "
                     "with a TLS server.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = ap_global_mutex_create(&ssl_ct_sct_update, NULL,
                                SSL_CT_MUTEX_TYPE, NULL, s_main, pconf, 0);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s_main,
                     APLOGNO(02712) "could not create global mutex");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_pool_cleanup_register(pconf, (void *)s_main, ssl_ct_mutex_remove,
                              apr_pool_cleanup_null);

    if (sconf->log_config_fname) {
        if (!sconf->db_log_config) {
            /* log config db in separate pool that can be cleared */
            apr_pool_create(&sconf->db_log_config_pool, pconf);
            apr_pool_tag(sconf->db_log_config_pool, "sct_db_log_config");
            sconf->db_log_config =
                apr_array_make(sconf->db_log_config_pool, 2,
                               sizeof(ct_log_config *));
        }
        rv = read_config_db(sconf->db_log_config_pool,
                            s_main, sconf->log_config_fname,
                            sconf->db_log_config);
        if (rv != APR_SUCCESS) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (sconf->static_log_config && sconf->db_log_config) {
        if (sconf->static_log_config->nelts > 0
            && sconf->db_log_config->nelts > 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                         APLOGNO(02713) "Either the static log configuration or "
                         "the db log configuration must be empty");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (sconf->static_log_config && sconf->static_log_config->nelts > 0) {
        active_log_config = sconf->static_log_config;
    }
    else if (sconf->db_log_config && sconf->db_log_config->nelts > 0) {
        active_log_config = sconf->db_log_config;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s_main,
                     APLOGNO(02714) "No log URLs were configured; only admin-"
                     "managed SCTs can be sent");
        /* if a db is configured, it could be updated later */
        if (!sconf->db_log_config) { /* no DB configured, need permanently
                                      * empty array */
            active_log_config = apr_array_make(pconf, 1,
                                               sizeof(ct_log_config *));
        }
    }

    /* Ensure that we already have, or can fetch, fresh SCTs for each 
     * certificate.  If so, start the daemon to maintain these and let
     * startup continue.  (Otherwise abort startup.)
     *
     * Except when we start up as root.  We don't want to run external
     * certificate-transparency tools as root, and we don't want to have
     * to fix up the permissions of everything we created so that the
     * SCT maintenance daemon can continue to maintain the SCTs as the
     * configured User/Group.
     */

#if AP_NEED_SET_MUTEX_PERMS /* Unix :) */
    if (!geteuid()) { /* root */
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s_main,
                     APLOGNO(02715) "SCTs will be fetched from configured logs "
                     "as needed and may not be available immediately");
    }
    else {
#endif
    rv = refresh_all_scts(s_main, pconf, active_log_config);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s_main,
                     APLOGNO(02716) "refresh_all_scts() failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#if AP_NEED_SET_MUTEX_PERMS
    }
#endif

#ifdef HAVE_SCT_DAEMON_CHILD
    if (ap_state_query(AP_SQ_MAIN_STATE) != AP_SQ_MS_CREATE_PRE_CONFIG) {
        int ret = daemon_start(pconf, s_main, procnew);
        if (ret != OK) {
            return ret;
        }
    }
#endif /* HAVE_SCT_DAEMON_CHILD */

#ifdef HAVE_SCT_DAEMON_THREAD
    /* WIN32-ism: ensure this is the parent by checking AP_PARENT_PID,
     * which is only set in WinNT children.
     */
    if (ap_state_query(AP_SQ_MAIN_STATE) != AP_SQ_MS_CREATE_PRE_CONFIG
        && !getenv("AP_PARENT_PID")) {
        int ret = daemon_thread_start(pconf, s_main);
        if (ret != OK) {
            return ret;
        }
    }
#endif /* HAVE_SCT_DAEMON_THREAD */

    return OK;
}

static int ssl_ct_check_config(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s_main)
{
    ct_server_config *sconf = ap_get_module_config(s_main->module_config,
                                                   &ssl_ct_module);

    if (!sconf->sct_storage) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                     APLOGNO(02717) "Directive CTSCTStorage is required");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!sconf->audit_storage) {
        /* umm, hard to tell if needed...  must have server with
         * SSL proxy enabled and server-specific-sconf->proxy_awareness
         * != PROXY_OBLIVIOUS...
         */
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s_main,
                     APLOGNO(02718) "Directive CTAuditStorage isn't set; proxy "
                     "will not save data for off-line audit");
    }

    if (!sconf->ct_exe) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s_main,
                     APLOGNO(02719) "Directive CTLogClient isn't set; server "
                     "certificates can't be submitted to configured logs; "
                     "only admin-managed SCTs can be provided to clients");
    }

    if (sconf->log_config_fname) {
        const char *msg = NULL;
        if (!log_config_readable(pconf, sconf->log_config_fname, &msg)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                         APLOGNO(02720) "Log config file %s cannot be read",
                         sconf->log_config_fname);
            if (msg) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main, APLOGNO(03027)
                             "%s", msg);
            }
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

static apr_status_t read_scts(apr_pool_t *p, const char *fingerprint,
                              const char *sct_dir,
                              server_rec *s,
                              char **scts, apr_size_t *scts_len)
{
    apr_status_t rv, tmprv;
    char *cert_dir, *sct_fn;

    rv = ctutil_path_join(&cert_dir, sct_dir, fingerprint, p, s);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = ctutil_path_join(&sct_fn, cert_dir, COLLATED_SCTS_BASENAME, p, s);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if ((rv = apr_global_mutex_lock(ssl_ct_sct_update)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02721) "global mutex lock failed");
        return rv;
    }

    rv = ctutil_read_file(p, s, sct_fn, MAX_SCTS_SIZE, scts, scts_len);

    if ((tmprv = apr_global_mutex_unlock(ssl_ct_sct_update)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, tmprv, s,
                     APLOGNO(02722) "global mutex unlock failed");
    }

    return rv;
}

static void look_for_server_certs(server_rec *s, SSL_CTX *ctx, const char *sct_dir)
{
    ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                   &ssl_ct_module);
    apr_pool_t *p = s->process->pool;
    apr_status_t rv;
    FILE *concat;
    X509 *x;
    STACK_OF(X509) *chain;
    int i, rc;
    char *cert_sct_dir, *servercerts_pem;
    const char *fingerprint;
    ct_server_cert_info *cert_info;

    sconf->server_cert_info = apr_array_make(p, 2, sizeof(ct_server_cert_info));

    rc = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST);
    while (rc) {
        x = SSL_CTX_get0_certificate(ctx); /* UNDOC (mentioned in ssl.pod) */
        if (x) {
            fingerprint = get_cert_fingerprint(s->process->pool, x);
            rv = ctutil_path_join(&cert_sct_dir, sct_dir, fingerprint, p, s);
            ap_assert(rv == APR_SUCCESS);

            if (!ctutil_dir_exists(p, cert_sct_dir)) {
                rv = apr_dir_make(cert_sct_dir, APR_FPROT_OS_DEFAULT, p);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                                 APLOGNO(02723) "can't create directory %s",
                                 cert_sct_dir);
                    ap_assert(rv == APR_SUCCESS);
                }
            }

            rv = ctutil_path_join(&servercerts_pem, cert_sct_dir,
                                  SERVERCERTS_BASENAME, p, s);
            ap_assert(rv == APR_SUCCESS);

            rv = ctutil_fopen(servercerts_pem, "wb", &concat);
            ap_assert(rv == APR_SUCCESS);

            ap_assert(1 == PEM_write_X509(concat, x)); /* leaf */

            chain = NULL;

            /* Not this: SSL_CTX_get0_chain_certs(ctx, &chain);
             *
             * See this thread:
             *   http://mail-archives.apache.org/mod_mbox/httpd-dev/
             *   201402.mbox/%3CCAKUrXK5-2_Sg8FokxBP8nW7tmSuTZZWL-%3
             *   DBDhNnwyK-Z4dmQiQ%40mail.gmail.com%3E
             */
            SSL_CTX_get_extra_chain_certs(ctx, &chain); /* UNDOC */

            if (chain) {
                for (i = 0; i < sk_X509_num(chain); i++) { /* UNDOC */
                    X509 *x = sk_X509_value(chain, i); /* UNDOC */
                    ap_assert(1 == PEM_write_X509(concat, x));
                }
            }
            ap_assert(0 == fclose(concat));

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         APLOGNO(02724) "wrote server cert and chain to %s",
                         servercerts_pem);

            cert_info = (ct_server_cert_info *)apr_array_push(sconf->server_cert_info);
            cert_info->sct_dir = cert_sct_dir;
            cert_info->fingerprint = fingerprint;
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         APLOGNO(02725) "could not find leaf certificate");
        }
        rc = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_NEXT);
    }
}

static ct_conn_config *get_conn_config(conn_rec *c)
{
    ct_conn_config *conncfg =
      ap_get_module_config(c->conn_config, &ssl_ct_module);

    if (!conncfg) {
        conncfg = apr_pcalloc(c->pool, sizeof *conncfg);
        ap_set_module_config(c->conn_config, &ssl_ct_module, conncfg);
    }

    return conncfg;
}

static void client_is_ct_aware(conn_rec *c)
{
    ct_conn_config *conncfg = get_conn_config(c);
    conncfg->peer_ct_aware = 1;
}

static int is_client_ct_aware(conn_rec *c)
{
    ct_conn_config *conncfg = get_conn_config(c);

    return conncfg->peer_ct_aware;
}

static void server_cert_has_sct_list(conn_rec *c)
{
    ct_conn_config *conncfg = get_conn_config(c);
    conncfg->server_cert_has_sct_list = 1;
    conncfg->peer_ct_aware = 1;
}

/* Look at SSLClient::VerifyCallback() and WriteSSLClientCTData()
 * for validation and saving of data for auditing in a form that
 * the c-t tools can use.
 */

static cert_chain *cert_chain_init(apr_pool_t *p, STACK_OF(X509) *chain)
{
    cert_chain *cc = apr_pcalloc(p, sizeof(cert_chain));
    int i;

    cc->cert_arr = apr_array_make(p, 4, sizeof(X509 *));

    for (i = 0; i < sk_X509_num(chain); i++) {
        X509 **spot = apr_array_push(cc->cert_arr);
        *spot = X509_dup(sk_X509_value(chain, i)); /* UNDOC */
        if (i == 0) {
            cc->leaf = *spot;
        }
    }

    return cc;
}

static void cert_chain_free(cert_chain *cc)
{
    X509 **elts = (X509 **)cc->cert_arr->elts;
    int i;

    for (i = 0; i < cc->cert_arr->nelts; i++) {
        X509_free(elts[i]);
    }
}

/* Create hash of leaf certificate and any SCTs so that
 * we can determine whether or not we've seen this exact
 * info from the server before.
 */
static const char *gen_key(conn_rec *c, cert_chain *cc,
                           ct_conn_config *conncfg)
{
    const char *fp;
    SHA256_CTX sha256ctx;
    unsigned char digest[SHA256_DIGEST_LENGTH];

    fp = get_cert_fingerprint(c->pool, cc->leaf);

    SHA256_Init(&sha256ctx); /* UNDOC */
    SHA256_Update(&sha256ctx, (unsigned char *)fp, strlen(fp)); /* UNDOC */
    if (conncfg->cert_sct_list) {
        SHA256_Update(&sha256ctx, conncfg->cert_sct_list, 
                      conncfg->cert_sct_list_size);
    }
    if (conncfg->serverhello_sct_list) {
        SHA256_Update(&sha256ctx, conncfg->serverhello_sct_list,
                      conncfg->serverhello_sct_list_size);
    }
    if (conncfg->ocsp_sct_list) {
        SHA256_Update(&sha256ctx, conncfg->ocsp_sct_list,
                      conncfg->ocsp_sct_list_size);
    }
    SHA256_Final(digest, &sha256ctx); /* UNDOC */
    return apr_pescape_hex(c->pool, digest, sizeof digest, 0);
}

static apr_status_t deserialize_SCTs(apr_pool_t *p,
                                     ct_conn_config *conncfg,
                                     void *sct_list,
                                     apr_size_t sct_list_size)
{
    apr_size_t avail, len_of_data;
    apr_status_t rv;
    const unsigned char *mem, *start_of_data;

    mem = sct_list;
    avail = sct_list_size;

    /* Make sure the overall length is correct */

    rv = ctutil_read_var_bytes((const unsigned char **)&mem,
                               &avail, &start_of_data, &len_of_data);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if (len_of_data + sizeof(apr_uint16_t) != sct_list_size) {
        return APR_EINVAL;
    }

    /* add each SCT in the list to the all_scts array */

    mem = (unsigned char *)sct_list + sizeof(apr_uint16_t);
    avail = sct_list_size - sizeof(apr_uint16_t);

    while (rv == APR_SUCCESS && avail > 0) {
        rv = ctutil_read_var_bytes((const unsigned char **)&mem, &avail, 
                                   &start_of_data, &len_of_data);
        if (rv == APR_SUCCESS) {
            ct_sct_data *sct = (ct_sct_data *)apr_array_push(conncfg->all_scts);

            sct->data = start_of_data;
            ap_assert(len_of_data <= USHRT_MAX);
            sct->len = (apr_uint16_t)len_of_data;
        }
    }

    if (rv == APR_SUCCESS && avail != 0) {
        return APR_EINVAL;
    }

    return APR_SUCCESS;
}

/* perform quick sanity check of server SCT(s) during handshake;
 * errors should result in fatal alert
 */
static apr_status_t validate_server_data(apr_pool_t *p, conn_rec *c,
                                         cert_chain *cc, ct_conn_config *conncfg,
                                         ct_server_config *sconf)
{
    apr_status_t rv = APR_SUCCESS;

    if (conncfg->serverhello_sct_list) {
        ap_log_cdata(APLOG_MARK, APLOG_TRACE6, c, "SCT(s) from ServerHello",
                     conncfg->serverhello_sct_list,
                     conncfg->serverhello_sct_list_size,
                     AP_LOG_DATA_SHOW_OFFSET);
    }

    if (conncfg->cert_sct_list) {
        ap_log_cdata(APLOG_MARK, APLOG_TRACE6, c, "SCT(s) from certificate",
                     conncfg->cert_sct_list,
                     conncfg->cert_sct_list_size,
                     AP_LOG_DATA_SHOW_OFFSET);
    }

    if (conncfg->ocsp_sct_list) {
        ap_log_cdata(APLOG_MARK, APLOG_TRACE6, c, "SCT(s) from stapled OCSP response",
                     conncfg->ocsp_sct_list,
                     conncfg->ocsp_sct_list_size,
                     AP_LOG_DATA_SHOW_OFFSET);
    }

    if (!conncfg->all_scts) {
        conncfg->all_scts = apr_array_make(p, 4, sizeof(ct_sct_data));
    }

    /* deserialize all the SCTs */
    if (conncfg->cert_sct_list) {
        rv = deserialize_SCTs(p, conncfg, conncfg->cert_sct_list,
                              conncfg->cert_sct_list_size);
        if (rv != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                          APLOGNO(02726) "couldn't deserialize SCT list from "
                          "certificate");
        }
    }
    if (rv == APR_SUCCESS && conncfg->serverhello_sct_list) {
        rv = deserialize_SCTs(p, conncfg, conncfg->serverhello_sct_list,
                              conncfg->serverhello_sct_list_size);
        if (rv != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                          APLOGNO(02727) "couldn't deserialize SCT list from "
                          "ServerHello");
        }
    }
    if (rv == APR_SUCCESS && conncfg->ocsp_sct_list) {
        rv = deserialize_SCTs(p, conncfg, conncfg->ocsp_sct_list,
                              conncfg->ocsp_sct_list_size);
        if (rv != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c,
                          APLOGNO(02728) "couldn't deserialize SCT list from "
                          "stapled OCSP response");
        }
    }

    if (rv == APR_SUCCESS) {
        if (conncfg->all_scts->nelts < 1) {
            /* How did we get here without at least one SCT? */
            ap_log_cerror(APLOG_MARK, APLOG_CRIT, 0, c,
                          APLOGNO(02729) "SNAFU: No deserialized SCTs found in "
                          "validate_server_data()");
            rv = APR_EINVAL;
        }
        else {
            apr_status_t tmprv;
            int i, verification_failures, verification_successes, unknown_log_ids;
            ct_sct_data *sct_elts;
            ct_sct_data sct;
            sct_fields_t fields;

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03028)
                          "%d SCTs received total", conncfg->all_scts->nelts);

            verification_failures = verification_successes = unknown_log_ids = 0;
            sct_elts = (ct_sct_data *)conncfg->all_scts->elts;
            for (i = 0; i < conncfg->all_scts->nelts; i++) {
                sct = sct_elts[i];
                tmprv = sct_parse("backend server", c->base_server, 
                                  sct.data, sct.len, cc,
                                  &fields);
                if (tmprv != APR_SUCCESS) {
                    rv = tmprv;
                }
                else {
                    tmprv = sct_verify_timestamp(c, &fields);
                    if (tmprv != APR_SUCCESS) {
                        verification_failures++;
                    }

                    if (active_log_config) {
                        /* will only block if we have a DB-based log
                         * configuration which is currently being refreshed
                         */
                        ap_assert(apr_thread_rwlock_rdlock(log_config_rwlock)
                                  == APR_SUCCESS);
                        tmprv = sct_verify_signature(c, &fields,
                                                     active_log_config);
                        ap_assert(apr_thread_rwlock_unlock(log_config_rwlock)
                                  == APR_SUCCESS);
                        if (tmprv == APR_NOTFOUND) {
                            ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c,
                                          APLOGNO(02730) "Server sent SCT from "
                                          "unrecognized log");
                            unknown_log_ids++;
                        }
                        else if (tmprv != APR_SUCCESS) {
                            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                                          APLOGNO(02731) "Server sent SCT with "
                                          "invalid signature");
                            tmprv = APR_EINVAL;
                            verification_failures++;
                        }
                        else {
                            verification_successes++;
                        }
                    }
                    else {
                        unknown_log_ids++;
                        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c,
                                      APLOGNO(02732) "Signature of SCT from "
                                      "server could not be verified (no "
                                      "configured log public keys)");
                    }
                }
                sct_release(&fields);
            }
            if (verification_failures && !verification_successes) {
                /* If no SCTs are valid, don't communicate. */
                rv = APR_EINVAL;
            }
            ap_log_cerror(APLOG_MARK,
                          rv != APR_SUCCESS ? APLOG_ERR : APLOG_INFO, 0, c,
                          APLOGNO(02733) "Signature/timestamp validation for %d "
                          "SCTs: %d successes, "
                          "%d failures, %d from unknown logs",
                          conncfg->all_scts->nelts, verification_successes,
                          verification_failures, unknown_log_ids);
        }
    }

    return rv;
}

/* Enqueue data from server for off-line audit (cert, SCT(s))
 * We already filtered out duplicate data being saved from this
 * process.  (With reverse proxy it will be the same data over
 * and over.)
 */
#define SERVER_START 0x0001
#define KEY_START    0x0002
#define CERT_START   0x0003
#define SCT_START    0x0004

static void save_server_data(conn_rec *c, cert_chain *cc,
                             ct_conn_config *conncfg,
                             const char *key)
{
    if (audit_file_mutex && audit_file) { /* child init successful, no
                                           * subsequent error
                                           */
        apr_size_t bytes_written;
        apr_status_t rv;
        int i;
        ct_sct_data *sct_elts;
        X509 **x509elts;
        server_rec *s = c->base_server;

        /* Any error in this function is a file I/O error;
         * if such an error occurs, the audit file will be closed
         * and removed, and this child won't be able to queue
         * anything for audit.  (It is likely that other child
         * processes will have the same problem.)
         */

        ctutil_thread_mutex_lock(audit_file_mutex);

        if (audit_file) { /* no error just occurred... */
            audit_file_nonempty = 1;

            rv = ctutil_file_write_uint16(s, audit_file,
                                          SERVER_START);

            if (rv == APR_SUCCESS) {
                rv = ctutil_file_write_uint16(s, audit_file, KEY_START);
            }

            if (rv == APR_SUCCESS) {
                ap_assert(strlen(key) <= USHRT_MAX);
                rv = ctutil_file_write_uint16(s, audit_file,
                                              (apr_uint16_t)strlen(key));
            }

            if (rv == APR_SUCCESS) {
                rv = apr_file_write_full(audit_file, key, strlen(key),
                                         &bytes_written);
            }

            /* Write each certificate, starting with leaf */
            x509elts = (X509 **)cc->cert_arr->elts;
            for (i = 0; rv == APR_SUCCESS && i < cc->cert_arr->nelts; i++) {
                unsigned char *der_buf = NULL;
                int der_length;

                rv = ctutil_file_write_uint16(s, audit_file, CERT_START);

                /* now write the cert!!! */

                if (rv == APR_SUCCESS) {
                    der_length = i2d_X509(x509elts[i], &der_buf);
                    ap_assert(der_length > 0);

                    rv = ctutil_file_write_uint24(s, audit_file, der_length);
                }

                if (rv == APR_SUCCESS) {
                    rv = apr_file_write_full(audit_file, der_buf, der_length,
                                             &bytes_written);
                }

                OPENSSL_free(der_buf);
            }

            /* Write each SCT */
            sct_elts = (ct_sct_data *)conncfg->all_scts->elts;
            for (i = 0; rv == APR_SUCCESS && i < conncfg->all_scts->nelts; i++) {
                ct_sct_data sct;

                rv = ctutil_file_write_uint16(s, audit_file, SCT_START);

                sct = sct_elts[i];

                if (rv == APR_SUCCESS) {
                    rv = ctutil_file_write_uint16(s, audit_file, sct.len);
                }

                if (rv == APR_SUCCESS) {
                    rv = apr_file_write_full(audit_file, sct.data, sct.len,
                                             &bytes_written);
                }
            }

            if (rv != APR_SUCCESS) {
                /* an I/O error occurred; file is not usable */
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                             APLOGNO(02734) "Failed to write to %s, disabling "
                             "audit for this child", audit_fn_active);
                apr_file_close(audit_file);
                audit_file = NULL;
                apr_file_remove(audit_fn_active,
                                /* not used in current implementations */
                                c->pool);
            }
        }

        ctutil_thread_mutex_unlock(audit_file_mutex);
    }
}

/* signed_certificate_timestamp */
static const unsigned short CT_EXTENSION_TYPE = 18;

/* See function of this name in openssl/apps/s_client.c */
static int ocsp_resp_cb(SSL *ssl, void *arg)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    ct_conn_config *conncfg = get_conn_config(c);
    const unsigned char *p;
    int i, len;
    OCSP_RESPONSE *rsp;
    OCSP_BASICRESP *br;
    OCSP_SINGLERESP *single;

    len = SSL_get_tlsext_status_ocsp_resp(ssl, &p); /* UNDOC */
    if (!p) {
        /* normal case */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "OCSP response callback called but no stapled response from server");
        return 1;
    }

    rsp = d2i_OCSP_RESPONSE(NULL, &p, len); /* UNDOC */
    if (!rsp) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      APLOGNO(02792) "Error parsing OCSP response");
        return 0;
    }

    br = OCSP_response_get1_basic(rsp); /* UNDOC */
    if (!br) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03029)
                      "no OCSP basic response");
        return 0;
    }

    for (i = 0; i < OCSP_resp_count(br); i++) {
        const unsigned char *p;
        X509_EXTENSION *ext;
        int idx;
        ASN1_OCTET_STRING *oct1, *oct2;

        single = OCSP_resp_get0(br, i);
        if (!single) {
            continue;
        }

        idx = OCSP_SINGLERESP_get_ext_by_NID(single,
                                             NID_ct_cert_scts, -1); /* UNDOC */

        if (idx == -1) {
            continue;
        }

        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                      "index of NID_ct_cert_scts: %d", idx);

        ext = OCSP_SINGLERESP_get_ext(single, idx);
        oct1 = X509_EXTENSION_get_data(ext); /* UNDOC */

        p = oct1->data;
        if ((oct2 = d2i_ASN1_OCTET_STRING(NULL, &p, oct1->length)) != NULL) {
            conncfg->ocsp_has_sct_list = 1;
            conncfg->peer_ct_aware = 1;
            conncfg->ocsp_sct_list_size = oct2->length;
            conncfg->ocsp_sct_list = apr_pmemdup(c->pool, oct2->data,
                                                 conncfg->ocsp_sct_list_size);
            ASN1_OCTET_STRING_free(oct2);
        }
    }

    OCSP_RESPONSE_free(rsp); /* UNDOC */

    return 1;
}

/* Callbacks and structures for handling custom TLS Extensions:
 *   client_extension_add_callback - sends data for ClientHello TLS Extension
 *   client_extension_parse_callback - receives data from ServerHello TLS Extension
 */
static int client_extension_add_callback(SSL *ssl, unsigned ext_type, 
                                         const unsigned char **out,
                                         size_t *outlen, int *al,
                                         void *arg)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);

    /* nothing to send in ClientHello */

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                  "client_extension_add_callback called, "
                  "ext %hu will be in ClientHello",
                  ext_type);

    return 1;
}

/* Get SCT(s) from ServerHello */
static int client_extension_parse_callback(SSL *ssl, unsigned ext_type,
                                           const unsigned char *in, size_t inlen, 
                                           int *al, void *arg)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    ct_conn_config *conncfg = get_conn_config(c);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                  "client_extension_parse_callback called, "
                  "ext %u was in ServerHello (len %" APR_SIZE_T_FMT ")",
                  ext_type, inlen);

    /* Note: Peer certificate is not available in this callback via
     *       SSL_get_peer_certificate(ssl)
     */

    conncfg->serverhello_has_sct_list = 1;
    conncfg->peer_ct_aware = 1;
    conncfg->serverhello_sct_list = apr_pmemdup(c->pool, in, inlen);
    conncfg->serverhello_sct_list_size = inlen;
    return 1;
}

/* See SSLClient::VerifyCallback() in c-t/src/client/ssl_client.cc
 * (That's a beast and hard to duplicate in depth when you consider
 * all the support classes it relies on; mod_ssl_ct needs to be a
 * C++ module so that the bugs are fixed in one place.)
 *
 * . This code should care about stapled SCTs but doesn't.
 * . This code, unlike SSLClient::VerifyCallback(), doesn't look
 *   at the OpenSSL "input" chain.
 */
static int ssl_ct_ssl_proxy_verify(server_rec *s, conn_rec *c,
                                   STACK_OF(X509) *chain)
{
    apr_pool_t *p = c->pool;
    ct_conn_config *conncfg = get_conn_config(c);
    ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                   &ssl_ct_module);
    int chain_size = sk_X509_num(chain);
    int extension_index;
    cert_chain *certs;

    if (sconf->proxy_awareness == PROXY_OBLIVIOUS) {
        return OK;
    }

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03030)
                  "ssl_ct_ssl_proxy_verify() - get server certificate info");

    if (chain_size < 1) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      APLOGNO(02735) "odd chain size %d -- cannot proceed",
                      chain_size);
        return APR_EINVAL;
    }

    /* Note: SSLClient::Verify looks in both the input chain and the
     *       verified chain.
     */

    certs = cert_chain_init(p, chain);
    conncfg->certs = certs;

    extension_index = 
        X509_get_ext_by_NID(certs->leaf,
                            NID_ct_precert_scts,
                            -1);
    /* use X509_get_ext(certs->leaf, extension_index) to obtain X509_EXTENSION * */

    if (extension_index >= 0) {
        void *ext_struct;

        server_cert_has_sct_list(c);
        /* as in Cert::ExtensionStructure() */
        ext_struct = X509_get_ext_d2i(certs->leaf,
                                      NID_ct_precert_scts,
                                      NULL, /* ignore criticality of extension */
                                      NULL); /* UNDOC */

        if (ext_struct == NULL) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                          APLOGNO(02736) "Could not retrieve SCT list from "
                          "certificate (unexpected)");
        }
        else {
            /* as in Cert::OctetStringExtensionData */
            ASN1_OCTET_STRING *octet = (ASN1_OCTET_STRING *)ext_struct;
            conncfg->cert_sct_list = apr_pmemdup(p,
                                                 octet->data,
                                                 octet->length);
            conncfg->cert_sct_list_size = octet->length;
            ASN1_OCTET_STRING_free(octet); /* UNDOC */
        }
    }

    return OK;
}

static int ssl_ct_proxy_post_handshake(conn_rec *c, SSL *ssl)
{
    apr_pool_t *p = c->pool;
    apr_status_t rv = APR_SUCCESS;
    const char *key;
    ct_cached_server_data *cached = NULL;
    ct_conn_config *conncfg = get_conn_config(c);
    server_rec *s = c->base_server;
    ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                   &ssl_ct_module);
    int validation_error = 0, missing_sct_error = 0;
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);

    if (sconf->proxy_awareness == PROXY_OBLIVIOUS) {
        return OK;
    }

    ssl_ct_ssl_proxy_verify(s, c, chain);

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03247)
                  "finally at the point where we can see where SCTs came from"
                  " %pp/%pp/%pp (c %pp)",
                  conncfg->cert_sct_list, conncfg->serverhello_sct_list,
                  conncfg->ocsp_sct_list, c);

    /* At this point we have the SCTs from the cert (if any) and the
     * SCTs from the TLS extension (if any) in ct_conn_config.
     */

    if (conncfg->cert_sct_list || conncfg->serverhello_sct_list
        || conncfg->ocsp_sct_list) {

        /* The key is critical to avoiding validating and queueing of
         * the same stuff over and over.
         *
         * Is there any cheaper check than server cert and SCTs all exactly
         * the same as before?
         */
        
        key = gen_key(c, conncfg->certs, conncfg);

        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03031)
                      "key for server data: %s", key);

        ctutil_thread_mutex_lock(cached_server_data_mutex);

        cached = apr_hash_get(cached_server_data, key, APR_HASH_KEY_STRING);

        ctutil_thread_mutex_unlock(cached_server_data_mutex);

        if (!cached) {
            ct_cached_server_data *new_server_data =
                (ct_cached_server_data *)calloc(1, sizeof(ct_cached_server_data));

            new_server_data->validation_result = 
                rv = validate_server_data(p, c, conncfg->certs, conncfg, sconf);

            if (rv != APR_SUCCESS) {
                validation_error = 1;
            }

            ctutil_thread_mutex_lock(cached_server_data_mutex);

            if ((cached = apr_hash_get(cached_server_data, key, APR_HASH_KEY_STRING))) {
                /* some other thread snuck in
                 * we assume that the other thread got the same validation
                 * result that we did
                 */
                free(new_server_data);
                new_server_data = NULL;
            }
            else {
                /* no other thread snuck in */
                apr_hash_set(cached_server_data, key, APR_HASH_KEY_STRING,
                             new_server_data);
                new_server_data = NULL;
            }

            ctutil_thread_mutex_unlock(cached_server_data_mutex);

            if (rv == APR_SUCCESS && !cached) {
                save_server_data(c, conncfg->certs, conncfg, key);
            }
        }
        else {
            /* cached */
            rv = cached->validation_result;
            if (rv != APR_SUCCESS) {
                validation_error = 1;
                ap_log_cerror(APLOG_MARK, APLOG_INFO, rv, c,
                              APLOGNO(02737) "bad cached validation result");
            }
        }
    }
    else {
        /* No SCTs at all; consult configuration to know what to do. */
        missing_sct_error = 1;
    }

    if (conncfg->certs) {
        cert_chain_free(conncfg->certs);
        conncfg->certs = NULL;
    }

    ap_log_cerror(APLOG_MARK,
                  rv == APR_SUCCESS ? APLOG_DEBUG : APLOG_ERR, rv, c,
                  APLOGNO(02738) "SCT list received in: %s%s%s(%s) (c %pp)",
                  conncfg->serverhello_has_sct_list ? "ServerHello " : "",
                  conncfg->server_cert_has_sct_list ? "certificate-extension " : "",
                  conncfg->ocsp_has_sct_list ? "OCSP " : "",
                  cached ? "already saved" : "seen for the first time",
                  c);

    if (sconf->proxy_awareness == PROXY_REQUIRE) {
        if (missing_sct_error || validation_error) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                          APLOGNO(02739) "Forbidding access to backend server; "
                          "no valid SCTs");
            return HTTP_FORBIDDEN;
        }
    }

    return OK;
}

static int server_extension_parse_callback(SSL *ssl, unsigned ext_type,
                                           const unsigned char *in,
                                           size_t inlen, int *al,
                                           void *arg)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);

    /* this callback tells us that client is CT-aware;
     * there's nothing of interest in the extension data
     */
    client_is_ct_aware(c);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                  "server_extension_parse_callback called, "
                  "ext %u was in ClientHello (len %" APR_SIZE_T_FMT ")",
                  ext_type, inlen);

    return 1;
}

static int server_extension_add_callback(SSL *ssl, unsigned ext_type,
                                         const unsigned char **out,
                                         size_t *outlen, int *al,
                                         void *arg)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    ct_server_config *sconf = ap_get_module_config(c->base_server->module_config,
                                                   &ssl_ct_module);
    X509 *server_cert;
    const char *fingerprint;
    const unsigned char *scts;
    apr_size_t scts_len;
    apr_status_t rv;

    if (!is_client_ct_aware(c)) {
        /* Hmmm...  Is this actually called if the client doesn't include
         * the extension in the ClientHello?  I don't think so.
         */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03032)
                      "server_extension_callback_2: client isn't CT-aware");
        /* Skip this extension for ServerHello */
        return 0;
    }

    /* need to reply with SCT */

    server_cert = SSL_get_certificate(ssl); /* no need to free! */
    fingerprint = get_cert_fingerprint(c->pool, server_cert);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                  "server_extension_add_callback called, "
                  "ext %hu will be in ServerHello",
                  ext_type);

    rv = read_scts(c->pool, fingerprint,
                   sconf->sct_storage,
                   c->base_server, (char **)&scts, &scts_len);
    if (rv == APR_SUCCESS) {
        *out = scts;
        ap_assert(scts_len <= USHRT_MAX);
        *outlen = (unsigned short)scts_len;
    }
    else {
        /* Skip this extension for ServerHello */
        return 0;
    }

    return 1;
}

static void tlsext_cb(SSL *ssl, int client_server, int type,
                      unsigned char *data, int len,
                      void *arg)
{
    conn_rec *c = arg;

    if (type == CT_EXTENSION_TYPE) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                      "tlsext_cb called, got CT TLS extension");

        client_is_ct_aware(c);
    }
}

static int ssl_ct_pre_handshake(conn_rec *c, SSL *ssl, int is_proxy)
{
    ct_conn_config *conncfg = get_conn_config(c);

    if (is_proxy) {
        conncfg->proxy_handshake = 1;
    }
    else {
        conncfg->client_handshake = 1;
    }

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03033)
                  "client connected (pre-handshake)");

    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp); /* UNDOC */

    /* This callback is needed only to determine that the peer is CT-aware
     * when resuming a session.  For an initial handshake, the callbacks
     * registered via SSL_CTX_set_custom_srv_ext() are sufficient.
     */
    SSL_set_tlsext_debug_callback(ssl, tlsext_cb); /* UNDOC */
    SSL_set_tlsext_debug_arg(ssl, c); /* UNDOC */

    return OK;
}

static int ssl_ct_init_server(server_rec *s, apr_pool_t *p, int is_proxy,
                              SSL_CTX *ssl_ctx)
{
    ct_callback_info *cbi = apr_pcalloc(p, sizeof *cbi);
    ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                   &ssl_ct_module);

    if (s != ap_server_conf) {
        ct_server_config *main_conf = 
            ap_get_module_config(ap_server_conf->module_config,
                                 &ssl_ct_module);

        if (sconf == main_conf) {
            /* There weren't any directives for this module in the vhost,
             * so core httpd gave us the global scope's module config.
             * We need to be able to represent some mod_ssl-related
             * config (certs) that are generally configured in the vhost,
             * so we have to create a vhost-specific module config.
             */
            sconf = copy_ct_server_config(p, main_conf);
            ap_set_module_config(s->module_config, &ssl_ct_module, sconf);
        }
    }

    cbi->s = s;

    if (is_proxy && sconf->proxy_awareness != PROXY_OBLIVIOUS) {
        if (!SSL_CTX_add_client_custom_ext(ssl_ctx, CT_EXTENSION_TYPE,
                                           client_extension_add_callback,
                                           NULL, NULL,
                                           client_extension_parse_callback, cbi)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                         APLOGNO(02740) "Unable to initialize Certificate "
                         "Transparency client extension callbacks "
                         "(callback for %d already registered?)",
                         CT_EXTENSION_TYPE);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Uhh, hopefully this doesn't collide with anybody else.  mod_ssl
         * currently only sets this on the server SSL_CTX, when OCSP is
         * enabled.
         */
        SSL_CTX_set_tlsext_status_cb(ssl_ctx, ocsp_resp_cb); /* UNDOC */
        SSL_CTX_set_tlsext_status_arg(ssl_ctx, cbi); /* UNDOC */
    }
    else if (!is_proxy) {
        look_for_server_certs(s, ssl_ctx, sconf->sct_storage);

        if (!SSL_CTX_add_server_custom_ext(ssl_ctx, CT_EXTENSION_TYPE,
                                           server_extension_add_callback,
                                           NULL, NULL,
                                           server_extension_parse_callback, cbi)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                         APLOGNO(02741) "Unable to initialize Certificate "
                         "Transparency server extension callback "
                         "(callbacks for %d already registered?)",
                         CT_EXTENSION_TYPE);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

static int ssl_ct_post_read_request(request_rec *r)
{
    ct_conn_config *conncfg =
      ap_get_module_config(r->connection->conn_config, &ssl_ct_module);

    if (conncfg) {
        if (conncfg->client_handshake) {
            apr_table_set(r->subprocess_env, CLIENT_STATUS_VAR,
                          conncfg->peer_ct_aware ?
                              STATUS_VAR_AWARE_VAL : STATUS_VAR_UNAWARE_VAL);
        }
        /* else no SSL on this client connection */
    }

    return DECLINED;
}

static int ssl_ct_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp)
{
    apr_status_t rv = ap_mutex_register(pconf, SSL_CT_MUTEX_TYPE, NULL,
                                        APR_LOCK_DEFAULT, 0);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    apr_dbd_init(pconf);

    ctutil_run_internal_tests(ptemp);

    return OK;
}

static apr_status_t inactivate_audit_file(void *data)
{
    apr_status_t rv;
    server_rec *s = data;

    if (!audit_file) { /* something bad happened after child init */
        return APR_SUCCESS;
    }

    /* the normal cleanup was disabled in the call to apr_file_open */
    rv = apr_file_close(audit_file);
    audit_file = NULL;
    if (rv == APR_SUCCESS) {
        if (audit_file_nonempty) {
            rv = apr_file_rename(audit_fn_active, audit_fn_perm,
                                 /* not used in current implementations */
                                 s->process->pool);
        }
        else {
            /* No data written; just remove the file */
            apr_file_remove(audit_fn_active,
                            /* not used in current implementations */
                            s->process->pool);
        }
    }
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     APLOGNO(02742) "error flushing/closing %s or renaming it "
                     "to %s",
                     audit_fn_active, audit_fn_perm);
    }

    return APR_SUCCESS; /* what, you think anybody cares? */
}

static void ssl_ct_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv;
    const char *audit_basename;
    ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                   &ssl_ct_module);

    cached_server_data = apr_hash_make(p);

    rv = apr_global_mutex_child_init(&ssl_ct_sct_update,
                                     apr_global_mutex_lockfile(ssl_ct_sct_update), p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     APLOGNO(02743) "could not initialize " SSL_CT_MUTEX_TYPE
                     " mutex in child");
        /* might crash otherwise due to lack of checking for initialized data
         * in all the right places, but this is going to skip pchild cleanup
         */
        exit(APEXIT_CHILDSICK);
    }

    rv = apr_thread_rwlock_create(&log_config_rwlock, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     APLOGNO(02744) "could not create rwlock in child");
        exit(APEXIT_CHILDSICK);
    }

    rv = apr_thread_create(&service_thread, NULL, run_service_thread, s, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     APLOGNO(02745) "could not create " SERVICE_THREAD_NAME
                     " in child");
        /* might crash otherwise due to lack of checking for initialized data
         * in all the right places, but this is going to skip pchild cleanup
         */
        exit(APEXIT_CHILDSICK);
    }

    apr_pool_pre_cleanup_register(p, service_thread, wait_for_thread);

    if (sconf->proxy_awareness != PROXY_OBLIVIOUS) {
        rv = apr_thread_mutex_create(&cached_server_data_mutex,
                                     APR_THREAD_MUTEX_DEFAULT,
                                     p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         APLOGNO(02746) "could not allocate a thread mutex");
            /* might crash otherwise due to lack of checking for initialized data
             * in all the right places, but this is going to skip pchild cleanup
             */
            exit(APEXIT_CHILDSICK);
        }
    }

    if (sconf->proxy_awareness != PROXY_OBLIVIOUS && sconf->audit_storage) {
        rv = apr_thread_mutex_create(&audit_file_mutex,
                                     APR_THREAD_MUTEX_DEFAULT, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         APLOGNO(02747) "could not allocate a thread mutex");
            /* might crash otherwise due to lack of checking for initialized data
             * in all the right places, but this is going to skip pchild cleanup
             */
            exit(APEXIT_CHILDSICK);
        }

        audit_basename = apr_psprintf(p, "audit_%" APR_PID_T_FMT,
                                      getpid());
        rv = ctutil_path_join((char **)&audit_fn_perm, sconf->audit_storage,
                              audit_basename, p, s);
        if (rv != APR_SUCCESS) {
            /* might crash otherwise due to lack of checking for initialized data
             * in all the right places, but this is going to skip pchild cleanup
             */
            exit(APEXIT_CHILDSICK);
        }

        audit_fn_active = apr_pstrcat(p, audit_fn_perm, ".tmp", NULL);
        audit_fn_perm = apr_pstrcat(p, audit_fn_perm, ".out", NULL);

        if (ctutil_file_exists(p, audit_fn_active)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                         APLOGNO(02748) "Pid-specific file %s was reused before "
                         "audit grabbed it! (removing)",
                         audit_fn_active);
            apr_file_remove(audit_fn_active, p);
        }

        if (ctutil_file_exists(p, audit_fn_perm)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                         APLOGNO(02749) "Pid-specific file %s was reused before "
                         "audit grabbed it! (removing)",
                         audit_fn_perm);
            apr_file_remove(audit_fn_perm, p);
        }

        rv = apr_file_open(&audit_file, audit_fn_active,
                           APR_FOPEN_WRITE|APR_FOPEN_CREATE|APR_FOPEN_TRUNCATE
                           |APR_FOPEN_BINARY|APR_FOPEN_BUFFERED|APR_FOPEN_NOCLEANUP,
                           APR_FPROT_OS_DEFAULT, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(02750) "can't create %s", audit_fn_active);
            audit_file = NULL;
        }

        if (audit_file) {
            apr_pool_cleanup_register(p, s, inactivate_audit_file, apr_pool_cleanup_null);
        }
    } /* !PROXY_OBLIVIOUS */
}

static void *create_ct_server_config(apr_pool_t *p, server_rec *s)
{
    ct_server_config *conf =
        (ct_server_config *)apr_pcalloc(p, sizeof(ct_server_config));

    conf->max_sct_age = apr_time_from_sec(3600 * 24);
    conf->proxy_awareness = PROXY_AWARENESS_UNSET;
    conf->max_sh_sct = 100;
    conf->static_cert_sct_dirs = apr_hash_make(p);
    
    return conf;
}

static void *merge_ct_server_config(apr_pool_t *p, void *basev, void *virtv)
{
    ct_server_config *base = (ct_server_config *)basev;
    ct_server_config *virt = (ct_server_config *)virtv;
    ct_server_config *conf;

    conf = (ct_server_config *)apr_pmemdup(p, virt, sizeof(ct_server_config));

    /* copy non-per-vhost fields from base (other than a few that aren't
     * referenced from per-vhost config)
     */
    conf->sct_storage = base->sct_storage;
    conf->audit_storage = base->audit_storage;
    conf->ct_exe = base->ct_exe;
    conf->max_sct_age = base->max_sct_age;
    conf->log_config_fname = base->log_config_fname;
    conf->db_log_config = base->db_log_config;
    conf->static_log_config = base->static_log_config;
    conf->max_sh_sct = base->max_sh_sct;
    conf->static_cert_sct_dirs = base->static_cert_sct_dirs;

    conf->proxy_awareness = (virt->proxy_awareness != PROXY_AWARENESS_UNSET)
        ? virt->proxy_awareness
        : base->proxy_awareness;

    return conf;
}

static ct_server_config *copy_ct_server_config(apr_pool_t *p,
                                               ct_server_config *base)
{
    /* make a copy of the existing server config and initialize anything
     * that is per-vhost
     */
    ct_server_config *sconf = 
        (ct_server_config *)apr_pmemdup(p, base, sizeof(ct_server_config));
    sconf->server_cert_info = NULL;
    return sconf;
}

#if AP_MODULE_MAGIC_AT_LEAST(20140207,2)
/* Only trunk has the proxy_detach_backend hook; without it,
 * no way to set the envvars which represent backend CT status
 */
static int ssl_ct_detach_backend(request_rec *r,
                                 proxy_conn_rec *backend)
{
    conn_rec *origin = backend->connection;

    if (origin) {
        ct_conn_config *conncfg = get_conn_config(origin);
        char *list, *last;

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03034)
                      "ssl_ct_detach_backend, %d%d%d",
                      conncfg->server_cert_has_sct_list,
                      conncfg->serverhello_has_sct_list,
                      conncfg->ocsp_has_sct_list);

        if (conncfg->proxy_handshake) {
            apr_table_set(r->subprocess_env, PROXY_STATUS_VAR,
                          conncfg->peer_ct_aware ?
                              STATUS_VAR_AWARE_VAL : STATUS_VAR_UNAWARE_VAL);

            list = apr_pstrcat(r->pool,
                               conncfg->server_cert_has_sct_list ? "certext," : "",
                               conncfg->serverhello_has_sct_list ? "tlsext," : "",
                               conncfg->ocsp_has_sct_list ? "ocsp" : "",
                               NULL);
            if (*list) {
                last = list + strlen(list) - 1;
                if (*last == ',') {
                    *last = '\0';
                }
            }

            apr_table_set(r->subprocess_env, PROXY_SCT_SOURCES_VAR, list);
        }
    }
    else {
        /* why here?  some odd error path? */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03035) 
                      "No backend connection available in ssl_ct_detach_backend()");
    }

    return OK;
}
#endif

static void ct_register_hooks(apr_pool_t *p)
{
    static const char * const run_after_mod_ssl[] = {"mod_ssl.c", NULL};

    ap_hook_pre_config(ssl_ct_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_config(ssl_ct_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(ssl_ct_post_config, run_after_mod_ssl, NULL,
                        APR_HOOK_MIDDLE);
    ap_hook_post_read_request(ssl_ct_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(ssl_ct_child_init, NULL, NULL, APR_HOOK_MIDDLE);
#if AP_MODULE_MAGIC_AT_LEAST(20140207,2)
    APR_OPTIONAL_HOOK(proxy, detach_backend, ssl_ct_detach_backend, NULL, NULL,
                      APR_HOOK_MIDDLE);
#endif
    APR_OPTIONAL_HOOK(ssl, init_server, ssl_ct_init_server, NULL, NULL,
                      APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ssl, pre_handshake,
                      ssl_ct_pre_handshake,
                      NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ssl, proxy_post_handshake, ssl_ct_proxy_post_handshake,
                      NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *parse_num(apr_pool_t *p,
                             const char *arg, long min_val,
                             long max_val, long *val,
                             const char *cmd_name)
{
    char *endptr;

    errno = 0;
    *val = strtol(arg, &endptr, 10);
    if (errno != 0
        || *endptr != '\0'
        || *val < min_val
        || *val > max_val) {
        return apr_psprintf(p, "%s must be between %ld "
                            "and %ld (was '%s')", cmd_name, min_val,
                            max_val, arg);
    }

    return NULL;
}
                             
static const char *ct_audit_storage(cmd_parms *cmd, void *x, const char *arg)
{
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }

    sconf->audit_storage = ap_runtime_dir_relative(cmd->pool, arg);

    if (!ctutil_dir_exists(cmd->temp_pool, sconf->audit_storage)) {
        return apr_pstrcat(cmd->pool, "CTAuditStorage: Directory ",
                           sconf->audit_storage,
                           " does not exist", NULL);
    }

    return NULL;
}

static const char *ct_log_config_db(cmd_parms *cmd, void *x, const char *arg)
{
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }

    sconf->log_config_fname = ap_server_root_relative(cmd->pool, arg);

    return NULL;
}

static const char *ct_max_sct_age(cmd_parms *cmd, void *x, const char *arg)
{
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    long val;

    if (err) {
        return err;
    }

    err = parse_num(cmd->pool, arg, 10, 3600 * 12, &val, "CTMaxSCTAge");
    if (err) {
        return err;
    }

    sconf->max_sct_age = apr_time_from_sec(val);
    return NULL;
}    

static const char *ct_proxy_awareness(cmd_parms *cmd, void *x, const char *arg)
{
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);

    if (!strcasecmp(arg, "oblivious")) {
        sconf->proxy_awareness = PROXY_OBLIVIOUS;
    }
    else if (!strcasecmp(arg, "aware")) {
        sconf->proxy_awareness = PROXY_AWARE;
    }
    else if (!strcasecmp(arg, "require")) {
        sconf->proxy_awareness = PROXY_REQUIRE;
    }
    else {
        return apr_pstrcat(cmd->pool, "CTProxyAwareness: Invalid argument \"",
                           arg, "\"", NULL);
    }

    return NULL;
}

static const char *ct_sct_storage(cmd_parms *cmd, void *x, const char *arg)
{
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }

    sconf->sct_storage = ap_runtime_dir_relative(cmd->pool, arg);

    if (!ctutil_dir_exists(cmd->temp_pool, sconf->sct_storage)) {
        return apr_pstrcat(cmd->pool, "CTSCTStorage: Directory ",
                           sconf->sct_storage,
                           " does not exist", NULL);
    }

    return NULL;
}

static const char *ct_sct_limit(cmd_parms *cmd, void *x, const char *arg)
{
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    long val;

    if (err) {
        return err;
    }

    err = parse_num(cmd->pool, arg, 1, 100, &val,
                    "CTServerHelloSCTLimit");
    if (err) {
        return err;
    }

    sconf->max_sh_sct = val;
    return NULL;
}

static const char *ct_static_log_config(cmd_parms *cmd, void *x, int argc,
                                        char *const argv[])
{
    apr_status_t rv;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    const char *log_id, *public_key, *distrusted, *min_valid_time,
        *max_valid_time, *url;
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    int cur_arg;

    if (err) {
        return err;
    }

    if (argc != 6) {
        return "CTStaticLogConfig: 6 arguments are required";
    }

    cur_arg = 0;
    log_id = argv[cur_arg++];
    if (!strcmp(log_id, "-")) {
        log_id = NULL;
    }

    public_key = argv[cur_arg++];
    if (!strcmp(public_key, "-")) {
        public_key = NULL;
    }
    else {
        public_key = ap_server_root_relative(cmd->pool, public_key);
    }

    distrusted = argv[cur_arg++];
    if (!strcmp(distrusted, "-")) {
        distrusted = NULL;
    }

    min_valid_time = argv[cur_arg++];
    if (!strcmp(min_valid_time, "-")) {
        min_valid_time = NULL;
    }

    max_valid_time = argv[cur_arg++];
    if (!strcmp(max_valid_time, "-")) {
        max_valid_time = NULL;
    }

    url = argv[cur_arg++];
    if (!strcmp(url, "-")) {
        url = NULL;
    }

    if (!sconf->static_log_config) {
        sconf->static_log_config =
            apr_array_make(cmd->pool, 2, sizeof(ct_log_config *));
    }
    rv = save_log_config_entry(sconf->static_log_config, cmd->pool,
                               log_id, public_key, distrusted, 
                               min_valid_time, max_valid_time, url);
    if (rv != APR_SUCCESS) {
        return "Error processing static log configuration";
    }

    return NULL;
}

static const char *ct_static_scts(cmd_parms *cmd, void *x, const char *cert_fn,
                                  const char *sct_dn)
{
    apr_pool_t *p = cmd->pool;
    apr_status_t rv;
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    const char *fingerprint;
    FILE *pemfile;
    X509 *cert;

    if (err) {
        return err;
    }

    cert_fn = ap_server_root_relative(p, cert_fn);
    sct_dn = ap_server_root_relative(p, sct_dn);

    rv = ctutil_fopen(cert_fn, "r", &pemfile);
    if (rv != APR_SUCCESS) {
        return apr_psprintf(p, "could not open certificate file %s (%pm)",
                            cert_fn, &rv);
    }
    
    cert = PEM_read_X509(pemfile, NULL, NULL, NULL);
    if (!cert) {
        return apr_psprintf(p, "could not read certificate from file %s",
                            cert_fn);
    }

    fclose(pemfile);

    fingerprint = get_cert_fingerprint(p, cert);
    X509_free(cert);

    if (!ctutil_dir_exists(cmd->temp_pool, sct_dn)) {
        return apr_pstrcat(p, "CTStaticSCTs: Directory ", sct_dn,
                           " does not exist", NULL);
    }

    apr_hash_set(sconf->static_cert_sct_dirs, fingerprint,
                 APR_HASH_KEY_STRING, sct_dn);

    return NULL;
}

static const char *ct_log_client(cmd_parms *cmd, void *x, const char *arg)
{
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }

    if (strcmp(DOTEXE, "")) {
        if (!ctutil_file_exists(cmd->temp_pool, arg)) {
            arg = apr_pstrcat(cmd->pool, arg, DOTEXE, NULL);
        }
    }

    if (!ctutil_file_exists(cmd->temp_pool, arg)) {
        return apr_pstrcat(cmd->pool,
                           "CTLogClient: File ",
                           arg,
                           " does not exist",
                           NULL);
    }

    sconf->ct_exe = arg;

    return NULL;
}

static const command_rec ct_cmds[] =
{
    AP_INIT_TAKE1("CTAuditStorage", ct_audit_storage, NULL,
                  RSRC_CONF, /* GLOBAL_ONLY - audit data spans servers */
                  "Location to store files of audit data"),
    AP_INIT_TAKE1("CTLogConfigDB", ct_log_config_db, NULL,
                  RSRC_CONF, /* GLOBAL_ONLY - otherwise, you couldn't share
                              * the same SCT list for a cert used by two
                              * different vhosts (and the SCT maintenance daemon
                              * would be more complex)
                              */
                  "Log configuration database"),
    AP_INIT_TAKE1("CTMaxSCTAge", ct_max_sct_age, NULL,
                  RSRC_CONF, /* GLOBAL_ONLY - otherwise, you couldn't share
                              * the same SCT list for a cert used by two
                              * different vhosts
                              */
                  "Max age of SCT obtained from log before refresh"),
    AP_INIT_TAKE1("CTProxyAwareness", ct_proxy_awareness, NULL,
                  RSRC_CONF, /* per-server */
                  "\"oblivious\" to neither ask for nor check SCTs, "
                  "\"aware\" to ask for and process SCTs but allow all connections, "
                  "or \"require\" to abort backend connections if an acceptable "
                  "SCT is not provided"),
    AP_INIT_TAKE1("CTServerHelloSCTLimit", ct_sct_limit, NULL,
                  RSRC_CONF, /* GLOBAL_ONLY - otherwise, you couldn't share
                              * the same SCT list for a cert used by two
                              * different vhosts
                              */
                  "Limit on number of SCTs sent in ServerHello"),
    AP_INIT_TAKE1("CTSCTStorage", ct_sct_storage, NULL,
                  RSRC_CONF, /* GLOBAL_ONLY - otherwise, you couldn't share
                              * the same SCT list for a cert used by two
                              * different vhosts (and the SCT maintenance daemon
                              * would be more complex)
                              */
                  "Location to store SCTs obtained from logs"),
    AP_INIT_TAKE_ARGV("CTStaticLogConfig", ct_static_log_config, NULL,
                      RSRC_CONF, /* GLOBAL_ONLY */
                      "Static log configuration record"),
    AP_INIT_TAKE2("CTStaticSCTs", ct_static_scts, NULL,
                  RSRC_CONF, /* GLOBAL_ONLY  - otherwise, you couldn't share
                              * the same SCT list for a cert used by two
                              * different vhosts (and the SCT maintenance daemon
                              * would be more complex)
                              */
                  "Point to directory with static SCTs corresponding to the "
                  "specified certificate"),
    AP_INIT_TAKE1("CTLogClient", ct_log_client, NULL,
                  RSRC_CONF, /* GLOBAL_ONLY - otherwise, you couldn't share
                              * the same SCTs for a cert used by two
                              * different vhosts (and it would be just plain
                              * silly :) )
                              */
                  "Location of certificate-transparency.org (or compatible) log client tool"),
    {NULL}
};

AP_DECLARE_MODULE(ssl_ct) =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_ct_server_config,
    merge_ct_server_config,
    ct_cmds,
    ct_register_hooks,
};
