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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_util.c
 *  Utility Functions
 */
                             /* ``Every day of my life
                                  I am forced to add another
                                  name to the list of people
                                  who piss me off!''
                                            -- Calvin          */

#include "ssl_private.h"
#include "ap_mpm.h"
#include "apr_thread_mutex.h"

/*  _________________________________________________________________
**
**  Utility Functions
**  _________________________________________________________________
*/

char *ssl_util_vhostid(apr_pool_t *p, server_rec *s)
{
    char *id;
    SSLSrvConfigRec *sc;
    char *host;
    apr_port_t port;

    host = s->server_hostname;
    if (s->port != 0)
        port = s->port;
    else {
        sc = mySrvConfig(s);
        if (sc->enabled == TRUE)
            port = DEFAULT_HTTPS_PORT;
        else
            port = DEFAULT_HTTP_PORT;
    }
    id = apr_psprintf(p, "%s:%lu", host, (unsigned long)port);
    return id;
}

/*
 * Return TRUE iff the given servername matches the server record when
 * selecting virtual hosts.
 */
BOOL ssl_util_vhost_matches(const char *servername, server_rec *s)
{
    apr_array_header_t *names;
    int i;
    
    /* check ServerName */
    if (!strcasecmp(servername, s->server_hostname)) {
        return TRUE;
    }
    
    /*
     * if not matched yet, check ServerAlias entries
     * (adapted from vhost.c:matches_aliases())
     */
    names = s->names;
    if (names) {
        char **name = (char **)names->elts;
        for (i = 0; i < names->nelts; ++i) {
            if (!name[i])
                continue;
            if (!strcasecmp(servername, name[i])) {
                return TRUE;
            }
        }
    }
    
    /* if still no match, check ServerAlias entries with wildcards */
    names = s->wild_names;
    if (names) {
        char **name = (char **)names->elts;
        for (i = 0; i < names->nelts; ++i) {
            if (!name[i])
                continue;
            if (!ap_strcasecmp_match(servername, name[i])) {
                return TRUE;
            }
        }
    }
    
    return FALSE;
}

apr_file_t *ssl_util_ppopen(server_rec *s, apr_pool_t *p, const char *cmd,
                            const char * const *argv)
{
    apr_procattr_t *procattr;
    apr_proc_t *proc;

    if (apr_procattr_create(&procattr, p) != APR_SUCCESS)
        return NULL;
    if (apr_procattr_io_set(procattr, APR_FULL_BLOCK, APR_FULL_BLOCK,
                            APR_FULL_BLOCK) != APR_SUCCESS)
        return NULL;
    if (apr_procattr_dir_set(procattr,
                             ap_make_dirstr_parent(p, cmd)) != APR_SUCCESS)
        return NULL;
    if (apr_procattr_cmdtype_set(procattr, APR_PROGRAM) != APR_SUCCESS)
        return NULL;
    proc = apr_pcalloc(p, sizeof(apr_proc_t));
    if (apr_proc_create(proc, cmd, argv, NULL, procattr, p) != APR_SUCCESS)
        return NULL;
    return proc->out;
}

void ssl_util_ppclose(server_rec *s, apr_pool_t *p, apr_file_t *fp)
{
    apr_file_close(fp);
    return;
}

/*
 * Run a filter program and read the first line of its stdout output
 */
char *ssl_util_readfilter(server_rec *s, apr_pool_t *p, const char *cmd,
                          const char * const *argv)
{
    static char buf[MAX_STRING_LEN];
    apr_file_t *fp;
    apr_size_t nbytes = 1;
    char c;
    int k;

    if ((fp = ssl_util_ppopen(s, p, cmd, argv)) == NULL)
        return NULL;
    /* XXX: we are reading 1 byte at a time here */
    for (k = 0; apr_file_read(fp, &c, &nbytes) == APR_SUCCESS
                && nbytes == 1 && (k < MAX_STRING_LEN-1)     ; ) {
        if (c == '\n' || c == '\r')
            break;
        buf[k++] = c;
    }
    buf[k] = NUL;
    ssl_util_ppclose(s, p, fp);

    return buf;
}

BOOL ssl_util_path_check(ssl_pathcheck_t pcm, const char *path, apr_pool_t *p)
{
    apr_finfo_t finfo;

    if (path == NULL)
        return FALSE;
    if (pcm & SSL_PCM_EXISTS && apr_stat(&finfo, path,
                                APR_FINFO_TYPE|APR_FINFO_SIZE, p) != 0)
        return FALSE;
    AP_DEBUG_ASSERT((pcm & SSL_PCM_EXISTS) ||
                    !(pcm & (SSL_PCM_ISREG|SSL_PCM_ISDIR|SSL_PCM_ISNONZERO)));
    if (pcm & SSL_PCM_ISREG && finfo.filetype != APR_REG)
        return FALSE;
    if (pcm & SSL_PCM_ISDIR && finfo.filetype != APR_DIR)
        return FALSE;
    if (pcm & SSL_PCM_ISNONZERO && finfo.size <= 0)
        return FALSE;
    return TRUE;
}

/*
 * certain key data needs to survive restarts,
 * which are stored in the user data table of s->process->pool.
 * to prevent "leaking" of this data, we use malloc/free
 * rather than apr_palloc and these wrappers to help make sure
 * we do not leak the malloc-ed data.
 */
unsigned char *ssl_asn1_table_set(apr_hash_t *table,
                                  const char *key,
                                  long int length)
{
    apr_ssize_t klen = strlen(key);
    ssl_asn1_t *asn1 = apr_hash_get(table, key, klen);

    /*
     * if a value for this key already exists,
     * reuse as much of the already malloc-ed data
     * as possible.
     */
    if (asn1) {
        if (asn1->nData != length) {
            free(asn1->cpData); /* XXX: realloc? */
            asn1->cpData = NULL;
        }
    }
    else {
        asn1 = ap_malloc(sizeof(*asn1));
        asn1->source_mtime = 0; /* used as a note for encrypted private keys */
        asn1->cpData = NULL;
    }

    asn1->nData = length;
    if (!asn1->cpData) {
        asn1->cpData = ap_malloc(length);
    }

    apr_hash_set(table, key, klen, asn1);

    return asn1->cpData; /* caller will assign a value to this */
}

ssl_asn1_t *ssl_asn1_table_get(apr_hash_t *table,
                               const char *key)
{
    return (ssl_asn1_t *)apr_hash_get(table, key, APR_HASH_KEY_STRING);
}

void ssl_asn1_table_unset(apr_hash_t *table,
                          const char *key)
{
    apr_ssize_t klen = strlen(key);
    ssl_asn1_t *asn1 = apr_hash_get(table, key, klen);

    if (!asn1) {
        return;
    }

    if (asn1->cpData) {
        free(asn1->cpData);
    }
    free(asn1);

    apr_hash_set(table, key, klen, NULL);
}

#if APR_HAS_THREADS && MODSSL_USE_OPENSSL_PRE_1_1_API

/*
 * To ensure thread-safetyness in OpenSSL - work in progress
 */

static apr_thread_mutex_t **lock_cs;
static int                  lock_num_locks;

static void ssl_util_thr_lock(int mode, int type,
                              const char *file, int line)
{
    if (type < lock_num_locks) {
        if (mode & CRYPTO_LOCK) {
            apr_thread_mutex_lock(lock_cs[type]);
        }
        else {
            apr_thread_mutex_unlock(lock_cs[type]);
        }
    }
}

/* Dynamic lock structure */
struct CRYPTO_dynlock_value {
    apr_pool_t *pool;
    const char* file;
    int line;
    apr_thread_mutex_t *mutex;
};

/* Global reference to the pool passed into ssl_util_thread_setup() */
apr_pool_t *dynlockpool = NULL;

/*
 * Dynamic lock creation callback
 */
static struct CRYPTO_dynlock_value *ssl_dyn_create_function(const char *file,
                                                     int line)
{
    struct CRYPTO_dynlock_value *value;
    apr_pool_t *p;
    apr_status_t rv;

    /*
     * We need a pool to allocate our mutex.  Since we can't clear
     * allocated memory from a pool, create a subpool that we can blow
     * away in the destruction callback.
     */
    apr_pool_create(&p, dynlockpool);
    ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_TRACE1, 0, p,
                  "Creating dynamic lock");

    value = apr_palloc(p, sizeof(struct CRYPTO_dynlock_value));
    value->pool = p;
    /* Keep our own copy of the place from which we were created,
       using our own pool. */
    value->file = apr_pstrdup(p, file);
    value->line = line;
    rv = apr_thread_mutex_create(&(value->mutex), APR_THREAD_MUTEX_DEFAULT,
                                p);
    if (rv != APR_SUCCESS) {
        ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_ERR, rv, p, APLOGNO(02186)
                      "Failed to create thread mutex for dynamic lock");
        apr_pool_destroy(p);
        return NULL;
    }
    return value;
}

/*
 * Dynamic locking and unlocking function
 */

static void ssl_dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
                           const char *file, int line)
{
    apr_status_t rv;

    if (mode & CRYPTO_LOCK) {
        ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_TRACE3, 0, l->pool,
                      "Acquiring mutex %s:%d", l->file, l->line);
        rv = apr_thread_mutex_lock(l->mutex);
        ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_TRACE3, rv, l->pool,
                      "Mutex %s:%d acquired!", l->file, l->line);
    }
    else {
        ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_TRACE3, 0, l->pool,
                      "Releasing mutex %s:%d", l->file, l->line);
        rv = apr_thread_mutex_unlock(l->mutex);
        ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_TRACE3, rv, l->pool,
                      "Mutex %s:%d released!", l->file, l->line);
    }
}

/*
 * Dynamic lock destruction callback
 */
static void ssl_dyn_destroy_function(struct CRYPTO_dynlock_value *l,
                          const char *file, int line)
{
    apr_status_t rv;

    ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_TRACE1, 0, l->pool,
                  "Destroying dynamic lock %s:%d", l->file, l->line);
    rv = apr_thread_mutex_destroy(l->mutex);
    if (rv != APR_SUCCESS) {
        ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_ERR, rv, l->pool,
                      APLOGNO(02192) "Failed to destroy mutex for dynamic "
                      "lock %s:%d", l->file, l->line);
    }

    /* Trust that whomever owned the CRYPTO_dynlock_value we were
     * passed has no future use for it...
     */
    apr_pool_destroy(l->pool);
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L

static void ssl_util_thr_id(CRYPTO_THREADID *id)
{
    /* OpenSSL needs this to return an unsigned long.  On OS/390, the pthread
     * id is a structure twice that big.  Use the TCB pointer instead as a
     * unique unsigned long.
     */
#ifdef __MVS__
    struct PSA {
        char unmapped[540]; /* PSATOLD is at offset 540 in the PSA */
        unsigned long PSATOLD;
    } *psaptr = 0; /* PSA is at address 0 */

    CRYPTO_THREADID_set_numeric(id, psaptr->PSATOLD);
#else
    CRYPTO_THREADID_set_numeric(id, (unsigned long) apr_os_thread_current());
#endif
}

static apr_status_t ssl_util_thr_id_cleanup(void *old)
{
    CRYPTO_THREADID_set_callback(old);
    return APR_SUCCESS;
}

#else

static unsigned long ssl_util_thr_id(void)
{
    /* OpenSSL needs this to return an unsigned long.  On OS/390, the pthread
     * id is a structure twice that big.  Use the TCB pointer instead as a
     * unique unsigned long.
     */
#ifdef __MVS__
    struct PSA {
        char unmapped[540];
        unsigned long PSATOLD;
    } *psaptr = 0;

    return psaptr->PSATOLD;
#else
    return (unsigned long) apr_os_thread_current();
#endif
}

static apr_status_t ssl_util_thr_id_cleanup(void *old)
{
    CRYPTO_set_id_callback(old);
    return APR_SUCCESS;
}

#endif

static apr_status_t ssl_util_thread_cleanup(void *data)
{
    CRYPTO_set_locking_callback(NULL);

    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);

    dynlockpool = NULL;

    /* Let the registered mutex cleanups do their own thing
     */
    return APR_SUCCESS;
}

void ssl_util_thread_setup(apr_pool_t *p)
{
    int i;

    lock_num_locks = CRYPTO_num_locks();
    lock_cs = apr_palloc(p, lock_num_locks * sizeof(*lock_cs));

    for (i = 0; i < lock_num_locks; i++) {
        apr_thread_mutex_create(&(lock_cs[i]), APR_THREAD_MUTEX_DEFAULT, p);
    }

    CRYPTO_set_locking_callback(ssl_util_thr_lock);

    /* Set up dynamic locking scaffolding for OpenSSL to use at its
     * convenience.
     */
    dynlockpool = p;
    CRYPTO_set_dynlock_create_callback(ssl_dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(ssl_dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(ssl_dyn_destroy_function);

    apr_pool_cleanup_register(p, NULL, ssl_util_thread_cleanup,
                                       apr_pool_cleanup_null);
}

void ssl_util_thread_id_setup(apr_pool_t *p)
{
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    CRYPTO_THREADID_set_callback(ssl_util_thr_id);
#else
    CRYPTO_set_id_callback(ssl_util_thr_id);
#endif
    apr_pool_cleanup_register(p, NULL, ssl_util_thr_id_cleanup,
                                       apr_pool_cleanup_null);
}

#endif /* #if APR_HAS_THREADS && MODSSL_USE_OPENSSL_PRE_1_1_API */
