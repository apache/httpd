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
    if ((proc = (apr_proc_t *)apr_pcalloc(p, sizeof(apr_proc_t))) == NULL)
        return NULL;
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
    if (pcm & SSL_PCM_ISREG && finfo.filetype != APR_REG)
        return FALSE;
    if (pcm & SSL_PCM_ISDIR && finfo.filetype != APR_DIR)
        return FALSE;
    if (pcm & SSL_PCM_ISNONZERO && finfo.size <= 0)
        return FALSE;
    return TRUE;
}

ssl_algo_t ssl_util_algotypeof(X509 *pCert, EVP_PKEY *pKey)
{
    ssl_algo_t t;
    EVP_PKEY *pFreeKey = NULL;

    t = SSL_ALGO_UNKNOWN;
    if (pCert != NULL)
        pFreeKey = pKey = X509_get_pubkey(pCert);
    if (pKey != NULL) {
        switch (EVP_PKEY_key_type(pKey)) {
            case EVP_PKEY_RSA:
                t = SSL_ALGO_RSA;
                break;
            case EVP_PKEY_DSA:
                t = SSL_ALGO_DSA;
                break;
#ifndef OPENSSL_NO_EC
            case EVP_PKEY_EC:
                t = SSL_ALGO_ECC;
                break;
#endif 
            default:
                break;
        }
    }
#ifdef OPENSSL_VERSION_NUMBER
    /* Only refcounted in OpenSSL */
    if (pFreeKey != NULL)
        EVP_PKEY_free(pFreeKey);
#endif
    return t;
}

char *ssl_util_algotypestr(ssl_algo_t t)
{
    char *cp;

    cp = "UNKNOWN";
    switch (t) {
        case SSL_ALGO_RSA:
            cp = "RSA";
            break;
        case SSL_ALGO_DSA:
            cp = "DSA";
            break;
#ifndef OPENSSL_NO_EC
        case SSL_ALGO_ECC:
            cp = "ECC";
            break;
#endif
        default:
            break;
    }
    return cp;
}

/*
 * certain key and cert data needs to survive restarts,
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
        asn1 = malloc(sizeof(*asn1));
        asn1->source_mtime = 0; /* used as a note for encrypted private keys */
        asn1->cpData = NULL;
    }

    asn1->nData = length;
    if (!asn1->cpData) {
        asn1->cpData = malloc(length);
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

#ifndef OPENSSL_NO_EC
static const char *ssl_asn1_key_types[] = {"RSA", "DSA", "ECC"};
#else
static const char *ssl_asn1_key_types[] = {"RSA", "DSA"};
#endif

const char *ssl_asn1_keystr(int keytype)
{
    if (keytype >= SSL_AIDX_MAX) {
        return NULL;
    }

    return ssl_asn1_key_types[keytype];
}

const char *ssl_asn1_table_keyfmt(apr_pool_t *p,
                                  const char *id,
                                  int keytype)
{
    const char *keystr = ssl_asn1_keystr(keytype);

    return apr_pstrcat(p, id, ":", keystr, NULL);
}

STACK_OF(X509) *ssl_read_pkcs7(server_rec *s, const char *pkcs7)
{
    PKCS7 *p7;
    STACK_OF(X509) *certs = NULL;
    FILE *f;

    f = fopen(pkcs7, "r");
    if (!f) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "Can't open %s", pkcs7);
        ssl_die();
    }

    p7 = PEM_read_PKCS7(f, NULL, NULL, NULL);
    if (!p7) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, s,
                     "Can't read PKCS7 object %s", pkcs7);
        ssl_log_ssl_error(APLOG_MARK, APLOG_CRIT, s);
        exit(1);
    }

    switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_signed:
        certs = p7->d.sign->cert;
        p7->d.sign->cert = NULL;
        PKCS7_free(p7);
        break;

    case NID_pkcs7_signedAndEnveloped:
        certs = p7->d.signed_and_enveloped->cert;
        p7->d.signed_and_enveloped->cert = NULL;
        PKCS7_free(p7);
        break;

    default:
        ap_log_error(APLOG_MARK, APLOG_CRIT|APLOG_NOERRNO, 0, s,
                     "Don't understand PKCS7 file %s", pkcs7);
        ssl_die();
    }

    if (!certs) {
        ap_log_error(APLOG_MARK, APLOG_CRIT|APLOG_NOERRNO, 0, s,
                     "No certificates in %s", pkcs7);
        ssl_die();
    }

    fclose(f);

    return certs;
}


#if APR_HAS_THREADS
/*
 * To ensure thread-safetyness in OpenSSL - work in progress
 */

static apr_thread_mutex_t **lock_cs;
static int                  lock_num_locks;

#ifdef HAVE_SSLC
#if SSLC_VERSION_NUMBER >= 0x2000
static int ssl_util_thr_lock(int mode, int type,
                             char *file, int line)
#else
static void ssl_util_thr_lock(int mode, int type,
                              char *file, int line)
#endif
#else
static void ssl_util_thr_lock(int mode, int type,
                              const char *file, int line)
#endif
{
    if (type < lock_num_locks) {
        if (mode & CRYPTO_LOCK) {
            apr_thread_mutex_lock(lock_cs[type]);
        }
        else {
            apr_thread_mutex_unlock(lock_cs[type]);
        }
#ifdef HAVE_SSLC
#if SSLC_VERSION_NUMBER >= 0x2000
        return 1;
    }
    else {
        return -1;
#endif
#endif
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
    rv = apr_pool_create(&p, dynlockpool);
    if (rv != APR_SUCCESS) {
        ap_log_perror(file, line, APLOG_ERR, rv, dynlockpool, 
                       "Failed to create subpool for dynamic lock");
        return NULL;
    }

    ap_log_perror(file, line, APLOG_DEBUG, 0, p, 
                  "Creating dynamic lock");
    
    value = (struct CRYPTO_dynlock_value *)apr_palloc(p, 
                                                      sizeof(struct CRYPTO_dynlock_value));
    if (!value) {
        ap_log_perror(file, line, APLOG_ERR, 0, p, 
                      "Failed to allocate dynamic lock structure");
        return NULL;
    }
    
    value->pool = p;
    /* Keep our own copy of the place from which we were created,
       using our own pool. */
    value->file = apr_pstrdup(p, file);
    value->line = line;
    rv = apr_thread_mutex_create(&(value->mutex), APR_THREAD_MUTEX_DEFAULT, 
                                p);
    if (rv != APR_SUCCESS) {
        ap_log_perror(file, line, APLOG_ERR, rv, p, 
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
        ap_log_perror(file, line, APLOG_DEBUG, 0, l->pool, 
                      "Acquiring mutex %s:%d", l->file, l->line);
        rv = apr_thread_mutex_lock(l->mutex);
        ap_log_perror(file, line, APLOG_DEBUG, rv, l->pool, 
                      "Mutex %s:%d acquired!", l->file, l->line);
    }
    else {
        ap_log_perror(file, line, APLOG_DEBUG, 0, l->pool, 
                      "Releasing mutex %s:%d", l->file, l->line);
        rv = apr_thread_mutex_unlock(l->mutex);
        ap_log_perror(file, line, APLOG_DEBUG, rv, l->pool, 
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

    ap_log_perror(file, line, APLOG_DEBUG, 0, l->pool, 
                  "Destroying dynamic lock %s:%d", l->file, l->line);
    rv = apr_thread_mutex_destroy(l->mutex);
    if (rv != APR_SUCCESS) {
        ap_log_perror(file, line, APLOG_ERR, rv, l->pool, 
                      "Failed to destroy mutex for dynamic lock %s:%d", 
                      l->file, l->line);
    }

    /* Trust that whomever owned the CRYPTO_dynlock_value we were
     * passed has no future use for it...
     */
    apr_pool_destroy(l->pool);
}

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

static apr_status_t ssl_util_thread_cleanup(void *data)
{
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    
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

    CRYPTO_set_id_callback(ssl_util_thr_id);

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
#endif
