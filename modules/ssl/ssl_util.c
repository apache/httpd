/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_util.c
**  Utility Functions
*/

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 */
                             /* ``Every day of my life
                                  I am forced to add another
                                  name to the list of people
                                  who piss me off!''
                                            -- Calvin          */

#include "mod_ssl.h"
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
        if (sc->enabled)
            port = DEFAULT_HTTPS_PORT;
        else
            port = DEFAULT_HTTP_PORT;
    }
    id = apr_psprintf(p, "%s:%lu", host, (unsigned long)port);
    return id;
}

void ssl_util_strupper(char *s)
{
    for (; *s; ++s)
        *s = apr_toupper(*s);
    return;
}

static const char ssl_util_uuencode_six2pr[64+1] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void ssl_util_uuencode(char *szTo, const char *szFrom, BOOL bPad)
{
    ssl_util_uuencode_binary((unsigned char *)szTo,
                             (const unsigned char *)szFrom,
                             strlen(szFrom), bPad);
}

void ssl_util_uuencode_binary(unsigned char *szTo,
                              const unsigned char *szFrom,
                              int nLength, BOOL bPad)
{
    const unsigned char *s;
    int nPad = 0;

    for (s = szFrom; nLength > 0; s += 3) {
        *szTo++ = ssl_util_uuencode_six2pr[s[0] >> 2];
        *szTo++ = ssl_util_uuencode_six2pr[(s[0] << 4 | s[1] >> 4) & 0x3f];
        if (--nLength == 0) {
            nPad = 2;
            break;
        }
        *szTo++ = ssl_util_uuencode_six2pr[(s[1] << 2 | s[2] >> 6) & 0x3f];
        if (--nLength == 0) {
            nPad = 1;
            break;
        }
        *szTo++ = ssl_util_uuencode_six2pr[s[2] & 0x3f];
        --nLength;
    }
    while(bPad && nPad--) {
        *szTo++ = NUL;
    }
    *szTo = NUL;
    return;
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
            
    t = SSL_ALGO_UNKNOWN;
    if (pCert != NULL)
        pKey = X509_get_pubkey(pCert);
    if (pKey != NULL) {
        switch (EVP_PKEY_key_type(pKey)) {
            case EVP_PKEY_RSA: 
                t = SSL_ALGO_RSA;
                break;
            case EVP_PKEY_DSA: 
                t = SSL_ALGO_DSA;
                break;
            default:
                break;
        }
    }
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
        default:
            break;
    }
    return cp;
}

char *ssl_util_ptxtsub(apr_pool_t *p, const char *cpLine,
                       const char *cpMatch, char *cpSubst)
{
#define MAX_PTXTSUB 100
    char *cppMatch[MAX_PTXTSUB];
    char *cpResult;
    int nResult;
    int nLine;
    int nSubst;
    int nMatch;
    char *cpI;
    char *cpO;
    char *cp;
    int i;

    /*
     * Pass 1: find substitution locations and calculate sizes
     */
    nLine  = strlen(cpLine);
    nMatch = strlen(cpMatch);
    nSubst = strlen(cpSubst);
    for (cpI = (char *)cpLine, i = 0, nResult = 0;
         cpI < cpLine+nLine && i < MAX_PTXTSUB;    ) {
        if ((cp = strstr(cpI, cpMatch)) != NULL) {
            cppMatch[i++] = cp;
            nResult += ((cp-cpI)+nSubst);
            cpI = (cp+nMatch);
        }
        else {
            nResult += strlen(cpI);
            break;
        }
    }
    cppMatch[i] = NULL;
    if (i == 0)
        return NULL;

    /*
     * Pass 2: allocate memory and assemble result
     */
    cpResult = apr_pcalloc(p, nResult+1);
    for (cpI = (char *)cpLine, cpO = cpResult, i = 0;
         cppMatch[i] != NULL;
         i++) {
        apr_cpystrn(cpO, cpI, cppMatch[i]-cpI+1);
        cpO += (cppMatch[i]-cpI);
        apr_cpystrn(cpO, cpSubst, nSubst+1);
        cpO += nSubst;
        cpI = (cppMatch[i]+nMatch);
    }
    apr_cpystrn(cpO, cpI, cpResult+nResult-cpO+1);

    return cpResult;
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

static const char *ssl_asn1_key_types[] = {"RSA", "DSA"};

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


#if APR_HAS_THREADS
/*
 * To ensure thread-safetyness in OpenSSL - work in progress
 */

static apr_thread_mutex_t **lock_cs;
static int                  lock_num_locks;

#ifdef SSLC_VERSION_NUMBER
#if SSLC_VERSION_NUMBER >= 0x2000
static int ssl_util_thr_lock(int mode, int type,
                              const char *file, int line)
#else
static void ssl_util_thr_lock(int mode, int type,
                              const char *file, int line)
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
#ifdef SSLC_VERSION_NUMBER
#if SSLC_VERSION_NUMBER >= 0x2000
        return 1;
    }
    else {
        return -1;
#endif
#endif
    }
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

    apr_pool_cleanup_register(p, NULL, ssl_util_thread_cleanup,
                                       apr_pool_cleanup_null);
}
#endif
