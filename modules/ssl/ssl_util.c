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
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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
        if (sc->bEnabled)
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

apr_file_t *ssl_util_ppopen(server_rec *s, apr_pool_t *p, char *cmd)
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
    if (apr_proc_create(proc, cmd, NULL, NULL, procattr, p) != APR_SUCCESS)
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
char *ssl_util_readfilter(server_rec *s, apr_pool_t *p, char *cmd)
{
    static char buf[MAX_STRING_LEN];
    apr_file_t *fp;
    apr_size_t nbytes;
    char c;
    int k;

    if ((fp = ssl_util_ppopen(s, p, cmd)) == NULL)
        return NULL;
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
        switch (EVP_PKEY_type(pKey->type)) {
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

apr_status_t ssl_util_setmodconfig(server_rec *s, const char *key,
                                   SSLModConfigRec *mc)
{
    return apr_pool_userdata_set((void *)mc, key, apr_pool_cleanup_null,
                                 s->process->pool);
}

SSLModConfigRec *ssl_util_getmodconfig(server_rec *s, const char *key)
{
    SSLModConfigRec *mc = NULL;

    if (apr_pool_userdata_get((void **)&mc, key, s->process->pool)
        != APR_SUCCESS) {
        ssl_log(s, SSL_LOG_TRACE,
                "Unable to retrieve SSLModConfig from global pool");
    }
    return mc;
}

SSLModConfigRec *ssl_util_getmodconfig_ssl(SSL *ssl, const char *key)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    SSLModConfigRec *mc = NULL;
     
    if (c != NULL)
        mc = ssl_util_getmodconfig(c->base_server, key);
    return mc;
}

#if APR_HAS_THREADS
/*
 * To ensure thread-safetyness in OpenSSL - work in progress
 */

static apr_thread_mutex_t **lock_cs;
static long                 lock_count[CRYPTO_NUM_LOCKS];

static void ssl_util_thr_lock(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        apr_thread_mutex_lock(lock_cs[type]);
        lock_count[type]++;
    }
    else {
        apr_thread_mutex_unlock(lock_cs[type]);
    }
}

static unsigned long ssl_util_thr_id(void)
{
    return (unsigned long) apr_os_thread_current();
}

static apr_status_t ssl_util_thread_cleanup(void *data)
{
    int i;

    CRYPTO_set_locking_callback(NULL);

    for (i = 0; i < CRYPTO_NUM_LOCKS; i++) {
        apr_thread_mutex_destroy(lock_cs[i]);
    }

    return APR_SUCCESS;
}

void ssl_util_thread_setup(server_rec *s, apr_pool_t *p)
{
    int i, threaded_mpm;
    /* This variable is not used? -aaron
    SSLModConfigRec *mc = myModConfig(s);
    */

    ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);

    if (!threaded_mpm) {
        return;
    }

    lock_cs = apr_palloc(p, CRYPTO_NUM_LOCKS * sizeof(apr_thread_mutex_t *));

    /*
     * XXX: CRYPTO_NUM_LOCKS == 28
     * should determine if there are lock types we do not need
     * for example: debug_malloc, debug_malloc2 (see crypto/cryptlib.c)
     */
    for (i = 0; i < CRYPTO_NUM_LOCKS; i++) {
        lock_count[i] = 0;
        /* XXX: Can we remove the lock_count now that apr_thread_mutex_t
         * can support nested (aka recursive) locks? -aaron */
        apr_thread_mutex_create(&(lock_cs[i]), APR_THREAD_MUTEX_DEFAULT, p);
    }

    CRYPTO_set_id_callback(ssl_util_thr_id);

    CRYPTO_set_locking_callback(ssl_util_thr_lock);

    apr_pool_cleanup_register(p, NULL,
                              ssl_util_thread_cleanup,
                              apr_pool_cleanup_null);

}
#endif
