/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_util_ssl.c
**  Additional Utility Functions for OpenSSL
*/

/* ====================================================================
 * Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * 4. The names "mod_ssl" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    rse@engelschall.com.
 *
 * 5. Products derived from this software may not be called "mod_ssl"
 *    nor may "mod_ssl" appear in their names without prior
 *    written permission of Ralf S. Engelschall.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include "mod_ssl.h"


/*  _________________________________________________________________
**
**  Additional High-Level Functions for OpenSSL
**  _________________________________________________________________
*/

int SSL_get_app_data2_idx(void)
{
   static int app_data2_idx = -1;

   if (app_data2_idx < 0) {
      app_data2_idx = SSL_get_ex_new_index(0,
           "Second Application Data for SSL", NULL, NULL, NULL);
      app_data2_idx = SSL_get_ex_new_index(0,
           "Second Application Data for SSL", NULL, NULL, NULL);
   }
   return(app_data2_idx);
}

void *SSL_get_app_data2(SSL *ssl)
{
    return (void *)SSL_get_ex_data(ssl, SSL_get_app_data2_idx());
}

void SSL_set_app_data2(SSL *ssl, void *arg)
{
    SSL_set_ex_data(ssl, SSL_get_app_data2_idx(), (char *)arg);
    return;
}

/*  _________________________________________________________________
**
**  High-Level Certificate / Private Key Loading
**  _________________________________________________________________
*/

X509 *SSL_read_X509(FILE *fp, X509 **x509, int (*cb)())
{
    X509 *rc;
    BIO *bioS;
    BIO *bioF;

    /* 1. try PEM (= DER+Base64+headers) */
#if SSL_LIBRARY_VERSION < 0x00904000
    rc = PEM_read_X509(fp, x509, cb);
#else
    rc = PEM_read_X509(fp, x509, cb, NULL);
#endif
    if (rc == NULL) {
        /* 2. try DER+Base64 */
        fseek(fp, 0L, SEEK_SET);
        if ((bioS = BIO_new(BIO_s_fd())) == NULL)
            return NULL;
        BIO_set_fd(bioS, fileno(fp), BIO_NOCLOSE);
        if ((bioF = BIO_new(BIO_f_base64())) == NULL) {
            BIO_free(bioS);
            return NULL;
        }
        bioS = BIO_push(bioF, bioS);
        rc = d2i_X509_bio(bioS, NULL);
        BIO_free_all(bioS);
        if (rc == NULL) {
            /* 3. try plain DER */
            fseek(fp, 0L, SEEK_SET);
            if ((bioS = BIO_new(BIO_s_fd())) == NULL)
                return NULL;
            BIO_set_fd(bioS, fileno(fp), BIO_NOCLOSE);
            rc = d2i_X509_bio(bioS, NULL);
            BIO_free(bioS);
        }
    }
    if (rc != NULL && x509 != NULL) {
        if (*x509 != NULL)
            X509_free(*x509);
        *x509 = rc;
    }
    return rc;
}

#if SSL_LIBRARY_VERSION <= 0x00904100
static EVP_PKEY *d2i_PrivateKey_bio(BIO *bio, EVP_PKEY **key)
{
     return ((EVP_PKEY *)ASN1_d2i_bio(
             (char *(*)())EVP_PKEY_new, 
             (char *(*)())d2i_PrivateKey, 
             (bio), (unsigned char **)(key)));
}
#endif

EVP_PKEY *SSL_read_PrivateKey(FILE *fp, EVP_PKEY **key, int (*cb)())
{
    EVP_PKEY *rc;
    BIO *bioS;
    BIO *bioF;

    /* 1. try PEM (= DER+Base64+headers) */
#if SSL_LIBRARY_VERSION < 0x00904000
    rc = PEM_read_PrivateKey(fp, key, cb);
#else
    rc = PEM_read_PrivateKey(fp, key, cb, NULL);
#endif
    if (rc == NULL) {
        /* 2. try DER+Base64 */
        fseek(fp, 0L, SEEK_SET);
        if ((bioS = BIO_new(BIO_s_fd())) == NULL)
            return NULL;
        BIO_set_fd(bioS, fileno(fp), BIO_NOCLOSE);
        if ((bioF = BIO_new(BIO_f_base64())) == NULL) {
            BIO_free(bioS);
            return NULL;
        }
        bioS = BIO_push(bioF, bioS);
        rc = d2i_PrivateKey_bio(bioS, NULL);
        BIO_free_all(bioS);
        if (rc == NULL) {
            /* 3. try plain DER */
            fseek(fp, 0L, SEEK_SET);
            if ((bioS = BIO_new(BIO_s_fd())) == NULL)
                return NULL;
            BIO_set_fd(bioS, fileno(fp), BIO_NOCLOSE);
            rc = d2i_PrivateKey_bio(bioS, NULL);
            BIO_free(bioS);
        }
    }
    if (rc != NULL && key != NULL) {
        if (*key != NULL)
            EVP_PKEY_free(*key);
        *key = rc;
    }
    return rc;
}

/*  _________________________________________________________________
**
**  Smart shutdown
**  _________________________________________________________________
*/

int SSL_smart_shutdown(SSL *ssl)
{
    int i;
    int rc;

    /*
     * Repeat the calls, because SSL_shutdown internally dispatches through a
     * little state machine. Usually only one or two interation should be
     * needed, so we restrict the total number of restrictions in order to
     * avoid process hangs in case the client played bad with the socket
     * connection and OpenSSL cannot recognize it.
     */
    rc = 0;
    for (i = 0; i < 4 /* max 2x pending + 2x data = 4 */; i++) {
        if ((rc = SSL_shutdown(ssl)))
            break;
    }
    return rc;
}

/*  _________________________________________________________________
**
**  Certificate Revocation List (CRL) Storage
**  _________________________________________________________________
*/

X509_STORE *SSL_X509_STORE_create(char *cpFile, char *cpPath)
{
    X509_STORE *pStore;
    X509_LOOKUP *pLookup;

    if (cpFile == NULL && cpPath == NULL)
        return NULL;
    if ((pStore = X509_STORE_new()) == NULL)
        return NULL;
    if (cpFile != NULL) {
        if ((pLookup = X509_STORE_add_lookup(pStore, X509_LOOKUP_file())) == NULL) {
            X509_STORE_free(pStore);
            return NULL;
        }
        X509_LOOKUP_load_file(pLookup, cpFile, X509_FILETYPE_PEM);
    }
    if (cpPath != NULL) {
        if ((pLookup = X509_STORE_add_lookup(pStore, X509_LOOKUP_hash_dir())) == NULL) {
            X509_STORE_free(pStore);
            return NULL;
        }
        X509_LOOKUP_add_dir(pLookup, cpPath, X509_FILETYPE_PEM);
    }
    return pStore;
}

int SSL_X509_STORE_lookup(X509_STORE *pStore, int nType,
                          X509_NAME *pName, X509_OBJECT *pObj)
{
    X509_STORE_CTX pStoreCtx;
    int rc;

    X509_STORE_CTX_init(&pStoreCtx, pStore, NULL, NULL);
    rc = X509_STORE_get_by_subject(&pStoreCtx, nType, pName, pObj);
    X509_STORE_CTX_cleanup(&pStoreCtx);
    return rc;
}

/*  _________________________________________________________________
**
**  Cipher Suite Spec String Creation
**  _________________________________________________________________
*/

char *SSL_make_ciphersuite(pool *p, SSL *ssl)
{
    STACK_OF(SSL_CIPHER) *sk;
    SSL_CIPHER *c;
    int i;
    int l;
    char *cpCipherSuite;
    char *cp;

    if (ssl == NULL) 
        return "";
    if ((sk = SSL_get_ciphers(ssl)) == NULL)
        return "";
    l = 0;
    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        c = sk_SSL_CIPHER_value(sk, i);
        l += strlen(c->name)+2+1;
    }
    if (l == 0)
        return "";
    cpCipherSuite = (char *)ap_palloc(p, l+1);
    cp = cpCipherSuite;
    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        c = sk_SSL_CIPHER_value(sk, i);
        l = strlen(c->name);
        memcpy(cp, c->name, l);
        cp += l;
        *cp++ = '/';
        *cp++ = (c->valid == 1 ? '1' : '0');
        *cp++ = ':';
    }
    *(cp-1) = NUL;
    return cpCipherSuite;
}

/*  _________________________________________________________________
**
**  Certificate Checks
**  _________________________________________________________________
*/

/* check whether cert contains extended key usage with a SGC tag */
BOOL SSL_X509_isSGC(X509 *cert)
{
    X509_EXTENSION *ext;
    int ext_nid;
    STACK *sk;
    BOOL is_sgc;
    int idx;
    int i;
    
    is_sgc = FALSE;
    idx = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1);
    if (idx >= 0) {
        ext = X509_get_ext(cert, idx);
        if ((sk = (STACK *)X509V3_EXT_d2i(ext)) != NULL) {
            for (i = 0; i < sk_num(sk); i++) {
                ext_nid = OBJ_obj2nid((ASN1_OBJECT *)sk_value(sk, i));
                if (ext_nid == NID_ms_sgc || ext_nid == NID_ns_sgc) {
                    is_sgc = TRUE;
                    break;
                }
            }
        }
    }
    return is_sgc;
}

/* retrieve basic constraints ingredients */
BOOL SSL_X509_getBC(X509 *cert, int *ca, int *pathlen)
{
    X509_EXTENSION *ext;
    BASIC_CONSTRAINTS *bc;
    int idx;
    BIGNUM *bn = NULL;
    char *cp;
    
    if ((idx = X509_get_ext_by_NID(cert, NID_basic_constraints, -1)) < 0)
        return FALSE;
    ext = X509_get_ext(cert, idx);
    if (ext == NULL)
        return FALSE;
    if ((bc = (BASIC_CONSTRAINTS *)X509V3_EXT_d2i(ext)) == NULL)
        return FALSE;
    *ca = bc->ca;
    *pathlen = -1 /* unlimited */;
    if (bc->pathlen != NULL) {
        if ((bn = ASN1_INTEGER_to_BN(bc->pathlen, NULL)) == NULL)
            return FALSE;
        if ((cp = BN_bn2dec(bn)) == NULL)
            return FALSE;
        *pathlen = atoi(cp);
        free(cp);
        BN_free(bn);
    }
    BASIC_CONSTRAINTS_free(bc);
    return TRUE;
}

/* retrieve subject CommonName of certificate */
BOOL SSL_X509_getCN(pool *p, X509 *xs, char **cppCN)
{
    X509_NAME *xsn;
    X509_NAME_ENTRY *xsne;
    int i, nid;

    xsn = X509_get_subject_name(xs);
    for (i = 0; i < sk_X509_NAME_ENTRY_num(xsn->entries); i++) {
        xsne = sk_X509_NAME_ENTRY_value(xsn->entries, i);
        nid = OBJ_obj2nid(xsne->object);
        if (nid == NID_commonName) {
            *cppCN = ap_palloc(p, xsne->value->length+1);
            ap_cpystrn(*cppCN, (char *)xsne->value->data, xsne->value->length+1);
            (*cppCN)[xsne->value->length] = NUL;
#ifdef CHARSET_EBCDIC
            ascii2ebcdic(*cppCN, *cppCN, strlen(*cppCN));
#endif
            return TRUE;
        }
    }
    return FALSE;
}

/*  _________________________________________________________________
**
**  Low-Level CA Certificate Loading
**  _________________________________________________________________
*/

#ifdef SSL_EXPERIMENTAL_PROXY

BOOL SSL_load_CrtAndKeyInfo_file(pool *p, STACK_OF(X509_INFO) *sk, char *filename)
{
    BIO *in;

    if ((in = BIO_new(BIO_s_file())) == NULL)
        return FALSE;
    if (BIO_read_filename(in, filename) <= 0) {
        BIO_free(in);
        return FALSE;
    }
    ERR_clear_error();
#if SSL_LIBRARY_VERSION < 0x00904000
    PEM_X509_INFO_read_bio(in, sk, NULL);
#else
    PEM_X509_INFO_read_bio(in, sk, NULL, NULL);
#endif
    BIO_free(in);
    return TRUE;
}

BOOL SSL_load_CrtAndKeyInfo_path(pool *p, STACK_OF(X509_INFO) *sk, char *pathname)
{
    struct stat st;
    DIR *dir;
    pool *sp;
    struct dirent *nextent;
    char *fullname;
    BOOL ok;

    sp = ap_make_sub_pool(p);
    if ((dir = ap_popendir(sp, pathname)) == NULL) {
        ap_destroy_pool(sp);
        return FALSE;
    }
    ok = FALSE;
    while ((nextent = readdir(dir)) != NULL) {
        fullname = ap_pstrcat(sp, pathname, "/", nextent->d_name, NULL);
        if (stat(fullname, &st) != 0)
            continue;
        if (!S_ISREG(st.st_mode))
            continue;
        if (SSL_load_CrtAndKeyInfo_file(sp, sk, fullname))
            ok = TRUE;
    }
    ap_pclosedir(p, dir);
    ap_destroy_pool(sp);
    return ok;
}              

#endif /* SSL_EXPERIMENTAL_PROXY */

/*  _________________________________________________________________
**
**  Extra Server Certificate Chain Support
**  _________________________________________________________________
*/

/* 
 * Read a file that optionally contains the server certificate in PEM
 * format, possibly followed by a sequence of CA certificates that
 * should be sent to the peer in the SSL Certificate message.
 */
int SSL_CTX_use_certificate_chain(
    SSL_CTX *ctx, char *file, int skipfirst, int (*cb)())
{
    BIO *bio;
    X509 *x509;
    unsigned long err;
    int n;

    if ((bio = BIO_new(BIO_s_file_internal())) == NULL)
        return -1;
    if (BIO_read_filename(bio, file) <= 0) {
        BIO_free(bio);
        return -1;
    }
    /* optionally skip a leading server certificate */
    if (skipfirst) {
#if SSL_LIBRARY_VERSION < 0x00904000
        if ((x509 = PEM_read_bio_X509(bio, NULL, cb)) == NULL) {
#else
        if ((x509 = PEM_read_bio_X509(bio, NULL, cb, NULL)) == NULL) {
#endif
            BIO_free(bio);
            return -1;
        }
        X509_free(x509);
    }
    /* free a perhaps already configured extra chain */
    if (ctx->extra_certs != NULL) {
        sk_X509_pop_free(ctx->extra_certs, X509_free);
        ctx->extra_certs = NULL;
    }
    /* create new extra chain by loading the certs */
    n = 0;
#if SSL_LIBRARY_VERSION < 0x00904000
    while ((x509 = PEM_read_bio_X509(bio, NULL, cb)) != NULL) {
#else
    while ((x509 = PEM_read_bio_X509(bio, NULL, cb, NULL)) != NULL) {
#endif
        if (!SSL_CTX_add_extra_chain_cert(ctx, x509)) { 
            X509_free(x509);
            BIO_free(bio);
            return -1;
        }
        n++;
    }
    /* Make sure that only the error is just an EOF */
    if ((err = ERR_peek_error()) > 0) {
        if (!(   ERR_GET_LIB(err) == ERR_LIB_PEM 
              && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)) {
            BIO_free(bio);
            return -1;
        }
        while (ERR_get_error() > 0) ;
    }
    BIO_free(bio);
    return n;
}

/*  _________________________________________________________________
**
**  Session Stuff
**  _________________________________________________________________
*/

char *SSL_SESSION_id2sz(unsigned char *id, int idlen)
{
    static char str[(SSL_MAX_SSL_SESSION_ID_LENGTH+1)*2];
    char *cp;
    int n;

    cp = str;
    for (n = 0; n < idlen && n < SSL_MAX_SSL_SESSION_ID_LENGTH; n++) {
        ap_snprintf(cp, sizeof(str)-(cp-str), "%02X", id[n]);
        cp += 2;
    }
    *cp = NUL;
    return str;
}

