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
 *  ssl_util_ssl.c
 *  Additional Utility Functions for OpenSSL
 */

#include "ssl_private.h"

/*  _________________________________________________________________
**
**  Additional High-Level Functions for OpenSSL
**  _________________________________________________________________
*/

/* we initialize this index at startup time
 * and never write to it at request time,
 * so this static is thread safe.
 * also note that OpenSSL increments at static variable when
 * SSL_get_ex_new_index() is called, so we _must_ do this at startup.
 */
static int SSL_app_data2_idx = -1;

void SSL_init_app_data2_idx(void)
{
    int i;

    if (SSL_app_data2_idx > -1) {
        return;
    }

    /* we _do_ need to call this twice */
    for (i=0; i<=1; i++) {
        SSL_app_data2_idx =
            SSL_get_ex_new_index(0,
                                 "Second Application Data for SSL",
                                 NULL, NULL, NULL);
    }
}

void *SSL_get_app_data2(SSL *ssl)
{
    return (void *)SSL_get_ex_data(ssl, SSL_app_data2_idx);
}

void SSL_set_app_data2(SSL *ssl, void *arg)
{
    SSL_set_ex_data(ssl, SSL_app_data2_idx, (char *)arg);
    return;
}

/*  _________________________________________________________________
**
**  High-Level Private Key Loading
**  _________________________________________________________________
*/

EVP_PKEY *SSL_read_PrivateKey(const char* filename, EVP_PKEY **key, pem_password_cb *cb, void *s)
{
    EVP_PKEY *rc;
    BIO *bioS;
    BIO *bioF;

    /* 1. try PEM (= DER+Base64+headers) */
    if ((bioS=BIO_new_file(filename, "r")) == NULL)
        return NULL;
    rc = PEM_read_bio_PrivateKey(bioS, key, cb, s);
    BIO_free(bioS);

    if (rc == NULL) {
        /* 2. try DER+Base64 */
        if ((bioS = BIO_new_file(filename, "r")) == NULL)
            return NULL;

        if ((bioF = BIO_new(BIO_f_base64())) == NULL) {
            BIO_free(bioS);
            return NULL;
        }
        bioS = BIO_push(bioF, bioS);
        rc = d2i_PrivateKey_bio(bioS, NULL);
        BIO_free_all(bioS);

        if (rc == NULL) {
            /* 3. try plain DER */
            if ((bioS = BIO_new_file(filename, "r")) == NULL)
                return NULL;
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
    int flush;

    /*
     * Repeat the calls, because SSL_shutdown internally dispatches through a
     * little state machine. Usually only one or two interation should be
     * needed, so we restrict the total number of restrictions in order to
     * avoid process hangs in case the client played bad with the socket
     * connection and OpenSSL cannot recognize it.
     */
    rc = 0;
    flush = !(SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN);
    for (i = 0; i < 4 /* max 2x pending + 2x data = 4 */; i++) {
        rc = SSL_shutdown(ssl);
        if (rc >= 0 && flush && (SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN)) {
            /* Once the close notity is sent through the output filters,
             * ensure it is flushed through the socket.
             */
            if (BIO_flush(SSL_get_wbio(ssl)) <= 0) {
                rc = -1;
                break;
            }
            flush = 0;
        }
        if (rc != 0)
            break;
    }
    return rc;
}

/*  _________________________________________________________________
**
**  Certificate Checks
**  _________________________________________________________________
*/

/* retrieve basic constraints ingredients */
BOOL SSL_X509_getBC(X509 *cert, int *ca, int *pathlen)
{
    BASIC_CONSTRAINTS *bc;
    BIGNUM *bn = NULL;
    char *cp;

    bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    if (bc == NULL)
        return FALSE;
    *ca = bc->ca;
    *pathlen = -1 /* unlimited */;
    if (bc->pathlen != NULL) {
        if ((bn = ASN1_INTEGER_to_BN(bc->pathlen, NULL)) == NULL) {
            BASIC_CONSTRAINTS_free(bc);
            return FALSE;
        }
        if ((cp = BN_bn2dec(bn)) == NULL) {
            BN_free(bn);
            BASIC_CONSTRAINTS_free(bc);
            return FALSE;
        }
        *pathlen = atoi(cp);
        OPENSSL_free(cp);
        BN_free(bn);
    }
    BASIC_CONSTRAINTS_free(bc);
    return TRUE;
}

/* convert an ASN.1 string to a UTF-8 string (escaping control characters) */
char *SSL_ASN1_STRING_to_utf8(apr_pool_t *p, ASN1_STRING *asn1str)
{
    char *result = NULL;
    BIO *bio;
    int len;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;

    ASN1_STRING_print_ex(bio, asn1str, ASN1_STRFLGS_ESC_CTRL|
                                       ASN1_STRFLGS_UTF8_CONVERT);
    len = BIO_pending(bio);
    if (len > 0) {
        result = apr_palloc(p, len+1);
        len = BIO_read(bio, result, len);
        result[len] = NUL;
    }
    BIO_free(bio);
    return result;
}

/* convert a NAME_ENTRY to UTF8 string */
char *SSL_X509_NAME_ENTRY_to_string(apr_pool_t *p, X509_NAME_ENTRY *xsne)
{
    char *result = SSL_ASN1_STRING_to_utf8(p, X509_NAME_ENTRY_get_data(xsne));
    ap_xlate_proto_from_ascii(result, len);
    return result;
}

/*
 * convert an X509_NAME to an RFC 2253 formatted string, optionally truncated
 * to maxlen characters (specify a maxlen of 0 for no length limit)
 */
char *SSL_X509_NAME_to_string(apr_pool_t *p, X509_NAME *dn, int maxlen)
{
    char *result = NULL;
    BIO *bio;
    int len;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    X509_NAME_print_ex(bio, dn, 0, XN_FLAG_RFC2253);
    len = BIO_pending(bio);
    if (len > 0) {
        result = apr_palloc(p, (maxlen > 0) ? maxlen+1 : len+1);
        if (maxlen > 0 && maxlen < len) {
            len = BIO_read(bio, result, maxlen);
            if (maxlen > 2) {
                /* insert trailing ellipsis if there's enough space */
                apr_snprintf(result + maxlen - 3, 4, "...");
            }
        } else {
            len = BIO_read(bio, result, len);
        }
        result[len] = NUL;
    }
    BIO_free(bio);

    return result;
}

/* 
 * Return an array of subjectAltName entries of type "type". If idx is -1,
 * return all entries of the given type, otherwise return an array consisting
 * of the n-th occurrence of that type only. Currently supported types:
 * GEN_EMAIL (rfc822Name)
 * GEN_DNS (dNSName)
 */
BOOL SSL_X509_getSAN(apr_pool_t *p, X509 *x509, int type, int idx,
                     apr_array_header_t **entries)
{
    STACK_OF(GENERAL_NAME) *names;

    if (!x509 || (type < GEN_OTHERNAME) || (type > GEN_RID) || (idx < -1) ||
        !(*entries = apr_array_make(p, 0, sizeof(char *)))) {
        *entries = NULL;
        return FALSE;
    }

    if ((names = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL))) {
        int i, n = 0;
        GENERAL_NAME *name;
        const char *utf8str;

        for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
            name = sk_GENERAL_NAME_value(names, i);
            if (name->type == type) {
                if ((idx == -1) || (n == idx)) {
                    switch (type) {
                    case GEN_EMAIL:
                    case GEN_DNS:
                        utf8str = SSL_ASN1_STRING_to_utf8(p, name->d.ia5);
                        if (utf8str) {
                            APR_ARRAY_PUSH(*entries, const char *) = utf8str;
                        }
                        break;
                    default:
                        /*
                         * Not implemented right now:
                         * GEN_OTHERNAME (otherName)
                         * GEN_X400 (x400Address)
                         * GEN_DIRNAME (directoryName)
                         * GEN_EDIPARTY (ediPartyName)
                         * GEN_URI (uniformResourceIdentifier)
                         * GEN_IPADD (iPAddress)
                         * GEN_RID (registeredID)
                         */
                        break;
                    }
                }
                if ((idx != -1) && (n++ > idx))
                   break;
            }
        }

        sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    }

    return apr_is_empty_array(*entries) ? FALSE : TRUE;
}

/* return an array of (RFC 6125 coined) DNS-IDs and CN-IDs in a certificate */
BOOL SSL_X509_getIDs(apr_pool_t *p, X509 *x509, apr_array_header_t **ids)
{
    X509_NAME *subj;
    int i = -1;

    /* First, the DNS-IDs (dNSName entries in the subjectAltName extension) */
    if (!x509 ||
        (SSL_X509_getSAN(p, x509, GEN_DNS, -1, ids) == FALSE && !*ids)) {
        *ids = NULL;
        return FALSE;
    }

    /* Second, the CN-IDs (commonName attributes in the subject DN) */
    subj = X509_get_subject_name(x509);
    while ((i = X509_NAME_get_index_by_NID(subj, NID_commonName, i)) != -1) {
        APR_ARRAY_PUSH(*ids, const char *) = 
            SSL_X509_NAME_ENTRY_to_string(p, X509_NAME_get_entry(subj, i));
    }

    return apr_is_empty_array(*ids) ? FALSE : TRUE;
}

/* 
 * Check if a certificate matches for a particular name, by iterating over its
 * DNS-IDs and CN-IDs (RFC 6125), optionally with basic wildcard matching.
 * If server_rec is non-NULL, some (debug/trace) logging is enabled.
 */
BOOL SSL_X509_match_name(apr_pool_t *p, X509 *x509, const char *name,
                         BOOL allow_wildcard, server_rec *s)
{
    BOOL matched = FALSE;
    apr_array_header_t *ids;

    /*
     * At some day in the future, this might be replaced with X509_check_host()
     * (available in OpenSSL 1.0.2 and later), but two points should be noted:
     * 1) wildcard matching in X509_check_host() might yield different
     *    results (by default, it supports a broader set of patterns, e.g.
     *    wildcards in non-initial positions);
     * 2) we lose the option of logging each DNS- and CN-ID (until a match
     *    is found).
     */

    if (SSL_X509_getIDs(p, x509, &ids)) {
        const char *cp;
        int i;
        char **id = (char **)ids->elts;
        BOOL is_wildcard;

        for (i = 0; i < ids->nelts; i++) {
            if (!id[i])
                continue;

            /*
             * Determine if it is a wildcard ID - we're restrictive
             * in the sense that we require the wildcard character to be
             * THE left-most label (i.e., the ID must start with "*.")
             */
            is_wildcard = (*id[i] == '*' && *(id[i]+1) == '.') ? TRUE : FALSE;

            /*
             * If the ID includes a wildcard character (and the caller is
             * allowing wildcards), check if it matches for the left-most
             * DNS label - i.e., the wildcard character is not allowed
             * to match a dot. Otherwise, try a simple string compare.
             */
            if ((allow_wildcard == TRUE && is_wildcard == TRUE &&
                 (cp = ap_strchr_c(name, '.')) && !strcasecmp(id[i]+1, cp)) ||
                !strcasecmp(id[i], name)) {
                matched = TRUE;
            }

            if (s) {
                ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
                             "[%s] SSL_X509_match_name: expecting name '%s', "
                             "%smatched by ID '%s'",
                             (mySrvConfig(s))->vhost_id, name,
                             matched == TRUE ? "" : "NOT ", id[i]);
            }

            if (matched == TRUE) {
                break;
            }
        }

    }

    if (s) {
        ssl_log_xerror(SSLLOG_MARK, APLOG_DEBUG, 0, p, s, x509,
                       APLOGNO(02412) "[%s] Cert %s for name '%s'",
                       (mySrvConfig(s))->vhost_id,
                       matched == TRUE ? "matches" : "does not match",
                       name);
    }

    return matched;
}

/*  _________________________________________________________________
**
**  Low-Level CA Certificate Loading
**  _________________________________________________________________
*/

BOOL SSL_X509_INFO_load_file(apr_pool_t *ptemp,
                             STACK_OF(X509_INFO) *sk,
                             const char *filename)
{
    BIO *in;

    if (!(in = BIO_new(BIO_s_file()))) {
        return FALSE;
    }

    if (BIO_read_filename(in, filename) <= 0) {
        BIO_free(in);
        return FALSE;
    }

    ERR_clear_error();

    PEM_X509_INFO_read_bio(in, sk, NULL, NULL);

    BIO_free(in);

    return TRUE;
}

BOOL SSL_X509_INFO_load_path(apr_pool_t *ptemp,
                             STACK_OF(X509_INFO) *sk,
                             const char *pathname)
{
    /* XXX: this dir read code is exactly the same as that in
     * ssl_engine_init.c, only the call to handle the fullname is different,
     * should fold the duplication.
     */
    apr_dir_t *dir;
    apr_finfo_t dirent;
    apr_int32_t finfo_flags = APR_FINFO_TYPE|APR_FINFO_NAME;
    const char *fullname;
    BOOL ok = FALSE;

    if (apr_dir_open(&dir, pathname, ptemp) != APR_SUCCESS) {
        return FALSE;
    }

    while ((apr_dir_read(&dirent, finfo_flags, dir)) == APR_SUCCESS) {
        if (dirent.filetype == APR_DIR) {
            continue; /* don't try to load directories */
        }

        fullname = apr_pstrcat(ptemp,
                               pathname, "/", dirent.name,
                               NULL);

        if (SSL_X509_INFO_load_file(ptemp, sk, fullname)) {
            ok = TRUE;
        }
    }

    apr_dir_close(dir);

    return ok;
}

/*  _________________________________________________________________
**
**  Custom (EC)DH parameter support
**  _________________________________________________________________
*/

DH *ssl_dh_GetParamFromFile(const char *file)
{
    DH *dh = NULL;
    BIO *bio;

    if ((bio = BIO_new_file(file, "r")) == NULL)
        return NULL;
    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return (dh);
}

#ifdef HAVE_ECC
EC_GROUP *ssl_ec_GetParamFromFile(const char *file)
{
    EC_GROUP *group = NULL;
    BIO *bio;

    if ((bio = BIO_new_file(file, "r")) == NULL)
        return NULL;
    group = PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return (group);
}
#endif

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
    SSL_CTX *ctx, char *file, int skipfirst, pem_password_cb *cb)
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
        if ((x509 = PEM_read_bio_X509(bio, NULL, cb, NULL)) == NULL) {
            BIO_free(bio);
            return -1;
        }
        X509_free(x509);
    }
    /* free a perhaps already configured extra chain */
#ifdef OPENSSL_NO_SSL_INTERN
    SSL_CTX_clear_extra_chain_certs(ctx);
#else
    if (ctx->extra_certs != NULL) {
        sk_X509_pop_free((STACK_OF(X509) *)ctx->extra_certs, X509_free);
        ctx->extra_certs = NULL;
    }
#endif
    /* create new extra chain by loading the certs */
    n = 0;
    while ((x509 = PEM_read_bio_X509(bio, NULL, cb, NULL)) != NULL) {
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

char *SSL_SESSION_id2sz(unsigned char *id, int idlen,
                        char *str, int strsize)
{
    if (idlen > SSL_MAX_SSL_SESSION_ID_LENGTH)
        idlen = SSL_MAX_SSL_SESSION_ID_LENGTH;
        
    /* We must ensure not to process more than what would fit in the
     * destination buffer, including terminating NULL */
    if (idlen > (strsize-1) / 2)
        idlen = (strsize-1) / 2;

    ap_bin2hex(id, idlen, str);

    return str;
}
