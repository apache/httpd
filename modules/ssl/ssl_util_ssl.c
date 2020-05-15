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
static int app_data2_idx = -1;

void modssl_init_app_data2_idx(void)
{
    int i;

    if (app_data2_idx > -1) {
        return;
    }

    /* we _do_ need to call this twice */
    for (i = 0; i <= 1; i++) {
        app_data2_idx =
            SSL_get_ex_new_index(0,
                                 "Second Application Data for SSL",
                                 NULL, NULL, NULL);
    }
}

void *modssl_get_app_data2(SSL *ssl)
{
    return (void *)SSL_get_ex_data(ssl, app_data2_idx);
}

void modssl_set_app_data2(SSL *ssl, void *arg)
{
    SSL_set_ex_data(ssl, app_data2_idx, (char *)arg);
    return;
}

/*  _________________________________________________________________
**
**  High-Level Private Key Loading
**  _________________________________________________________________
*/

EVP_PKEY *modssl_read_privatekey(const char *filename, pem_password_cb *cb, void *s)
{
    EVP_PKEY *rc;
    BIO *bioS;
    BIO *bioF;

    /* 1. try PEM (= DER+Base64+headers) */
    if ((bioS=BIO_new_file(filename, "r")) == NULL)
        return NULL;
    rc = PEM_read_bio_PrivateKey(bioS, NULL, cb, s);
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
    return rc;
}

/*  _________________________________________________________________
**
**  Smart shutdown
**  _________________________________________________________________
*/

int modssl_smart_shutdown(SSL *ssl)
{
    int i;
    int rc;
    int flush;

    /*
     * Repeat the calls, because SSL_shutdown internally dispatches through a
     * little state machine. Usually only one or two iterations should be
     * needed, so we restrict the total number of restrictions in order to
     * avoid process hangs in case the client played bad with the socket
     * connection and OpenSSL cannot recognize it.
     */
    rc = 0;
    flush = !(SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN);
    for (i = 0; i < 4 /* max 2x pending + 2x data = 4 */; i++) {
        rc = SSL_shutdown(ssl);
        if (rc >= 0 && flush && (SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN)) {
            /* Once the close notify is sent through the output filters,
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
BOOL modssl_X509_getBC(X509 *cert, int *ca, int *pathlen)
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

char *modssl_bio_free_read(apr_pool_t *p, BIO *bio)
{
    int len = BIO_pending(bio);
    char *result = NULL;

    if (len > 0) {
        result = apr_palloc(p, len+1);
        len = BIO_read(bio, result, len);
        result[len] = NUL;
    }
    BIO_free(bio);
    return result;
}

/* Convert ASN.1 string to a pool-allocated char * string, escaping
 * control characters.  If raw is zero, convert to UTF-8, otherwise
 * unchanged from the character set. */
static char *asn1_string_convert(apr_pool_t *p, ASN1_STRING *asn1str, int raw)
{
    BIO *bio;
    int flags = ASN1_STRFLGS_ESC_CTRL;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;

    if (!raw) flags |= ASN1_STRFLGS_UTF8_CONVERT;
    
    ASN1_STRING_print_ex(bio, asn1str, flags);

    return modssl_bio_free_read(p, bio);
}

#define asn1_string_to_utf8(p, a) asn1_string_convert(p, a, 0)

/* convert a NAME_ENTRY to UTF8 string */
char *modssl_X509_NAME_ENTRY_to_string(apr_pool_t *p, X509_NAME_ENTRY *xsne,
                                       int raw)
{
    char *result = asn1_string_convert(p, X509_NAME_ENTRY_get_data(xsne), raw);
    ap_xlate_proto_from_ascii(result, len);
    return result;
}

/*
 * convert an X509_NAME to an RFC 2253 formatted string, optionally truncated
 * to maxlen characters (specify a maxlen of 0 for no length limit)
 */
char *modssl_X509_NAME_to_string(apr_pool_t *p, X509_NAME *dn, int maxlen)
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

static void parse_otherName_value(apr_pool_t *p, ASN1_TYPE *value,
                                  const char *onf, apr_array_header_t **entries)
{
    const char *str;
    int nid = onf ? OBJ_txt2nid(onf) : NID_undef;

    if (!value || (nid == NID_undef) || !*entries)
       return;

    /* 
     * Currently supported otherName forms (values for "onf"):
     * "msUPN" (1.3.6.1.4.1.311.20.2.3): Microsoft User Principal Name
     * "id-on-dnsSRV" (1.3.6.1.5.5.7.8.7): SRVName, as specified in RFC 4985
     */
    if ((nid == NID_ms_upn) && (value->type == V_ASN1_UTF8STRING) &&
        (str = asn1_string_to_utf8(p, value->value.utf8string))) {
        APR_ARRAY_PUSH(*entries, const char *) = str;
    } else if (strEQ(onf, "id-on-dnsSRV") &&
               (value->type == V_ASN1_IA5STRING) &&
               (str = asn1_string_to_utf8(p, value->value.ia5string))) {
        APR_ARRAY_PUSH(*entries, const char *) = str;
    }
}

/* 
 * Return an array of subjectAltName entries of type "type". If idx is -1,
 * return all entries of the given type, otherwise return an array consisting
 * of the n-th occurrence of that type only. Currently supported types:
 * GEN_EMAIL (rfc822Name)
 * GEN_DNS (dNSName)
 * GEN_OTHERNAME (requires the otherName form ["onf"] argument to be supplied,
 *                see parse_otherName_value for the currently supported forms)
 */
BOOL modssl_X509_getSAN(apr_pool_t *p, X509 *x509, int type, const char *onf,
                        int idx, apr_array_header_t **entries)
{
    STACK_OF(GENERAL_NAME) *names;
    int nid = onf ? OBJ_txt2nid(onf) : NID_undef;

    if (!x509 || (type < GEN_OTHERNAME) ||
        ((type == GEN_OTHERNAME) && (nid == NID_undef)) ||
        (type > GEN_RID) || (idx < -1) ||
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

            if (name->type != type)
                continue;

            switch (type) {
            case GEN_EMAIL:
            case GEN_DNS:
                if (((idx == -1) || (n == idx)) &&
                    (utf8str = asn1_string_to_utf8(p, name->d.ia5))) {
                    APR_ARRAY_PUSH(*entries, const char *) = utf8str;
                }
                n++;
                break;
            case GEN_OTHERNAME:
                if (OBJ_obj2nid(name->d.otherName->type_id) == nid) {
                    if (((idx == -1) || (n == idx))) {
                        parse_otherName_value(p, name->d.otherName->value,
                                              onf, entries);
                    }
                    n++;
                }
                break;
            default:
                /*
                 * Not implemented right now:
                 * GEN_X400 (x400Address)
                 * GEN_DIRNAME (directoryName)
                 * GEN_EDIPARTY (ediPartyName)
                 * GEN_URI (uniformResourceIdentifier)
                 * GEN_IPADD (iPAddress)
                 * GEN_RID (registeredID)
                 */
                break;
            }

            if ((idx != -1) && (n > idx))
               break;
        }

        sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    }

    return apr_is_empty_array(*entries) ? FALSE : TRUE;
}

/* return an array of (RFC 6125 coined) DNS-IDs and CN-IDs in a certificate */
static BOOL getIDs(apr_pool_t *p, X509 *x509, apr_array_header_t **ids)
{
    X509_NAME *subj;
    int i = -1;

    /* First, the DNS-IDs (dNSName entries in the subjectAltName extension) */
    if (!x509 ||
        (modssl_X509_getSAN(p, x509, GEN_DNS, NULL, -1, ids) == FALSE && !*ids)) {
        *ids = NULL;
        return FALSE;
    }

    /* Second, the CN-IDs (commonName attributes in the subject DN) */
    subj = X509_get_subject_name(x509);
    while ((i = X509_NAME_get_index_by_NID(subj, NID_commonName, i)) != -1) {
        APR_ARRAY_PUSH(*ids, const char *) = 
            modssl_X509_NAME_ENTRY_to_string(p, X509_NAME_get_entry(subj, i), 0);
    }

    return apr_is_empty_array(*ids) ? FALSE : TRUE;
}

/* 
 * Check if a certificate matches for a particular name, by iterating over its
 * DNS-IDs and CN-IDs (RFC 6125), optionally with basic wildcard matching.
 * If server_rec is non-NULL, some (debug/trace) logging is enabled.
 */
BOOL modssl_X509_match_name(apr_pool_t *p, X509 *x509, const char *name,
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

    if (getIDs(p, x509, &ids)) {
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
                             "[%s] modssl_X509_match_name: expecting name '%s', "
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
**  Custom (EC)DH parameter support
**  _________________________________________________________________
*/

#if OPENSSL_VERSION_NUMBER < 0x30000000L
DH *modssl_dh_from_file(const char *file)
{
    DH *dh;
    BIO *bio;

    if ((bio = BIO_new_file(file, "r")) == NULL)
        return NULL;
    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return dh;
}
#else
EVP_PKEY *modssl_dh_pkey_from_file(const char *file)
{
    EVP_PKEY *pkey;
    BIO *bio;

    if ((bio = BIO_new_file(file, "r")) == NULL)
        return NULL;
    pkey = PEM_read_bio_Parameters(bio, NULL);
    BIO_free(bio);

    return pkey;
}
#endif

#ifdef HAVE_ECC
EC_GROUP *modssl_ec_group_from_file(const char *file)
{
    EC_GROUP *group;
    BIO *bio;

    if ((bio = BIO_new_file(file, "r")) == NULL)
        return NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    group = PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL);
#else
    group = PEM_ASN1_read_bio((void *)d2i_ECPKParameters,
                              PEM_STRING_ECPARAMETERS, bio,
                              NULL, NULL, NULL);
#endif
    BIO_free(bio);

    return group;
}
#endif

/*  _________________________________________________________________
**
**  Session Stuff
**  _________________________________________________________________
*/

char *modssl_SSL_SESSION_id2sz(IDCONST unsigned char *id, int idlen,
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

/*  _________________________________________________________________
**
**  Certificate/Key Stuff
**  _________________________________________________________________
*/

apr_status_t modssl_read_cert(apr_pool_t *p, 
                              const char *cert_pem, const char *key_pem,
                              pem_password_cb *cb, void *ud,
                              X509 **pcert, EVP_PKEY **pkey)
{
    BIO *in;
    X509 *x = NULL;
    EVP_PKEY *key = NULL;
    apr_status_t rv = APR_SUCCESS;

    in = BIO_new_mem_buf(cert_pem, -1);
    if (in == NULL) {
        rv = APR_ENOMEM;
        goto cleanup;
    }
    
    x = PEM_read_bio_X509(in, NULL, cb, ud);
    if (x == NULL) {
        rv = APR_ENOENT;
        goto cleanup;
    }
    
    BIO_free(in);
    in = BIO_new_mem_buf(key_pem? key_pem : cert_pem, -1);
    if (in == NULL) {
        rv = APR_ENOMEM;
        goto cleanup;
    }
    key = PEM_read_bio_PrivateKey(in, NULL, cb, ud);
    if (key == NULL) {
        rv = APR_ENOENT;
        goto cleanup;
    }
    
cleanup:
    if (rv == APR_SUCCESS) {
        *pcert = x;
        *pkey = key;
    }
    else {
        *pcert = NULL;
        *pkey = NULL;
        if (x) X509_free(x);
        if (key) EVP_PKEY_free(key);
    }
    if (in != NULL) BIO_free(in);
    return rv;
}

apr_status_t modssl_cert_get_pem(apr_pool_t *p,
                                 X509 *cert1, X509 *cert2,
                                 const char **ppem)
{
    apr_status_t rv = APR_ENOMEM;
    BIO *bio;

    if ((bio = BIO_new(BIO_s_mem())) == NULL) goto cleanup;
    if (PEM_write_bio_X509(bio, cert1) != 1) goto cleanup;
    if (cert2 && PEM_write_bio_X509(bio, cert2) != 1) goto cleanup;
    rv = APR_SUCCESS;

cleanup:
    if (rv != APR_SUCCESS) {
        *ppem = NULL;
        if (bio) BIO_free(bio);
    }
    else {
        *ppem = modssl_bio_free_read(p, bio);
    }
    return rv;
}

void modssl_set_reneg_state(SSLConnRec *sslconn, modssl_reneg_state state)
{
#ifdef SSL_OP_NO_RENEGOTIATION
    switch (state) {
    case RENEG_ALLOW:
        SSL_clear_options(sslconn->ssl, SSL_OP_NO_RENEGOTIATION);
        break;
    default:
        SSL_set_options(sslconn->ssl, SSL_OP_NO_RENEGOTIATION);
        break;
    }
#else
    sslconn->reneg_state = state;
#endif
}
