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
 *  ssl_engine_vars.c
 *  Variable Lookup Facility
 */
                             /* ``Those of you who think they
                                  know everything are very annoying
                                  to those of us who do.''
                                                  -- Unknown       */
#include "ssl_private.h"
#include "mod_ssl.h"

#include "apr_time.h"

/*  _________________________________________________________________
**
**  Variable Lookup
**  _________________________________________________________________
*/

static char *ssl_var_lookup_ssl(apr_pool_t *p, conn_rec *c, char *var);
static char *ssl_var_lookup_ssl_cert(apr_pool_t *p, X509 *xs, char *var);
static char *ssl_var_lookup_ssl_cert_dn(apr_pool_t *p, X509_NAME *xsname, char *var);
static char *ssl_var_lookup_ssl_cert_valid(apr_pool_t *p, ASN1_UTCTIME *tm);
static char *ssl_var_lookup_ssl_cert_remain(apr_pool_t *p, ASN1_UTCTIME *tm);
static char *ssl_var_lookup_ssl_cert_serial(apr_pool_t *p, X509 *xs);
static char *ssl_var_lookup_ssl_cert_chain(apr_pool_t *p, STACK_OF(X509) *sk, char *var);
static char *ssl_var_lookup_ssl_cert_PEM(apr_pool_t *p, X509 *xs);
static char *ssl_var_lookup_ssl_cert_verify(apr_pool_t *p, conn_rec *c);
static char *ssl_var_lookup_ssl_cipher(apr_pool_t *p, conn_rec *c, char *var);
static void  ssl_var_lookup_ssl_cipher_bits(SSL *ssl, int *usekeysize, int *algkeysize);
static char *ssl_var_lookup_ssl_version(apr_pool_t *p, char *var);
static char *ssl_var_lookup_ssl_compress_meth(SSL *ssl);

static int ssl_is_https(conn_rec *c)
{
    SSLConnRec *sslconn = myConnConfig(c);
    return sslconn && sslconn->ssl;
}

static const char var_interface[] = "mod_ssl/" MOD_SSL_VERSION;
static char var_library_interface[] = SSL_LIBRARY_TEXT;
static char *var_library = NULL;

void ssl_var_register(apr_pool_t *p)
{
    char *cp, *cp2;

    APR_REGISTER_OPTIONAL_FN(ssl_is_https);
    APR_REGISTER_OPTIONAL_FN(ssl_var_lookup);
    APR_REGISTER_OPTIONAL_FN(ssl_ext_lookup);

    /* Perform once-per-process library version determination: */
    var_library = apr_pstrdup(p, SSL_LIBRARY_DYNTEXT);

    if ((cp = strchr(var_library, ' ')) != NULL) {
        *cp = '/';
        if ((cp2 = strchr(cp, ' ')) != NULL)
            *cp2 = NUL;
    }

    if ((cp = strchr(var_library_interface, ' ')) != NULL) {
        *cp = '/';
        if ((cp2 = strchr(cp, ' ')) != NULL)
            *cp2 = NUL;
    }
}

/* This function must remain safe to use for a non-SSL connection. */
char *ssl_var_lookup(apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, char *var)
{
    SSLModConfigRec *mc = myModConfig(s);
    const char *result;
    BOOL resdup;
    apr_time_exp_t tm;

    result = NULL;
    resdup = TRUE;

    /*
     * When no pool is given try to find one
     */
    if (p == NULL) {
        if (r != NULL)
            p = r->pool;
        else if (c != NULL)
            p = c->pool;
        else
            p = mc->pPool;
    }

    /*
     * Request dependent stuff
     */
    if (r != NULL) {
        switch (var[0]) {
        case 'H':
        case 'h':
            if (strcEQ(var, "HTTP_USER_AGENT"))
                result = apr_table_get(r->headers_in, "User-Agent");
            else if (strcEQ(var, "HTTP_REFERER"))
                result = apr_table_get(r->headers_in, "Referer");
            else if (strcEQ(var, "HTTP_COOKIE"))
                result = apr_table_get(r->headers_in, "Cookie");
            else if (strcEQ(var, "HTTP_FORWARDED"))
                result = apr_table_get(r->headers_in, "Forwarded");
            else if (strcEQ(var, "HTTP_HOST"))
                result = apr_table_get(r->headers_in, "Host");
            else if (strcEQ(var, "HTTP_PROXY_CONNECTION"))
                result = apr_table_get(r->headers_in, "Proxy-Connection");
            else if (strcEQ(var, "HTTP_ACCEPT"))
                result = apr_table_get(r->headers_in, "Accept");
            else if (strlen(var) > 5 && strcEQn(var, "HTTP:", 5))
                /* all other headers from which we are still not know about */
                result = apr_table_get(r->headers_in, var+5);
            break;

        case 'R':
        case 'r':
            if (strcEQ(var, "REQUEST_METHOD"))
                result = r->method;
            else if (strcEQ(var, "REQUEST_SCHEME"))
                result = ap_http_scheme(r);
            else if (strcEQ(var, "REQUEST_URI"))
                result = r->uri;
            else if (strcEQ(var, "REQUEST_FILENAME"))
                result = r->filename;
            else if (strcEQ(var, "REMOTE_HOST"))
                result = ap_get_remote_host(r->connection, r->per_dir_config,
                                            REMOTE_NAME, NULL);
            else if (strcEQ(var, "REMOTE_IDENT"))
                result = ap_get_remote_logname(r);
            else if (strcEQ(var, "REMOTE_USER"))
                result = r->user;
            break;

        case 'S':
        case 's':
            if (strcEQn(var, "SSL", 3)) break; /* shortcut common case */

            if (strcEQ(var, "SERVER_ADMIN"))
                result = r->server->server_admin;
            else if (strcEQ(var, "SERVER_NAME"))
                result = ap_get_server_name(r);
            else if (strcEQ(var, "SERVER_PORT"))
                result = apr_psprintf(p, "%u", ap_get_server_port(r));
            else if (strcEQ(var, "SERVER_PROTOCOL"))
                result = r->protocol;
            else if (strcEQ(var, "SCRIPT_FILENAME"))
                result = r->filename;
            break;

        default:
            if (strcEQ(var, "PATH_INFO"))
                result = r->path_info;
            else if (strcEQ(var, "QUERY_STRING"))
                result = r->args;
            else if (strcEQ(var, "IS_SUBREQ"))
                result = (r->main != NULL ? "true" : "false");
            else if (strcEQ(var, "DOCUMENT_ROOT"))
                result = ap_document_root(r);
            else if (strcEQ(var, "AUTH_TYPE"))
                result = r->ap_auth_type;
            else if (strcEQ(var, "THE_REQUEST"))
                result = r->the_request;
            break;
        }
    }

    /*
     * Connection stuff
     */
    if (result == NULL && c != NULL) {
        SSLConnRec *sslconn = myConnConfig(c);
        if (strlen(var) > 4 && strcEQn(var, "SSL_", 4)
            && sslconn && sslconn->ssl)
            result = ssl_var_lookup_ssl(p, c, var+4);
        else if (strcEQ(var, "REMOTE_ADDR"))
            result = c->remote_ip;
        else if (strcEQ(var, "HTTPS")) {
            if (sslconn && sslconn->ssl)
                result = "on";
            else
                result = "off";
        }
    }

    /*
     * Totally independent stuff
     */
    if (result == NULL) {
        if (strlen(var) > 12 && strcEQn(var, "SSL_VERSION_", 12))
            result = ssl_var_lookup_ssl_version(p, var+12);
        else if (strcEQ(var, "SERVER_SOFTWARE"))
            result = ap_get_server_banner();
        else if (strcEQ(var, "API_VERSION")) {
            result = apr_itoa(p, MODULE_MAGIC_NUMBER);
            resdup = FALSE;
        }
        else if (strcEQ(var, "TIME_YEAR")) {
            apr_time_exp_lt(&tm, apr_time_now());
            result = apr_psprintf(p, "%02d%02d",
                                 (tm.tm_year / 100) + 19, tm.tm_year % 100);
            resdup = FALSE;
        }
#define MKTIMESTR(format, tmfield) \
            apr_time_exp_lt(&tm, apr_time_now()); \
            result = apr_psprintf(p, format, tm.tmfield); \
            resdup = FALSE;
        else if (strcEQ(var, "TIME_MON")) {
            MKTIMESTR("%02d", tm_mon+1)
        }
        else if (strcEQ(var, "TIME_DAY")) {
            MKTIMESTR("%02d", tm_mday)
        }
        else if (strcEQ(var, "TIME_HOUR")) {
            MKTIMESTR("%02d", tm_hour)
        }
        else if (strcEQ(var, "TIME_MIN")) {
            MKTIMESTR("%02d", tm_min)
        }
        else if (strcEQ(var, "TIME_SEC")) {
            MKTIMESTR("%02d", tm_sec)
        }
        else if (strcEQ(var, "TIME_WDAY")) {
            MKTIMESTR("%d", tm_wday)
        }
        else if (strcEQ(var, "TIME")) {
            apr_time_exp_lt(&tm, apr_time_now());
            result = apr_psprintf(p,
                        "%02d%02d%02d%02d%02d%02d%02d", (tm.tm_year / 100) + 19,
                        (tm.tm_year % 100), tm.tm_mon+1, tm.tm_mday,
                        tm.tm_hour, tm.tm_min, tm.tm_sec);
            resdup = FALSE;
        }
        /* all other env-variables from the parent Apache process */
        else if (strlen(var) > 4 && strcEQn(var, "ENV:", 4)) {
            result = apr_table_get(r->notes, var+4);
            if (result == NULL)
                result = apr_table_get(r->subprocess_env, var+4);
            if (result == NULL)
                result = getenv(var+4);
        }
    }

    if (result != NULL && resdup)
        result = apr_pstrdup(p, result);
    if (result == NULL)
        result = "";
    return (char *)result;
}

static char *ssl_var_lookup_ssl(apr_pool_t *p, conn_rec *c, char *var)
{
    SSLConnRec *sslconn = myConnConfig(c);
    char *result;
    X509 *xs;
    STACK_OF(X509) *sk;
    SSL *ssl;

    result = NULL;

    ssl = sslconn->ssl;
    if (strlen(var) > 8 && strcEQn(var, "VERSION_", 8)) {
        result = ssl_var_lookup_ssl_version(p, var+8);
    }
    else if (ssl != NULL && strcEQ(var, "PROTOCOL")) {
        result = (char *)SSL_get_version(ssl);
    }
    else if (ssl != NULL && strcEQ(var, "SESSION_ID")) {
        char buf[SSL_SESSION_ID_STRING_LEN];
        SSL_SESSION *pSession = SSL_get_session(ssl);
        if (pSession) {
            result = apr_pstrdup(p, SSL_SESSION_id2sz(
                                     SSL_SESSION_get_session_id(pSession),
                                     SSL_SESSION_get_session_id_length(pSession),
                                     buf, sizeof(buf)));
        }
    }
    else if (ssl != NULL && strlen(var) >= 6 && strcEQn(var, "CIPHER", 6)) {
        result = ssl_var_lookup_ssl_cipher(p, c, var+6);
    }
    else if (ssl != NULL && strlen(var) > 18 && strcEQn(var, "CLIENT_CERT_CHAIN_", 18)) {
        sk = SSL_get_peer_cert_chain(ssl);
        result = ssl_var_lookup_ssl_cert_chain(p, sk, var+18);
    }
    else if (ssl != NULL && strcEQ(var, "CLIENT_VERIFY")) {
        result = ssl_var_lookup_ssl_cert_verify(p, c);
    }
    else if (ssl != NULL && strlen(var) > 7 && strcEQn(var, "CLIENT_", 7)) {
        if ((xs = SSL_get_peer_certificate(ssl)) != NULL) {
            result = ssl_var_lookup_ssl_cert(p, xs, var+7);
            X509_free(xs);
        }
    }
    else if (ssl != NULL && strlen(var) > 7 && strcEQn(var, "SERVER_", 7)) {
        if ((xs = SSL_get_certificate(ssl)) != NULL)
            result = ssl_var_lookup_ssl_cert(p, xs, var+7);
    }
    else if (ssl != NULL && strcEQ(var, "COMPRESS_METHOD")) {
        result = ssl_var_lookup_ssl_compress_meth(ssl);
    }
#ifndef OPENSSL_NO_TLSEXT
    else if (ssl != NULL && strcEQ(var, "TLS_SNI")) {
        result = apr_pstrdup(p, SSL_get_servername(ssl,
                                                   TLSEXT_NAMETYPE_host_name));
    }
#endif
    return result;
}

static char *ssl_var_lookup_ssl_cert(apr_pool_t *p, X509 *xs, char *var)
{
    char *result;
    BOOL resdup;
    X509_NAME *xsname;
    int nid;
    char *cp;

    result = NULL;
    resdup = TRUE;

    if (strcEQ(var, "M_VERSION")) {
        result = apr_psprintf(p, "%lu", X509_get_version(xs)+1);
        resdup = FALSE;
    }
    else if (strcEQ(var, "M_SERIAL")) {
        result = ssl_var_lookup_ssl_cert_serial(p, xs);
    }
    else if (strcEQ(var, "V_START")) {
        result = ssl_var_lookup_ssl_cert_valid(p, X509_get_notBefore(xs));
    }
    else if (strcEQ(var, "V_END")) {
        result = ssl_var_lookup_ssl_cert_valid(p, X509_get_notAfter(xs));
    }
    else if (strcEQ(var, "V_REMAIN")) {
        result = ssl_var_lookup_ssl_cert_remain(p, X509_get_notAfter(xs));
        resdup = FALSE;
    }
    else if (strcEQ(var, "S_DN")) {
        xsname = X509_get_subject_name(xs);
        cp = X509_NAME_oneline(xsname, NULL, 0);
        result = apr_pstrdup(p, cp);
        modssl_free(cp);
        resdup = FALSE;
    }
    else if (strlen(var) > 5 && strcEQn(var, "S_DN_", 5)) {
        xsname = X509_get_subject_name(xs);
        result = ssl_var_lookup_ssl_cert_dn(p, xsname, var+5);
        resdup = FALSE;
    }
    else if (strcEQ(var, "I_DN")) {
        xsname = X509_get_issuer_name(xs);
        cp = X509_NAME_oneline(xsname, NULL, 0);
        result = apr_pstrdup(p, cp);
        modssl_free(cp);
        resdup = FALSE;
    }
    else if (strlen(var) > 5 && strcEQn(var, "I_DN_", 5)) {
        xsname = X509_get_issuer_name(xs);
        result = ssl_var_lookup_ssl_cert_dn(p, xsname, var+5);
        resdup = FALSE;
    }
    else if (strcEQ(var, "A_SIG")) {
        nid = OBJ_obj2nid((ASN1_OBJECT *)X509_get_signature_algorithm(xs));
        result = apr_pstrdup(p,
                             (nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(nid));
        resdup = FALSE;
    }
    else if (strcEQ(var, "A_KEY")) {
        nid = OBJ_obj2nid((ASN1_OBJECT *)X509_get_key_algorithm(xs));
        result = apr_pstrdup(p,
                             (nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(nid));
        resdup = FALSE;
    }
    else if (strcEQ(var, "CERT")) {
        result = ssl_var_lookup_ssl_cert_PEM(p, xs);
    }

    if (result != NULL && resdup)
        result = apr_pstrdup(p, result);
    return result;
}

/* In this table, .extract is non-zero if RDNs using the NID should be
 * extracted to for the SSL_{CLIENT,SERVER}_{I,S}_DN_* environment
 * variables. */
static const struct {
    char *name;
    int   nid;
    int   extract;
} ssl_var_lookup_ssl_cert_dn_rec[] = {
    { "C",     NID_countryName,            1 },
    { "ST",    NID_stateOrProvinceName,    1 }, /* officially    (RFC2156) */
    { "SP",    NID_stateOrProvinceName,    0 }, /* compatibility (SSLeay)  */
    { "L",     NID_localityName,           1 },
    { "O",     NID_organizationName,       1 },
    { "OU",    NID_organizationalUnitName, 1 },
    { "CN",    NID_commonName,             1 },
    { "T",     NID_title,                  1 },
    { "I",     NID_initials,               1 },
    { "G",     NID_givenName,              1 },
    { "S",     NID_surname,                1 },
    { "D",     NID_description,            1 },
#ifdef NID_userId
    { "UID",   NID_x500UniqueIdentifier,   1 },
#endif
    { "Email", NID_pkcs9_emailAddress,     1 },
    { NULL,    0,                          0 }
};

static char *ssl_var_lookup_ssl_cert_dn(apr_pool_t *p, X509_NAME *xsname, char *var)
{
    char *result, *ptr;
    X509_NAME_ENTRY *xsne;
    int i, j, n, idx = 0;
    apr_size_t varlen;

    /* if an _N suffix is used, find the Nth attribute of given name */
    ptr = strchr(var, '_');
    if (ptr != NULL && strspn(ptr + 1, "0123456789") == strlen(ptr + 1)) {
        idx = atoi(ptr + 1);
        varlen = ptr - var;
    } else {
        varlen = strlen(var);
    }

    result = NULL;

    for (i = 0; ssl_var_lookup_ssl_cert_dn_rec[i].name != NULL; i++) {
        if (strEQn(var, ssl_var_lookup_ssl_cert_dn_rec[i].name, varlen)
            && strlen(ssl_var_lookup_ssl_cert_dn_rec[i].name) == varlen) {
            for (j = 0; j < sk_X509_NAME_ENTRY_num((STACK_OF(X509_NAME_ENTRY) *)
                                                 X509_NAME_get_entries(xsname));
                 j++) {
                xsne = sk_X509_NAME_ENTRY_value((STACK_OF(X509_NAME_ENTRY) *)
                                             X509_NAME_get_entries(xsname), j);

                n =OBJ_obj2nid((ASN1_OBJECT *)X509_NAME_ENTRY_get_object(xsne));

                if (n == ssl_var_lookup_ssl_cert_dn_rec[i].nid && idx-- == 0) {
                    unsigned char *data = X509_NAME_ENTRY_get_data_ptr(xsne);
                    /* cast needed from unsigned char to char */
                    result = apr_pstrmemdup(p, (char *)data,
                                            X509_NAME_ENTRY_get_data_len(xsne));
#if APR_CHARSET_EBCDIC
                    ap_xlate_proto_from_ascii(result, X509_NAME_ENTRY_get_data_len(xsne));
#endif /* APR_CHARSET_EBCDIC */
                    break;
                }
            }
            break;
        }
    }
    return result;
}

static char *ssl_var_lookup_ssl_cert_valid(apr_pool_t *p, ASN1_UTCTIME *tm)
{
    char *result;
    BIO* bio;
    int n;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    ASN1_UTCTIME_print(bio, tm);
    n = BIO_pending(bio);
    result = apr_pcalloc(p, n+1);
    n = BIO_read(bio, result, n);
    result[n] = NUL;
    BIO_free(bio);
    return result;
}

#define DIGIT2NUM(x) (((x)[0] - '0') * 10 + (x)[1] - '0')

/* Return a string giving the number of days remaining until 'tm', or
 * "0" if this can't be determined. */
static char *ssl_var_lookup_ssl_cert_remain(apr_pool_t *p, ASN1_UTCTIME *tm)
{
    apr_time_t then, now = apr_time_now();
    apr_time_exp_t exp = {0};
    long diff;

    /* Fail if the time isn't a valid ASN.1 UTCTIME; RFC3280 mandates
     * that the seconds digits are present even though ASN.1
     * doesn't. */
    if (tm->length < 11 || !ASN1_UTCTIME_check(tm)) {
        return apr_pstrdup(p, "0");
    }

    exp.tm_year = DIGIT2NUM(tm->data);
    exp.tm_mon = DIGIT2NUM(tm->data + 2) - 1;
    exp.tm_mday = DIGIT2NUM(tm->data + 4) + 1;
    exp.tm_hour = DIGIT2NUM(tm->data + 6);
    exp.tm_min = DIGIT2NUM(tm->data + 8);
    exp.tm_sec = DIGIT2NUM(tm->data + 10);

    if (exp.tm_year <= 50) exp.tm_year += 100;

    if (apr_time_exp_gmt_get(&then, &exp) != APR_SUCCESS) {
        return apr_pstrdup(p, "0");
    }

    diff = (long)((apr_time_sec(then) - apr_time_sec(now)) / (60*60*24));

    return diff > 0 ? apr_ltoa(p, diff) : apr_pstrdup(p, "0");
}

static char *ssl_var_lookup_ssl_cert_serial(apr_pool_t *p, X509 *xs)
{
    char *result;
    BIO *bio;
    int n;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    i2a_ASN1_INTEGER(bio, X509_get_serialNumber(xs));
    n = BIO_pending(bio);
    result = apr_pcalloc(p, n+1);
    n = BIO_read(bio, result, n);
    result[n] = NUL;
    BIO_free(bio);
    return result;
}

static char *ssl_var_lookup_ssl_cert_chain(apr_pool_t *p, STACK_OF(X509) *sk, char *var)
{
    char *result;
    X509 *xs;
    int n;

    result = NULL;

    if (strspn(var, "0123456789") == strlen(var)) {
        n = atoi(var);
        if (n < sk_X509_num(sk)) {
            xs = sk_X509_value(sk, n);
            result = ssl_var_lookup_ssl_cert_PEM(p, xs);
        }
    }

    return result;
}

static char *ssl_var_lookup_ssl_cert_PEM(apr_pool_t *p, X509 *xs)
{
    char *result;
    BIO *bio;
    int n;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    PEM_write_bio_X509(bio, xs);
    n = BIO_pending(bio);
    result = apr_pcalloc(p, n+1);
    n = BIO_read(bio, result, n);
    result[n] = NUL;
    BIO_free(bio);
    return result;
}

static char *ssl_var_lookup_ssl_cert_verify(apr_pool_t *p, conn_rec *c)
{
    SSLConnRec *sslconn = myConnConfig(c);
    char *result;
    long vrc;
    const char *verr;
    const char *vinfo;
    SSL *ssl;
    X509 *xs;

    result = NULL;
    ssl   = sslconn->ssl;
    verr  = sslconn->verify_error;
    vinfo = sslconn->verify_info;
    vrc   = SSL_get_verify_result(ssl);
    xs    = SSL_get_peer_certificate(ssl);

    if (vrc == X509_V_OK && verr == NULL && xs == NULL)
        /* no client verification done at all */
        result = "NONE";
    else if (vrc == X509_V_OK && verr == NULL && vinfo == NULL && xs != NULL)
        /* client verification done successful */
        result = "SUCCESS";
    else if (vrc == X509_V_OK && vinfo != NULL && strEQ(vinfo, "GENEROUS"))
        /* client verification done in generous way */
        result = "GENEROUS";
    else
        /* client verification failed */
        result = apr_psprintf(p, "FAILED:%s", verr);

    if (xs)
        X509_free(xs);
    return result;
}

static char *ssl_var_lookup_ssl_cipher(apr_pool_t *p, conn_rec *c, char *var)
{
    SSLConnRec *sslconn = myConnConfig(c);
    char *result;
    BOOL resdup;
    int usekeysize, algkeysize;
    SSL *ssl;

    result = NULL;
    resdup = TRUE;

    ssl = sslconn->ssl;
    ssl_var_lookup_ssl_cipher_bits(ssl, &usekeysize, &algkeysize);

    if (ssl && strEQ(var, "")) {
        MODSSL_SSL_CIPHER_CONST SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
        result = (cipher != NULL ? (char *)SSL_CIPHER_get_name(cipher) : NULL);
    }
    else if (strcEQ(var, "_EXPORT"))
        result = (usekeysize < 56 ? "true" : "false");
    else if (strcEQ(var, "_USEKEYSIZE")) {
        result = apr_itoa(p, usekeysize);
        resdup = FALSE;
    }
    else if (strcEQ(var, "_ALGKEYSIZE")) {
        result = apr_itoa(p, algkeysize);
        resdup = FALSE;
    }

    if (result != NULL && resdup)
        result = apr_pstrdup(p, result);
    return result;
}

static void ssl_var_lookup_ssl_cipher_bits(SSL *ssl, int *usekeysize, int *algkeysize)
{
    MODSSL_SSL_CIPHER_CONST SSL_CIPHER *cipher;

    *usekeysize = 0;
    *algkeysize = 0;
    if (ssl != NULL)
        if ((cipher = SSL_get_current_cipher(ssl)) != NULL)
            *usekeysize = SSL_CIPHER_get_bits(cipher, algkeysize);
    return;
}

static char *ssl_var_lookup_ssl_version(apr_pool_t *p, char *var)
{
    if (strEQ(var, "INTERFACE")) {
        return apr_pstrdup(p, var_interface);
    }
    else if (strEQ(var, "LIBRARY_INTERFACE")) {
        return apr_pstrdup(p, var_library_interface);
    }
    else if (strEQ(var, "LIBRARY")) {
        return apr_pstrdup(p, var_library);
    }
    return NULL;
}

/* Add each RDN in 'xn' to the table 't' where the NID is present in
 * 'nids', using key prefix 'pfx'.  */
static void extract_dn(apr_table_t *t, apr_hash_t *nids, const char *pfx, 
                       X509_NAME *xn, apr_pool_t *p)
{
    STACK_OF(X509_NAME_ENTRY) *ents = X509_NAME_get_entries(xn);
    X509_NAME_ENTRY *xsne;
    apr_hash_t *count;
    int i, nid;
  
    /* Hash of (int) NID -> (int *) counter to count each time an RDN
     * with the given NID has been seen. */
    count = apr_hash_make(p);

    /* For each RDN... */
    for (i = 0; i < sk_X509_NAME_ENTRY_num(ents); i++) {
         const char *tag;

         xsne = sk_X509_NAME_ENTRY_value(ents, i);

         /* Retrieve the nid, and check whether this is one of the nids
          * which are to be extracted. */
         nid = OBJ_obj2nid((ASN1_OBJECT *)X509_NAME_ENTRY_get_object(xsne));

         tag = apr_hash_get(nids, &nid, sizeof nid);
         if (tag) {
             unsigned char *data = X509_NAME_ENTRY_get_data_ptr(xsne);
             const char *key;
             int *dup;
             char *value;

             /* Check whether a variable with this nid was already
              * been used; if so, use the foo_N=bar syntax. */
             dup = apr_hash_get(count, &nid, sizeof nid);
             if (dup) {
                 key = apr_psprintf(p, "%s%s_%d", pfx, tag, ++(*dup));
             }
             else {
                 /* Otherwise, use the plain foo=bar syntax. */
                 dup = apr_pcalloc(p, sizeof *dup);
                 apr_hash_set(count, &nid, sizeof nid, dup);
                 key = apr_pstrcat(p, pfx, tag, NULL);
             }
             
             /* cast needed from 'unsigned char *' to 'char *' */
             value = apr_pstrmemdup(p, (char *)data,
                                    X509_NAME_ENTRY_get_data_len(xsne));
#if APR_CHARSET_EBCDIC
             ap_xlate_proto_from_ascii(value, X509_NAME_ENTRY_get_data_len(xsne));
#endif /* APR_CHARSET_EBCDIC */
             apr_table_setn(t, key, value);
         }
    }
}

void modssl_var_extract_dns(apr_table_t *t, SSL *ssl, apr_pool_t *p)
{
    apr_hash_t *nids;
    unsigned n;
    X509 *xs;

    /* Build up a hash table of (int *)NID->(char *)short-name for all
     * the tags which are to be extracted: */
    nids = apr_hash_make(p);
    for (n = 0; ssl_var_lookup_ssl_cert_dn_rec[n].name; n++) {
        if (ssl_var_lookup_ssl_cert_dn_rec[n].extract) {
            apr_hash_set(nids, &ssl_var_lookup_ssl_cert_dn_rec[n].nid,
                         sizeof(ssl_var_lookup_ssl_cert_dn_rec[0].nid),
                         ssl_var_lookup_ssl_cert_dn_rec[n].name);
        }
    }
    
    /* Extract the server cert DNS -- note that the refcount does NOT
     * increase: */
    xs = SSL_get_certificate(ssl);
    if (xs) {
        extract_dn(t, nids, "SSL_SERVER_S_DN_", X509_get_subject_name(xs), p);
        extract_dn(t, nids, "SSL_SERVER_I_DN_", X509_get_issuer_name(xs), p);
    }
    
    /* Extract the client cert DNs -- note that the refcount DOES
     * increase: */
    xs = SSL_get_peer_certificate(ssl);
    if (xs) {
        extract_dn(t, nids, "SSL_CLIENT_S_DN_", X509_get_subject_name(xs), p);
        extract_dn(t, nids, "SSL_CLIENT_I_DN_", X509_get_issuer_name(xs), p);
        X509_free(xs);
    }
}

const char *ssl_ext_lookup(apr_pool_t *p, conn_rec *c, int peer,
                           const char *oidnum)
{
    SSLConnRec *sslconn = myConnConfig(c);
    SSL *ssl;
    X509 *xs = NULL;
    ASN1_OBJECT *oid;
    int count = 0, j;
    char *result = NULL;

    if (!sslconn || !sslconn->ssl) {
        return NULL;
    }
    ssl = sslconn->ssl;

    oid = OBJ_txt2obj(oidnum, 1);
    if (!oid) {
        ERR_clear_error();
        return NULL;
    }

    xs = peer ? SSL_get_peer_certificate(ssl) : SSL_get_certificate(ssl);
    if (xs == NULL) {
        return NULL;
    }

    count = X509_get_ext_count(xs);

    for (j = 0; j < count; j++) {
        X509_EXTENSION *ext = X509_get_ext(xs, j);

        if (OBJ_cmp(ext->object, oid) == 0) {
            BIO *bio = BIO_new(BIO_s_mem());

            if (X509V3_EXT_print(bio, ext, 0, 0) == 1) {
                BUF_MEM *buf;

                BIO_get_mem_ptr(bio, &buf);
                result = apr_pstrmemdup(p, buf->data, buf->length);
            }

            BIO_vfree(bio);
            break;
        }
    }

    if (peer) {
        /* only SSL_get_peer_certificate raises the refcount */
        X509_free(xs);
    }

    ERR_clear_error();
    return result;
}

static char *ssl_var_lookup_ssl_compress_meth(SSL *ssl)
{
    char *result = "NULL";
#ifdef OPENSSL_VERSION_NUMBER
#if (OPENSSL_VERSION_NUMBER >= 0x00908000)
    SSL_SESSION *pSession = SSL_get_session(ssl);

    if (pSession) {
        switch (pSession->compress_meth) {
        case 0:
            /* default "NULL" already set */
            break;

            /* Defined by RFC 3749, deflate is coded by "1" */
        case 1:
            result = "DEFLATE";
            break;

            /* IANA assigned compression number for LZS */
        case 0x40:
            result = "LZS";
            break;

        default:
            result = "UNKNOWN";
            break;
        }
    }
#endif
#endif
    return result;
}

/*  _________________________________________________________________
**
**  SSL Extension to mod_log_config
**  _________________________________________________________________
*/

#include "../../modules/loggers/mod_log_config.h"

static const char *ssl_var_log_handler_c(request_rec *r, char *a);
static const char *ssl_var_log_handler_x(request_rec *r, char *a);

/*
 * register us for the mod_log_config function registering phase
 * to establish %{...}c and to be able to expand %{...}x variables.
 */
void ssl_var_log_config_register(apr_pool_t *p)
{
    static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

    if (log_pfn_register) {
        log_pfn_register(p, "c", ssl_var_log_handler_c, 0);
        log_pfn_register(p, "x", ssl_var_log_handler_x, 0);
    }
    return;
}

/*
 * implement the %{..}c log function
 * (we are the only function)
 */
static const char *ssl_var_log_handler_c(request_rec *r, char *a)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    char *result;

    if (sslconn == NULL || sslconn->ssl == NULL)
        return NULL;
    result = NULL;
    if (strEQ(a, "version"))
        result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_PROTOCOL");
    else if (strEQ(a, "cipher"))
        result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER");
    else if (strEQ(a, "subjectdn") || strEQ(a, "clientcert"))
        result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENT_S_DN");
    else if (strEQ(a, "issuerdn") || strEQ(a, "cacert"))
        result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENT_I_DN");
    else if (strEQ(a, "errcode"))
        result = "-";
    else if (strEQ(a, "errstr"))
        result = (char *)sslconn->verify_error;
    if (result != NULL && result[0] == NUL)
        result = NULL;
    return result;
}

/*
 * extend the implementation of the %{..}x log function
 * (there can be more functions)
 */
static const char *ssl_var_log_handler_x(request_rec *r, char *a)
{
    char *result;

    result = ssl_var_lookup(r->pool, r->server, r->connection, r, a);
    if (result != NULL && result[0] == NUL)
        result = NULL;
    return result;
}

