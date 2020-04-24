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
 *  ssl_engine_log.c
 *  Logging Facility
 */
                             /* ``The difference between a computer
                                  industry job and open-source software
                                  hacking is about 30 hours a week.''
                                         -- Ralf S. Engelschall     */
#include "ssl_private.h"

/*  _________________________________________________________________
**
**  Logfile Support
**  _________________________________________________________________
*/

static const struct {
    const char *cpPattern;
    const char *cpAnnotation;
} ssl_log_annotate[] = {
    { "*envelope*bad*decrypt*", "wrong pass phrase!?" },
    { "*CLIENT_HELLO*unknown*protocol*", "speaking not SSL to HTTPS port!?" },
    { "*CLIENT_HELLO*http*request*", "speaking HTTP to HTTPS port!?" },
    { "*SSL3_READ_BYTES:sslv3*alert*bad*certificate*", "Subject CN in certificate not server name or identical to CA!?" },
    { "*self signed certificate in certificate chain*", "Client certificate signed by CA not known to server?" },
    { "*peer did not return a certificate*", "No CAs known to server for verification?" },
    { "*no shared cipher*", "Too restrictive SSLCipherSuite or using DSA server certificate?" },
    { "*no start line*", "Bad file contents or format - or even just a forgotten SSLCertificateKeyFile?" },
    { "*bad password read*", "You entered an incorrect pass phrase!?" },
    { "*bad mac decode*", "Browser still remembered details of a re-created server certificate?" },
    { NULL, NULL }
};

static const char *ssl_log_annotation(const char *error)
{
    int i = 0;

    while (ssl_log_annotate[i].cpPattern != NULL
           && ap_strcmp_match(error, ssl_log_annotate[i].cpPattern) != 0)
        i++;

    return ssl_log_annotate[i].cpAnnotation;
}

apr_status_t ssl_die(server_rec *s)
{
    if (s != NULL && s->is_virtual && s->error_fname != NULL)
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, APLOGNO(02311)
                     "Fatal error initialising mod_ssl, exiting. "
                     "See %s for more information",
                     ap_server_root_relative(s->process->pool,
                                             s->error_fname));
    else
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, APLOGNO(02312)
                     "Fatal error initialising mod_ssl, exiting.");

    return APR_EGENERAL;
}

static APR_INLINE
unsigned long modssl_ERR_peek_error_data(const char **data, int *flags)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    return ERR_peek_error_line_data(NULL, NULL, data, flags);
#else
    return ERR_peek_error_data(data, flags);
#endif
}

/*
 * Prints the SSL library error information.
 */
void ssl_log_ssl_error(const char *file, int line, int level, server_rec *s)
{
    unsigned long e;
    const char *data;
    int flags;

    while ((e = modssl_ERR_peek_error_data(&data, &flags))) {
        const char *annotation;
        char err[256];

        if (!(flags & ERR_TXT_STRING)) {
            data = NULL;
        }

        ERR_error_string_n(e, err, sizeof err);
        annotation = ssl_log_annotation(err);

        ap_log_error(file, line, APLOG_MODULE_INDEX, level, 0, s,
                     "SSL Library Error: %s%s%s%s%s%s",
                     /* %s */
                     err,
                     /* %s%s%s */
                     data ? " (" : "", data ? data : "", data ? ")" : "",
                     /* %s%s */
                     annotation ? " -- " : "",
                     annotation ? annotation : "");

        /* Pop the error off the stack: */
        ERR_get_error();
    }
}

static void ssl_log_cert_error(const char *file, int line, int level,
                               apr_status_t rv, const server_rec *s,
                               const conn_rec *c, const request_rec *r,
                               apr_pool_t *p, X509 *cert, const char *format,
                               va_list ap)
{
    char buf[HUGE_STRING_LEN];
    int msglen, n;
    char *name;

    msglen = apr_vsnprintf(buf, sizeof buf, format, ap);
    
    if (cert) {
        BIO *bio = BIO_new(BIO_s_mem());

        if (bio) {
            /*
             * Limit the maximum length of the subject and issuer DN strings
             * in the log message. 300 characters should always be sufficient
             * for holding both the timestamp, module name, pid etc. stuff
             * at the beginning of the line and the trailing information about
             * serial, notbefore and notafter.
             */
            int maxdnlen = (HUGE_STRING_LEN - msglen - 300) / 2;

            BIO_puts(bio, " [subject: ");
            name = modssl_X509_NAME_to_string(p, X509_get_subject_name(cert),
                                              maxdnlen);
            if (!strIsEmpty(name)) {
                BIO_puts(bio, name);
            } else {
                BIO_puts(bio, "-empty-");
            }

            BIO_puts(bio, " / issuer: ");
            name = modssl_X509_NAME_to_string(p, X509_get_issuer_name(cert),
                                              maxdnlen);
            if (!strIsEmpty(name)) {
                BIO_puts(bio, name);
            } else {
                BIO_puts(bio, "-empty-");
            }

            BIO_puts(bio, " / serial: ");
            if (i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert)) == -1)
                BIO_puts(bio, "(ERROR)");

            BIO_puts(bio, " / notbefore: ");
            ASN1_TIME_print(bio, X509_get_notBefore(cert));

            BIO_puts(bio, " / notafter: ");
            ASN1_TIME_print(bio, X509_get_notAfter(cert));

            BIO_puts(bio, "]");

            n = BIO_read(bio, buf + msglen, sizeof buf - msglen - 1);
            if (n > 0)
               buf[msglen + n] = '\0';

            BIO_free(bio);
        }
        else {
            ap_abort_on_oom();
        }
    }
    else {
        apr_snprintf(buf + msglen, sizeof buf - msglen,
                     " [certificate: -not available-]");
    }

    if (r) {
        ap_log_rerror(file, line, APLOG_MODULE_INDEX, level, rv, r, "%s", buf);
    }
    else if (c) {
        ap_log_cerror(file, line, APLOG_MODULE_INDEX, level, rv, c, "%s", buf);
    }
    else if (s) {
        ap_log_error(file, line, APLOG_MODULE_INDEX, level, rv, s, "%s", buf);
    }

}

/*
 * Wrappers for ap_log_error/ap_log_cerror/ap_log_rerror which log additional
 * details of the X509 cert. For ssl_log_xerror, a pool needs to be passed in
 * as well (for temporary allocation of the cert's subject/issuer name strings,
 * in the other cases we use the connection and request pool, respectively).
 */
void ssl_log_xerror(const char *file, int line, int level, apr_status_t rv,
                    apr_pool_t *ptemp, server_rec *s, X509 *cert,
                    const char *fmt, ...)
{
    if (APLOG_IS_LEVEL(s,level)) {
       va_list ap;
       va_start(ap, fmt);
       ssl_log_cert_error(file, line, level, rv, s, NULL, NULL, ptemp,
                          cert, fmt, ap);
       va_end(ap);
    }
}

void ssl_log_cxerror(const char *file, int line, int level, apr_status_t rv,
                     conn_rec *c, X509 *cert, const char *fmt, ...)
{
    if (APLOG_IS_LEVEL(mySrvFromConn(c),level)) {
       va_list ap;
       va_start(ap, fmt);
       ssl_log_cert_error(file, line, level, rv, NULL, c, NULL, c->pool,
                          cert, fmt, ap);
       va_end(ap);
    }
}

void ssl_log_rxerror(const char *file, int line, int level, apr_status_t rv,
                     request_rec *r, X509 *cert, const char *fmt, ...)
{
    if (APLOG_R_IS_LEVEL(r,level)) {
       va_list ap;
       va_start(ap, fmt);
       ssl_log_cert_error(file, line, level, rv, NULL, NULL, r, r->pool,
                          cert, fmt, ap);
       va_end(ap);
    }
}
