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

void ssl_die(void)
{
    /*
     * This is used for fatal errors and here
     * it is common module practice to really
     * exit from the complete program.
     */
    exit(1);
}

/*
 * Prints the SSL library error information.
 */
void ssl_log_ssl_error(const char *file, int line, int level, server_rec *s)
{
    unsigned long e;
    const char *data;
    int flags;

    while ((e = ERR_peek_error_line_data(NULL, NULL, &data, &flags))) {
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

void ssl_log_cxerror(const char *file, int line, int level, 
                     apr_status_t rv, conn_rec *c, X509 *cert,
                     const char *format, ...)
{
    va_list ap;
    char buf[HUGE_STRING_LEN];
    
    if (!APLOG_IS_LEVEL(mySrvFromConn(c),level)) {
        /* Bail early since the rest of this function is expensive. */
        return;
    }

    va_start(ap, format);
    apr_vsnprintf(buf, sizeof buf, format, ap);
    va_end(ap);

    if (cert) {
        BIO *bio = BIO_new(BIO_s_mem());

        if (bio) {
            int n, msglen;

            BIO_puts(bio, " [subject: ");
            n = X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0,
                                   XN_FLAG_RFC2253 & ~XN_FLAG_DN_REV);
            if (n == 0) {
                BIO_puts(bio, "-empty-");
            } else if (n < 0) {
                BIO_puts(bio, "(ERROR)");
            }

            BIO_puts(bio, " / issuer: ");
            n = X509_NAME_print_ex(bio, X509_get_issuer_name(cert), 0,
                                   XN_FLAG_RFC2253 & ~XN_FLAG_DN_REV);
            if (n == 0) {
                BIO_puts(bio, "-empty-");
            } else if (n < 0) {
                BIO_puts(bio, "(ERROR)");
            }

            BIO_puts(bio, " / serial: ");
            if (i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert)) == -1)
                BIO_puts(bio, "(ERROR)");

            BIO_puts(bio, " / notbefore: ");
            ASN1_TIME_print(bio, X509_get_notBefore(cert));

            BIO_puts(bio, " / notafter: ");
            ASN1_TIME_print(bio, X509_get_notAfter(cert));

            BIO_puts(bio, "]");

            msglen = strlen(buf);
            n = BIO_read(bio, buf + msglen, sizeof buf - msglen - 1);
            if (n > 0)
               buf[msglen + n] = '\0';

            BIO_free(bio);
        }
    }

    ap_log_cerror(file, line, APLOG_MODULE_INDEX, level, rv, c,
                  "%s%s", buf, cert ? "" : " [certificate: -not available-]");
}
