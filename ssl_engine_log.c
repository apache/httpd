/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_log.c
**  Logging Facility
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
                             /* ``The difference between a computer
                                  industry job and open-source software
                                  hacking is about 30 hours a week.''
                                         -- Ralf S. Engelschall     */
#include "mod_ssl.h"

/*  _________________________________________________________________
**
**  Logfile Support
**  _________________________________________________________________
*/

static struct {
    char *cpPattern;
    char *cpAnnotation;
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

static char *ssl_log_annotation(char *error)
{
    char *errstr;
    int i;

    errstr = NULL;
    for (i = 0; ssl_log_annotate[i].cpPattern != NULL; i++) {
        if (ap_strcmp_match(error, ssl_log_annotate[i].cpPattern) == 0) {
            errstr = ssl_log_annotate[i].cpAnnotation;
            break;
        }
    }
    return errstr;
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

    while ((e = ERR_get_error())) {
        char *err, *annotation;
        err = ERR_error_string(e, NULL);
        annotation = ssl_log_annotation(err);

        if (annotation) {
            ap_log_error(file, line, level, 0, s,
                         "SSL Library Error: %ld %s %s",
                         e, err, annotation); 
        }
        else {
            ap_log_error(file, line, level, 0, s,
                         "SSL Library Error: %ld %s",
                         e, err); 
        }
    }
}
