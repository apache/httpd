/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_io.c
**  I/O Functions
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
                             /* ``MY HACK: This universe.
                                  Just one little problem:
                                  core keeps dumping.''
                                            -- Unknown    */
#include "mod_ssl.h"

#if 0 /* XXX */

/*  _________________________________________________________________
**
**  I/O Hooks
**  _________________________________________________________________
*/

static int ssl_io_hook_read(BUFF *fb, char *buf, int len);
static int ssl_io_hook_write(BUFF *fb, char *buf, int len);

void ssl_io_register(void)
{
    ap_hook_register("ap::buff::read",   ssl_io_hook_read,  AP_HOOK_NOCTX);
    ap_hook_register("ap::buff::write",  ssl_io_hook_write, AP_HOOK_NOCTX);
    return;
}

void ssl_io_unregister(void)
{
    ap_hook_unregister("ap::buff::read",   ssl_io_hook_read);
    ap_hook_unregister("ap::buff::write",  ssl_io_hook_write);
    return;
}

static int ssl_io_hook_read(BUFF *fb, char *buf, int len)
{
    SSL *ssl;
    conn_rec *c;
    int rc;

    if ((ssl = ap_ctx_get(fb->ctx, "ssl")) != NULL) {
        rc = SSL_read(ssl, buf, len);
        /*
         * Simulate an EINTR in case OpenSSL wants to read more.
         * (This is usually the case when the client forces an SSL
         * renegotation which is handled implicitly by OpenSSL.)
         */
        if (rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ)
            errno = EINTR;
        /*
         * Log SSL errors
         */
        if (rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_SSL) {
            c = (conn_rec *)SSL_get_app_data(ssl);
            ssl_log(c->server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "SSL error on reading data");
        }
        /*
         * read(2) returns only the generic error number -1
         */
        if (rc < 0)
            rc = -1;
    }
    else
        rc = read(fb->fd_in, buf, len);
    return rc;
}

static int ssl_io_hook_write(BUFF *fb, char *buf, int len)
{
    SSL *ssl;
    conn_rec *c;
    int rc;

    if ((ssl = ap_ctx_get(fb->ctx, "ssl")) != NULL) {
        rc = SSL_write(ssl, buf, len);
        /*
         * Simulate an EINTR in case OpenSSL wants to write more.
         */
        if (rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_WANT_WRITE)
            errno = EINTR;
        /*
         * Log SSL errors
         */
        if (rc < 0 && SSL_get_error(ssl, rc) == SSL_ERROR_SSL) {
            c = (conn_rec *)SSL_get_app_data(ssl);
            ssl_log(c->server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "SSL error on writing data");
        }
        /*
         * write(2) returns only the generic error number -1
         */
        if (rc < 0)
            rc = -1;
    }
    else
        rc = write(fb->fd, buf, len);
    return rc;
}

/*  _________________________________________________________________
**
**  I/O Data Debugging
**  _________________________________________________________________
*/

#define DUMP_WIDTH 16

static void ssl_io_data_dump(server_rec *srvr, const char *s, long len)
{
    char buf[256];
    char tmp[64];
    int i, j, rows, trunc;
    unsigned char ch;

    trunc = 0;
    for(; (len > 0) && ((s[len-1] == ' ') || (s[len-1] == '\0')); len--)
        trunc++;
    rows = (len / DUMP_WIDTH);
    if ((rows * DUMP_WIDTH) < len)
        rows++;
    ssl_log(srvr, SSL_LOG_DEBUG|SSL_NO_TIMESTAMP|SSL_NO_LEVELID,
            "+-------------------------------------------------------------------------+");
    for(i = 0 ; i< rows; i++) {
        ap_snprintf(tmp, sizeof(tmp), "| %04x: ", i * DUMP_WIDTH);
        ap_cpystrn(buf, tmp, sizeof(buf));
        for (j = 0; j < DUMP_WIDTH; j++) {
            if (((i * DUMP_WIDTH) + j) >= len)
                ap_cpystrn(buf+strlen(buf), "   ", sizeof(buf)-strlen(buf));
            else {
                ch = ((unsigned char)*((char *)(s) + i * DUMP_WIDTH + j)) & 0xff;
                ap_snprintf(tmp, sizeof(tmp), "%02x%c", ch , j==7 ? '-' : ' ');
                ap_cpystrn(buf+strlen(buf), tmp, sizeof(buf)-strlen(buf));
            }
        }
        ap_cpystrn(buf+strlen(buf), " ", sizeof(buf)-strlen(buf));
        for (j = 0; j < DUMP_WIDTH; j++) {
            if (((i * DUMP_WIDTH) + j) >= len)
                ap_cpystrn(buf+strlen(buf), " ", sizeof(buf)-strlen(buf));
            else {
                ch = ((unsigned char)*((char *)(s) + i * DUMP_WIDTH + j)) & 0xff;
                ap_snprintf(tmp, sizeof(tmp), "%c", ((ch >= ' ') && (ch <= '~')) ? ch : '.');
                ap_cpystrn(buf+strlen(buf), tmp, sizeof(buf)-strlen(buf));
            }
        }
        ap_cpystrn(buf+strlen(buf), " |", sizeof(buf)-strlen(buf));
        ssl_log(srvr, SSL_LOG_DEBUG|SSL_NO_TIMESTAMP|SSL_NO_LEVELID, "%s", buf);
    }
    if (trunc > 0)
        ssl_log(srvr, SSL_LOG_DEBUG|SSL_NO_TIMESTAMP|SSL_NO_LEVELID,
                "| %04x - <SPACES/NULS>", len + trunc);
    ssl_log(srvr, SSL_LOG_DEBUG|SSL_NO_TIMESTAMP|SSL_NO_LEVELID,
            "+-------------------------------------------------------------------------+");
    return;
}

long ssl_io_data_cb(BIO *bio, int cmd, const char *argp, int argi, long argl, long rc)
{
    SSL *ssl;
    conn_rec *c;
    server_rec *s;

    if ((ssl = (SSL *)BIO_get_callback_arg(bio)) == NULL)
        return rc;
    if ((c = (conn_rec *)SSL_get_app_data(ssl)) == NULL)
        return rc;
    s = c->server;

    if (   cmd == (BIO_CB_WRITE|BIO_CB_RETURN)
        || cmd == (BIO_CB_READ |BIO_CB_RETURN) ) {
        if (rc >= 0) {
            ssl_log(s, SSL_LOG_DEBUG,
                    "%s: %s %ld/%d bytes %s BIO#%08X [mem: %08lX] %s",
                    SSL_LIBRARY_NAME,
                    (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "write" : "read"),
                    rc, argi, (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "to" : "from"),
                    bio, argp,
                    (argp != NULL ? "(BIO dump follows)" : "(Ops, no memory buffer?)"));
            if (argp != NULL)
                ssl_io_data_dump(s, argp, rc);
        }
        else {
            ssl_log(s, SSL_LOG_DEBUG,
                    "%s: I/O error, %d bytes expected to %s on BIO#%08X [mem: %08lX]",
                    SSL_LIBRARY_NAME, argi,
                    (cmd == (BIO_CB_WRITE|BIO_CB_RETURN) ? "write" : "read"),
                    bio, argp);
        }
    }
    return rc;
}

#endif /* XXX */

