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

#ifndef NO_WRITEV
#include <sys/types.h>
#include <sys/uio.h>
#endif

static int ssl_io_hook_read(BUFF *fb, char *buf, int len);
static int ssl_io_hook_write(BUFF *fb, char *buf, int len);
#ifndef NO_WRITEV
static int ssl_io_hook_writev(BUFF *fb, const struct iovec *iov, int iovcnt);
#endif
#ifdef WIN32
static int ssl_io_hook_recvwithtimeout(BUFF *fb, char *buf, int len);
static int ssl_io_hook_sendwithtimeout(BUFF *fb, const char *buf, int len);
#endif /* WIN32 */

void ssl_io_register(void)
{
    ap_hook_register("ap::buff::read",   ssl_io_hook_read,  AP_HOOK_NOCTX);
    ap_hook_register("ap::buff::write",  ssl_io_hook_write, AP_HOOK_NOCTX);
#ifndef NO_WRITEV
    ap_hook_register("ap::buff::writev", ssl_io_hook_writev, AP_HOOK_NOCTX);
#endif
#ifdef WIN32
    ap_hook_register("ap::buff::recvwithtimeout",
                     ssl_io_hook_recvwithtimeout, AP_HOOK_NOCTX);
    ap_hook_register("ap::buff::sendwithtimeout",
                     ssl_io_hook_sendwithtimeout, AP_HOOK_NOCTX);
#endif
    return;
}

void ssl_io_unregister(void)
{
    ap_hook_unregister("ap::buff::read",   ssl_io_hook_read);
    ap_hook_unregister("ap::buff::write",  ssl_io_hook_write);
#ifndef NO_WRITEV
    ap_hook_unregister("ap::buff::writev", ssl_io_hook_writev);
#endif
#ifdef WIN32
    ap_hook_unregister("ap::buff::recvwithtimeout", ssl_io_hook_recvwithtimeout);
    ap_hook_unregister("ap::buff::sendwithtimeout", ssl_io_hook_sendwithtimeout);
#endif
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

#ifndef NO_WRITEV
/* the prototype for our own SSL_writev() */
static int SSL_writev(SSL *, const struct iovec *, int);

static int ssl_io_hook_writev(BUFF *fb, const struct iovec *iov, int iovcnt)
{
    SSL *ssl;
    conn_rec *c;
    int rc;

    if ((ssl = ap_ctx_get(fb->ctx, "ssl")) != NULL) {
        rc = SSL_writev(ssl, iov, iovcnt);
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
         * writev(2) returns only the generic error number -1
         */
        if (rc < 0)
            rc = -1;
    }
    else
        rc = writev(fb->fd, iov, iovcnt);
    return rc;
}
#endif

#ifdef WIN32

/* these two functions are exported from buff.c under WIN32 */
API_EXPORT(int) sendwithtimeout(int sock, const char *buf, int len, int flags);
API_EXPORT(int) recvwithtimeout(int sock, char *buf, int len, int flags);

/* and the prototypes for our SSL_xxx variants */
static int SSL_sendwithtimeout(BUFF *fb, const char *buf, int len);
static int SSL_recvwithtimeout(BUFF *fb, char *buf, int len);

static int ssl_io_hook_recvwithtimeout(BUFF *fb, char *buf, int len)
{
    SSL *ssl;
    int rc;

    if ((ssl = ap_ctx_get(fb->ctx, "ssl")) != NULL)
        rc = SSL_recvwithtimeout(fb, buf, len);
    else
        rc = recvwithtimeout(fb->fd, buf, len, 0);
    return rc;
}

static int ssl_io_hook_sendwithtimeout(BUFF *fb, const char *buf, int len)
{
    SSL *ssl;
    int rc;

    if ((ssl = ap_ctx_get(fb->ctx, "ssl")) != NULL)
        rc = SSL_sendwithtimeout(fb, buf, len);
    else
        rc = sendwithtimeout(fb->fd, buf, len, 0);
    return rc;
}

#endif /* WIN32 */

/*  _________________________________________________________________
**
**  Special Functions for OpenSSL
**  _________________________________________________________________
*/

#ifdef WIN32

static int SSL_sendwithtimeout(BUFF *fb, const char *buf, int len)
{
    int iostate = 1;
    fd_set fdset;
    struct timeval tv;
    int err = WSAEWOULDBLOCK;
    int rv;
    int retry;
    int sock = fb->fd;
    SSL *ssl;

    ssl = ap_ctx_get(fb->ctx, "ssl");

    if (!(tv.tv_sec = ap_check_alarm()))
        return (SSL_write(ssl, (char*)buf, len));

    rv = ioctlsocket(sock, FIONBIO, &iostate);
    iostate = 0;
    if (rv) {
        err = WSAGetLastError();
        ap_assert(0);
    }
    rv = SSL_write(ssl, (char*)buf, len);
    if (rv <= 0) {
        if (BIO_sock_should_retry(rv)) {
            do {
                retry = 0;
                FD_ZERO(&fdset);
                FD_SET((unsigned int)sock, &fdset);
                tv.tv_usec = 0;
                rv = select(FD_SETSIZE, NULL, &fdset, NULL, &tv);
                if (rv == SOCKET_ERROR)
                    err = WSAGetLastError();
                else if (rv == 0) {
                    ioctlsocket(sock, FIONBIO, &iostate);
                    if(ap_check_alarm() < 0) {
                        WSASetLastError(EINTR); /* Simulate an alarm() */
                        return (SOCKET_ERROR);
                    }
                }
                else {
                    rv = SSL_write(ssl, (char*)buf, len);
                    if (BIO_sock_should_retry(rv)) {
                        ap_log_error(APLOG_MARK,APLOG_DEBUG, NULL,
                                     "select claimed we could write, "
                                     "but in fact we couldn't. "
                                     "This is a bug in Windows.");
                        retry = 1;
                        Sleep(100);
                    }
                }
            } while(retry);
        }
    }
    ioctlsocket(sock, FIONBIO, &iostate);
    if (rv == SOCKET_ERROR)
        WSASetLastError(err);
    return (rv);
}

static int SSL_recvwithtimeout(BUFF *fb, char *buf, int len)
{
    int iostate = 1;
    fd_set fdset;
    struct timeval tv;
    int err = WSAEWOULDBLOCK;
    int rv;
    int sock = fb->fd_in;
    SSL *ssl;
    int retry;

    ssl = ap_ctx_get(fb->ctx, "ssl");

    if (!(tv.tv_sec = ap_check_alarm()))
        return (SSL_read(ssl, buf, len));

    rv = ioctlsocket(sock, FIONBIO, &iostate);
    iostate = 0;
    ap_assert(!rv);
    rv = SSL_read(ssl, buf, len);
    if (rv <= 0) {
        if (BIO_sock_should_retry(rv)) {
            do {
                retry = 0;
                FD_ZERO(&fdset);
                FD_SET((unsigned int)sock, &fdset);
                tv.tv_usec = 0;
                rv = select(FD_SETSIZE, &fdset, NULL, NULL, &tv);
                if (rv == SOCKET_ERROR)
                    err = WSAGetLastError();
                else if (rv == 0) {
                    ioctlsocket(sock, FIONBIO, &iostate);
                    ap_check_alarm();
                    WSASetLastError(WSAEWOULDBLOCK);
                    return (SOCKET_ERROR);
                }
                else {
                    rv = SSL_read(ssl, buf, len);
                    if (rv == SOCKET_ERROR) {
                        if (BIO_sock_should_retry(rv)) {
                          ap_log_error(APLOG_MARK,APLOG_DEBUG, NULL,
                                       "select claimed we could read, "
                                       "but in fact we couldn't. "
                                       "This is a bug in Windows.");
                          retry = 1;
                          Sleep(100);
                        }
                        else {
                            err = WSAGetLastError();
                        }
                    }
                }
            } while(retry);
        }
    }
    ioctlsocket(sock, FIONBIO, &iostate);
    if (rv == SOCKET_ERROR)
        WSASetLastError(err);
    return (rv);
}

#endif /*WIN32*/

/*
 * There is no SSL_writev() provided by OpenSSL. The reason is mainly because
 * OpenSSL has to fragment the data itself again for the SSL record layer, so a
 * writev() like interface makes not much sense.  What we do is to emulate it
 * to at least being able to use the write() like interface. But keep in mind
 * that the network I/O performance is not write() like, of course.
 */
#ifndef NO_WRITEV
static int SSL_writev(SSL *ssl, const struct iovec *iov, int iovcnt)
{
    int i;
    int n;
    int rc;

    rc = 0;
    for (i = 0; i < iovcnt; i++) {
        if ((n = SSL_write(ssl, iov[i].iov_base, iov[i].iov_len)) == -1) {
            rc = -1;
            break;
        }
        rc += n;
    }
    return rc;
}
#endif

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

