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
                             /* ``MY HACK: This universe.
                                  Just one little problem:
                                  core keeps dumping.''
                                            -- Unknown    */
#include "mod_ssl.h"

/*  _________________________________________________________________
**
**  I/O Request Body Sucking and Re-Injection
**  _________________________________________________________________
*/

#ifndef SSL_CONSERVATIVE

/*
 * Background:
 *
 * 1. When the client sends a HTTP/HTTPS request, Apache's core code
 * reads only the request line ("METHOD /path HTTP/x.y") and the
 * attached MIME headers ("Foo: bar") up to the terminating line ("CR
 * LF"). An attached request body (for instance the data of a POST
 * method) is _NOT_ read. Instead it is read by mod_cgi's content
 * handler and directly passed to the CGI script.
 *
 * 2. mod_ssl supports per-directory re-configuration of SSL parameters.
 * This is implemented by performing an SSL renegotiation of the
 * re-configured parameters after the request is read, but before the
 * response is sent. In more detail: the renegotiation happens after the
 * request line and MIME headers were read, but _before_ the attached
 * request body is read. The reason simply is that in the HTTP protocol
 * usually there is no acknowledgment step between the headers and the
 * body (there is the 100-continue feature and the chunking facility
 * only), so Apache has no API hook for this step.
 *
 * 3. the problem now occurs when the client sends a POST request for
 * URL /foo via HTTPS the server and the server has SSL parameters
 * re-configured on a per-URL basis for /foo. Then mod_ssl has to
 * perform an SSL renegotiation after the request was read and before
 * the response is sent. But the problem is the pending POST body data
 * in the receive buffer of SSL (which Apache still has not read - it's
 * pending until mod_cgi sucks it in). When mod_ssl now tries to perform
 * the renegotiation the pending data leads to an I/O error.
 *
 * Solution Idea:
 *
 * There are only two solutions: Either to simply state that POST
 * requests to URLs with SSL re-configurations are not allowed, or to
 * renegotiate really after the _complete_ request (i.e. including
 * the POST body) was read. Obviously the latter would be preferred,
 * but it cannot be done easily inside Apache, because as already
 * mentioned, there is no API step between the body reading and the body
 * processing. And even when we mod_ssl would hook directly into the
 * loop of mod_cgi, we wouldn't solve the problem for other handlers, of
 * course. So the only general solution is to suck in the pending data
 * of the request body from the OpenSSL BIO into the Apache BUFF. Then
 * the renegotiation can be done and after this step Apache can proceed
 * processing the request as before.
 *
 * Solution Implementation:
 *
 * We cannot simply suck in the data via an SSL_read-based loop because of
 * HTTP chunking. Instead we _have_ to use the Apache API for this step which
 * is aware of HTTP chunking. So the trick is to suck in the pending request
 * data via the Apache API (which uses Apache's BUFF code and in the
 * background mod_ssl's I/O glue code) and re-inject it later into the Apache
 * BUFF code again. This way the data flows twice through the Apache BUFF, of
 * course. But this way the solution doesn't depend on any Apache specifics
 * and is fully transparent to Apache modules.
 */

struct ssl_io_suck_st {
    BOOL  active;
    char *bufptr;
    int   buflen;
    char *pendptr;
    int   pendlen;
};

/* prepare request_rec structure for input sucking */
static void ssl_io_suck_start(request_rec *r)
{
    struct ssl_io_suck_st *ss;

    ss = ap_ctx_get(r->ctx, "ssl::io::suck");
    if (ss == NULL) {
        ss = ap_palloc(r->pool, sizeof(struct ssl_io_suck_st));
        ap_ctx_set(r->ctx, "ssl::io::suck", ss);
        ss->buflen  = 8192;
        ss->bufptr  = ap_palloc(r->pool, ss->buflen);
    }
    ss->pendptr = ss->bufptr;
    ss->pendlen = 0;
    ss->active = FALSE;
    return;
}

/* record a sucked input chunk */
static void ssl_io_suck_record(request_rec *r, char *buf, int len)
{
    struct ssl_io_suck_st *ss;
    
    if ((ss = ap_ctx_get(r->ctx, "ssl::io::suck")) == NULL)
        return;
    if (((ss->bufptr + ss->buflen) - (ss->pendptr + ss->pendlen)) < len) {
        /* "expand" buffer: actually we cannot really expand the buffer
           here, because Apache's pool system doesn't support expanding chunks
           of memory. Instead we have to either reuse processed data or
           allocate a new chunk of memory in advance if we really need more
           memory. */
        int newlen;
        char *newptr;

        if ((  (ss->pendptr - ss->bufptr) 
             + ((ss->bufptr + ss->buflen) - (ss->pendptr + ss->pendlen)) ) >= len) {
            /* make memory available by reusing already processed data */
            memmove(ss->bufptr, ss->pendptr, ss->pendlen);
            ss->pendptr = ss->bufptr;
        }
        else {
            /* too bad, we have to allocate a new larger buffer */
            newlen = (ss->buflen * 2) + len;
            newptr = ap_palloc(r->pool, newlen);
            ss->bufptr  = newptr;
            ss->buflen  = newlen;
            memcpy(ss->bufptr, ss->pendptr, ss->pendlen);
            ss->pendptr = ss->bufptr;
        }
    }
    memcpy(ss->pendptr+ss->pendlen, buf, len);
    ss->pendlen += len;
    return;
}

/* finish request_rec after input sucking */
static void ssl_io_suck_end(request_rec *r)
{
    struct ssl_io_suck_st *ss;
    
    if ((ss = ap_ctx_get(r->ctx, "ssl::io::suck")) == NULL)
        return;
    ss->active = TRUE;
    r->read_body    = REQUEST_NO_BODY;
    r->read_length  = 0;
    r->read_chunked = 0;
    r->remaining    = 0;
    ap_bsetflag(r->connection->client, B_CHUNK, 0);
    return;
}

void ssl_io_suck(request_rec *r, SSL *ssl)
{
    int rc;
    int len;
    char *buf;
    int buflen;
    char c;
    int sucked;

    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK)) == OK) {
        if (ap_should_client_block(r)) {

            /* read client request block through Apache API */
            buflen = HUGE_STRING_LEN;
            buf = ap_palloc(r->pool, buflen);
            ap_hard_timeout("SSL I/O request body pre-sucking", r);
            sucked = 0;
            ssl_io_suck_start(r);
            while ((len = ap_get_client_block(r, buf, buflen)) > 0) {
                ssl_io_suck_record(r, buf, len);
                sucked += len;
            }
            ssl_io_suck_end(r);
            ap_kill_timeout(r);

            /* suck trailing data (usually CR LF) which 
               is still in the Apache BUFF layer */
            while (ap_bpeekc(r->connection->client) != EOF) {
                c = ap_bgetc(r->connection->client);
                ssl_io_suck_record(r, &c, 1);
                sucked++;
            }

            ssl_log(r->server, SSL_LOG_TRACE, 
                    "I/O: sucked %d bytes of input data from SSL/TLS I/O layer "
                    "for delayed injection into Apache I/O layer", sucked);
        }
    }
    return;
}
    
/* the SSL_read replacement routine which knows about the suck buffer */
static int ssl_io_suck_read(SSL *ssl, char *buf, int len)
{
    ap_ctx *actx;
    struct ssl_io_suck_st *ss;
    request_rec *r = NULL;
    int rv;

    actx = (ap_ctx *)SSL_get_app_data2(ssl);
    if (actx != NULL)
        r = (request_rec *)ap_ctx_get(actx, "ssl::request_rec");

    rv = -1;
    if (r != NULL) {
        ss = ap_ctx_get(r->ctx, "ssl::io::suck");
        if (ss != NULL) {
            if (ss->active && ss->pendlen > 0) {
                /* ok, there is pre-sucked data */
                len = (ss->pendlen > len ? len : ss->pendlen);
                memcpy(buf, ss->pendptr, len);
                ss->pendptr += len;
                ss->pendlen -= len;
                ssl_log(r->server, SSL_LOG_TRACE, 
                        "I/O: injecting %d bytes of pre-sucked data "
                        "into Apache I/O layer", len);
                rv = len;
            }
        }
    }
    if (rv == -1)
        rv = SSL_read(ssl, buf, len);
    return rv;
}

/* override SSL_read in the following code... */
#define SSL_read ssl_io_suck_read

#endif /* !SSL_CONSERVATIVE */

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

