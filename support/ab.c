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
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/*
   ** This program is based on ZeusBench V1.0 written by Adam Twiss
   ** which is Copyright (c) 1996 by Zeus Technology Ltd. http://www.zeustech.net/
   **
   ** This software is provided "as is" and any express or implied waranties,
   ** including but not limited to, the implied warranties of merchantability and
   ** fitness for a particular purpose are disclaimed.  In no event shall
   ** Zeus Technology Ltd. be liable for any direct, indirect, incidental, special,
   ** exemplary, or consequential damaged (including, but not limited to,
   ** procurement of substitute good or services; loss of use, data, or profits;
   ** or business interruption) however caused and on theory of liability.  Whether
   ** in contract, strict liability or tort (including negligence or otherwise)
   ** arising in any way out of the use of this software, even if advised of the
   ** possibility of such damage.
   **
 */

/*
   ** HISTORY:
   **    - Originally written by Adam Twiss <adam@zeus.co.uk>, March 1996
   **      with input from Mike Belshe <mbelshe@netscape.com> and
   **      Michael Campanella <campanella@stevms.enet.dec.com>
   **    - Enhanced by Dean Gaudet <dgaudet@apache.org>, November 1997
   **    - Cleaned up by Ralf S. Engelschall <rse@apache.org>, March 1998
   **    - POST and verbosity by Kurt Sussman <kls@merlot.com>, August 1998
   **    - HTML table output added by David N. Welton <davidw@prosa.it>, January 1999
   **    - Added Cookie, Arbitrary header and auth support. <dirkx@webweaving.org>, April 1999
   ** Version 1.3d
   **    - Increased version number - as some of the socket/error handling has
   **      fundamentally changed - and will give fundamentally different results
   **      in situations where a server is dropping requests. Therefore you can
   **      no longer compare results of AB as easily. Hence the inc of the version.
   **      They should be closer to the truth though. Sander & <dirkx@covalent.net>, End 2000.
   **    - Fixed proxy functionality, added median/mean statistics, added gnuplot
   **      output option, added _experimental/rudimentary_ SSL support. Added
   **      confidence guestimators and warnings. Sander & <dirkx@covalent.net>, End 2000
   **    - Fixed serious int overflow issues which would cause realistic (longer
   **      than a few minutes) run's to have wrong (but believable) results. Added
   **      trapping of connection errors which influenced measurements.
   **      Contributed by Sander Temme, Early 2001
   ** Version 1.3e
   **    - Changed timeout behavour during write to work whilst the sockets
   **      are filling up and apr_write() does writes a few - but not all.
   **      This will potentially change results. <dirkx@webweaving.org>, April 2001
   ** Version 2.0.36-dev
   **    Improvements to concurrent processing:
   **      - Enabled non-blocking connect()s.
   **      - Prevent blocking calls to apr_recv() (thereby allowing AB to
   **        manage its entire set of socket descriptors).
   **      - Any error returned from apr_recv() that is not EAGAIN or EOF
   **        is now treated as fatal.
   **      Contributed by Aaron Bannert, April 24, 2002
   **
   ** Version 2.0.36-2
   **	  Internalized the version string - this string is part
   **     of the Agent: header and the result output.
   **
   ** Version 2.0.37-dev
   **     Adopted SSL code by Madhu Mathihalli <madhusudan_mathihalli@hp.com>
   **     [PATCH] ab with SSL support  Posted Wed, 15 Aug 2001 20:55:06 GMT
   **     Introduces four 'if (int == value)' tests per non-ssl request.
   **
   ** Version 2.0.40-dev
   **     Switched to the new abstract pollset API, allowing ab to
   **     take advantage of future apr_pollset_t scalability improvements.
   **     Contributed by Brian Pane, August 31, 2002
   **/

/* Note: this version string should start with \d+[\d\.]* and be a valid
 * string for an HTTP Agent: header when prefixed with 'ApacheBench/'. 
 * It should reflect the version of AB - and not that of the apache server 
 * it happens to accompany. And it should be updated or changed whenever 
 * the results are no longer fundamentally comparable to the results of 
 * a previous version of ab. Either due to a change in the logic of
 * ab - or to due to a change in the distribution it is compiled with 
 * (such as an APR change in for example blocking).
 */
#define AP_AB_BASEREVISION "2.0.40-dev"    

/*
 * BUGS:
 *
 * - uses strcpy/etc.
 * - has various other poor buffer attacks related to the lazy parsing of
 *   response headers from the server
 * - doesn't implement much of HTTP/1.x, only accepts certain forms of
 *   responses
 * - (performance problem) heavy use of strstr shows up top in profile
 *   only an issue for loopback usage
 */

/*  -------------------------------------------------------------------- */

#if 'A' != 0x41
/* Hmmm... This source code isn't being compiled in ASCII.
 * In order for data that flows over the network to make
 * sense, we need to translate to/from ASCII.
 */
#define NOT_ASCII
#endif

/* affects include files on Solaris */
#define BSD_COMP

#include "apr.h"
#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_file_io.h"
#include "apr_time.h"
#include "apr_getopt.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "apr_portable.h"
#include "ap_release.h"
#include "apr_poll.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "apr_base64.h"
#ifdef NOT_ASCII
#include "apr_xlate.h"
#endif
#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#if !defined(WIN32) && !defined(NETWARE)
#include "ap_config_auto.h"
#endif

#if defined(HAVE_SSLC)

/* Libraries for RSA SSL-C */
#include <rsa.h>
#include <x509.h>
#include <pem.h>
#include <err.h>
#include <ssl.h>
#include <r_rand.h>
#include <sslc.h>
#define USE_SSL
#define RSAREF

#elif defined(HAVE_OPENSSL)

/* Libraries on most systems.. */
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#define USE_SSL

#endif

#include <math.h>
#if APR_HAVE_CTYPE_H
#include <ctype.h>
#endif

/* ------------------- DEFINITIONS -------------------------- */

#ifndef LLONG_MAX
#define AB_MAX APR_INT64_C(0x7fffffffffffffff)
#else
#define AB_MAX LLONG_MAX
#endif

/* maximum number of requests on a time limited test */
#define MAX_REQUESTS 50000

/* good old state hostname */
#define STATE_UNCONNECTED 0
#define STATE_CONNECTING  1
#define STATE_READ        2

#define CBUFFSIZE (2048)

struct connection {
    apr_pool_t *ctx;
    apr_socket_t *aprsock;
    int state;
    apr_size_t read;		/* amount of bytes read */
    apr_size_t bread;		/* amount of body read */
    apr_size_t rwrite, rwrote;	/* keep pointers in what we write - across
				 * EAGAINs */
    apr_size_t length;	        /* Content-Length value used for keep-alive */
    char cbuff[CBUFFSIZE];	/* a buffer to store server response header */
    int cbx;			/* offset in cbuffer */
    int keepalive;		/* non-zero if a keep-alive request */
    int gotheader;		/* non-zero if we have the entire header in
				 * cbuff */
    apr_time_t start,		/* Start of connection */
               connect,		/* Connected, start writing */
               endwrite,	/* Request written */
               beginread,	/* First byte of input */
               done;		/* Connection closed */

    int socknum;
#ifdef USE_SSL
    SSL *ssl;
#endif
};

struct data {
#ifdef USE_SSL
    /* XXXX insert SSL timings */
#endif
    int read;              /* number of bytes read */
    apr_time_t starttime;  /* start time of connection in seconds since
                            * Jan. 1, 1970 */
    apr_interval_time_t waittime;   /* Between writing request and reading
                                     * response */
    apr_interval_time_t ctime;      /* time in ms to connect */
    apr_interval_time_t time;       /* time in ms for connection */
};

#define ap_min(a,b) ((a)<(b))?(a):(b)
#define ap_max(a,b) ((a)>(b))?(a):(b)

/* --------------------- GLOBALS ---------------------------- */

int verbosity = 0;		/* no verbosity by default */
int posting = 0;		/* GET by default */
int requests = 1;		/* Number of requests to make */
int heartbeatres = 100;		/* How often do we say we're alive */
int concurrency = 1;		/* Number of multiple requests to make */
int percentile = 1;		/* Show percentile served */
int confidence = 1;		/* Show confidence estimator and warnings */
int tlimit = 0;			/* time limit in secs */
int keepalive = 0;		/* try and do keepalive connections */
char servername[1024];		/* name that server reports */
char *hostname;			/* host name from URL */
char *host_field;		/* value of "Host:" header field */
char *path;                     /* path name */
char postfile[1024];		/* name of file containing post data */
char *postdata;			/* *buffer containing data from postfile */
apr_size_t postlen = 0;		/* length of data to be POSTed */
char content_type[1024];	/* content type to put in POST header */
char *cookie,                   /* optional cookie line */
     *auth,                     /* optional (basic/uuencoded) auhentication */
     *hdrs;                     /* optional arbitrary headers */
apr_port_t port;		/* port number */
char proxyhost[1024];		/* proxy host name */
int proxyport = 0;		/* proxy port */
char *connecthost;
apr_port_t connectport;
char *gnuplot;			/* GNUplot file */
char *csvperc;			/* CSV Percentile file */
char url[1024];
char * fullurl, * colonhost;
int isproxy = 0;
apr_interval_time_t aprtimeout = apr_time_from_sec(30);	/* timeout value */
 /*
  * XXX - this is now a per read/write transact type of value
  */

int use_html = 0;		/* use html in the report */
const char *tablestring;
const char *trstring;
const char *tdstring;

apr_size_t doclen = 0;		/* the length the document should be */
long started = 0;		/* number of requests started, so no excess */
long totalread = 0;		/* total number of bytes read */
long totalbread = 0;		/* totoal amount of entity body read */
long totalposted = 0;		/* total number of bytes posted, inc. headers */
long done = 0;			/* number of requests we have done */
long doneka = 0;		/* number of keep alive connections done */
long good = 0, bad = 0;		/* number of good and bad requests */
long epipe = 0;			/* number of broken pipe writes */

#ifdef USE_SSL
int ssl = 0;
SSL_CTX *ctx;
BIO *bio_out,*bio_err;
static void write_request(struct connection * c);
#endif

/* store error cases */
int err_length = 0, err_conn = 0, err_except = 0;
int err_response = 0;

apr_time_t start, endtime;

/* global request (and its length) */
char _request[512];
char *request = _request;
apr_size_t reqlen;

/* one global throw-away buffer to read stuff into */
char buffer[8192];

/* interesting percentiles */
int percs[] = {50, 66, 75, 80, 90, 95, 98, 99, 100};

struct connection *con;		/* connection array */
struct data *stats;		/* date for each request */
apr_pool_t *cntxt;

apr_pollset_t *readbits;

apr_sockaddr_t *destsa;

#ifdef NOT_ASCII
apr_xlate_t *from_ascii, *to_ascii;
#endif

static void close_connection(struct connection * c);
/* --------------------------------------------------------- */

/* simple little function to write an error string and exit */

static void err(char *s)
{
    fprintf(stderr, "%s\n", s);
    if (done)
        printf("Total of %ld requests completed\n" , done);
    exit(1);
}

/* simple little function to write an APR error string and exit */

static void apr_err(char *s, apr_status_t rv)
{
    char buf[120];

    fprintf(stderr,
	    "%s: %s (%d)\n",
	    s, apr_strerror(rv, buf, sizeof buf), rv);
    if (done)
        printf("Total of %ld requests completed\n" , done);
    exit(rv);
}

#if defined(USE_SSL) && USE_THREADS
/*
 * To ensure thread-safetyness in OpenSSL - work in progress
 */

static apr_thread_mutex_t **lock_cs;
static int                  lock_num_locks;

static void ssl_util_thr_lock(int mode, int type,
                              const char *file, int line)
{
    if (type < lock_num_locks) {
        if (mode & CRYPTO_LOCK) {
            apr_thread_mutex_lock(lock_cs[type]);
        }
        else {
            apr_thread_mutex_unlock(lock_cs[type]);
        }
    }
}

static unsigned long ssl_util_thr_id(void)
{
    /* OpenSSL needs this to return an unsigned long.  On OS/390, the pthread 
     * id is a structure twice that big.  Use the TCB pointer instead as a 
     * unique unsigned long.
     */
#ifdef __MVS__
    struct PSA {
        char unmapped[540];
        unsigned long PSATOLD;
    } *psaptr = 0;

    return psaptr->PSATOLD;
#else
    return (unsigned long) apr_os_thread_current();
#endif
}

static apr_status_t ssl_util_thread_cleanup(void *data)
{
    CRYPTO_set_locking_callback(NULL);

    /* Let the registered mutex cleanups do their own thing 
     */
    return APR_SUCCESS;
}

void ssl_util_thread_setup(apr_pool_t *p)
{
    int i;

    lock_num_locks = CRYPTO_num_locks();
    lock_cs = apr_palloc(p, lock_num_locks * sizeof(*lock_cs));

    for (i = 0; i < lock_num_locks; i++) {
        apr_thread_mutex_create(&(lock_cs[i]), APR_THREAD_MUTEX_DEFAULT, p);
    }

    CRYPTO_set_id_callback(ssl_util_thr_id);

    CRYPTO_set_locking_callback(ssl_util_thr_lock);

    apr_pool_cleanup_register(p, NULL, ssl_util_thread_cleanup,
                                       apr_pool_cleanup_null);
}
#endif

/* --------------------------------------------------------- */
/* write out request to a connection - assumes we can write
 * (small) request out in one go into our new socket buffer
 *
 */
#ifdef USE_SSL
long ssl_print_cb(BIO *bio,int cmd,const char *argp,int argi,long argl,long ret)
{
    BIO *out;

    out=(BIO *)BIO_get_callback_arg(bio);
    if (out == NULL) return(ret);

    if (cmd == (BIO_CB_READ|BIO_CB_RETURN))
    {
        BIO_printf(out,"read from %08X [%08lX] (%d bytes => %ld (0x%X))\n",
                bio,argp,argi,ret,ret);
        BIO_dump(out,(char *)argp,(int)ret);
        return(ret);
    }
    else if (cmd == (BIO_CB_WRITE|BIO_CB_RETURN))
    {
        BIO_printf(out,"write to %08X [%08lX] (%d bytes => %ld (0x%X))\n",
            bio,argp,argi,ret,ret);
        BIO_dump(out,(char *)argp,(int)ret);
    }
    return(ret);
}

#ifndef RAND_MAX
#include <limits.h>
#define RAND_MAX INT_MAX
#endif

static int ssl_rand_choosenum(int l, int h)
{
    int i;
    char buf[50];

    srand((unsigned int)time(NULL));
    apr_snprintf(buf, sizeof(buf), "%.0f",
                 (((double)(rand()%RAND_MAX)/RAND_MAX)*(h-l)));
    i = atoi(buf)+1;
    if (i < l) i = l;
    if (i > h) i = h;
    return i;
}

void ssl_rand_seed()
{
    int nDone = 0;
    int n, l;
    time_t t;
    pid_t pid;
    unsigned char stackdata[256];

    /*
     * seed in the current time (usually just 4 bytes)
     */
    t = time(NULL);
    l = sizeof(time_t);
    RAND_seed((unsigned char *)&t, l);
    nDone += l;

    /*
     * seed in the current process id (usually just 4 bytes)
     */
    pid = getpid();
    l = sizeof(pid_t);
    RAND_seed((unsigned char *)&pid, l);
    nDone += l;

    /*
     * seed in some current state of the run-time stack (128 bytes)
     */
    n = ssl_rand_choosenum(0, sizeof(stackdata)-128-1);
    RAND_seed(stackdata+n, 128);
    nDone += 128;
}

int ssl_print_connection_info(bio,ssl)
BIO *bio;
SSL *ssl;
{
        SSL_CIPHER *c;
        int alg_bits,bits;

        c=SSL_get_current_cipher(ssl);
        BIO_printf(bio,"Cipher Suite Protocol   :%s\n", SSL_CIPHER_get_version(c));
        BIO_printf(bio,"Cipher Suite Name       :%s\n",SSL_CIPHER_get_name(c));

        bits=SSL_CIPHER_get_bits(c,&alg_bits);
        BIO_printf(bio,"Cipher Suite Cipher Bits:%d (%d)\n",bits,alg_bits);

        return(1);
}

int ssl_print_cert_info(bio,x509cert)
BIO *bio;
X509 *x509cert;
{
        X509_NAME *dn;
        char buf[64];

        BIO_printf(bio,"Certificate version: %d\n",X509_get_version(x509cert)+1);

        BIO_printf(bio,"Valid from: ");
        ASN1_UTCTIME_print(bio, X509_get_notBefore(x509cert));
        BIO_printf(bio,"\n");

        BIO_printf(bio,"Valid to  : ");
        ASN1_UTCTIME_print(bio, X509_get_notAfter(x509cert));
        BIO_printf(bio,"\n");

        BIO_printf(bio,"Public key is %d bits\n",
            EVP_PKEY_bits(X509_get_pubkey(x509cert)));

        dn=X509_get_issuer_name(x509cert);
        X509_NAME_oneline(dn, buf, BUFSIZ);
        BIO_printf(bio,"The issuer name is %s\n", buf);

        dn=X509_get_subject_name(x509cert);
        X509_NAME_oneline(dn, buf, BUFSIZ);
        BIO_printf(bio,"The subject name is %s\n", buf);

        /* dump the extension list too */
        BIO_printf(bio,"Extension Count: %d\n",X509_get_ext_count(x509cert));

        return(1);
}

void ssl_start_connect(struct connection * c)
{
    BIO *bio;
    X509 *x509cert;
#ifdef RSAREF
    STACK *sk;
#else
    STACK_OF(X509) *sk;
#endif
    int i, count, hdone = 0;
    char ssl_hostname[80];
    
    /* XXX - Verify if it's okay - TBD */
    if (requests < concurrency)
        requests = concurrency;

    if (!(started < requests))
        return;

    c->read = 0;
    c->bread = 0;
    c->keepalive = 0;
    c->cbx = 0;
    c->gotheader = 0;
    c->rwrite = 0;
    if (c->ctx)
        apr_pool_destroy(c->ctx);
    apr_pool_create(&c->ctx, cntxt);

    if ((c->ssl=SSL_new(ctx)) == NULL)
    {
        BIO_printf(bio_err,"SSL_new failed\n");
        exit(1);
    }

    ssl_rand_seed();

    c->start = apr_time_now();
    memset(ssl_hostname, 0, 80);
    sprintf(ssl_hostname, "%s:%d", hostname, port);

    if ((bio = BIO_new_connect(ssl_hostname)) == NULL)
    {
        BIO_printf(bio_err,"BIO_new_connect failed\n");
        exit(1);
    }
    SSL_set_bio(c->ssl,bio,bio);
    SSL_set_connect_state(c->ssl);

    if (verbosity >= 4)
    {
        BIO_set_callback(bio,ssl_print_cb);
        BIO_set_callback_arg(bio,(void*)bio_err);
    }

    while (!hdone)
    {
        i = SSL_do_handshake(c->ssl);

        switch (SSL_get_error(c->ssl,i))
        {
            case SSL_ERROR_NONE:
                hdone=1;
                break;
            case SSL_ERROR_SSL:
            case SSL_ERROR_SYSCALL:
                BIO_printf(bio_err,"SSL connection failed\n");
                err_conn++;
                c->state = STATE_UNCONNECTED;
                if (bad++ > 10) {
                    SSL_free (c->ssl);
                    BIO_printf(bio_err,"\nTest aborted after 10 failures\n\n");
                    exit (1);
                }
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_CONNECT:
                BIO_printf(bio_err, "Waiting .. sleep(1)\n");
                apr_sleep(apr_time_from_sec(1));
                c->state = STATE_CONNECTING;
                c->rwrite = 0;
                break;
            case SSL_ERROR_ZERO_RETURN:
                BIO_printf(bio_err,"socket closed\n");
                break;
        }
    }
    
    if (verbosity >= 2)
    {
        BIO_printf(bio_err, "\n");
        sk = SSL_get_peer_cert_chain(c->ssl);
#ifdef RSAREF
        if ((count = sk_num(sk)) > 0)
#else
        if ((count = sk_X509_num(sk)) > 0)
#endif
        {
            for (i=1; i<count; i++)
            {
#ifdef RSAREF
                x509cert = (X509 *)sk_value(sk,i);
#else
                x509cert = (X509 *)sk_X509_value(sk,i);
#endif
                ssl_print_cert_info(bio_out,x509cert);
                X509_free(x509cert);
            }
        }

        x509cert = SSL_get_peer_certificate(c->ssl);
        if (x509cert == NULL)
            BIO_printf(bio_out, "Anon DH\n");
        else
        {
            BIO_printf(bio_out, "Peer certificate\n");
            ssl_print_cert_info(bio_out,x509cert);
            X509_free(x509cert);
        }

        ssl_print_connection_info(bio_err,c->ssl);
        SSL_SESSION_print(bio_err,SSL_get_session(c->ssl));
    }

    /* connected first time */
    started++;
    write_request(c);
}
#endif /* USE_SSL */

static void write_request(struct connection * c)
{
    do {
	apr_time_t tnow = apr_time_now();
	apr_size_t l = c->rwrite;
	apr_status_t e;

	/*
	 * First time round ?
	 */
	if (c->rwrite == 0) {
#ifdef USE_SSL
            if (ssl != 1)
#endif
	    apr_socket_timeout_set(c->aprsock, 0);
	    c->connect = tnow;
	    c->rwrite = reqlen;
	    c->rwrote = 0;
	    if (posting)
		c->rwrite += postlen;
	}
	else if (tnow > c->connect + aprtimeout) {
	    printf("Send request timed out!\n");
	    close_connection(c);
	    return;
	}

#ifdef USE_SSL
        if (ssl == 1) {
            apr_size_t e_ssl;
            e_ssl = SSL_write(c->ssl,request + c->rwrote, l);
            if (e_ssl != l)
            {
                printf("SSL write failed - closing connection\n");
                close_connection (c);
                return;
            }
            l = e_ssl;
        }
        else
#endif
	e = apr_send(c->aprsock, request + c->rwrote, &l);

	/*
	 * Bail early on the most common case
	 */
	if (l == c->rwrite)
	    break;

#ifdef USE_SSL
        if (ssl != 1)
	if (e != APR_SUCCESS) {
	    /*
	     * Let's hope this traps EWOULDBLOCK too !
	     */
	    if (!APR_STATUS_IS_EAGAIN(e)) {
		epipe++;
		printf("Send request failed!\n");
		close_connection(c);
	    }
	    return;
	}
#endif
	c->rwrote += l;
	c->rwrite -= l;
    } while (1);

    totalposted += c->rwrite;
    c->state = STATE_READ;
    c->endwrite = apr_time_now();
#ifdef USE_SSL
    if (ssl != 1)
#endif
    {
        apr_pollfd_t new_pollfd;
        new_pollfd.desc_type = APR_POLL_SOCKET;
        new_pollfd.reqevents = APR_POLLIN;
        new_pollfd.desc.s = c->aprsock;
        new_pollfd.client_data = c;
        apr_pollset_add(readbits, &new_pollfd);
    }
}

/* --------------------------------------------------------- */

/* calculate and output results */

static int compradre(struct data * a, struct data * b)
{
    if ((a->ctime) < (b->ctime))
	return -1;
    if ((a->ctime) > (b->ctime))
	return +1;
    return 0;
}

static int comprando(struct data * a, struct data * b)
{
    if ((a->time) < (b->time))
	return -1;
    if ((a->time) > (b->time))
	return +1;
    return 0;
}

static int compri(struct data * a, struct data * b)
{
    apr_interval_time_t p = a->time - a->ctime;
    apr_interval_time_t q = b->time - b->ctime;
    if (p < q)
	return -1;
    if (p > q)
	return +1;
    return 0;
}

static int compwait(struct data * a, struct data * b)
{
    if ((a->waittime) < (b->waittime))
	return -1;
    if ((a->waittime) > (b->waittime))
	return 1;
    return 0;
}

static void output_results(void)
{
    apr_interval_time_t timetakenusec;
    float timetaken;

    endtime = apr_time_now();
    timetakenusec = endtime - start;
    timetaken = ((float)apr_time_sec(timetakenusec)) +
        ((float)apr_time_usec(timetakenusec)) / 1000000.0F;
    
    printf("\n\n");
    printf("Server Software:        %s\n", servername);
    printf("Server Hostname:        %s\n", hostname);
    printf("Server Port:            %hd\n", port);
    printf("\n");
    printf("Document Path:          %s\n", path);
    printf("Document Length:        %" APR_SIZE_T_FMT " bytes\n", doclen);
    printf("\n");
    printf("Concurrency Level:      %d\n", concurrency);
    printf("Time taken for tests:   %ld.%03ld seconds\n",
           (long) apr_time_sec(timetakenusec),
           (long) apr_time_usec(timetakenusec));
    printf("Complete requests:      %ld\n", done);
    printf("Failed requests:        %ld\n", bad);
    if (bad)
	printf("   (Connect: %d, Length: %d, Exceptions: %d)\n",
	       err_conn, err_length, err_except);
    printf("Write errors:           %ld\n", epipe);
    if (err_response)
	printf("Non-2xx responses:      %d\n", err_response);
    if (keepalive)
	printf("Keep-Alive requests:    %ld\n", doneka);
    printf("Total transferred:      %ld bytes\n", totalread);
    if (posting > 0)
	printf("Total POSTed:           %ld\n", totalposted);
    printf("HTML transferred:       %ld bytes\n", totalbread);

    /* avoid divide by zero */
    if (timetaken) {
	printf("Requests per second:    %.2f [#/sec] (mean)\n", 
               (float) (done / timetaken));
	printf("Time per request:       %.3f [ms] (mean)\n", 
               (float) (1000 * concurrency * timetaken / done));
	printf("Time per request:       %.3f [ms] (mean, across all concurrent requests)\n",
	       (float) (1000 * timetaken / done));
	printf("Transfer rate:          %.2f [Kbytes/sec] received\n",
	       (float) (totalread / 1024 / timetaken));
	if (posting > 0) {
	    printf("                        %.2f kb/s sent\n",
		   (float) (totalposted / timetaken / 1024));
	    printf("                        %.2f kb/s total\n",
		   (float) ((totalread + totalposted) / timetaken / 1024));
	}
    }

    if (requests) {
	/* work out connection times */
	long i;
	apr_time_t totalcon = 0, total = 0, totald = 0, totalwait = 0;
        apr_interval_time_t mincon = AB_MAX, mintot = AB_MAX, mind = AB_MAX, 
                            minwait = AB_MAX;
        apr_interval_time_t maxcon = 0, maxtot = 0, maxd = 0, maxwait = 0;
        apr_interval_time_t meancon = 0, meantot = 0, meand = 0, meanwait = 0;
        double sdtot = 0, sdcon = 0, sdd = 0, sdwait = 0;

	for (i = 0; i < requests; i++) {
	    struct data s = stats[i];
	    mincon = ap_min(mincon, s.ctime);
	    mintot = ap_min(mintot, s.time);
	    mind = ap_min(mind, s.time - s.ctime);
	    minwait = ap_min(minwait, s.waittime);

	    maxcon = ap_max(maxcon, s.ctime);
	    maxtot = ap_max(maxtot, s.time);
	    maxd = ap_max(maxd, s.time - s.ctime);
	    maxwait = ap_max(maxwait, s.waittime);

	    totalcon += s.ctime;
	    total += s.time;
	    totald += s.time - s.ctime;
	    totalwait += s.waittime;
	}
	totalcon /= requests;
	total /= requests;
	totald /= requests;
	totalwait /= requests;

	for (i = 0; i < requests; i++) {
	    struct data s = stats[i];
            double a;
            a = ((double)s.time - total);
            sdtot += a * a;
	    a = ((double)s.ctime - totalcon);
	    sdcon += a * a;
	    a = ((double)s.time - (double)s.ctime - totald);
	    sdd += a * a;
	    a = ((double)s.waittime - totalwait);
	    sdwait += a * a;
	}

	sdtot = (requests > 1) ? sqrt(sdtot / (requests - 1)) : 0;
	sdcon = (requests > 1) ? sqrt(sdcon / (requests - 1)) : 0;
	sdd = (requests > 1) ? sqrt(sdd / (requests - 1)) : 0;
	sdwait = (requests > 1) ? sqrt(sdwait / (requests - 1)) : 0;

	if (gnuplot) {
	    FILE *out = fopen(gnuplot, "w");
	    long i;
	    apr_time_t sttime;
	    char tmstring[1024];/* XXXX */
	    if (!out) {
		perror("Cannot open gnuplot output file");
		exit(1);
	    }
	    fprintf(out, "starttime\tseconds\tctime\tdtime\tttime\twait\n");
	    for (i = 0; i < requests; i++) {
                apr_time_t diff = stats[i].time - stats[i].ctime;

		sttime = stats[i].starttime;
		(void) apr_ctime(tmstring, sttime);
		fprintf(out, "%s\t%" APR_TIME_T_FMT "\t%" APR_TIME_T_FMT "\t%" APR_TIME_T_FMT "\t%" APR_TIME_T_FMT "\t%" APR_TIME_T_FMT "\n",
			tmstring,
			sttime,
			stats[i].ctime,
			diff,
			stats[i].time,
			stats[i].waittime);
	    }
	    fclose(out);
	}
    /*
     * XXX: what is better; this hideous cast of the compradre function; or
     * the four warnings during compile ? dirkx just does not know and
     * hates both/
     */
	qsort(stats, requests, sizeof(struct data),
	      (int (*) (const void *, const void *)) compradre);
	if ((requests > 1) && (requests % 2))
	    meancon = (stats[requests / 2].ctime + stats[requests / 2 + 1].ctime) / 2;
	else
	    meancon = stats[requests / 2].ctime;

	qsort(stats, requests, sizeof(struct data),
	      (int (*) (const void *, const void *)) compri);
	if ((requests > 1) && (requests % 2))
	    meand = (stats[requests / 2].time + stats[requests / 2 + 1].time \
	    -stats[requests / 2].ctime - stats[requests / 2 + 1].ctime) / 2;
	else
	    meand = stats[requests / 2].time - stats[requests / 2].ctime;

	qsort(stats, requests, sizeof(struct data),
	      (int (*) (const void *, const void *)) compwait);
	if ((requests > 1) && (requests % 2))
	    meanwait = (stats[requests / 2].waittime + stats[requests / 2 + 1].waittime) / 2;
	else
	    meanwait = stats[requests / 2].waittime;

	qsort(stats, requests, sizeof(struct data),
	      (int (*) (const void *, const void *)) comprando);
	if ((requests > 1) && (requests % 2))
	    meantot = (stats[requests / 2].time + stats[requests / 2 + 1].time) / 2;
	else
	    meantot = stats[requests / 2].time;

	printf("\nConnection Times (ms)\n");

	if (confidence) {
#define CONF_FMT_STRING "%5" APR_TIME_T_FMT " %4d %5.1f %6" APR_TIME_T_FMT " %7" APR_TIME_T_FMT "\n"
	    printf("              min  mean[+/-sd] median   max\n");
	    printf("Connect:    " CONF_FMT_STRING, 
                   mincon, (int) (totalcon + 0.5), sdcon, meancon, maxcon);
	    printf("Processing: " CONF_FMT_STRING,
		   mind, (int) (totald + 0.5), sdd, meand, maxd);
	    printf("Waiting:    " CONF_FMT_STRING,
	           minwait, (int) (totalwait + 0.5), sdwait, meanwait, maxwait);
	    printf("Total:      " CONF_FMT_STRING,
		   mintot, (int) (total + 0.5), sdtot, meantot, maxtot);
#undef CONF_FMT_STRING

#define     SANE(what,avg,mean,sd) \
              { \
                double d = (double)avg - mean; \
                if (d < 0) d = -d; \
                if (d > 2 * sd ) \
                    printf("ERROR: The median and mean for " what " are more than twice the standard\n" \
                           "       deviation apart. These results are NOT reliable.\n"); \
                else if (d > sd ) \
                    printf("WARNING: The median and mean for " what " are not within a normal deviation\n" \
                           "        These results are probably not that reliable.\n"); \
            }
	    SANE("the initial connection time", totalcon, meancon, sdcon);
	    SANE("the processing time", totald, meand, sdd);
	    SANE("the waiting time", totalwait, meanwait, sdwait);
	    SANE("the total time", total, meantot, sdtot);
	}
	else {
	    printf("              min   avg   max\n");
#define CONF_FMT_STRING "%5" APR_TIME_T_FMT " %5" APR_TIME_T_FMT "%5" APR_TIME_T_FMT "\n"
	    printf("Connect:    " CONF_FMT_STRING, 
                   mincon, totalcon / requests, maxcon);
	    printf("Processing: " CONF_FMT_STRING, mintot - mincon, 
                   (total / requests) - (totalcon / requests), 
                   maxtot - maxcon);
	    printf("Total:      " CONF_FMT_STRING, 
                   mintot, total / requests, maxtot);
#undef CONF_FMT_STRING
	}


	/* Sorted on total connect times */
	if (percentile && (requests > 1)) {
	    printf("\nPercentage of the requests served within a certain time (ms)\n");
	    for (i = 0; i < sizeof(percs) / sizeof(int); i++)
		if (percs[i] <= 0)
		    printf(" 0%%  <0> (never)\n");
                else if (percs[i] >= 100)
		    printf(" 100%%  %5" APR_TIME_T_FMT " (longest request)\n",
                           stats[requests - 1].time);
                else
		    printf("  %d%%  %5" APR_TIME_T_FMT "\n", percs[i], 
                           stats[(int) (requests * percs[i] / 100)].time);
	}
	if (csvperc) {
	    FILE *out = fopen(csvperc, "w");
	    int i;
	    if (!out) {
		perror("Cannot open CSV output file");
		exit(1);
	    }
	    fprintf(out, "" "Percentage served" "," "Time in ms" "\n");
	    for (i = 0; i < 100; i++) {
		apr_time_t t;
		if (i == 0)
		    t = stats[0].time;
		else if (i == 100)
		    t = stats[requests - 1].time;
		else
		    t = stats[(int) (0.5 + requests * i / 100.0)].time;
		fprintf(out, "%d,%e\n", i, (double)t);
	    }
	    fclose(out);
        }

    }
}

/* --------------------------------------------------------- */

/* calculate and output results in HTML  */

static void output_html_results(void)
{
    long timetaken;

    endtime = apr_time_now();
    timetaken = (long)((endtime - start) / 1000);

    printf("\n\n<table %s>\n", tablestring);
    printf("<tr %s><th colspan=2 %s>Server Software:</th>"
	   "<td colspan=2 %s>%s</td></tr>\n",
	   trstring, tdstring, tdstring, servername);
    printf("<tr %s><th colspan=2 %s>Server Hostname:</th>"
	   "<td colspan=2 %s>%s</td></tr>\n",
	   trstring, tdstring, tdstring, hostname);
    printf("<tr %s><th colspan=2 %s>Server Port:</th>"
	   "<td colspan=2 %s>%hd</td></tr>\n",
	   trstring, tdstring, tdstring, port);
    printf("<tr %s><th colspan=2 %s>Document Path:</th>"
	   "<td colspan=2 %s>%s</td></tr>\n",
	   trstring, tdstring, tdstring, path);
    printf("<tr %s><th colspan=2 %s>Document Length:</th>"
	   "<td colspan=2 %s>%" APR_SIZE_T_FMT " bytes</td></tr>\n",
	   trstring, tdstring, tdstring, doclen);
    printf("<tr %s><th colspan=2 %s>Concurrency Level:</th>"
	   "<td colspan=2 %s>%d</td></tr>\n",
	   trstring, tdstring, tdstring, concurrency);
    printf("<tr %s><th colspan=2 %s>Time taken for tests:</th>"
	   "<td colspan=2 %s>%" APR_INT64_T_FMT ".%03ld seconds</td></tr>\n",
	   trstring, tdstring, tdstring, apr_time_sec(timetaken),
           (long)apr_time_usec(timetaken));
    printf("<tr %s><th colspan=2 %s>Complete requests:</th>"
	   "<td colspan=2 %s>%ld</td></tr>\n",
	   trstring, tdstring, tdstring, done);
    printf("<tr %s><th colspan=2 %s>Failed requests:</th>"
	   "<td colspan=2 %s>%ld</td></tr>\n",
	   trstring, tdstring, tdstring, bad);
    if (bad)
	printf("<tr %s><td colspan=4 %s >   (Connect: %d, Length: %d, Exceptions: %d)</td></tr>\n",
	       trstring, tdstring, err_conn, err_length, err_except);
    if (err_response)
	printf("<tr %s><th colspan=2 %s>Non-2xx responses:</th>"
	       "<td colspan=2 %s>%d</td></tr>\n",
	       trstring, tdstring, tdstring, err_response);
    if (keepalive)
	printf("<tr %s><th colspan=2 %s>Keep-Alive requests:</th>"
	       "<td colspan=2 %s>%ld</td></tr>\n",
	       trstring, tdstring, tdstring, doneka);
    printf("<tr %s><th colspan=2 %s>Total transferred:</th>"
	   "<td colspan=2 %s>%ld bytes</td></tr>\n",
	   trstring, tdstring, tdstring, totalread);
    if (posting > 0)
	printf("<tr %s><th colspan=2 %s>Total POSTed:</th>"
	       "<td colspan=2 %s>%ld</td></tr>\n",
	       trstring, tdstring, tdstring, totalposted);
    printf("<tr %s><th colspan=2 %s>HTML transferred:</th>"
	   "<td colspan=2 %s>%ld bytes</td></tr>\n",
	   trstring, tdstring, tdstring, totalbread);

    /* avoid divide by zero */
    if (timetaken) {
	printf("<tr %s><th colspan=2 %s>Requests per second:</th>"
	       "<td colspan=2 %s>%.2f</td></tr>\n",
	   trstring, tdstring, tdstring, 1000 * (float) (done) / timetaken);
	printf("<tr %s><th colspan=2 %s>Transfer rate:</th>"
	       "<td colspan=2 %s>%.2f kb/s received</td></tr>\n",
	     trstring, tdstring, tdstring, (float) (totalread) / timetaken);
	if (posting > 0) {
	    printf("<tr %s><td colspan=2 %s>&nbsp;</td>"
		   "<td colspan=2 %s>%.2f kb/s sent</td></tr>\n",
		   trstring, tdstring, tdstring,
		   (float) (totalposted) / timetaken);
	    printf("<tr %s><td colspan=2 %s>&nbsp;</td>"
		   "<td colspan=2 %s>%.2f kb/s total</td></tr>\n",
		   trstring, tdstring, tdstring,
		   (float) (totalread + totalposted) / timetaken);
	}
    } {
	/* work out connection times */
	long i;
	apr_interval_time_t totalcon = 0, total = 0;
	apr_interval_time_t mincon = AB_MAX, mintot = AB_MAX;
	apr_interval_time_t maxcon = 0, maxtot = 0;

	for (i = 0; i < requests; i++) {
	    struct data s = stats[i];
	    mincon = ap_min(mincon, s.ctime);
	    mintot = ap_min(mintot, s.time);
	    maxcon = ap_max(maxcon, s.ctime);
	    maxtot = ap_max(maxtot, s.time);
	    totalcon += s.ctime;
	    total += s.time;
	}

	if (requests > 0) {	/* avoid division by zero (if 0 requests) */
	    printf("<tr %s><th %s colspan=4>Connnection Times (ms)</th></tr>\n",
		   trstring, tdstring);
	    printf("<tr %s><th %s>&nbsp;</th> <th %s>min</th>   <th %s>avg</th>   <th %s>max</th></tr>\n",
		   trstring, tdstring, tdstring, tdstring, tdstring);
	    printf("<tr %s><th %s>Connect:</th>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td></tr>\n",
		   trstring, tdstring, tdstring, mincon, tdstring, totalcon / requests, tdstring, maxcon);
	    printf("<tr %s><th %s>Processing:</th>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td></tr>\n",
		   trstring, tdstring, tdstring, mintot - mincon, tdstring,
		   (total / requests) - (totalcon / requests), tdstring, maxtot - maxcon);
	    printf("<tr %s><th %s>Total:</th>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td>"
		   "<td %s>%5" APR_TIME_T_FMT "</td></tr>\n",
		   trstring, tdstring, tdstring, mintot, tdstring, total / requests, tdstring, maxtot);
	}
	printf("</table>\n");
    }
}

/* --------------------------------------------------------- */

/* start asnchronous non-blocking connection */

static void start_connect(struct connection * c)
{
    apr_status_t rv;

#ifdef USE_SSL
    if (ssl == 1) {
        ssl_start_connect(c);
        return;
    }
#endif
    
    if (!(started < requests))
	return;

    c->read = 0;
    c->bread = 0;
    c->keepalive = 0;
    c->cbx = 0;
    c->gotheader = 0;
    c->rwrite = 0;
    if (c->ctx)
        apr_pool_destroy(c->ctx);
    apr_pool_create(&c->ctx, cntxt);

    if ((rv = apr_socket_create(&c->aprsock, destsa->family,
				SOCK_STREAM, c->ctx)) != APR_SUCCESS) {
	apr_err("socket", rv);
    }
    if ((rv = apr_socket_opt_set(c->aprsock, APR_SO_NONBLOCK, 1))
         != APR_SUCCESS) {
        apr_err("socket nonblock", rv);
    }
    c->start = apr_time_now();
    if ((rv = apr_connect(c->aprsock, destsa)) != APR_SUCCESS) {
	if (APR_STATUS_IS_EINPROGRESS(rv)) {
            apr_pollfd_t new_pollfd;
	    c->state = STATE_CONNECTING;
	    c->rwrite = 0;
            new_pollfd.desc_type = APR_POLL_SOCKET;
            new_pollfd.reqevents = APR_POLLOUT | APR_POLLIN;
            new_pollfd.desc.s = c->aprsock;
            new_pollfd.client_data = c;
	    apr_pollset_add(readbits, &new_pollfd);
	    return;
	}
	else {
            apr_pollfd_t remove_pollfd;
            remove_pollfd.desc_type = APR_POLL_SOCKET;
            remove_pollfd.desc.s = c->aprsock;
	    apr_pollset_remove(readbits, &remove_pollfd);
	    apr_socket_close(c->aprsock);
	    err_conn++;
	    if (bad++ > 10) {
		fprintf(stderr,
			"\nTest aborted after 10 failures\n\n");
		apr_err("apr_connect()", rv);
	    }
	    c->state = STATE_UNCONNECTED;
	    start_connect(c);
	    return;
	}
    }

    /* connected first time */
    started++;
    write_request(c);
}

/* --------------------------------------------------------- */

/* close down connection and save stats */

static void close_connection(struct connection * c)
{
    if (c->read == 0 && c->keepalive) {
	/*
	 * server has legitimately shut down an idle keep alive request
	 */
	if (good)
	    good--;		/* connection never happened */
    }
    else {
	if (good == 1) {
	    /* first time here */
	    doclen = c->bread;
	}
	else if (c->bread != doclen) {
	    bad++;
	    err_length++;
	}
	/* save out time */
	if (done < requests) {
	    struct data s;
	    if ((done) && heartbeatres && !(done % heartbeatres)) {
		fprintf(stderr, "Completed %ld requests\n", done);
		fflush(stderr);
	    }
	    c->done = apr_time_now();
	    s.read = c->read;
	    s.starttime = c->start;
	    s.ctime = (c->connect - c->start) / 1000;
	    s.time = (c->done - c->start) / 1000;
	    s.waittime = (c->beginread - c->endwrite) / 1000;
	    stats[done++] = s;
	}
    }

#ifdef USE_SSL
    if (ssl == 1) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    else
#endif
    {
        apr_pollfd_t remove_pollfd;
        remove_pollfd.desc_type = APR_POLL_SOCKET;
        remove_pollfd.desc.s = c->aprsock;
        apr_pollset_remove(readbits, &remove_pollfd);
        apr_socket_close(c->aprsock);
    }
    c->state = STATE_UNCONNECTED;

    /* connect again */
    start_connect(c);
    return;
}

/* --------------------------------------------------------- */

/* read data from connection */

static void read_connection(struct connection * c)
{
    apr_size_t r;
    apr_status_t status;
    char *part;
    char respcode[4];		/* 3 digits and null */

    r = sizeof(buffer);
#ifdef USE_SSL
    if (ssl == 1)
    {
        status = SSL_read (c->ssl, buffer, r);
        if (status <= 0) {
            good++; c->read = 0;
            if (status < 0) printf("SSL read failed - closing connection\n");
            close_connection(c);
            return;
        }
    r = status;
    }
    else {
#endif
    status = apr_recv(c->aprsock, buffer, &r);
    if (APR_STATUS_IS_EAGAIN(status))
	return;
    else if (r == 0 && APR_STATUS_IS_EOF(status)) {
	good++;
	close_connection(c);
	return;
    }
    /* catch legitimate fatal apr_recv errors */
    else if (status != APR_SUCCESS) {
        err_except++; /* XXX: is this the right error counter? */
        /* XXX: Should errors here be fatal, or should we allow a
         * certain number of them before completely failing? -aaron */
        apr_err("apr_recv", status);
    }
#ifdef USE_SSL
    }
#endif

    totalread += r;
    if (c->read == 0) {
	c->beginread = apr_time_now();
    }
    c->read += r;


    if (!c->gotheader) {
	char *s;
	int l = 4;
	apr_size_t space = CBUFFSIZE - c->cbx - 1; /* -1 allows for \0 term */
	int tocopy = (space < r) ? space : r;
#ifdef NOT_ASCII
	apr_size_t inbytes_left = space, outbytes_left = space;

	status = apr_xlate_conv_buffer(from_ascii, buffer, &inbytes_left,
				       c->cbuff + c->cbx, &outbytes_left);
	if (status || inbytes_left || outbytes_left) {
	    fprintf(stderr, "only simple translation is supported (%d/%u/%u)\n",
		    status, inbytes_left, outbytes_left);
	    exit(1);
	}
#else
	memcpy(c->cbuff + c->cbx, buffer, space);
#endif				/* NOT_ASCII */
	c->cbx += tocopy;
	space -= tocopy;
	c->cbuff[c->cbx] = 0;	/* terminate for benefit of strstr */
        if (verbosity >= 2) {
	    printf("LOG: header received:\n%s\n", c->cbuff);
	}
	s = strstr(c->cbuff, "\r\n\r\n");
	/*
	 * this next line is so that we talk to NCSA 1.5 which blatantly
	 * breaks the http specifaction
	 */
	if (!s) {
	    s = strstr(c->cbuff, "\n\n");
	    l = 2;
	}

	if (!s) {
	    /* read rest next time */
	    if (space) {
		return;
	    }
	    else {
		/* header is in invalid or too big - close connection */
                apr_pollfd_t remove_pollfd;
                remove_pollfd.desc_type = APR_POLL_SOCKET;
                remove_pollfd.desc.s = c->aprsock;
                apr_pollset_remove(readbits, &remove_pollfd);
		apr_socket_close(c->aprsock);
		err_response++;
		if (bad++ > 10) {
		    err("\nTest aborted after 10 failures\n\n");
		}
		start_connect(c);
	    }
	}
	else {
	    /* have full header */
	    if (!good) {
		/*
		 * this is first time, extract some interesting info
		 */
		char *p, *q;
		p = strstr(c->cbuff, "Server:");
		q = servername;
		if (p) {
		    p += 8;
		    while (*p > 32)
			*q++ = *p++;
		}
		*q = 0;
	    }
	    /*
	     * XXX: this parsing isn't even remotely HTTP compliant... but in
	     * the interest of speed it doesn't totally have to be, it just
	     * needs to be extended to handle whatever servers folks want to
	     * test against. -djg
	     */

	    /* check response code */
	    part = strstr(c->cbuff, "HTTP");	/* really HTTP/1.x_ */
            if (part && strlen(part) > strlen("HTTP/1.x_")) {
                strncpy(respcode, (part + strlen("HTTP/1.x_")), 3);
                respcode[3] = '\0';
            }
            else {
                strcpy(respcode, "500");
            }

	    if (respcode[0] != '2') {
		err_response++;
		if (verbosity >= 2)
		    printf("WARNING: Response code not 2xx (%s)\n", respcode);
	    }
	    else if (verbosity >= 3) {
		printf("LOG: Response code = %s\n", respcode);
	    }
	    c->gotheader = 1;
	    *s = 0;		/* terminate at end of header */
	    if (keepalive &&
		(strstr(c->cbuff, "Keep-Alive")
		 || strstr(c->cbuff, "keep-alive"))) {	/* for benefit of MSIIS */
		char *cl;
		cl = strstr(c->cbuff, "Content-Length:");
		/* handle NCSA, which sends Content-length: */
		if (!cl)
		    cl = strstr(c->cbuff, "Content-length:");
		if (cl) {
		    c->keepalive = 1;
		    c->length = atoi(cl + 16);
		}
	    }
	    c->bread += c->cbx - (s + l - c->cbuff) + r - tocopy;
	    totalbread += c->bread;
	}
    }
    else {
	/* outside header, everything we have read is entity body */
	c->bread += r;
	totalbread += r;
    }

    if (c->keepalive && (c->bread >= c->length)) {
	/* finished a keep-alive connection */
	good++;
	doneka++;
	/* save out time */
	if (good == 1) {
	    /* first time here */
	    doclen = c->bread;
	}
	else if (c->bread != doclen) {
	    bad++;
	    err_length++;
	}
	if (done < requests) {
	    struct data s;
	    if (done && heartbeatres && !(done % heartbeatres)) {
		fprintf(stderr, "Completed %ld requests\n", done);
		fflush(stderr);
	    }
	    c->done = apr_time_now();
	    s.read = c->read;
	    s.starttime = c->start;
	    s.ctime = (c->connect - c->start) / 1000;
	    s.waittime = (c->beginread - c->endwrite) / 1000;
	    s.time = (c->done - c->start) / 1000;
	    stats[done++] = s;
	}
	c->keepalive = 0;
	c->length = 0;
	c->gotheader = 0;
	c->cbx = 0;
	c->read = c->bread = 0;
	write_request(c);
	c->start = c->connect;	/* zero connect time with keep-alive */
    }
}

/* --------------------------------------------------------- */

/* run the tests */

static void test(void)
{
    apr_time_t now;
    apr_int16_t rv;
    long i;
    apr_status_t status;
#ifdef NOT_ASCII
    apr_size_t inbytes_left, outbytes_left;
#endif

    if (isproxy) {
	connecthost = apr_pstrdup(cntxt, proxyhost);
	connectport = proxyport;
    }
    else {
	connecthost = apr_pstrdup(cntxt, hostname);
	connectport = port;
    }

    if (!use_html) {
	printf("Benchmarking %s ", hostname);
	if (isproxy)
	    printf("[through %s:%d] ", proxyhost, proxyport);
	printf("(be patient)%s",
	       (heartbeatres ? "\n" : "..."));
	fflush(stdout);
    }

    now = apr_time_now();

    con = calloc(concurrency * sizeof(struct connection), 1);
    
    stats = calloc(requests * sizeof(struct data), 1);
    apr_pollset_create(&readbits, concurrency, cntxt, 0);

    /* setup request */
    if (posting <= 0) {
	sprintf(request, "%s %s HTTP/1.0\r\n"
		"User-Agent: ApacheBench/%s\r\n"
		"%s" "%s" "%s"
		"Host: %s%s\r\n"
		"Accept: */*\r\n"
		"%s" "\r\n",
		(posting == 0) ? "GET" : "HEAD",
		(isproxy) ? fullurl : path,
		AP_AB_BASEREVISION,
		keepalive ? "Connection: Keep-Alive\r\n" : "",
		cookie, auth, host_field, colonhost, hdrs);
    }
    else {
	sprintf(request, "POST %s HTTP/1.0\r\n"
		"User-Agent: ApacheBench/%s\r\n"
		"%s" "%s" "%s"
		"Host: %s%s\r\n"
		"Accept: */*\r\n"
		"Content-length: %" APR_SIZE_T_FMT "\r\n"
		"Content-type: %s\r\n"
		"%s"
		"\r\n",
		(isproxy) ? fullurl : path,
		AP_AB_BASEREVISION,
		keepalive ? "Connection: Keep-Alive\r\n" : "",
		cookie, auth,
		host_field, colonhost, postlen,
		(content_type[0]) ? content_type : "text/plain", hdrs);
    }

    if (verbosity >= 2)
	printf("INFO: POST header == \n---\n%s\n---\n", request);

    reqlen = strlen(request);

    /*
     * Combine headers and (optional) post file into one contineous buffer
     */
    if (posting == 1) {
	char *buff = malloc(postlen + reqlen + 1);
        if (!buff) {
            fprintf(stderr, "error creating request buffer: out of memory\n");
            return;
        }
	strcpy(buff, request);
	strcpy(buff + reqlen, postdata);
	request = buff;
    }

#ifdef NOT_ASCII
    inbytes_left = outbytes_left = reqlen;
    status = apr_xlate_conv_buffer(to_ascii, request, &inbytes_left,
				   request, &outbytes_left);
    if (status || inbytes_left || outbytes_left) {
	fprintf(stderr, "only simple translation is supported (%d/%u/%u)\n",
		status, inbytes_left, outbytes_left);
	exit(1);
    }
#endif				/* NOT_ASCII */

    /* This only needs to be done once */
#ifdef USE_SSL
    if (ssl != 1)
#endif
    if ((rv = apr_sockaddr_info_get(&destsa, connecthost, APR_UNSPEC, connectport, 0, cntxt))
	!= APR_SUCCESS) {
	char buf[120];
	apr_snprintf(buf, sizeof(buf),
		     "apr_sockaddr_info_get() for %s", connecthost);
	apr_err(buf, rv);
    }

    /* ok - lets start */
    start = apr_time_now();

    /* initialise lots of requests */
    for (i = 0; i < concurrency; i++) {
	con[i].socknum = i;
	start_connect(&con[i]);
    }

    while (done < requests) {
	apr_int32_t n;
	apr_int32_t timed;
        const apr_pollfd_t *pollresults;

	/* check for time limit expiry */
	now = apr_time_now();
	timed = (apr_int32_t)apr_time_sec(now - start);
	if (tlimit && timed >= tlimit) {
	    requests = done;	/* so stats are correct */
	    break;		/* no need to do another round */
	}

	n = concurrency;
#ifdef USE_SSL
        if (ssl == 1)
            status = APR_SUCCESS;
        else
#endif
	status = apr_pollset_poll(readbits, aprtimeout, &n, &pollresults);
	if (status != APR_SUCCESS)
	    apr_err("apr_poll", status);

	if (!n) {
	    err("\nServer timed out\n\n");
	}

	for (i = 0; i < n; i++) {
            const apr_pollfd_t *next_fd = &(pollresults[i]);
            struct connection *c = next_fd->client_data;

	    /*
	     * If the connection isn't connected how can we check it?
	     */
	    if (c->state == STATE_UNCONNECTED)
		continue;

#ifdef USE_SSL
            if (ssl == 1)
                rv = APR_POLLIN;
            else
#endif
            rv = next_fd->rtnevents;

	    /*
	     * Notes: APR_POLLHUP is set after FIN is received on some
	     * systems, so treat that like APR_POLLIN so that we try to read
	     * again.
	     *
	     * Some systems return APR_POLLERR with APR_POLLHUP.  We need to
	     * call read_connection() for APR_POLLHUP, so check for
	     * APR_POLLHUP first so that a closed connection isn't treated
	     * like an I/O error.  If it is, we never figure out that the
	     * connection is done and we loop here endlessly calling
	     * apr_poll().
	     */
	    if ((rv & APR_POLLIN) || (rv & APR_POLLPRI) || (rv & APR_POLLHUP))
		read_connection(c);
	    if ((rv & APR_POLLERR) || (rv & APR_POLLNVAL)) {
		bad++;
		err_except++;
		start_connect(c);
		continue;
	    }
	    if (rv & APR_POLLOUT)
		write_request(c);

	    /*
	     * When using a select based poll every time we check the bits
	     * are reset. In 1.3's ab we copied the FD_SET's each time
	     * through, but here we're going to check the state and if the
	     * connection is in STATE_READ or STATE_CONNECTING we'll add the
	     * socket back in as APR_POLLIN.
	     */
#ifdef USE_SSL
            if (ssl != 1)
#endif
	    if (c->state == STATE_READ ||
                c->state == STATE_CONNECTING) {
                    apr_pollfd_t new_pollfd;
                    new_pollfd.desc_type = APR_POLL_SOCKET;
                    new_pollfd.reqevents = APR_POLLIN;
                    new_pollfd.desc.s = c->aprsock;
                    new_pollfd.client_data = c;
                    apr_pollset_add(readbits, &new_pollfd);
                }
	}
    }

    if (heartbeatres)
	fprintf(stderr, "Finished %ld requests\n", done);
    else
	printf("..done\n");

    if (use_html)
	output_html_results();
    else
	output_results();
}

/* ------------------------------------------------------- */

/* display copyright information */
static void copyright(void)
{
    if (!use_html) {
	printf("This is ApacheBench, Version %s\n", AP_AB_BASEREVISION " <$Revision: 1.128 $> apache-2.0");
	printf("Copyright (c) 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/\n");
	printf("Copyright (c) 1998-2002 The Apache Software Foundation, http://www.apache.org/\n");
	printf("\n");
    }
    else {
	printf("<p>\n");
	printf(" This is ApacheBench, Version %s <i>&lt;%s&gt;</i> apache-2.0<br>\n", AP_AB_BASEREVISION, "$Revision: 1.128 $");
	printf(" Copyright (c) 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>\n");
	printf(" Copyright (c) 1998-2002 The Apache Software Foundation, http://www.apache.org/<br>\n");
	printf("</p>\n<p>\n");
    }
}

/* display usage information */
static void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [options] [http"
#ifdef USE_SSL
	    "[s]"
#endif
	    "://]hostname[:port]/path\n", progname);
    fprintf(stderr, "Options are:\n");
    fprintf(stderr, "    -n requests     Number of requests to perform\n");
    fprintf(stderr, "    -c concurrency  Number of multiple requests to make\n");
    fprintf(stderr, "    -t timelimit    Seconds to max. wait for responses\n");
    fprintf(stderr, "    -p postfile     File containing data to POST\n");
    fprintf(stderr, "    -T content-type Content-type header for POSTing\n");
    fprintf(stderr, "    -v verbosity    How much troubleshooting info to print\n");
    fprintf(stderr, "    -w              Print out results in HTML tables\n");
    fprintf(stderr, "    -i              Use HEAD instead of GET\n");
    fprintf(stderr, "    -x attributes   String to insert as table attributes\n");
    fprintf(stderr, "    -y attributes   String to insert as tr attributes\n");
    fprintf(stderr, "    -z attributes   String to insert as td or th attributes\n");
    fprintf(stderr, "    -C attribute    Add cookie, eg. 'Apache=1234. (repeatable)\n");
    fprintf(stderr, "    -H attribute    Add Arbitrary header line, eg. 'Accept-Encoding: gzip'\n");
    fprintf(stderr, "                    Inserted after all normal header lines. (repeatable)\n");
    fprintf(stderr, "    -A attribute    Add Basic WWW Authentication, the attributes\n");
    fprintf(stderr, "                    are a colon separated username and password.\n");
    fprintf(stderr, "    -P attribute    Add Basic Proxy Authentication, the attributes\n");
    fprintf(stderr, "                    are a colon separated username and password.\n");
    fprintf(stderr, "    -X proxy:port   Proxyserver and port number to use\n");
    fprintf(stderr, "    -V              Print version number and exit\n");
    fprintf(stderr, "    -k              Use HTTP KeepAlive feature\n");
    fprintf(stderr, "    -d              Do not show percentiles served table.\n");
    fprintf(stderr, "    -S              Do not show confidence estimators and warnings.\n");
    fprintf(stderr, "    -g filename     Output collected data to gnuplot format file.\n");
    fprintf(stderr, "    -e filename     Output CSV file with percentages served\n");
#ifdef USE_SSL
    fprintf(stderr, "    -s              Use httpS instead of HTTP (SSL)\n");
#endif
    fprintf(stderr, "    -h              Display usage information (this message)\n");
    exit(EINVAL);
}

/* ------------------------------------------------------- */

/* split URL into parts */

static int parse_url(char *url)
{
    char *cp;
    char *h;
    char *scope_id;
    apr_status_t rv;

    /* Save a copy for the proxy */
    fullurl = apr_pstrdup(cntxt, url);

    if (strlen(url) > 7 && strncmp(url, "http://", 7) == 0) {
	url += 7;
#ifdef USE_SSL
	ssl = 0;
#endif
    }
    else
#ifdef USE_SSL
    if (strlen(url) > 8 && strncmp(url, "https://", 8) == 0) {
	url += 8;
	ssl = 1;
    }
#else
    if (strlen(url) > 8 && strncmp(url, "https://", 8) == 0) {
	fprintf(stderr, "SSL not compiled in; no https support\n");
	exit(1);
    }
#endif

    if ((cp = strchr(url, '/')) == NULL)
	return 1;
    h = apr_palloc(cntxt, cp - url + 1);
    memcpy(h, url, cp - url);
    h[cp - url] = '\0';
    rv = apr_parse_addr_port(&hostname, &scope_id, &port, h, cntxt);
    if (rv != APR_SUCCESS || !hostname || scope_id) {
	return 1;
    }
    path = apr_pstrdup(cntxt, cp);
    *cp = '\0';
    if (*url == '[') {		/* IPv6 numeric address string */
	host_field = apr_psprintf(cntxt, "[%s]", hostname);
    }
    else {
	host_field = hostname;
    }

    if (port == 0) {		/* no port specified */
#ifdef USE_SSL
        if (ssl == 1)
            port = 443;
        else
#endif
            port = 80;
    }

    if ((
#ifdef USE_SSL
         (ssl == 1) && (port != 443)) || (( ssl == 0 ) && 
#endif
         (port != 80)))
    {
	colonhost = apr_psprintf(cntxt,":%d",port);
    } else
	colonhost = "";
    return 0;
}

/* ------------------------------------------------------- */

/* read data to POST from file, save contents and length */

static int open_postfile(const char *pfile)
{
    apr_file_t *postfd = NULL;
    apr_finfo_t finfo;
    apr_fileperms_t mode = APR_OS_DEFAULT;
    apr_size_t length;
    apr_status_t rv;
    char errmsg[120];

    rv = apr_file_open(&postfd, pfile, APR_READ, mode, cntxt);
    if (rv != APR_SUCCESS) {
	printf("Invalid postfile name (%s): %s\n", pfile,
	       apr_strerror(rv, errmsg, sizeof errmsg));
	return rv;
    }

    apr_file_info_get(&finfo, APR_FINFO_NORM, postfd);
    postlen = (apr_size_t)finfo.size;
    postdata = (char *) malloc(postlen);
    if (!postdata) {
	printf("Can\'t alloc postfile buffer\n");
	return APR_ENOMEM;
    }
    length = postlen;
    rv = apr_file_read(postfd, postdata, &length);
    if (rv != APR_SUCCESS) {
	printf("error reading postfile: %s\n",
	       apr_strerror(rv, errmsg, sizeof errmsg));
	return rv;
    }
    if (length != postlen) {
	printf("error reading postfile: read only %"
	       APR_SIZE_T_FMT " bytes",
	       length);
	return APR_EINVAL;
    }
    apr_file_close(postfd);
    return 0;
}

/* ------------------------------------------------------- */

/* sort out command-line args and call test */
int main(int argc, const char * const argv[])
{
    int r, l;
    char tmp[1024];
    apr_status_t status;
    apr_getopt_t *opt;
    const char *optarg;
    char c;

    /* table defaults  */
    tablestring = "";
    trstring = "";
    tdstring = "bgcolor=white";
    cookie = "";
    auth = "";
    proxyhost[0] = '\0';
    hdrs = "";

    apr_app_initialize(&argc, &argv, NULL);
    atexit(apr_terminate);
    apr_pool_create(&cntxt, NULL);

#ifdef NOT_ASCII
    status = apr_xlate_open(&to_ascii, "ISO8859-1", APR_DEFAULT_CHARSET, cntxt);
    if (status) {
	fprintf(stderr, "apr_xlate_open(to ASCII)->%d\n", status);
	exit(1);
    }
    status = apr_xlate_open(&from_ascii, APR_DEFAULT_CHARSET, "ISO8859-1", cntxt);
    if (status) {
	fprintf(stderr, "apr_xlate_open(from ASCII)->%d\n", status);
	exit(1);
    }
    status = apr_base64init_ebcdic(to_ascii, from_ascii);
    if (status) {
	fprintf(stderr, "apr_base64init_ebcdic()->%d\n", status);
	exit(1);
    }
#endif

    apr_getopt_init(&opt, cntxt, argc, argv);
    while ((status = apr_getopt(opt, "n:c:t:T:p:v:kVhwix:y:z:C:H:P:A:g:X:de:Sq"
#ifdef USE_SSL
				"s"
#endif
				,&c, &optarg)) == APR_SUCCESS) {
	switch (c) {
	case 's':
#ifdef USE_SSL
        ssl = 1;
        break;
#else
        fprintf(stderr, "SSL not compiled in; no https support\n");
        exit(1);
#endif
	case 'n':
	    requests = atoi(optarg);
	    if (!requests) {
		err("Invalid number of requests\n");
	    }
	    break;
	case 'k':
	    keepalive = 1;
	    break;
	case 'q':
	    heartbeatres = 0;
	    break;
	case 'c':
	    concurrency = atoi(optarg);
	    break;
	case 'i':
	    if (posting == 1)
		err("Cannot mix POST and HEAD\n");
	    posting = -1;
	    break;
	case 'g':
	    gnuplot = strdup(optarg);
	    break;
	case 'd':
	    percentile = 0;
	    break;
	case 'e':
	    csvperc = strdup(optarg);
	    break;
	case 'S':
	    confidence = 0;
	    break;
	case 'p':
	    if (posting != 0)
		err("Cannot mix POST and HEAD\n");

	    if (0 == (r = open_postfile(optarg))) {
		posting = 1;
	    }
	    else if (postdata) {
		exit(r);
	    }
	    break;
	case 'v':
	    verbosity = atoi(optarg);
	    break;
	case 't':
	    tlimit = atoi(optarg);
	    requests = MAX_REQUESTS;	/* need to size data array on
					 * something */
	    break;
	case 'T':
	    strcpy(content_type, optarg);
	    break;
	case 'C':
            cookie = apr_pstrcat(cntxt, "Cookie: ", optarg, "\r\n", NULL);
	    break;
	case 'A':
	    /*
	     * assume username passwd already to be in colon separated form.
	     * Ready to be uu-encoded.
	     */
	    while (apr_isspace(*optarg))
		optarg++;
            if (apr_base64_encode_len(strlen(optarg)) > sizeof(tmp)) {
                err("Authentication credentials too long\n");
            }
	    l = apr_base64_encode(tmp, optarg, strlen(optarg));
	    tmp[l] = '\0';

            auth = apr_pstrcat(cntxt, auth, "Authorization: Basic ", tmp,
                               "\r\n", NULL);
	    break;
	case 'P':
	    /*
             * assume username passwd already to be in colon separated form.
             */
	    while (apr_isspace(*optarg))
		optarg++;
            if (apr_base64_encode_len(strlen(optarg)) > sizeof(tmp)) {
                err("Proxy credentials too long\n");
            }
	    l = apr_base64_encode(tmp, optarg, strlen(optarg));
	    tmp[l] = '\0';

            auth = apr_pstrcat(cntxt, auth, "Proxy-Authorization: Basic ",
                               tmp, "\r\n", NULL);
	    break;
	case 'H':
            hdrs = apr_pstrcat(cntxt, hdrs, optarg, "\r\n", NULL);
	    break;
	case 'w':
	    use_html = 1;
	    break;
	    /*
	     * if any of the following three are used, turn on html output
	     * automatically
	     */
	case 'x':
	    use_html = 1;
	    tablestring = optarg;
	    break;
	case 'X':
	    {
		char *p;
		/*
                 * assume proxy-name[:port]
                 */
		if ((p = strchr(optarg, ':'))) {
		    *p = '\0';
		    p++;
		    proxyport = atoi(p);
		}
		strcpy(proxyhost, optarg);
		isproxy = 1;
	    }
	    break;
	case 'y':
	    use_html = 1;
	    trstring = optarg;
	    break;
	case 'z':
	    use_html = 1;
	    tdstring = optarg;
	    break;
	case 'h':
	    usage(argv[0]);
	    break;
	case 'V':
	    copyright();
	    return 0;
	}
    }

    if (opt->ind != argc - 1) {
	fprintf(stderr, "%s: wrong number of arguments\n", argv[0]);
	usage(argv[0]);
    }

    if (parse_url(apr_pstrdup(cntxt, opt->argv[opt->ind++]))) {
	fprintf(stderr, "%s: invalid URL\n", argv[0]);
	usage(argv[0]);
    }


    if ((heartbeatres) && (requests > 150)) {
	heartbeatres = requests / 10;	/* Print line every 10% of requests */
	if (heartbeatres < 100)
	    heartbeatres = 100;	/* but never more often than once every 100
				 * connections. */
    }
    else
	heartbeatres = 0;

#ifdef USE_SSL
#ifdef RSAREF
    R_malloc_init();
#else
    CRYPTO_malloc_init();
#endif
    SSL_load_error_strings();
    SSL_library_init();
    bio_out=BIO_new_fp(stdout,BIO_NOCLOSE);
    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);

    /* TODO: Allow force SSLv2_client_method() (TLSv1?) */
    if (!(ctx = SSL_CTX_new(SSLv23_client_method()))) {
	fprintf(stderr, "Could not init SSL CTX");
	ERR_print_errors_fp(stderr);
	exit(1);
    }
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
#ifdef USE_THREADS
    ssl_util_thread_setup(cntxt);
#endif
#endif
#ifdef SIGPIPE
    apr_signal(SIGPIPE, SIG_IGN);       /* Ignore writes to connections that
					 * have been closed at the other end. */
#endif
    copyright();
    test();
    apr_pool_destroy(cntxt);

    return 0;
}
