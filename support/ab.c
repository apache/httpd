/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
   **
 */

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

#define AB_VERSION "1.3c"

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

#include "apr_network_io.h"
#include "apr_file_io.h"
#include "apr_time.h"
#include "apr_getopt.h"
#include "ap_base64.h"
#ifdef NOT_ASCII
#include "apr_xlate.h"
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

/* ------------------- DEFINITIONS -------------------------- */

/* maximum number of requests on a time limited test */
#define MAX_REQUESTS 50000

/* good old state hostname */
#define STATE_UNCONNECTED 0
#define STATE_CONNECTING  1
#define STATE_READ        2

#define CBUFFSIZE       2048

struct connection {
    apr_socket_t *aprsock;
    int state;
    int read;        		/* amount of bytes read */
    int bread;        		/* amount of body read */
    int length;        		/* Content-Length value used for keep-alive */
    char cbuff[CBUFFSIZE];      /* a buffer to store server response header */
    int cbx;        		/* offset in cbuffer */
    int keepalive;        	/* non-zero if a keep-alive request */
    int gotheader;        	/* non-zero if we have the entire header in
        			 * cbuff */
    apr_time_t start, connect, done;
    int socknum;
};

struct data {
    int read;        		/* number of bytes read */
    int ctime;        		/* time in ms to connect */
    int time;        		/* time in ms for connection */
};

#define ap_min(a,b) ((a)<(b))?(a):(b)
#define ap_max(a,b) ((a)>(b))?(a):(b)

/* --------------------- GLOBALS ---------------------------- */

int verbosity = 0;        	/* no verbosity by default */
int posting = 0;        	/* GET by default */
int requests = 1;        	/* Number of requests to make */
int concurrency = 1;        	/* Number of multiple requests to make */
int tlimit = 0;        		/* time limit in cs */
int keepalive = 0;        	/* try and do keepalive connections */
char servername[1024];        	/* name that server reports */
char hostname[1024];        	/* host name */
char path[1024];        	/* path name */
char postfile[1024];        	/* name of file containing post data */
char *postdata;        		/* *buffer containing data from postfile */
apr_ssize_t postlen = 0;        	/* length of data to be POSTed */
char content_type[1024];        /* content type to put in POST header */
char cookie[1024],        	/* optional cookie line */
     auth[1024],        	/* optional (basic/uuencoded)
        			 * authentification */
     hdrs[4096];        	/* optional arbitrary headers */
int port = 80;        		/* port number */
time_t aprtimeout = 30 * AP_USEC_PER_SEC; /* timeout value */

int use_html = 0;        	/* use html in the report */
char *tablestring;
char *trstring;
char *tdstring;

int doclen = 0;        		/* the length the document should be */
int totalread = 0;        	/* total number of bytes read */
int totalbread = 0;        	/* totoal amount of entity body read */
int totalposted = 0;        	/* total number of bytes posted, inc. headers */
int done = 0;        		/* number of requests we have done */
int doneka = 0;        		/* number of keep alive connections done */
int started = 0;		/* number of requests started, so no excess */
int good = 0, bad = 0;        	/* number of good and bad requests */

/* store error cases */
int err_length = 0, err_conn = 0, err_except = 0;
int err_response = 0;

apr_time_t start, endtime;

/* global request (and its length) */
char request[512];
apr_ssize_t reqlen;

/* one global throw-away buffer to read stuff into */
char buffer[8192];

struct connection *con;        	/* connection array */
struct data *stats;        	/* date for each request */
apr_pool_t *cntxt;

apr_pollfd_t *readbits;
#ifdef NOT_ASCII
apr_xlate_t *from_ascii, *to_ascii;
#endif

/* --------------------------------------------------------- */

/* simple little function to write an error string and exit */

static void err(char *s)
{
    fprintf(stderr, "%s", s);
    exit(1);
}

/* simple little function to write an APR error string and exit */

static void apr_err(char *s, apr_status_t rv)
{
    char buf[120];

    fprintf(stderr,
            "%s: %s (%d)\n", 
            s, apr_strerror(rv, buf, sizeof buf), rv);
    exit(rv);
}

/* --------------------------------------------------------- */

/* write out request to a connection - assumes we can write
   (small) request out in one go into our new socket buffer  */

static void write_request(struct connection *c)
{
    apr_ssize_t len = reqlen;
    c->connect = apr_now();
    apr_setsocketopt(c->aprsock, APR_SO_TIMEOUT, 30 * AP_USEC_PER_SEC);
    if (apr_send(c->aprsock, request, &reqlen) != APR_SUCCESS ||
        reqlen != len) {
        printf("Send request failed!\n");
    }
    if (posting) {
        apr_send(c->aprsock, postdata, &postlen);
        totalposted += (reqlen + postlen);
    }

    c->state = STATE_READ;
    apr_add_poll_socket(readbits, c->aprsock, APR_POLLIN);
}

/* --------------------------------------------------------- */

/* calculate and output results */

static void output_results(void)
{
    int timetaken;

    endtime = apr_now();
    timetaken = (endtime - start) / 1000;

    printf("\r                                                                           \r");
    printf("Server Software:        %s\n", servername);
    printf("Server Hostname:        %s\n", hostname);
    printf("Server Port:            %d\n", port);
    printf("\n");
    printf("Document Path:          %s\n", path);
    printf("Document Length:        %d bytes\n", doclen);
    printf("\n");
    printf("Concurrency Level:      %d\n", concurrency);
    printf("Time taken for tests:   %d.%03d seconds\n",
           timetaken / 1000, timetaken % 1000);
    printf("Complete requests:      %d\n", done);
    printf("Failed requests:        %d\n", bad);
    if (bad)
        printf("   (Connect: %d, Length: %d, Exceptions: %d)\n",
               err_conn, err_length, err_except);
    if (err_response)
        printf("Non-2xx responses:      %d\n", err_response);
    if (keepalive)
        printf("Keep-Alive requests:    %d\n", doneka);
    printf("Total transferred:      %d bytes\n", totalread);
    if (posting)
        printf("Total POSTed:           %d\n", totalposted);
    printf("HTML transferred:       %d bytes\n", totalbread);

    /* avoid divide by zero */
    if (timetaken) {
        printf("Requests per second:    %.2f\n", 1000 * (float) (done) / timetaken);
        printf("Transfer rate:          %.2f kb/s received\n",
               (float) (totalread) / timetaken);
        if (posting>0) {
            printf("                        %.2f kb/s sent\n",
                  (float) (totalposted) / timetaken);
            printf("                        %.2f kb/s total\n",
                  (float) (totalread + totalposted) / timetaken);
        }
    }

    {
        /* work out connection times */
        int i;
        int totalcon = 0, total = 0;
        int mincon = 9999999, mintot = 999999;
        int maxcon = 0, maxtot = 0;

        for (i = 0; i < requests; i++) {
            struct data s = stats[i];
            mincon = ap_min(mincon, s.ctime);
            mintot = ap_min(mintot, s.time);
            maxcon = ap_max(maxcon, s.ctime);
            maxtot = ap_max(maxtot, s.time);
            totalcon += s.ctime;
            total += s.time;
        }
        if (requests > 0) { /* avoid division by zero (if 0 requests) */
            printf("\nConnnection Times (ms)\n");
            printf("              min   avg   max\n");
            printf("Connect:    %5d %5d %5d\n", mincon, totalcon / requests, maxcon);
            printf("Processing: %5d %5d %5d\n",
                   mintot - mincon, (total / requests) - (totalcon / requests),
                   maxtot - maxcon);
            printf("Total:      %5d %5d %5d\n", mintot, total / requests, maxtot);
        }
    }
}

/* --------------------------------------------------------- */

/* calculate and output results in HTML  */

static void output_html_results(void)
{
    int timetaken;

    endtime = apr_now();
    timetaken = (endtime - start) / 1000;

    printf("\n\n<table %s>\n", tablestring);
    printf("<tr %s><th colspan=2 %s>Server Software:</th>"
           "<td colspan=2 %s>%s</td></tr>\n",
           trstring, tdstring, tdstring, servername);
    printf("<tr %s><th colspan=2 %s>Server Hostname:</th>"
           "<td colspan=2 %s>%s</td></tr>\n",
           trstring, tdstring, tdstring, hostname);
    printf("<tr %s><th colspan=2 %s>Server Port:</th>"
           "<td colspan=2 %s>%d</td></tr>\n",
           trstring, tdstring, tdstring, port);
    printf("<tr %s><th colspan=2 %s>Document Path:</th>"
           "<td colspan=2 %s>%s</td></tr>\n",
           trstring, tdstring, tdstring, path);
    printf("<tr %s><th colspan=2 %s>Document Length:</th>"
           "<td colspan=2 %s>%d bytes</td></tr>\n",
           trstring, tdstring, tdstring, doclen);
    printf("<tr %s><th colspan=2 %s>Concurrency Level:</th>"
           "<td colspan=2 %s>%d</td></tr>\n",
           trstring, tdstring, tdstring, concurrency);
    printf("<tr %s><th colspan=2 %s>Time taken for tests:</th>"
           "<td colspan=2 %s>%d.%03d seconds</td></tr>\n",
           trstring, tdstring, tdstring, timetaken / 1000, timetaken % 1000);
    printf("<tr %s><th colspan=2 %s>Complete requests:</th>"
           "<td colspan=2 %s>%d</td></tr>\n",
           trstring, tdstring, tdstring, done);
    printf("<tr %s><th colspan=2 %s>Failed requests:</th>"
           "<td colspan=2 %s>%d</td></tr>\n",
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
               "<td colspan=2 %s>%d</td></tr>\n",
               trstring, tdstring, tdstring, doneka);
    printf("<tr %s><th colspan=2 %s>Total transferred:</th>"
           "<td colspan=2 %s>%d bytes</td></tr>\n",
           trstring, tdstring, tdstring, totalread);
    if (posting>0)
        printf("<tr %s><th colspan=2 %s>Total POSTed:</th>"
               "<td colspan=2 %s>%d</td></tr>\n",
               trstring, tdstring, tdstring, totalposted);
    printf("<tr %s><th colspan=2 %s>HTML transferred:</th>"
           "<td colspan=2 %s>%d bytes</td></tr>\n",
           trstring, tdstring, tdstring, totalbread);

    /* avoid divide by zero */
    if (timetaken) {
        printf("<tr %s><th colspan=2 %s>Requests per second:</th>"
               "<td colspan=2 %s>%.2f</td></tr>\n",
           trstring, tdstring, tdstring, 1000 * (float) (done) / timetaken);
        printf("<tr %s><th colspan=2 %s>Transfer rate:</th>"
               "<td colspan=2 %s>%.2f kb/s received</td></tr>\n",
             trstring, tdstring, tdstring, (float) (totalread) / timetaken);
        if (posting>0) {
            printf("<tr %s><td colspan=2 %s>&nbsp;</td>"
        	   "<td colspan=2 %s>%.2f kb/s sent</td></tr>\n",
        	   trstring, tdstring, tdstring,
        	   (float) (totalposted) / timetaken);
            printf("<tr %s><td colspan=2 %s>&nbsp;</td>"
        	   "<td colspan=2 %s>%.2f kb/s total</td></tr>\n",
        	   trstring, tdstring, tdstring,
        	   (float) (totalread + totalposted) / timetaken);
        }
    }

    {
        /* work out connection times */
        int i;
        int totalcon = 0, total = 0;
        int mincon = 9999999, mintot = 999999;
        int maxcon = 0, maxtot = 0;

        for (i = 0; i < requests; i++) {
            struct data s = stats[i];
            mincon = ap_min(mincon, s.ctime);
            mintot = ap_min(mintot, s.time);
            maxcon = ap_max(maxcon, s.ctime);
            maxtot = ap_max(maxtot, s.time);
            totalcon += s.ctime;
            total += s.time;
        }

        if (requests > 0) { /* avoid division by zero (if 0 requests) */
            printf("<tr %s><th %s colspan=4>Connnection Times (ms)</th></tr>\n",
        	   trstring, tdstring);
            printf("<tr %s><th %s>&nbsp;</th> <th %s>min</th>   <th %s>avg</th>   <th %s>max</th></tr>\n",
        	   trstring, tdstring, tdstring, tdstring, tdstring);
            printf("<tr %s><th %s>Connect:</th>"
        	   "<td %s>%5d</td>"
        	   "<td %s>%5d</td>"
        	   "<td %s>%5d</td></tr>\n",
        	   trstring, tdstring, tdstring, mincon, tdstring, totalcon / requests, tdstring, maxcon);
            printf("<tr %s><th %s>Processing:</th>"
        	   "<td %s>%5d</td>"
        	   "<td %s>%5d</td>"
        	   "<td %s>%5d</td></tr>\n",
        	   trstring, tdstring, tdstring, mintot - mincon, tdstring,
        	   (total / requests) - (totalcon / requests), tdstring, maxtot - maxcon);
            printf("<tr %s><th %s>Total:</th>"
        	   "<td %s>%5d</td>"
        	   "<td %s>%5d</td>"
        	   "<td %s>%5d</td></tr>\n",
        	   trstring, tdstring, tdstring, mintot, tdstring, total / requests, tdstring, maxtot);
        }
        printf("</table>\n");
    }
}

/* --------------------------------------------------------- */

/* start asnchronous non-blocking connection */

static void start_connect(struct connection *c)
{
    apr_status_t rv;

    if(!(started < requests)) return;

    c->read = 0;
    c->bread = 0;
    c->keepalive = 0;
    c->cbx = 0;
    c->gotheader = 0;

    if ((rv = apr_create_tcp_socket(&c->aprsock, cntxt)) != APR_SUCCESS) {
        apr_err("Socket:", rv);
    }
    if ((rv = apr_set_remote_port(c->aprsock, port)) != APR_SUCCESS) {
        apr_err("Port:", rv);
    }
    c->start = apr_now();
    if ((rv = apr_connect(c->aprsock, hostname)) != APR_SUCCESS) {
        if (apr_canonical_error(rv) == APR_EINPROGRESS) {
            c->state = STATE_CONNECTING;
            apr_add_poll_socket(readbits, c->aprsock, APR_POLLOUT);
            return;
        }
        else {
            apr_remove_poll_socket(readbits, c->aprsock);
            apr_close_socket(c->aprsock);
            err_conn++;
            if (bad++ > 10) {
                fprintf(stderr,
                        "\nTest aborted after 10 failures\n\n");
                apr_err("apr_connect()", rv);
            }
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

static void close_connection(struct connection *c)
{
    if (c->read == 0 && c->keepalive) {
        /* server has legitimately shut down an idle keep alive request */
        if (good) good--;	/* connection never happened */
    }
    else {
        if (good == 1) {
            /* first time here */
            doclen = c->bread;
        }
        else if (c->bread != doclen) {
            bad ++;
            err_length++;
        }
        /* save out time */
        if (done < requests) {
            struct data s;
            c->done = apr_now();
            s.read  = c->read;
            s.ctime = (c->connect - c->start) / 1000;
            s.time  = (c->done - c->start) / 1000;
            stats[done++] = s;
        }
    }

    apr_remove_poll_socket(readbits, c->aprsock);
    apr_close_socket(c->aprsock);

    /* connect again */
    start_connect(c);
    return;
}

/* --------------------------------------------------------- */

/* read data from connection */

static void read_connection(struct connection *c)
{
    apr_ssize_t r;
    apr_status_t status;
    char *part;
    char respcode[4];        	/* 3 digits and null */

    r = sizeof(buffer);
    apr_setsocketopt(c->aprsock, APR_SO_TIMEOUT, aprtimeout);
    status = apr_recv(c->aprsock, buffer, &r);
    if (r == 0 || (status != 0 && apr_canonical_error(status) != APR_EAGAIN)) {
        good++;
        close_connection(c);
        return;
    }

    if (apr_canonical_error(status) == APR_EAGAIN)
        return;

    c->read += r;
    totalread += r;

    if (!c->gotheader) {
        char *s;
        int l = 4;
        int space = CBUFFSIZE - c->cbx - 1;  /* -1 to allow for 0 terminator */
        int tocopy = (space < r) ? space : r;
#ifdef NOT_ASCII
        apr_size_t inbytes_left = space, outbytes_left = space;

        status = ap_xlate_conv_buffer(from_ascii, buffer, &inbytes_left,
                                      c->cbuff + c->cbx, &outbytes_left);
        if (status || inbytes_left || outbytes_left) {
            fprintf(stderr, "only simple translation is supported (%d/%u/%u)\n",
                    status, inbytes_left, outbytes_left);
            exit(1);
        }
#else
        memcpy(c->cbuff + c->cbx, buffer, space);
#endif /*NOT_ASCII */
        c->cbx += tocopy;
        space -= tocopy;
        c->cbuff[c->cbx] = 0;  /* terminate for benefit of strstr */
        if (verbosity >= 4) {
            printf("LOG: header received:\n%s\n", c->cbuff);
        }
        s = strstr(c->cbuff, "\r\n\r\n");
            /* this next line is so that we talk to NCSA 1.5 which blatantly 
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
                apr_remove_poll_socket(readbits, c->aprsock);
                apr_close_socket(c->aprsock);
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
               /* this is first time, extract some interesting info */
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

            /* XXX: this parsing isn't even remotely HTTP compliant...
             * but in the interest of speed it doesn't totally have to be,
             * it just needs to be extended to handle whatever servers
             * folks want to test against. -djg */

            /* check response code */
            part = strstr(c->cbuff, "HTTP");   /* really HTTP/1.x_ */
            strncpy(respcode, (part + strlen("HTTP/1.x_")), 3);
            respcode[3] = '\0';
            if (respcode[0] != '2') {
               err_response++;
               if (verbosity >= 2)
                   printf("WARNING: Response code not 2xx (%s)\n", respcode);
            }
            else if (verbosity >= 3) {
               printf("LOG: Response code = %s\n", respcode);
            }

            c->gotheader = 1;
            *s = 0;            /* terminate at end of header */
            if (keepalive &&
               (strstr(c->cbuff, "Keep-Alive")
               || strstr(c->cbuff, "keep-alive"))) {  /* for benefit of MSIIS */
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
           c->done = apr_now();
            s.read = c->read;
           s.ctime = (c->connect - c->start) / 1000;
           s.time = (c->done - c->start) / 1000;
            stats[done++] = s;
        }
        c->keepalive = 0;
        c->length = 0;
        c->gotheader = 0;
        c->cbx = 0;
        c->read = c->bread = 0;
        write_request(c);
        c->start = c->connect; /* zero connect time with keep-alive */
    }
}

/* --------------------------------------------------------- */

/* run the tests */

static void test(void)
{
    apr_time_t now;
    apr_interval_time_t timeout;
    apr_int16_t rv;
    int i;
    apr_status_t status;
#ifdef NOT_ASCII
    apr_size_t inbytes_left, outbytes_left;
#endif

    if (!use_html) {
        printf("Benchmarking %s (be patient)...", hostname);
        fflush(stdout);
    }

    now = apr_now();

    con = malloc(concurrency * sizeof(struct connection));
    memset(con, 0, concurrency * sizeof(struct connection));

    stats = malloc(requests * sizeof(struct data));
    apr_setup_poll(&readbits, concurrency, cntxt);

    /* setup request */
    if (!posting) {
        sprintf(request, "%s %s HTTP/1.0\r\n"
        	"User-Agent: ApacheBench/%s\r\n"
        	"%s" "%s" "%s"
        	"Host: %s\r\n"
        	"Accept: */*\r\n"
        	"%s" "\r\n",
        	(posting == 0) ? "GET" : "HEAD",
        	path,
        	AB_VERSION,
        	keepalive ? "Connection: Keep-Alive\r\n" : "",
        	cookie, auth, hostname, hdrs);
    }
    else {
        sprintf(request, "POST %s HTTP/1.0\r\n"
        	"User-Agent: ApacheBench/%s\r\n"
        	"%s" "%s" "%s"
        	"Host: %s\r\n"
        	"Accept: */*\r\n"
        	"Content-length: %d\r\n"
        	"Content-type: %s\r\n"
        	"%s"
        	"\r\n",
        	path,
        	AB_VERSION,
        	keepalive ? "Connection: Keep-Alive\r\n" : "",
        	cookie, auth,
        	hostname, postlen,
        	(content_type[0]) ? content_type : "text/plain", hdrs);
    }

    if (verbosity >= 2)
        printf("INFO: POST header == \n---\n%s\n---\n", request);

    reqlen = strlen(request);

#ifdef NOT_ASCII
    inbytes_left = outbytes_left = reqlen;
    status = ap_xlate_conv_buffer(to_ascii, request, &inbytes_left,
                                  request, &outbytes_left);
    if (status || inbytes_left || outbytes_left) {
        fprintf(stderr, "only simple translation is supported (%d/%u/%u)\n",
                status, inbytes_left, outbytes_left);
        exit(1);
    }
#endif /*NOT_ASCII*/

    /* ok - lets start */
    start = apr_now();

    /* initialise lots of requests */
    for (i = 0; i < concurrency; i++) {
        con[i].socknum = i;
        start_connect(&con[i]);
    }

    while (done < requests) {
        apr_int32_t n;
        apr_int32_t timed;

        /* check for time limit expiry */
        now = apr_now();
        timed = (now - start) / AP_USEC_PER_SEC;
        if (tlimit && timed > (tlimit * 1000)) {
            requests = done;   /* so stats are correct */
        }
        /* Timeout of 30 seconds. */
        timeout = 30 * AP_USEC_PER_SEC;

        n = concurrency;
        status = apr_poll(readbits, &n, timeout);
        if (status != APR_SUCCESS)
            apr_err("apr_poll", status);

        if (!n) {
            err("\nServer timed out\n\n");
        }

        for (i = 0; i < concurrency; i++) {
            apr_get_revents(&rv, con[i].aprsock, readbits);

            /* Note: APR_POLLHUP is set after FIN is received on some
             * systems, so treat that like APR_POLLIN so that we try
             * to read again.
             */
            if ((rv & APR_POLLERR) || (rv & APR_POLLNVAL)) {
               bad++;
               err_except++;
               start_connect(&con[i]);
               continue;
            }
            if ((rv & APR_POLLIN) || (rv & APR_POLLPRI) || (rv & APR_POLLHUP))
               read_connection(&con[i]);
            if (rv & APR_POLLOUT)
               write_request(&con[i]);
        }
    }
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
        printf("This is ApacheBench, Version %s\n", AB_VERSION " <$Revision: 1.21 $> apache-2.0");
        printf("Copyright (c) 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/\n");
        printf("Copyright (c) 1998-2000 The Apache Software Foundation, http://www.apache.org/\n");
        printf("\n");
    }
    else {
        printf("<p>\n");
        printf(" This is ApacheBench, Version %s <i>&lt;%s&gt;</i> apache-2.0<br>\n", AB_VERSION, "$Revision: 1.21 $");
        printf(" Copyright (c) 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>\n");
        printf(" Copyright (c) 1998-2000 The Apache Software Foundation, http://www.apache.org/<br>\n");
        printf("</p>\n<p>\n");
    }
}

/* display usage information */
static void usage(char *progname)
{
    fprintf(stderr, "Usage: %s [options] [http://]hostname[:port]/path\n", progname);
    fprintf(stderr, "Options are:\n");
    fprintf(stderr, "    -n requests     Number of requests to perform\n");
    fprintf(stderr, "    -c concurrency  Number of multiple requests to make\n");
    fprintf(stderr, "    -t timelimit    Seconds to max. wait for responses\n");
    fprintf(stderr, "    -p postfile     File containg data to POST\n");
    fprintf(stderr, "    -T content-type Content-type header for POSTing\n");
    fprintf(stderr, "    -v verbosity    How much troubleshooting info to print\n");
    fprintf(stderr, "    -w              Print out results in HTML tables\n");
    fprintf(stderr, "    -i              Use HEAD instead of GET\n");
    fprintf(stderr, "    -x attributes   String to insert as table attributes\n");
    fprintf(stderr, "    -y attributes   String to insert as tr attributes\n");
    fprintf(stderr, "    -z attributes   String to insert as td or th attributes\n");
    fprintf(stderr, "    -C attribute    Add cookie, eg. 'Apache=1234. (repeatable)\n");
    fprintf(stderr, "    -H attribute    Add Arbitrary header line, eg. 'Accept-Encoding: zop'\n");
    fprintf(stderr, "                    Inserted after all normal header lines. (repeatable)\n");
    fprintf(stderr, "    -A attribute    Add Basic WWW Authentication, the attributes\n");
    fprintf(stderr, "                    are a colon separated username and password.\n");
    fprintf(stderr, "    -p attribute    Add Basic Proxy Authentication, the attributes\n");
    fprintf(stderr, "                    are a colon separated username and password.\n");
    fprintf(stderr, "    -V              Print version number and exit\n");
    fprintf(stderr, "    -k              Use HTTP KeepAlive feature\n");
    fprintf(stderr, "    -h              Display usage information (this message)\n");
    exit(EINVAL);
}

/* ------------------------------------------------------- */

/* split URL into parts */

static int parse_url(char *url)
{
    char *cp;
    char *h;
    char *p = NULL; /* points to port if url has it */

    if (strlen(url) > 7 && strncmp(url, "http://", 7) == 0)
        url += 7;
    h = url;
    if ((cp = strchr(url, ':')) != NULL) {
        *cp++ = '\0';
        p = cp;
        url = cp;
    }
    if ((cp = strchr(url, '/')) == NULL)
        return 1;
    strcpy(path, cp);
    *cp = '\0';
    strcpy(hostname, h);
    if (p != NULL)
        port = atoi(p);
    return 0;
}

/* ------------------------------------------------------- */

/* read data to POST from file, save contents and length */

static int open_postfile(char *pfile)
{
    apr_file_t *postfd = NULL;
    apr_finfo_t finfo;
    apr_fileperms_t mode = APR_OS_DEFAULT;
    apr_ssize_t length;

    if (apr_open(&postfd, pfile, APR_READ, mode, cntxt) != APR_SUCCESS) {
        printf("Invalid postfile name (%s)\n", pfile);
        return errno;
    }

    apr_getfileinfo(&finfo, postfd);
    postlen = finfo.size;
    postdata = (char *)malloc(postlen);
    if (!postdata) {
        printf("Can\'t alloc postfile buffer\n");
        return ENOMEM;
    }
    length = postlen;
    if (apr_read(postfd, postdata, &length) != APR_SUCCESS &&
        length != postlen) {
        printf("error reading postfilen");
        return EIO;
    }
    return 0;
}

/* ------------------------------------------------------- */

/* sort out command-line args and call test */
int main(int argc, char **argv)
{
    int c, r, l;
    char tmp[1024];
#ifdef NOT_ASCII
    apr_status_t status;
#endif

    /* table defaults  */
    tablestring = "";
    trstring = "";
    tdstring = "bgcolor=white";
    cookie[0] = '\0';
    auth[0] = '\0';
    hdrs[0] = '\0';

    apr_initialize();
    atexit(apr_terminate);
    apr_create_pool(&cntxt, NULL);

#ifdef NOT_ASCII
    status = ap_xlate_open(&to_ascii, "ISO8859-1", APR_DEFAULT_CHARSET, cntxt);
    if (status) {
        fprintf(stderr, "ap_xlate_open(to ASCII)->%d\n", status);
        exit(1);
    }
    status = ap_xlate_open(&from_ascii, APR_DEFAULT_CHARSET, "ISO8859-1", cntxt);
    if (status) {
        fprintf(stderr, "ap_xlate_open(from ASCII)->%d\n", status);
        exit(1);
    }
    status = ap_base64init_ebcdic(to_ascii, from_ascii);
    if (status) {
        fprintf(stderr, "ap_base64init_ebcdic()->%d\n", status);
        exit(1);
    }
#endif

    ap_optind = 1;
    while (apr_getopt(argc, argv, "n:c:t:T:p:v:kVhwix:y:z:C:H:P:A:", &c, cntxt) == APR_SUCCESS) {
        switch (c) {
        case 'n':
            requests = atoi(ap_optarg);
            if (!requests) {
               err("Invalid number of requests\n");
            }
            break;
        case 'k':
            keepalive = 1;
            break;
        case 'c':
            concurrency = atoi(ap_optarg);
            break;
        case 'i':
            if (posting == 1)
                err("Cannot mix POST and HEAD\n");
            posting = -1;
            break;
        case 'p':
            if (posting != 0)
                err("Cannot mix POST and HEAD\n");

            if (0 == (r = open_postfile(ap_optarg))) {
               posting = 1;
            }
            else if (postdata) {
               exit(r);
            }
            break;
        case 'v':
            verbosity = atoi(ap_optarg);
            break;
        case 't':
            tlimit = atoi(ap_optarg);
            requests = MAX_REQUESTS;  /* need to size data array on something */
            break;
        case 'T':
            strcpy(content_type, ap_optarg);
            break;
        case 'C':
            strncat(cookie, "Cookie: ", sizeof(cookie));
            strncat(cookie, ap_optarg, sizeof(cookie));
            strncat(cookie, "\r\n", sizeof(cookie));
            break;
        case 'A':
            /* assume username passwd already to be in colon separated form. 
             * Ready to be uu-encoded.
             */
            while(isspace(*ap_optarg))
                ap_optarg++;
            l=ap_base64encode(tmp, ap_optarg, strlen(ap_optarg));
            tmp[l]='\0';
 
            strncat(auth, "Authorization: basic ", sizeof(auth));
            strncat(auth, tmp, sizeof(auth));
            strncat(auth, "\r\n", sizeof(auth));
            break;
        case 'P':
            /*
             * assume username passwd already to be in colon separated form.
             */
            while(isspace(*ap_optarg))
                ap_optarg++;
            l=ap_base64encode(tmp, ap_optarg, strlen(ap_optarg));
            tmp[l]='\0';
 
            strncat(auth, "Proxy-Authorization: basic ", sizeof(auth));
            strncat(auth, tmp, sizeof(auth));
            strncat(auth, "\r\n", sizeof(auth));
            break;
        case 'H':
            strncat(hdrs, ap_optarg, sizeof(hdrs));
            strncat(hdrs, "\r\n", sizeof(hdrs));
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
	    tablestring = ap_optarg;
	    break;
	case 'y':
	    use_html = 1;
	    trstring = ap_optarg;
	    break;
	case 'z':
	    use_html = 1;
	    tdstring = ap_optarg;
	    break;
	case 'h':
	    usage(argv[0]);
	    break;
	case 'V':
	    copyright();
	    return 0;
        }
    }

    if (ap_optind != argc - 1) {
        fprintf(stderr, "%s: wrong number of arguments\n", argv[0]);
        usage(argv[0]);
    }

    if (parse_url(argv[ap_optind++])) {
        fprintf(stderr, "%s: invalid URL\n", argv[0]);
        usage(argv[0]);
    }

    copyright();
    test();

    return 0;
}
