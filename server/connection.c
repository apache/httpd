/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this 
 *    software must display the following acknowledgment: 
 *    "This product includes software developed by the Apache Group 
 *    for use in the Apache HTTP server project (http://www.apache.org/)." 
 * 
 * 4. The names "Apache Server" and "Apache Group" must not be used to 
 *    endorse or promote products derived from this software without 
 *    prior written permission. For written permission, please contact 
 *    apache@apache.org. 
 * 
 * 5. Products derived from this software may not be called "Apache" 
 *    nor may "Apache" appear in their names without prior written 
 *    permission of the Apache Group. 
 * 
 * 6. Redistributions of any form whatsoever must retain the following 
 *    acknowledgment: 
 *    "This product includes software developed by the Apache Group 
 *    for use in the Apache HTTP server project (http://www.apache.org/)." 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY 
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR 
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
 * OF THE POSSIBILITY OF SUCH DAMAGE. 
 * ==================================================================== 
 * 
 * This software consists of voluntary contributions made by many 
 * individuals on behalf of the Apache Group and was originally based 
 * on public domain software written at the National Center for 
 * Supercomputing Applications, University of Illinois, Urbana-Champaign. 
 * For more information on the Apache Group and the Apache HTTP server 
 * project, please see <http://www.apache.org/>. 
 * 
 */ 
 
#define CORE_PRIVATE
#include "httpd.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_mpm.h"
#include "http_config.h"
#include "http_vhost.h"

/* TODO: re-implement the lingering close stuff */
#define NO_LINGCLOSE

/*
 * More machine-dependent networking gooo... on some systems,
 * you've got to be *really* sure that all the packets are acknowledged
 * before closing the connection, since the client will not be able
 * to see the last response if their TCP buffer is flushed by a RST
 * packet from us, which is what the server's TCP stack will send
 * if it receives any request data after closing the connection.
 *
 * In an ideal world, this function would be accomplished by simply
 * setting the socket option SO_LINGER and handling it within the
 * server's TCP stack while the process continues on to the next request.
 * Unfortunately, it seems that most (if not all) operating systems
 * block the server process on close() when SO_LINGER is used.
 * For those that don't, see USE_SO_LINGER below.  For the rest,
 * we have created a home-brew lingering_close.
 *
 * Many operating systems tend to block, puke, or otherwise mishandle
 * calls to shutdown only half of the connection.  You should define
 * NO_LINGCLOSE in ap_config.h if such is the case for your system.
 */
#ifndef MAX_SECS_TO_LINGER
#define MAX_SECS_TO_LINGER 30
#endif

#ifdef USE_SO_LINGER
#define NO_LINGCLOSE		/* The two lingering options are exclusive */

static void sock_enable_linger(int s) // ZZZZZ abstract the socket, s
{
    struct linger li;                 // ZZZZZ SocketOptions...

    li.l_onoff = 1;
    li.l_linger = MAX_SECS_TO_LINGER;

    if (setsockopt(s, SOL_SOCKET, SO_LINGER, // ZZZZZ abstract, return SUCCESS or not
		   (char *) &li, sizeof(struct linger)) < 0) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf,
	            "setsockopt: (SO_LINGER)");
	/* not a fatal error */
    }
}

#else
#define sock_enable_linger(s)	/* NOOP */
#endif /* USE_SO_LINGER */

#ifndef NO_LINGCLOSE

/* Since many clients will abort a connection instead of closing it,
 * attempting to log an error message from this routine will only
 * confuse the webmaster.  There doesn't seem to be any portable way to
 * distinguish between a dropped connection and something that might be
 * worth logging.
 */
/*ZZZ this routine needs to be adapted for use with poll()*/
static void lingering_close(request_rec *r)     
{
  /*ZZZ remove the hardwired 512. This is an IO Buffer Size */
    char dummybuf[512];    
    struct pollfd pd;
    int lsd;
    int max_wait;

    /* Prevent a slow-drip client from holding us here indefinitely */

    max_wait = 30;
    ap_bsetopt(r->connection->client, BO_TIMEOUT, &max_wait);

    /* Send any leftover data to the client, but never try to again */

    if (ap_bflush(r->connection->client) == -1) {
	ap_bclose(r->connection->client);
	return;
    }
    ap_bsetflag(r->connection->client, B_EOUT, 1);

    /* Close our half of the connection --- send the client a FIN */

    lsd = r->connection->client->fd;

    if ((shutdown(lsd, 1) != 0)  /* ZZZ abstract shutdown */
        || ap_is_aborted(r->connection)) {
	ap_bclose(r->connection->client);
	return;
    }

    /* Set up to wait for readable data on socket... */
    pd.fd = lsd;
    pd.events = POLLIN;

    /* Wait for readable data or error condition on socket;
     * slurp up any data that arrives...  We exit when we go for an
     * interval of tv length without getting any more data, get an error
     * from poll(), get an error or EOF on a read, or the timer expires.
     */
    /* We use a 2 second timeout because current (Feb 97) browsers
     * fail to close a connection after the server closes it.  Thus,
     * to avoid keeping the child busy, we are only lingering long enough
     * for a client that is actively sending data on a connection.
     * This should be sufficient unless the connection is massively
     * losing packets, in which case we might have missed the RST anyway.
     * These parameters are reset on each pass, since they might be
     * changed by poll.
     */
    do {
        pd.revents = 0;
    } while ((poll(&pd, 1, 2) == 1)   
             && read(lsd, dummybuf, sizeof(dummybuf)));
      /* && (time() = epoch) < max_wait); */    /* ZZZZ time function is not good... */

    /* Should now have seen final ack.  Safe to finally kill socket */
    ap_bclose(r->connection->client);
}
#endif /* ndef NO_LINGCLOSE */


CORE_EXPORT(void) ap_process_connection(conn_rec *c)
{
    request_rec *r;

    ap_update_vhost_given_ip(c);

    /*
     * Read and process each request found on our connection
     * until no requests are left or we decide to close.
     */

    while ((r = ap_read_request(c)) != NULL) {

	/* process the request if it was read without error */

	if (r->status == HTTP_OK)
	    ap_process_request(r);

	if (!c->keepalive || c->aborted)
	    break;

	ap_destroy_pool(r->pool);

	if (ap_graceful_stop_signalled()) {
	    /* XXX: hey wait, this should do a lingering_close! */
	    ap_bclose(c->client);
	    return;
	}
    }

    /*
     * Close the connection, being careful to send out whatever is still
     * in our buffers.  If possible, try to avoid a hard close until the
     * client has ACKed our FIN and/or has stopped sending us data.
     */

#ifdef NO_LINGCLOSE
    ap_bclose(c->client);	/* just close it */
#else
    if (r && r->connection
	&& !r->connection->aborted
	&& r->connection->client
	&& (r->connection->client->fd >= 0)) {

	lingering_close(r);
    }
    else {
	ap_bsetflag(c->client, B_EOUT, 1);
	ap_bclose(c->client);
    }
#endif
}
