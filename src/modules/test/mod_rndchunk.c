/* ====================================================================
 * Copyright (c) 1998-1999 The Apache Group.  All rights reserved.
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

/*
 * This module is intended to be used for testing chunked encoding.  It
 * generates a whole whack of output using ap_bputc() and ap_bputs().  It
 * also exercises start_chunk() and end_chunk() in buff.c.  To use it
 * you should use a tool like netcat and the src/test/check_chunked
 * tool.  Add something like this to your access.conf file:
 *
 * <Location /rndchunk>
 * SetHandler rndchunk
 * </Location>
 *
 * Then fake requests such as:
 *
 * GET /rndchunk?0,1000000 HTTP/1.1
 * Host: localhost
 *
 * The first arg is the random seed, the second is the number of
 * "things" to do.  You should try a few seeds.
 *
 * You should also edit main/buff.c and change DEFAULT_BUFSIZE (and
 * CHUNK_HEADER_SIZE).  Small values are particularly useful for
 * finding bugs.  Try a few different values.
 *
 * -djg
 */

#include "httpd.h"
#include "http_protocol.h"
#include "http_config.h"
#include "http_main.h"

#define MAX_SEGMENT	32
#define ONE_WEIGHT	(256-32)

static int send_rndchunk(request_rec *r)
{
    const char *args;
    char *endptr;
    unsigned int seed;
    unsigned int count;
    int i;
    char buf[MAX_SEGMENT + 1];
    unsigned int len;

    r->allowed |= (1 << M_GET);
    if (r->method_number != M_GET)
	return DECLINED;

    r->content_type = "text/html";		
    ap_send_http_header(r);
    if(r->header_only) {
	return 0;
    }
    ap_hard_timeout("send_rndchunk", r);

    if (!r->chunked) {
	ap_rputs("Not chunked!", r);
	ap_kill_timeout(r);
	return 0;
    }

    args = r->args;
    if (!args) {
error:
	ap_rputs("Must include args! ... of the form <code>?seed,count</code>", r);
	ap_kill_timeout(r);
	return 0;
    }
    seed = strtol(args, &endptr, 0);
    if (!endptr || *endptr != ',') {
	goto error;
    }
    ++endptr;
    count = strtol(endptr, &endptr, 0);

    srandom(seed);
    for (i = 0; i < count; ++i) {
	len = random() % (MAX_SEGMENT + ONE_WEIGHT);
	if (len >= MAX_SEGMENT) {
	    ap_rputc((i & 1) ? '0' : '1', r);
	}
	else if (len == 0) {
	    /* not a really nice thing to do, but we need to test
	     * beginning/ending chunks as well
	     */
	    ap_bsetflag(r->connection->client, B_CHUNK, 0);
	    ap_bsetflag(r->connection->client, B_CHUNK, 1);
	}
	else {
	    memset(buf, '2' + len, len);
	    buf[len] = 0;
	    ap_rputs(buf, r);
	}
    }
    ap_kill_timeout(r);
    return 0;
}

static const handler_rec rndchunk_handlers[] =
{
    {"rndchunk", send_rndchunk},
    {NULL}
};

module rndchunk_module = {
    STANDARD_MODULE_STUFF,
    NULL,                       /* initializer */
    NULL,			/* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    NULL,			/* command table */
    rndchunk_handlers,	        /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    NULL,                       /* logger */
    NULL                        /* header parser */
};
