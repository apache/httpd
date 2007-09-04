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
#ifdef CHARSET_EBCDIC
    /* Server-generated response, converted */
    ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, r->ebcdic.conv_out = 1);
#endif
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
    seed = ap_strtol(args, &endptr, 0);
    if (!endptr || *endptr != ',') {
	goto error;
    }
    ++endptr;
    count = ap_strtol(endptr, &endptr, 0);

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
