/* ====================================================================
 * Copyright (c) 1995-1998 The Apache Group.  All rights reserved.
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
 * mod_unique_id.c: generate a unique identifier for each request
 *
 * Original author: Dean Gaudet <dgaudet@arctic.org>
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "multithread.h"

#ifdef MULTITHREAD
#error sorry this module does not support multithreaded servers yet
#endif

typedef struct {
    time_t stamp;
    unsigned int in_addr;
    unsigned int pid;
    unsigned short counter;
}      unique_id_rec;

/* Comments:
 *
 * We want an identifier which is unique across all hits, everywhere.
 * "everywhere" includes multiple httpd instances on the same machine, or on
 * multiple machines.  Essentially "everywhere" should include all possible
 * httpds across all servers at a particular "site".  We make some assumptions
 * that if the site has a cluster of machines then their time is relatively
 * synchronized.  We also assume that the first address returned by a
 * gethostbyname (gethostname()) is unique across all the machines at the
 * "site".
 *
 * We also further assume that pids fit in 32-bits.  If something uses more
 * than 32-bits, the fix is trivial, but it requires the unrolled uuencoding
 * loop to be extended.  * A similar fix is needed to support multithreaded
 * servers, using a pid/tid combo.
 *
 * Together, the in_addr and pid are assumed to absolutely uniquely identify
 * this one child from all other currently running children on all servers
 * (including this physical server if it is running multiple httpds) from each
 * other.
 *
 * The stamp and counter are used to distinguish all hits for a particular
 * (in_addr,pid) pair.  The stamp is updated using r->request_time,
 * saving cpu cycles.  The counter is never reset, and is used to permit up to
 * 64k requests in a single second by a single child.
 *
 * The 112-bits of unique_id_rec are uuencoded using the alphabet
 * [A-Za-z0-9@-], resulting in 19 bytes of printable characters.  That is then
 * stuffed into the environment variable UNIQUE_ID so that it is available to
 * other modules.  The alphabet choice differs from normal base64 encoding
 * [A-Za-z0-9+/] because + and / are special characters in URLs and we want to
 * make it easy to use UNIQUE_ID in URLs.
 *
 * Note that UNIQUE_ID should be considered an opaque token by other
 * applications.  No attempt should be made to dissect its internal components.
 * It is an abstraction that may change in the future as the needs of this
 * module change.
 *
 * It is highly desirable that identifiers exist for "eternity".  But future
 * needs (such as much faster webservers, moving to 64-bit pids, or moving to a
 * multithreaded server) may dictate a need to change the contents of
 * unique_id_rec.  Such a future implementation should ensure that the first
 * field is still a time_t stamp.  By doing that, it is possible for a site to
 * have a "flag second" in which they stop all of their old-format servers,
 * wait one entire second, and then start all of their new-servers.  This
 * procedure will ensure that the new space of identifiers is completely unique
 * from the old space.  (Since the first four unencoded bytes always differ.)
 */

static unsigned global_in_addr;

static APACHE_TLS unique_id_rec cur_unique_id;

static void unique_id_global_init(server_rec *s, pool *p)
{
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif
    char str[MAXHOSTNAMELEN + 1];
    struct hostent *hent;
#ifndef NO_GETTIMEOFDAY
    struct timeval tv;
#endif

    /*
     * First of all, verify some assumptions that have been made about the
     * contents of unique_id_rec.  We do it this way because it isn't
     * affected by trailing padding.
     */
    if (XtOffsetOf(unique_id_rec, counter) + sizeof(cur_unique_id.counter)
        != 14) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, s,
                    "mod_unique_id: sorry the size assumptions are wrong "
                    "in mod_unique_id.c, please remove it from your server "
                    "or fix the code!");
        exit(1);
    }

    /*
     * Now get the global in_addr.  Note that it is not sufficient to use one
     * of the addresses from the main_server, since those aren't as likely to
     * be unique as the physical address of the machine
     */
    if (gethostname(str, sizeof(str) - 1) != 0) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, s,
          "gethostname: mod_unique_id requires the hostname of the server");
        exit(1);
    }
    str[sizeof(str) - 1] = '\0';

    if ((hent = gethostbyname(str)) == NULL) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, s,
                    "mod_unique_id: unable to gethostbyname(\"%s\")", str);
        exit(1);
    }

    global_in_addr = ((struct in_addr *) hent->h_addr_list[0])->s_addr;

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, s,
                "mod_unique_id: using ip addr %s",
                inet_ntoa(*(struct in_addr *) hent->h_addr_list[0]));

    /*
     * If the server is pummelled with restart requests we could possibly end
     * up in a situation where we're starting again during the same second
     * that has been used in previous identifiers.  Avoid that situation.
     * 
     * In truth, for this to actually happen not only would it have to restart
     * in the same second, but it would have to somehow get the same pids as
     * one of the other servers that was running in that second. Which would
     * mean a 64k wraparound on pids ... not very likely at all.
     * 
     * But protecting against it is relatively cheap.  We just sleep into the
     * next second.
     */
#ifdef NO_GETTIMEOFDAY
    sleep(1);
#else
    if (gettimeofday(&tv, NULL) == -1) {
        sleep(1);
    }
    else if (tv.tv_usec) {
        tv.tv_sec = 0;
        tv.tv_usec = 1000000 - tv.tv_usec;
        select(0, NULL, NULL, NULL, &tv);
    }
#endif
}

static void unique_id_child_init(server_rec *s, pool *p)
{
    pid_t pid;
#ifndef NO_GETTIMEOFDAY
    struct timeval tv;
#endif

    /*
     * Note that we use the pid because it's possible that on the same
     * physical machine there are multiple servers (i.e. using Listen). But
     * it's guaranteed that none of them will share the same pids between
     * children.
     * 
     * XXX: for multithread this needs to use a pid/tid combo and probably
     * needs to be expanded to 32 bits
     */
    pid = getpid();
    cur_unique_id.pid = pid;

    /*
     * Test our assumption that the pid is 32-bits.  It's possible that
     * 64-bit machines will declare pid_t to be 64 bits but only use 32
     * of them.  It would have been really nice to test this during
     * global_init ... but oh well.
     */
    if (cur_unique_id.pid != pid) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_CRIT, s,
                    "oh no! pids are greater than 32-bits!  I'm broken!");
    }

    cur_unique_id.in_addr = global_in_addr;

    /*
     * If we use 0 as the initial counter we have a little less protection
     * against restart problems, and a little less protection against a clock
     * going backwards in time.
     */
#ifndef NO_GETTIMEOFDAY
    if (gettimeofday(&tv, NULL) == -1) {
        cur_unique_id.counter = 0;
    }
    else {
	/* Some systems have very low variance on the low end of their
	 * system counter, defend against that.
	 */
        cur_unique_id.counter = tv.tv_usec / 10;
    }
#else
    cur_unique_id.counter = 0;
#endif

    /*
     * We must always use network ordering for these bytes, so that
     * identifiers are comparable between machines of different byte
     * orderings.  Note in_addr is already in network order.
     */
    cur_unique_id.pid = htons(cur_unique_id.pid);
    cur_unique_id.counter = htons(cur_unique_id.counter);
}

/* NOTE: This is *NOT* the same encoding used by uuencode ... the last two
 * characters should be + and /.  But those two characters have very special
 * meanings in URLs, and we want to make it easy to use identifiers in
 * URLs.  So we replace them with @ and -.
 */
static const char uuencoder[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '@', '-',
};

static int gen_unique_id(request_rec *r)
{
    /* when we uuencode it will take 19 bytes plus \0 */
    char str[19 + 1];
    const unsigned char *x;
    unsigned short counter;
    char *e;

    /* copy the unique_id if this is an internal redirect (we're never
     * actually called for sub requests, so we don't need to test for
     * them) */
    if (r->prev && (e = ap_table_get(r->subprocess_env, "REDIRECT_UNIQUE_ID"))) {
	ap_table_setn(r->subprocess_env, "UNIQUE_ID", e);
	return DECLINED;
    }

    cur_unique_id.stamp = htonl(r->request_time);

    /* do the uuencoding */
    x = (const unsigned char *) &cur_unique_id;
    str[0] = uuencoder[x[0] >> 2];
    str[1] = uuencoder[((x[0] & 0x03) << 4) | ((x[1] & 0xf0) >> 4)];
    str[2] = uuencoder[((x[1] & 0x0f) << 2) | ((x[2] & 0xc0) >> 6)];
    str[3] = uuencoder[x[2] & 0x3f];
    x += 3;
    str[4] = uuencoder[x[0] >> 2];
    str[5] = uuencoder[((x[0] & 0x03) << 4) | ((x[1] & 0xf0) >> 4)];
    str[6] = uuencoder[((x[1] & 0x0f) << 2) | ((x[2] & 0xc0) >> 6)];
    str[7] = uuencoder[x[2] & 0x3f];
    x += 3;
    str[8] = uuencoder[x[0] >> 2];
    str[9] = uuencoder[((x[0] & 0x03) << 4) | ((x[1] & 0xf0) >> 4)];
    str[10] = uuencoder[((x[1] & 0x0f) << 2) | ((x[2] & 0xc0) >> 6)];
    str[11] = uuencoder[x[2] & 0x3f];
    x += 3;
    str[12] = uuencoder[x[0] >> 2];
    str[13] = uuencoder[((x[0] & 0x03) << 4) | ((x[1] & 0xf0) >> 4)];
    str[14] = uuencoder[((x[1] & 0x0f) << 2) | ((x[2] & 0xc0) >> 6)];
    str[15] = uuencoder[x[2] & 0x3f];
    x += 3;
    str[16] = uuencoder[x[0] >> 2];
    str[17] = uuencoder[((x[0] & 0x03) << 4) | ((x[1] & 0xf0) >> 4)];
    str[18] = uuencoder[((x[1] & 0x0f) << 2) | ((0 & 0xc0) >> 6)];
    str[19] = '\0';

    ap_table_setn(r->subprocess_env, "UNIQUE_ID", ap_pstrdup(r->pool, str));

    /* and increment the identifier for the next call */
    counter = ntohs(cur_unique_id.counter) + 1;
    cur_unique_id.counter = htons(counter);

    return DECLINED;
}


module MODULE_VAR_EXPORT unique_id_module = {
    STANDARD_MODULE_STUFF,
    unique_id_global_init,      /* initializer */
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    NULL,                       /* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    unique_id_child_init,       /* child_init */
    NULL,                       /* child_exit */
    gen_unique_id               /* post_read_request */
};
