/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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
 * mod_unique_id.c: generate a unique identifier for each request
 *
 * Original author: Dean Gaudet <dgaudet@arctic.org>
 * UUencoding modified by: Alvaro Martinez Echevarria <alvaro@lander.es>
 */

#define APR_WANT_BYTEFUNC   /* for htons() et al */
#include "apr_want.h"
#include "apr_general.h"    /* for APR_OFFSETOF                */
#include "apr_network_io.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"  /* for ap_hook_post_read_request */

#if APR_HAVE_UNISTD_H
#include <unistd.h>         /* for getpid() */
#endif

typedef struct {
    unsigned int stamp;
    unsigned int in_addr;
    unsigned int pid;
    unsigned short counter;
    unsigned int thread_index;
} unique_id_rec;

/* We are using thread_index (the index into the scoreboard), because we
 * cannot guarantee the thread_id will be an integer.
 *
 * This code looks like it won't give a unique ID with the new thread logic.
 * It will.  The reason is, we don't increment the counter in a thread_safe 
 * manner.  Because the thread_index is also in the unique ID now, this does
 * not matter.  In order for the id to not be unique, the same thread would
 * have to get the same counter twice in the same second. 
 */

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
 * The 112-bits of unique_id_rec are encoded using the alphabet
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
/*
 * Sun Jun  7 05:43:49 CEST 1998 -- Alvaro
 * More comments:
 * 1) The UUencoding prodecure is now done in a general way, avoiding the problems
 * with sizes and paddings that can arise depending on the architecture. Now the
 * offsets and sizes of the elements of the unique_id_rec structure are calculated
 * in unique_id_global_init; and then used to duplicate the structure without the
 * paddings that might exist. The multithreaded server fix should be now very easy:
 * just add a new "tid" field to the unique_id_rec structure, and increase by one
 * UNIQUE_ID_REC_MAX.
 * 2) unique_id_rec.stamp has been changed from "time_t" to "unsigned int", because
 * its size is 64bits on some platforms (linux/alpha), and this caused problems with
 * htonl/ntohl. Well, this shouldn't be a problem till year 2106.
 */

static unsigned global_in_addr;

static unique_id_rec cur_unique_id;

/*
 * Number of elements in the structure unique_id_rec.
 */
#define UNIQUE_ID_REC_MAX 5 

static unsigned short unique_id_rec_offset[UNIQUE_ID_REC_MAX],
                      unique_id_rec_size[UNIQUE_ID_REC_MAX],
                      unique_id_rec_total_size,
                      unique_id_rec_size_uu;

static int unique_id_global_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *main_server)
{
    char str[APRMAXHOSTLEN + 1];
    apr_status_t rv;
    char *ipaddrstr;
    apr_sockaddr_t *sockaddr;

    /*
     * Calculate the sizes and offsets in cur_unique_id.
     */
    unique_id_rec_offset[0] = APR_OFFSETOF(unique_id_rec, stamp);
    unique_id_rec_size[0] = sizeof(cur_unique_id.stamp);
    unique_id_rec_offset[1] = APR_OFFSETOF(unique_id_rec, in_addr);
    unique_id_rec_size[1] = sizeof(cur_unique_id.in_addr);
    unique_id_rec_offset[2] = APR_OFFSETOF(unique_id_rec, pid);
    unique_id_rec_size[2] = sizeof(cur_unique_id.pid);
    unique_id_rec_offset[3] = APR_OFFSETOF(unique_id_rec, counter);
    unique_id_rec_size[3] = sizeof(cur_unique_id.counter);
    unique_id_rec_offset[4] = APR_OFFSETOF(unique_id_rec, thread_index);
    unique_id_rec_size[4] = sizeof(cur_unique_id.thread_index);
    unique_id_rec_total_size = unique_id_rec_size[0] + unique_id_rec_size[1] +
                               unique_id_rec_size[2] + unique_id_rec_size[3] +
                               unique_id_rec_size[4];

    /*
     * Calculate the size of the structure when encoded.
     */
    unique_id_rec_size_uu = (unique_id_rec_total_size*8+5)/6;

    /*
     * Now get the global in_addr.  Note that it is not sufficient to use one
     * of the addresses from the main_server, since those aren't as likely to
     * be unique as the physical address of the machine
     */
    if ((rv = apr_gethostname(str, sizeof(str) - 1, p)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, main_server,
          "mod_unique_id: unable to find hostname of the server");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if ((rv = apr_sockaddr_info_get(&sockaddr, str, AF_INET, 0, 0, p)) == APR_SUCCESS) {
        global_in_addr = sockaddr->sa.sin.sin_addr.s_addr;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, main_server,
                    "mod_unique_id: unable to find IPv4 address of \"%s\"", str);
#if APR_HAVE_IPV6
        if ((rv = apr_sockaddr_info_get(&sockaddr, str, AF_INET6, 0, 0, p)) == APR_SUCCESS) {
            memcpy(&global_in_addr,
                   (char *)sockaddr->ipaddr_ptr + sockaddr->ipaddr_len - sizeof(global_in_addr),
                   sizeof(global_in_addr));
            ap_log_error(APLOG_MARK, APLOG_ALERT, rv, main_server,
                         "mod_unique_id: using low-order bits of IPv6 address "
                         "as if they were unique");
        }
        else
#endif
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_sockaddr_ip_get(&ipaddrstr, sockaddr);
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, main_server,
                "mod_unique_id: using ip addr %s",
                 ipaddrstr);

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
    apr_sleep(apr_time_from_sec(1) - apr_time_usec(apr_time_now()));
    return OK;
}

static void unique_id_child_init(apr_pool_t *p, server_rec *s)
{
    pid_t pid;
    apr_time_t tv;

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
    if ((pid_t)cur_unique_id.pid != pid) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                    "oh no! pids are greater than 32-bits!  I'm broken!");
    }

    cur_unique_id.in_addr = global_in_addr;

    /*
     * If we use 0 as the initial counter we have a little less protection
     * against restart problems, and a little less protection against a clock
     * going backwards in time.
     */
    tv = apr_time_now();
    /* Some systems have very low variance on the low end of their system
     * counter, defend against that.
     */
    cur_unique_id.counter = (unsigned short)(apr_time_usec(tv) / 10);

    /*
     * We must always use network ordering for these bytes, so that
     * identifiers are comparable between machines of different byte
     * orderings.  Note in_addr is already in network order.
     */
    cur_unique_id.pid = htonl(cur_unique_id.pid);
    cur_unique_id.counter = htons(cur_unique_id.counter);
}

/* NOTE: This is *NOT* the same encoding used by base64encode ... the last two
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
    char *str;
    /*
     * Buffer padded with two final bytes, used to copy the unique_id_red
     * structure without the internal paddings that it could have.
     */
    unique_id_rec new_unique_id;
    struct {
	unique_id_rec foo;
	unsigned char pad[2];
    } paddedbuf;
    unsigned char *x,*y;
    unsigned short counter;
    const char *e;
    int i,j,k;

    /* copy the unique_id if this is an internal redirect (we're never
     * actually called for sub requests, so we don't need to test for
     * them) */
    if (r->prev && (e = apr_table_get(r->subprocess_env, "REDIRECT_UNIQUE_ID"))) {
	apr_table_setn(r->subprocess_env, "UNIQUE_ID", e);
	return DECLINED;
    }
    
    new_unique_id.in_addr = cur_unique_id.in_addr;
    new_unique_id.pid = cur_unique_id.pid;
    new_unique_id.counter = cur_unique_id.counter;

    new_unique_id.stamp = htonl((unsigned int)r->request_time);
    new_unique_id.thread_index = htonl((unsigned int)r->connection->id);

    /* we'll use a temporal buffer to avoid uuencoding the possible internal
     * paddings of the original structure */
    x = (unsigned char *) &paddedbuf;
    y = (unsigned char *) &new_unique_id;
    k = 0;
    for (i = 0; i < UNIQUE_ID_REC_MAX; i++) {
        y = ((unsigned char *) &new_unique_id) + unique_id_rec_offset[i];
        for (j = 0; j < unique_id_rec_size[i]; j++, k++) {
            x[k] = y[j];
        }
    }
    /*
     * We reset two more bytes just in case padding is needed for the uuencoding.
     */
    x[k++] = '\0';
    x[k++] = '\0';
    
    /* alloc str and do the uuencoding */
    str = (char *)apr_palloc(r->pool, unique_id_rec_size_uu + 1);
    k = 0;
    for (i = 0; i < unique_id_rec_total_size; i += 3) {
        y = x + i;
        str[k++] = uuencoder[y[0] >> 2];
        str[k++] = uuencoder[((y[0] & 0x03) << 4) | ((y[1] & 0xf0) >> 4)];
        if (k == unique_id_rec_size_uu) break;
        str[k++] = uuencoder[((y[1] & 0x0f) << 2) | ((y[2] & 0xc0) >> 6)];
        if (k == unique_id_rec_size_uu) break;
        str[k++] = uuencoder[y[2] & 0x3f];
    }
    str[k++] = '\0';

    /* set the environment variable */
    apr_table_setn(r->subprocess_env, "UNIQUE_ID", str);

    /* and increment the identifier for the next call */

    counter = ntohs(new_unique_id.counter) + 1;
    cur_unique_id.counter = htons(counter);

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(unique_id_global_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(unique_id_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(gen_unique_id, NULL, NULL, APR_HOOK_MIDDLE); 
}

module AP_MODULE_DECLARE_DATA unique_id_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};
