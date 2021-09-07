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
 * mod_unique_id.c: generate a unique identifier for each request
 *
 * Original author: Dean Gaudet <dgaudet@arctic.org>
 * UUencoding modified by: Alvaro Martinez Echevarria <alvaro@lander.es>
 */

#define APR_WANT_BYTEFUNC   /* for htons() et al */
#include "apr_want.h"
#include "apr_general.h"    /* for APR_OFFSETOF                */
#include "apr_network_io.h"

#ifdef APR_HAS_THREADS
#include "apr_atomic.h"     /* for apr_atomic_inc32 */
#include "mpm_common.h"     /* for ap_mpm_query */
#endif

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"  /* for ap_hook_post_read_request */

#define ROOT_SIZE 10

typedef struct {
    unsigned int stamp;
    char root[ROOT_SIZE];
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
 * The root is assumed to absolutely uniquely identify this one child
 * from all other currently running children on all servers (including
 * this physical server if it is running multiple httpds) from each
 * other.
 *
 * The stamp and counter are used to distinguish all hits for a
 * particular root.  The stamp is updated using r->request_time,
 * saving cpu cycles.  The counter is never reset, and is used to
 * permit up to 64k requests in a single second by a single child.
 *
 * The 144-bits of unique_id_rec are encoded using the alphabet
 * [A-Za-z0-9@-], resulting in 24 bytes of printable characters.  That is then
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
 * needs (such as much faster webservers, or moving to a
 * multithreaded server) may dictate a need to change the contents of
 * unique_id_rec.  Such a future implementation should ensure that the first
 * field is still a time_t stamp.  By doing that, it is possible for a site to
 * have a "flag second" in which they stop all of their old-format servers,
 * wait one entire second, and then start all of their new-servers.  This
 * procedure will ensure that the new space of identifiers is completely unique
 * from the old space.  (Since the first four unencoded bytes always differ.)
 *
 * Note: previous implementations used 32-bits of IP address plus pid
 * in place of the PRNG output in the "root" field.  This was
 * insufficient for IPv6-only hosts, required working DNS to determine
 * a unique IP address (fragile), and needed a [0, 1) second sleep
 * call at startup to avoid pid reuse.  Use of the PRNG avoids all
 * these issues.
 */

/*
 * Sun Jun  7 05:43:49 CEST 1998 -- Alvaro
 * More comments:
 * 1) The UUencoding procedure is now done in a general way, avoiding the problems
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

/*
 * XXX: We should have a per-thread counter and not use cur_unique_id.counter
 * XXX: in all threads, because this is bad for performance on multi-processor
 * XXX: systems: Writing to the same address from several CPUs causes cache
 * XXX: thrashing.
 */
static unique_id_rec cur_unique_id;
static apr_uint32_t cur_unique_counter;
#ifdef APR_HAS_THREADS
static int is_threaded_mpm;
#endif

/*
 * Number of elements in the structure unique_id_rec.
 */
#define UNIQUE_ID_REC_MAX 4

static unsigned short unique_id_rec_offset[UNIQUE_ID_REC_MAX],
                      unique_id_rec_size[UNIQUE_ID_REC_MAX],
                      unique_id_rec_total_size,
                      unique_id_rec_size_uu;

static int unique_id_global_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *main_server)
{
    /*
     * Calculate the sizes and offsets in cur_unique_id.
     */
    unique_id_rec_offset[0] = APR_OFFSETOF(unique_id_rec, stamp);
    unique_id_rec_size[0] = sizeof(cur_unique_id.stamp);
    unique_id_rec_offset[1] = APR_OFFSETOF(unique_id_rec, root);
    unique_id_rec_size[1] = sizeof(cur_unique_id.root);
    unique_id_rec_offset[2] = APR_OFFSETOF(unique_id_rec, counter);
    unique_id_rec_size[2] = sizeof(cur_unique_id.counter);
    unique_id_rec_offset[3] = APR_OFFSETOF(unique_id_rec, thread_index);
    unique_id_rec_size[3] = sizeof(cur_unique_id.thread_index);
    unique_id_rec_total_size = unique_id_rec_size[0] + unique_id_rec_size[1] +
                               unique_id_rec_size[2] + unique_id_rec_size[3];

    /*
     * Calculate the size of the structure when encoded.
     */
    unique_id_rec_size_uu = (unique_id_rec_total_size*8+5)/6;

    return OK;
}

static void unique_id_child_init(apr_pool_t *p, server_rec *s)
{
#ifdef APR_HAS_THREADS
    is_threaded_mpm = 0;
    ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded_mpm);
#endif

    ap_random_insecure_bytes(&cur_unique_id.root,
                             sizeof(cur_unique_id.root));

    /*
     * If we use 0 as the initial counter we have a little less protection
     * against restart problems, and a little less protection against a clock
     * going backwards in time.
     */
    ap_random_insecure_bytes(&cur_unique_counter,
                             sizeof(cur_unique_counter));
}

/* Use the base64url encoding per RFC 4648, avoiding characters which
 * are not safe in URLs.  ### TODO: can switch to apr_encode_*. */
static const char uuencoder[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_',
};

#ifndef APR_UINT16_MAX
#define APR_UINT16_MAX 0xffffu
#endif

static const char *gen_unique_id(const request_rec *r)
{
    char *str;
    /*
     * Buffer padded with two final bytes, used to copy the unique_id_rec
     * structure without the internal paddings that it could have.
     */
    unique_id_rec new_unique_id;
    struct {
        unique_id_rec foo;
        unsigned char pad[2];
    } paddedbuf;
    apr_uint32_t counter;
    unsigned char *x,*y;
    int i,j,k;

    memcpy(&new_unique_id.root, &cur_unique_id.root, ROOT_SIZE);
    new_unique_id.stamp = htonl((unsigned int)apr_time_sec(r->request_time));
    new_unique_id.thread_index = htonl((unsigned int)r->connection->id);
#ifdef APR_HAS_THREADS
    if (is_threaded_mpm)
        counter = apr_atomic_inc32(&cur_unique_counter);
    else
#endif
        counter = cur_unique_counter++;

    /* The counter is two bytes for the uuencoded unique id, in network
     * byte order.
     */
    new_unique_id.counter = htons(counter % APR_UINT16_MAX);

    /* we'll use a temporal buffer to avoid uuencoding the possible internal
     * paddings of the original structure */
    x = (unsigned char *) &paddedbuf;
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

    return str;
}

/*
 * There are two ways the generation of a unique id can be triggered:
 *
 * - from the post_read_request hook which calls set_unique_id()
 * - from error logging via the generate_log_id hook which calls
 *   generate_log_id(). This may happen before or after set_unique_id()
 *   has been called, or not at all.
 */

static int generate_log_id(const conn_rec *c, const request_rec *r,
                           const char **id)
{
    /* we do not care about connection ids */
    if (r == NULL)
        return DECLINED;

    /* XXX: do we need special handling for internal redirects? */

    /* if set_unique_id() has been called for this request, use it */
    *id = apr_table_get(r->subprocess_env, "UNIQUE_ID");

    if (!*id)
        *id = gen_unique_id(r);
    return OK;
}

static int set_unique_id(request_rec *r)
{
    const char *id = NULL;
    /* copy the unique_id if this is an internal redirect (we're never
     * actually called for sub requests, so we don't need to test for
     * them) */
    if (r->prev) {
       id = apr_table_get(r->subprocess_env, "REDIRECT_UNIQUE_ID");
    }

    if (!id) {
        /* if we have a log id, it was set by our generate_log_id() function
         * and we should reuse the same id
         */
        id = r->log_id;
    }

    if (!id) {
        id = gen_unique_id(r);
    }

    /* set the environment variable */
    apr_table_setn(r->subprocess_env, "UNIQUE_ID", id);

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(unique_id_global_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(unique_id_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(set_unique_id, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_generate_log_id(generate_log_id, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(unique_id) = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};
