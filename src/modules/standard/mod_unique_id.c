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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "multithread.h"

typedef struct {
    unsigned int stamp;
    unsigned int in_addr;
    unsigned int pid;
#ifdef MULTITHREAD
    unsigned int tid;
#endif
    unsigned short counter;
} unique_id_rec;

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
 * loop to be extended.
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
 * 1) The UUencoding prodecure is now done in a general way, avoiding
 * the problems with sizes and paddings that can arise depending on
 * the architecture. Now the offsets and sizes of the elements of the
 * unique_id_rec structure are calculated in unique_id_global_init;
 * and then used to duplicate the structure without the paddings that
 * might exist. The multithreaded server fix should be now very easy:
 * just add a new "tid" field to the unique_id_rec structure, and
 * increase by one UNIQUE_ID_REC_MAX.
 * 2) unique_id_rec.stamp has been changed from "time_t" to
 * "unsigned int", because its size is 64bits on some platforms
 * (linux/alpha), and this caused problems with htonl/ntohl. Well,
 * this shouldn't be a problem till year 2106.
 */

static unsigned global_in_addr;

#ifdef WIN32

static DWORD tls_index;

BOOL WINAPI DllMain (HINSTANCE dllhandle, DWORD reason, LPVOID reserved)
{
    LPVOID memptr;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
	tls_index = TlsAlloc();
    case DLL_THREAD_ATTACH: /* intentional no break */
	TlsSetValue(tls_index, calloc(sizeof(unique_id_rec), 1));
	break;
    case DLL_THREAD_DETACH:
	memptr = TlsGetValue(tls_index);
	if (memptr) {
	    free (memptr);
	    TlsSetValue (tls_index, 0);
	}
	break;
    }

    return TRUE;
}

static unique_id_rec* get_cur_unique_id(int parent)
{
    /* Apache initializes the child process, not the individual child threads.
     * Copy the original parent record if this->pid is not yet initialized.
     */
    static unique_id_rec *parent_id;
    unique_id_rec *cur_unique_id = (unique_id_rec *) TlsGetValue(tls_index);

    if (parent) {
        parent_id = cur_unique_id;
    }
    else if (!cur_unique_id->pid) {
        memcpy(cur_unique_id, parent_id, sizeof(*parent_id));
    }
    return cur_unique_id;
}

#else /* !WIN32 */

/* Even when not MULTITHREAD, this will return a single structure, since
 * APACHE_TLS should be defined as empty on single-threaded platforms.
 */
static unique_id_rec* get_cur_unique_id(int parent)
{
    static APACHE_TLS unique_id_rec spcid;
    return &spcid;
}

#endif /* !WIN32 */


/*
 * Number of elements in the structure unique_id_rec.
 */
#ifdef MULTITHREAD
#define UNIQUE_ID_REC_MAX 5
#else
#define UNIQUE_ID_REC_MAX 4
#endif

static unsigned short unique_id_rec_offset[UNIQUE_ID_REC_MAX],
                      unique_id_rec_size[UNIQUE_ID_REC_MAX],
                      unique_id_rec_total_size,
                      unique_id_rec_size_uu;

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
    unique_id_rec *cur_unique_id = get_cur_unique_id(1);

    /*
     * Calculate the sizes and offsets in cur_unique_id.
     */
    unique_id_rec_offset[0] = XtOffsetOf(unique_id_rec, stamp);
    unique_id_rec_size[0] = sizeof(cur_unique_id->stamp);
    unique_id_rec_offset[1] = XtOffsetOf(unique_id_rec, in_addr);
    unique_id_rec_size[1] = sizeof(cur_unique_id->in_addr);
    unique_id_rec_offset[2] = XtOffsetOf(unique_id_rec, pid);
    unique_id_rec_size[2] = sizeof(cur_unique_id->pid);
#ifdef MULTITHREAD
    unique_id_rec_offset[3] = XtOffsetOf(unique_id_rec, tid);
    unique_id_rec_size[3] = sizeof(cur_unique_id->tid);
    unique_id_rec_offset[4] = XtOffsetOf(unique_id_rec, counter);
    unique_id_rec_size[4] = sizeof(cur_unique_id->counter);
    unique_id_rec_total_size = unique_id_rec_size[0] + unique_id_rec_size[1]
                             + unique_id_rec_size[2] + unique_id_rec_size[3]
                             + unique_id_rec_size[4];
#else
    unique_id_rec_offset[3] = XtOffsetOf(unique_id_rec, counter);
    unique_id_rec_size[3] = sizeof(cur_unique_id->counter);
    unique_id_rec_total_size = unique_id_rec_size[0] + unique_id_rec_size[1]
                             + unique_id_rec_size[2] + unique_id_rec_size[3];
#endif

    /*
     * Calculate the size of the structure when encoded.
     */
    unique_id_rec_size_uu = (unique_id_rec_total_size*8+5)/6;

    /*
     * Now get the global in_addr.  Note that it is not sufficient to use one
     * of the addresses from the main_server, since those aren't as likely to
     * be unique as the physical address of the machine
     */
    if (gethostname(str, sizeof(str) - 1) != 0) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, s,
		     "gethostname: mod_unique_id requires the "
		     "hostname of the server");
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
    unique_id_rec *cur_unique_id = get_cur_unique_id(1);

    /*
     * Note that we use the pid because it's possible that on the same
     * physical machine there are multiple servers (i.e. using Listen). But
     * it's guaranteed that none of them will share the same pids between
     * children.
     */
    pid = getpid();
    cur_unique_id->pid = pid;

    /*
     * Test our assumption that the pid is 32-bits.  It's possible that
     * 64-bit machines will declare pid_t to be 64 bits but only use 32
     * of them.  It would have been really nice to test this during
     * global_init ... but oh well.
     */
    if ((pid_t)cur_unique_id->pid != pid) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_CRIT, s,
		     "oh no! pids are greater than 32-bits!  I'm broken!");
    }

    cur_unique_id->in_addr = global_in_addr;

    /*
     * If we use 0 as the initial counter we have a little less protection
     * against restart problems, and a little less protection against a clock
     * going backwards in time.
     */
#ifndef NO_GETTIMEOFDAY
    if (gettimeofday(&tv, NULL) == -1) {
        cur_unique_id->counter = 0;
    }
    else {
	/* Some systems have very low variance on the low end of their
	 * system counter, defend against that.
	 */
        cur_unique_id->counter = tv.tv_usec / 10;
    }
#else
    cur_unique_id->counter = 0;
#endif

    /*
     * We must always use network ordering for these bytes, so that
     * identifiers are comparable between machines of different byte
     * orderings.  Note in_addr is already in network order.
     */
    cur_unique_id->pid = htonl(cur_unique_id->pid);
    cur_unique_id->counter = htons(cur_unique_id->counter);
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
    struct {
	unique_id_rec foo;
	unsigned char pad[2];
    } paddedbuf;
    unsigned char *x,*y;
    unsigned short counter;
    const char *e;
    int i,j,k;
    unique_id_rec *cur_unique_id = get_cur_unique_id(0);

    /* copy the unique_id if this is an internal redirect (we're never
     * actually called for sub requests, so we don't need to test for
     * them) */
    if (r->prev
	&& (e = ap_table_get(r->subprocess_env, "REDIRECT_UNIQUE_ID"))) {
	ap_table_setn(r->subprocess_env, "UNIQUE_ID", e);
	return DECLINED;
    }

    cur_unique_id->stamp = htonl((unsigned int)r->request_time);

#ifdef MULTITHREAD
    /*
     * Note that we use the pid because it's possible that on the same
     * physical machine there are multiple servers (i.e. using Listen). But
     * it's guaranteed that none of them will share the same pid+tids between
     * children.
     */
    cur_unique_id->tid = gettid();
    cur_unique_id->tid = htonl(cur_unique_id->tid);
#endif

    /* we'll use a temporal buffer to avoid uuencoding the possible internal
     * paddings of the original structure
     */
    x = (unsigned char *) &paddedbuf;
    y = (unsigned char *) cur_unique_id;
    k = 0;
    for (i = 0; i < UNIQUE_ID_REC_MAX; i++) {
        y = ((unsigned char *) cur_unique_id) + unique_id_rec_offset[i];
        for (j = 0; j < unique_id_rec_size[i]; j++, k++) {
            x[k] = y[j];
        }
    }
    /*
     * We reset two more bytes just in case padding is needed for
     * the uuencoding.
     */
    x[k++] = '\0';
    x[k++] = '\0';
    
    /* alloc str and do the uuencoding */
    str = (char *)ap_palloc(r->pool, unique_id_rec_size_uu + 1);
    k = 0;
    for (i = 0; i < unique_id_rec_total_size; i += 3) {
        y = x + i;
        str[k++] = uuencoder[y[0] >> 2];
        str[k++] = uuencoder[((y[0] & 0x03) << 4) | ((y[1] & 0xf0) >> 4)];
        if (k == unique_id_rec_size_uu) {
	    break;
	}
        str[k++] = uuencoder[((y[1] & 0x0f) << 2) | ((y[2] & 0xc0) >> 6)];
        if (k == unique_id_rec_size_uu) {
	    break;
	}
        str[k++] = uuencoder[y[2] & 0x3f];
    }
    str[k++] = '\0';

    /* set the environment variable */
    ap_table_setn(r->subprocess_env, "UNIQUE_ID", str);

    /* and increment the identifier for the next call */
    counter = ntohs(cur_unique_id->counter) + 1;
    cur_unique_id->counter = htons(counter);

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
