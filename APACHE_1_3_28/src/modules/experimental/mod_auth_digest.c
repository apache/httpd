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
 * mod_auth_digest: MD5 digest authentication
 *
 * Originally by Alexei Kosut <akosut@nueva.pvt.k12.ca.us>
 * Updated to RFC-2617 by Ronald Tschalär <ronald@innovation.ch>
 * based on mod_auth, by Rob McCool and Robert S. Thau
 *
 * This module an updated version of modules/standard/mod_digest.c
 * However, it has not been extensively tested yet, and is therefore
 * currently marked experimental. Send problem reports to me
 * (ronald@innovation.ch)
 *
 * Requires either /dev/random (or equivalent) or the truerand library,
 * available for instance from
 * ftp://research.att.com/dist/mab/librand.shar
 *
 * Open Issues:
 *   - qop=auth-int (when streams and trailer support available)
 *   - nonce-format configurability
 *   - Proxy-Authorization-Info header is set by this module, but is
 *     currently ignored by mod_proxy (needs patch to mod_proxy)
 *   - generating the secret takes a while (~ 8 seconds) if using the
 *     truerand library
 *   - The source of the secret should be run-time directive (with server
 *     scope: RSRC_CONF). However, that could be tricky when trying to
 *     choose truerand vs. file...
 *   - shared-mem not completely tested yet. Seems to work ok for me,
 *     but... (definitely won't work on Windoze)
 *   - Sharing a realm among multiple servers has following problems:
 *     o Server name and port can't be included in nonce-hash
 *       (we need two nonce formats, which must be configured explicitly)
 *     o Nonce-count check can't be for equal, or then nonce-count checking
 *       must be disabled. What we could do is the following:
 *       (expected < received) ? set expected = received : issue error
 *       The only problem is that it allows replay attacks when somebody
 *       captures a packet sent to one server and sends it to another
 *       one. Should we add "AuthDigestNcCheck Strict"?
 */

/* The section for the Configure script:
 * MODULE-DEFINITION-START
 * Name: digest_auth_module
 * ConfigStart

    RULE_DEV_RANDOM=`./helpers/CutRule DEV_RANDOM $file`
    if [ "$RULE_DEV_RANDOM" = "default" ]; then
	if [ -r "/dev/random" ]; then
	    RULE_DEV_RANDOM="/dev/random"
	elif [ -r "/dev/urandom" ]; then
	    RULE_DEV_RANDOM="/dev/urandom"
	else
	    RULE_DEV_RANDOM="truerand"
	    if helpers/TestCompile func randbyte; then
		:
	    elif helpers/TestCompile lib rand randbyte; then
		:
	    else
		echo "      (mod_auth_digest) truerand library missing!"
		echo "** This will most probably defeat successful compilation."
		echo "** See Rule DEV_RANDOM in src/Configuration.tmpl for more information."
	    fi
	fi
    fi
    if [ "$RULE_DEV_RANDOM" = "truerand" ]; then
	echo "      using truerand library (-lrand) for the random seed"
	LIBS="$LIBS -L/usr/local/lib -lrand"
    else
	echo "      using $RULE_DEV_RANDOM for the random seed"
	CFLAGS="$CFLAGS -DDEV_RANDOM=$RULE_DEV_RANDOM"
    fi

 * ConfigEnd
 * MODULE-DEFINITION-END
 */

#include "httpd.h"
#include "http_config.h"
#include "http_conf_globals.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "ap_ctype.h"
#include "util_uri.h"
#include "util_md5.h"
#include "ap_sha1.h"

#ifdef WIN32
/* Crypt APIs are available on Win95 with OSR 2 */
#include <wincrypt.h>
#endif

#ifdef HAVE_SHMEM_MM
#include "mm.h"
#endif	/* HAVE_SHMEM_MM */


/* struct to hold the configuration info */

typedef struct digest_config_struct {
    const char  *dir_name;
    const char  *pwfile;
    const char  *grpfile;
    const char  *realm;
    const char **qop_list;
    AP_SHA1_CTX  nonce_ctx;
    long         nonce_lifetime;
    const char  *nonce_format;
    int          check_nc;
    const char  *algorithm;
    char        *uri_list;
    const char  *ha1;
} digest_config_rec;


#define	DFLT_ALGORITHM	"MD5"

#define	DFLT_NONCE_LIFE	300L
#define NEXTNONCE_DELTA	30


#define NONCE_TIME_LEN	(((sizeof(time_t)+2)/3)*4)
#define NONCE_HASH_LEN	(2*SHA_DIGESTSIZE)
#define NONCE_LEN	(NONCE_TIME_LEN + NONCE_HASH_LEN)

#define	SECRET_LEN	20


/* client list definitions */

typedef struct hash_entry {
    unsigned long      key;			/* the key for this entry    */
    struct hash_entry *next;			/* next entry in the bucket  */
    unsigned long      nonce_count;		/* for nonce-count checking  */
    char               ha1[2*MD5_DIGESTSIZE+1];	/* for algorithm=MD5-sess    */
    char               last_nonce[NONCE_LEN+1];	/* for one-time nonce's      */
} client_entry;

static struct hash_table {
    client_entry  **table;
    unsigned long   tbl_len;
    unsigned long   num_entries;
    unsigned long   num_created;
    unsigned long   num_removed;
    unsigned long   num_renewed;
} *client_list;


/* struct to hold a parsed Authorization header */

enum hdr_sts { NO_HEADER, NOT_DIGEST, INVALID, VALID };

typedef struct digest_header_struct {
    const char           *scheme;
    const char           *realm;
    const char           *username;
          char           *nonce;
    const char           *uri;
    const char           *digest;
    const char           *algorithm;
    const char           *cnonce;
    const char           *opaque;
    unsigned long         opaque_num;
    const char           *message_qop;
    const char           *nonce_count;
    /* the following fields are not (directly) from the header */
    time_t                nonce_time;
    enum hdr_sts          auth_hdr_sts;
    const char           *raw_request_uri;
    uri_components       *psd_request_uri;
    int                   needed_auth;
    client_entry         *client;
} digest_header_rec;


/* (mostly) nonce stuff */

typedef union time_union {
    time_t	  time;
    unsigned char arr[sizeof(time_t)];
} time_rec;


static unsigned char secret[SECRET_LEN];
static int call_cnt = 0;


#ifdef HAVE_SHMEM_MM
/* opaque stuff */

static MM            *opaque_mm;
static unsigned long *opaque_cntr;

static MM            *client_mm;

static MM            *otn_count_mm;
static time_t        *otn_counter;	/* one-time-nonce counter */

#define	SHMEM_SIZE 	1000		/* ~ 12 entries */
#define	NUM_BUCKETS	15UL

#else	/* HAVE_SHMEM_MM */
static void          *client_mm = NULL;
#endif	/* HAVE_SHMEM_MM */

module MODULE_VAR_EXPORT digest_auth_module;

/*
 * initialization code
 */

#ifdef HAVE_SHMEM_MM
static void cleanup_tables(void *not_used)
{
    fprintf(stderr, "Digest: cleaning up shared memory\n");
    fflush(stderr);

    if (client_mm) {
	mm_destroy(client_mm);
	client_mm = NULL;
    }

    if (opaque_mm) {
	mm_destroy(opaque_mm);
	opaque_mm = NULL;
    }

    if (otn_count_mm) {
	mm_destroy(otn_count_mm);
	otn_count_mm = NULL;
    }
}
#endif	/* HAVE_SHMEM_MM */

#ifdef __OpenBSD__
static void initialize_secret(server_rec *s)
{
    u_int32_t rnd = 0, i;

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s,
		 "Digest: generating secret for digest authentication ...");

    for (i = 0; i < sizeof(secret); i++) {
	if (i % 4 == 0)
	    rnd = arc4random();
	secret[i] = rnd;
	rnd >>= 8;
    }
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s,
		 "Digest: done");
}
#elif defined(WIN32)
/* TODO: abstract out the random number generation. APR? */
static void initialize_secret(server_rec *s)
{
    HCRYPTPROV hProv;

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s,
		 "Digest: generating secret for digest authentication ...");
    if (!CryptAcquireContext(&hProv,NULL,NULL,PROV_RSA_FULL,0)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, s, 
                     "Digest: Error acquiring context. Errno = %d",
                     GetLastError());
        exit(EXIT_FAILURE);
    }
    if (!CryptGenRandom(hProv,sizeof(secret),secret)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, s, 
                     "Digest: Error generating secret. Errno = %d",
                     GetLastError());
        exit(EXIT_FAILURE);
    }

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s, "Digest: done");
}
#else
static void initialize_secret(server_rec *s)
{
#ifdef	DEV_RANDOM
    int rnd;
    ssize_t got;
    size_t tot;
#else
    extern int randbyte(void);	/* from the truerand library */
    unsigned int idx;
#endif

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s,
		 "Digest: generating secret for digest authentication ...");

#ifdef	DEV_RANDOM
#define	XSTR(x)	#x
#define	STR(x)	XSTR(x)
    if ((rnd = open(STR(DEV_RANDOM), O_RDONLY)) == -1) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, s,
		     "Digest: Couldn't open " STR(DEV_RANDOM));
	exit(EXIT_FAILURE);
    }
    for (tot=0; tot<sizeof(secret); tot += got) {
	if ((got = read(rnd, secret+tot, sizeof(secret)-tot)) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_CRIT, s,
			 "Digest: Error reading " STR(DEV_RANDOM));
	    exit(EXIT_FAILURE);
	}
    }
    close(rnd);
#undef	STR
#undef	XSTR
#else	/* use truerand */
    /* this will increase the startup time of the server, unfortunately...
     * (generating 20 bytes takes about 8 seconds)
     */
    for (idx=0; idx<sizeof(secret); idx++)
	secret[idx] = (unsigned char) randbyte();
#endif	/* DEV_RANDOM */

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s, "Digest: done");
}
#endif

#ifdef HAVE_SHMEM_MM
static void initialize_tables(server_rec *s)
{
    unsigned long idx;

    /* set up client list */

    client_mm = mm_create(SHMEM_SIZE, tmpnam(NULL));
    if (client_mm == NULL)
	goto failed;
#ifdef MPE
    if (geteuid() == 1) {
#else
    if (geteuid() == 0) {
#endif
	if (mm_permission(client_mm, 0600, ap_user_id, ap_group_id))
	    goto failed;
    }
    client_list = mm_malloc(client_mm, sizeof(*client_list) +
				       sizeof(client_entry*)*NUM_BUCKETS);
    if (!client_list)  goto failed;
    client_list->table = (client_entry**) (client_list + 1);
    for (idx=0; idx<NUM_BUCKETS; idx++)
	client_list->table[idx] = NULL;
    client_list->tbl_len     = NUM_BUCKETS;
    client_list->num_entries = 0;


    /* setup opaque */

    opaque_mm = mm_create(sizeof(*opaque_cntr), tmpnam(NULL));
    if (opaque_mm == NULL)
	goto failed;
#ifdef MPE
    if (geteuid() == 1) {
#else
    if (geteuid() == 0) {
#endif
	if (mm_permission(opaque_mm, 0600, ap_user_id, ap_group_id))
	    goto failed;
    }
    opaque_cntr = mm_malloc(opaque_mm, sizeof(*opaque_cntr));
    if (opaque_cntr == NULL)
	goto failed;
    *opaque_cntr = 1UL;


    /* setup one-time-nonce counter */

    otn_count_mm = mm_create(sizeof(*otn_counter), tmpnam(NULL));
    if (otn_count_mm == NULL)
	goto failed;
#ifdef MPE
    if (geteuid() == 1) {
#else
    if (geteuid() == 0) {
#endif
	if (mm_permission(otn_count_mm, 0600, ap_user_id, ap_group_id))
	    goto failed;
    }
    otn_counter = mm_malloc(otn_count_mm, sizeof(*otn_counter));
    if (otn_counter == NULL)
	goto failed;
    *otn_counter = 0;


    /* success */
    return;

failed:
    if (!client_mm || (client_list && client_list->table && !opaque_mm)
	|| (opaque_cntr && !otn_count_mm))
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
		     "Digest: failed to create shared memory segments; reason "
		     "was `%s' - all nonce-count checking, one-time nonces, "
		     "and MD5-sess algorithm disabled", mm_error());
    else
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s,
		     "Digest: failed to allocate shared mem; reason was `%s' "
		     "- all nonce-count checking, one-time nonces, and "
		     "MD5-sess algorithm disabled", mm_error());

    cleanup_tables(NULL);
}
#endif	/* HAVE_SHMEM_MM */

static void initialize_module(server_rec *s, pool *p)
{
    /* keep from doing the init more than once at startup, and delay
     * the init until the second round
     */
    if (++call_cnt < 2)
	return;

    /* only initialize the secret on startup, not on restarts */
    if (call_cnt == 2)
	initialize_secret(s);

#ifdef HAVE_SHMEM_MM
    /* Note: this stuff is currently fixed for the lifetime of the server,
     * i.e. even across restarts. This means that A) any shmem-size
     * configuration changes are ignored, and B) certain optimizations,
     * such as only allocating the smallest necessary entry for each
     * client, can't be done. However, the alternative is a nightmare:
     * we can't call mm_destroy on a graceful restart because there will
     * be children using the tables, and we also don't know when the
     * last child dies. Therefore we can never clean up the old stuff,
     * creating a creeping memory leak.
     */
    initialize_tables(s);
    /* atexit(cleanup_tables); */
    ap_register_cleanup(p, NULL, cleanup_tables, ap_null_cleanup);
#endif	/* HAVE_SHMEM_MM */
}


/*
 * configuration code
 */

static void *create_digest_dir_config(pool *p, char *dir)
{
    digest_config_rec *conf;

    if (dir == NULL)  return NULL;

    conf = (digest_config_rec *) ap_pcalloc(p, sizeof(digest_config_rec));
    if (conf) {
	conf->qop_list       = ap_palloc(p, sizeof(char*));
	conf->qop_list[0]    = NULL;
	conf->nonce_lifetime = DFLT_NONCE_LIFE;
	conf->dir_name       = ap_pstrdup(p, dir);
	conf->algorithm      = DFLT_ALGORITHM;
    }

    return conf;
}

static const char *set_realm(cmd_parms *cmd, void *config, const char *realm)
{
    digest_config_rec *conf = (digest_config_rec *) config;

    /* The core already handles the realm, but it's just too convenient to
     * grab it ourselves too and cache some setups. However, we need to
     * let the core get at it too, which is why we decline at the end -
     * this relies on the fact that http_core is last in the list.
     */
    conf->realm = realm;

    /* we precompute the part of the nonce hash that is constant (well,
     * the host:port would be too, but that varies for .htaccess files
     * and directives outside a virtual host section)
     */
    ap_SHA1Init(&conf->nonce_ctx);
    ap_SHA1Update_binary(&conf->nonce_ctx, secret, sizeof(secret));
    ap_SHA1Update_binary(&conf->nonce_ctx, (const unsigned char *) realm,
			 strlen(realm));

    return DECLINE_CMD;
}

static const char *set_digest_file(cmd_parms *cmd, void *config,
				   const char *file)
{
    ((digest_config_rec *) config)->pwfile = file;
    return NULL;
}

static const char *set_group_file(cmd_parms *cmd, void *config,
				  const char *file)
{
    ((digest_config_rec *) config)->grpfile = file;
    return NULL;
}

static const char *set_qop(cmd_parms *cmd, void *config, const char *op)
{
    digest_config_rec *conf = (digest_config_rec *) config;
    char **tmp;
    int cnt;

    if (!strcasecmp(op, "none")) {
	if (conf->qop_list[0] == NULL) {
	    conf->qop_list = ap_palloc(cmd->pool, 2 * sizeof(char*));
	    conf->qop_list[1] = NULL;
	}
	conf->qop_list[0] = "none";
	return NULL;
    }

    if (!strcasecmp(op, "auth-int"))
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, cmd->server,
		     "Digest: WARNING: qop `auth-int' currently only works "
		     "correctly for responses with no entity");
    else if (strcasecmp(op, "auth"))
	return ap_pstrcat(cmd->pool, "Unrecognized qop: ", op, NULL);

    for (cnt=0; conf->qop_list[cnt] != NULL; cnt++)
	;
    tmp = ap_palloc(cmd->pool, (cnt+2)*sizeof(char*));
    memcpy(tmp, conf->qop_list, cnt*sizeof(char*));
    tmp[cnt]   = ap_pstrdup(cmd->pool, op);
    tmp[cnt+1] = NULL;
    conf->qop_list = (const char **)tmp;

    return NULL;
}

static const char *set_nonce_lifetime(cmd_parms *cmd, void *config,
				      const char *t)
{
    char *endptr;
    long  lifetime;

    lifetime = ap_strtol(t, &endptr, 10);
    if (endptr < (t+strlen(t)) && !ap_isspace(*endptr))
	return ap_pstrcat(cmd->pool, "Invalid time in AuthDigestNonceLifetime: ", t, NULL);

    ((digest_config_rec *) config)->nonce_lifetime = lifetime;
    return NULL;
}

static const char *set_nonce_format(cmd_parms *cmd, void *config,
				    const char *fmt)
{
    ((digest_config_rec *) config)->nonce_format = fmt;
    return "AuthDigestNonceFormat is not implemented (yet)";
}

static const char *set_nc_check(cmd_parms *cmd, void *config, int flag)
{
    ((digest_config_rec *) config)->check_nc = flag;
    return NULL;
}

static const char *set_algorithm(cmd_parms *cmd, void *config, const char *alg)
{
    if (!strcasecmp(alg, "MD5-sess"))
#ifdef HAVE_SHMEM_MM
	;
#else	/* HAVE_SHMEM_MM */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, cmd->server,
		     "Digest: WARNING: algorithm `MD5-sess' is currently not "
		     "correctly implemented");
#endif	/* HAVE_SHMEM_MM */
    else if (strcasecmp(alg, "MD5"))
	return ap_pstrcat(cmd->pool, "Invalid algorithm in AuthDigestAlgorithm: ", alg, NULL);

    ((digest_config_rec *) config)->algorithm = alg;
    return NULL;
}

static const char *set_uri_list(cmd_parms *cmd, void *config, const char *uri)
{
    digest_config_rec *c = (digest_config_rec *) config;
    if (c->uri_list) {
	c->uri_list[strlen(c->uri_list)-1] = '\0';
	c->uri_list = ap_pstrcat(cmd->pool, c->uri_list, " ", uri, "\"", NULL);
    }
    else
	c->uri_list = ap_pstrcat(cmd->pool, ", domain=\"", uri, "\"", NULL);
    return NULL;
}

static const command_rec digest_cmds[] =
{
    {"AuthName", set_realm, NULL, OR_AUTHCFG, TAKE1,
     "The authentication realm (e.g. \"Members Only\")"},
    {"AuthDigestFile", set_digest_file, NULL, OR_AUTHCFG, TAKE1,
     "The name of the file containing the usernames and password hashes"},
    {"AuthDigestGroupFile", set_group_file, NULL, OR_AUTHCFG, TAKE1,
     "The name of the file containing the group names and members"},
    {"AuthDigestQop", set_qop, NULL, OR_AUTHCFG, ITERATE,
     "A list of quality-of-protection options"},
    {"AuthDigestNonceLifetime", set_nonce_lifetime, NULL, OR_AUTHCFG, TAKE1,
     "Maximum lifetime of the server nonce (seconds)"},
    {"AuthDigestNonceFormat", set_nonce_format, NULL, OR_AUTHCFG, TAKE1,
     "The format to use when generating the server nonce"},
    {"AuthDigestNcCheck", set_nc_check, NULL, OR_AUTHCFG, FLAG,
     "Whether or not to check the nonce-count sent by the client"},
    {"AuthDigestAlgorithm", set_algorithm, NULL, OR_AUTHCFG, TAKE1,
     "The algorithm used for the hash calculation"},
    {"AuthDigestDomain", set_uri_list, NULL, OR_AUTHCFG, ITERATE,
     "A list of URI's which belong to the same protection space as the current URI"},
    {NULL, NULL, NULL, 0, 0, NULL}
};


#ifdef HAVE_SHMEM_MM
/*
 * client list code
 *
 * Each client is assigned a number, which is transferred in the opaque
 * field of the WWW-Authenticate and Authorization headers. The number
 * is just a simple counter which is incremented for each new client.
 * Clients can't forge this number because it is hashed up into the
 * server nonce, and that is checked.
 *
 * The clients are kept in a simple hash table, which consists of an
 * array of client_entry's, each with a linked list of entries hanging
 * off it. The client's number modulo the size of the array gives the
 * bucket number.
 *
 * The clients are garbage collected whenever a new client is allocated
 * but there is not enough space left in the shared memory segment. A
 * simple semi-LRU is used for this: whenever a client entry is accessed
 * it is moved to the beginning of the linked list in its bucket (this
 * also makes for faster lookups for current clients). The garbage
 * collecter then just removes the oldest entry (i.e. the one at the
 * end of the list) in each bucket.
 *
 * The main advantages of the above scheme are that it's easy to implement
 * and it keeps the hash table evenly balanced (i.e. same number of entries
 * in each bucket). The major disadvantage is that you may be throwing
 * entries out which are in active use. This is not tragic, as these
 * clients will just be sent a new client id (opaque field) and nonce
 * with a stale=true (i.e. it will just look like the nonce expired,
 * thereby forcing an extra round trip). If the shared memory segment
 * has enough headroom over the current client set size then this should
 * not occur too often.
 *
 * To help tune the size of the shared memory segment (and see if the
 * above algorithm is really sufficient) a set of counters is kept
 * indicating the number of clients held, the number of garbage collected
 * clients, and the number of erroneously purged clients. These are printed
 * out at each garbage collection run. Note that access to the counters is
 * not synchronized because they are just indicaters, and whether they are
 * off by a few doesn't matter; and for the same reason no attempt is made
 * to guarantee the num_renewed is correct in the face of clients spoofing
 * the opaque field.
 */

/*
 * Get the client given its client number (the key). Returns the entry,
 * or NULL if its not found.
 *
 * Access to the list itself is synchronized via locks. However, access
 * to the entry returned by get_client() is NOT synchronized. This means
 * that there are potentially problems if a client uses multiple,
 * simultaneous connections to access url's within the same protection
 * space. However, these problems are not new: when using multiple
 * connections you have no guarantee of the order the requests are
 * processed anyway, so you have problems with the nonce-count and
 * one-time nonces anyway.
 */
static client_entry *get_client(unsigned long key, const request_rec *r)
{
    int bucket;
    client_entry *entry, *prev = NULL;


    if (!key || !client_mm)  return NULL;

    bucket = key % client_list->tbl_len;
    entry  = client_list->table[bucket];

    mm_lock(client_mm, MM_LOCK_RD);

    while(entry && key != entry->key) {
	prev  = entry;
	entry = entry->next;
    }

    if (entry && prev) {		/* move entry to front of list */
	prev->next  = entry->next;
	entry->next = client_list->table[bucket];
	client_list->table[bucket] = entry;
    }

    mm_unlock(client_mm);

    if (entry)
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
		      "get_client(): client %lu found", key);
    else
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r,
		      "get_client(): client %lu not found", key);

    return entry;
}


/* A simple garbage-collecter to remove unused clients. It removes the
 * last entry in each bucket and updates the counters. Returns the
 * number of removed entries.
 */
static long gc(void)
{
    client_entry *entry, *prev;
    unsigned long num_removed = 0, idx;

    /* garbage collect all last entries */

    for (idx=0; idx<client_list->tbl_len; idx++) {
	entry = client_list->table[idx];
	prev  = NULL;
	while (entry->next) {	/* find last entry */
	    prev  = entry;
	    entry = entry->next;
	}
	if (prev)  prev->next = NULL;	/* cut list */
	else       client_list->table[idx] = NULL;
	if (entry) {			/* remove entry */
	    mm_free(client_mm, entry);
	    num_removed++;
	}
    }

    /* update counters and log */

    client_list->num_entries -= num_removed;
    client_list->num_removed += num_removed;

    return num_removed;
}


/*
 * Add a new client to the list. Returns the entry if successful, NULL
 * otherwise. This triggers the garbage collection if memory is low.
 */
static client_entry *add_client(unsigned long key, client_entry *info,
				server_rec *s)
{
    int bucket;
    client_entry *entry;


    if (!key || !client_mm)  return NULL;

    bucket = key % client_list->tbl_len;
    entry  = client_list->table[bucket];

    mm_lock(client_mm, MM_LOCK_RW);

    /* try to allocate a new entry */

    entry = mm_malloc(client_mm, sizeof(client_entry));
    if (!entry) {
	long num_removed = gc();
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, s,
		     "Digest: gc'd %ld client entries. Total new clients: "
		     "%ld; Total removed clients: %ld; Total renewed clients: "
		     "%ld", num_removed,
		     client_list->num_created - client_list->num_renewed,
		     client_list->num_removed, client_list->num_renewed);
	entry = mm_malloc(client_mm, sizeof(client_entry));
	if (!entry)  return NULL;	/* give up */
    }

    /* now add the entry */

    memcpy(entry, info, sizeof(client_entry));
    entry->key  = key;
    entry->next = client_list->table[bucket];
    client_list->table[bucket] = entry;
    client_list->num_created++;
    client_list->num_entries++;

    mm_unlock(client_mm);

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, s,
		 "allocated new client %lu", key);

    return entry;
}
#else	/* HAVE_SHMEM_MM */
static client_entry *get_client(unsigned long key, const request_rec *r)
{
    return NULL;
}
#endif	/* HAVE_SHMEM_MM */


/*
 * Authorization header parser code
 */

/* Parse the Authorization header, if it exists */
static int get_digest_rec(request_rec *r, digest_header_rec *resp)
{
    const char *auth_line;
    size_t l;
    int vk = 0, vv = 0;
    char *key, *value;

    auth_line = ap_table_get(r->headers_in,
			     r->proxyreq == STD_PROXY ? "Proxy-Authorization"
						      : "Authorization");
    if (!auth_line) {
	resp->auth_hdr_sts = NO_HEADER;
	return !OK;
    }

    resp->scheme = ap_getword_white(r->pool, &auth_line);
    if (strcasecmp(resp->scheme, "Digest")) {
	resp->auth_hdr_sts = NOT_DIGEST;
	return !OK;
    }

    l = strlen(auth_line);

    key   = ap_palloc(r->pool, l+1);
    value = ap_palloc(r->pool, l+1);

    while (auth_line[0] != '\0') {

	/* find key */

	while (ap_isspace(auth_line[0])) auth_line++;
	vk = 0;
	while (auth_line[0] != '=' && auth_line[0] != ','
	       && auth_line[0] != '\0' && !ap_isspace(auth_line[0]))
	    key[vk++] = *auth_line++;
	key[vk] = '\0';
	while (ap_isspace(auth_line[0])) auth_line++;

	/* find value */

	if (auth_line[0] == '=') {
	    auth_line++;
	    while (ap_isspace(auth_line[0])) auth_line++;

	    vv = 0;
	    if (auth_line[0] == '\"') {		/* quoted string */
		auth_line++;
		while (auth_line[0] != '\"' && auth_line[0] != '\0') {
		    if (auth_line[0] == '\\' && auth_line[1] != '\0')
			auth_line++;		/* escaped char */
		    value[vv++] = *auth_line++;
		}
		if (auth_line[0] != '\0') auth_line++;
	    }
	    else {				 /* token */
		while (auth_line[0] != ',' && auth_line[0] != '\0'
		       && !ap_isspace(auth_line[0]))
		    value[vv++] = *auth_line++;
	    }
	    value[vv] = '\0';
	}

	while (auth_line[0] != ',' && auth_line[0] != '\0')  auth_line++;
	if (auth_line[0] != '\0') auth_line++;

	if (!strcasecmp(key, "username"))
	    resp->username = ap_pstrdup(r->pool, value);
	else if (!strcasecmp(key, "realm"))
	    resp->realm = ap_pstrdup(r->pool, value);
	else if (!strcasecmp(key, "nonce"))
	    resp->nonce = ap_pstrdup(r->pool, value);
	else if (!strcasecmp(key, "uri"))
	    resp->uri = ap_pstrdup(r->pool, value);
	else if (!strcasecmp(key, "response"))
	    resp->digest = ap_pstrdup(r->pool, value);
	else if (!strcasecmp(key, "algorithm"))
	    resp->algorithm = ap_pstrdup(r->pool, value);
	else if (!strcasecmp(key, "cnonce"))
	    resp->cnonce = ap_pstrdup(r->pool, value);
	else if (!strcasecmp(key, "opaque"))
	    resp->opaque = ap_pstrdup(r->pool, value);
	else if (!strcasecmp(key, "qop"))
	    resp->message_qop = ap_pstrdup(r->pool, value);
	else if (!strcasecmp(key, "nc"))
	    resp->nonce_count = ap_pstrdup(r->pool, value);
    }

    if (!resp->username || !resp->realm || !resp->nonce || !resp->uri
	|| !resp->digest
	|| (resp->message_qop && (!resp->cnonce || !resp->nonce_count))) {
	resp->auth_hdr_sts = INVALID;
	return !OK;
    }

    if (resp->opaque)
	resp->opaque_num = (unsigned long) ap_strtol(resp->opaque, NULL, 16);

    resp->auth_hdr_sts = VALID;
    return OK;
}


/* Because the browser may preemptively send auth info, incrementing the
 * nonce-count when it does, and because the client does not get notified
 * if the URI didn't need authentication after all, we need to be sure to
 * update the nonce-count each time we receive an Authorization header no
 * matter what the final outcome of the request. Furthermore this is a
 * convenient place to get the request-uri (before any subrequests etc
 * are initiated) and to initialize the request_config.
 *
 * Note that this must be called after mod_proxy had its go so that
 * r->proxyreq is set correctly.
 */
static int update_nonce_count(request_rec *r)
{
    digest_header_rec *resp;
    int res;

    if (!ap_is_initial_req(r))
	return DECLINED;

    resp = ap_pcalloc(r->pool, sizeof(digest_header_rec));
    resp->raw_request_uri = r->unparsed_uri;
    resp->psd_request_uri = &r->parsed_uri;
    resp->needed_auth = 0;
    ap_set_module_config(r->request_config, &digest_auth_module, resp);

    res = get_digest_rec(r, resp);
    resp->client = get_client(resp->opaque_num, r);
    if (res == OK && resp->client)
	resp->client->nonce_count++;

    return DECLINED;
}


/*
 * Nonce generation code
 */

/* The hash part of the nonce is a SHA-1 hash of the time, realm, server host
 * and port, opaque, and our secret.
 */
static void gen_nonce_hash(char *hash, const char *timestr, const char *opaque,
			   const server_rec *server,
			   const digest_config_rec *conf)
{
    const char *hex = "0123456789abcdef";
    unsigned char sha1[SHA_DIGESTSIZE];
    AP_SHA1_CTX ctx;
    int idx;

    memcpy(&ctx, &conf->nonce_ctx, sizeof(ctx));
    /*
    ap_SHA1Update_binary(&ctx, (const unsigned char *) server->server_hostname,
			 strlen(server->server_hostname));
    ap_SHA1Update_binary(&ctx, (const unsigned char *) &server->port,
			 sizeof(server->port));
     */
    ap_SHA1Update_binary(&ctx, (const unsigned char *) timestr, strlen(timestr));
    if (opaque)
	ap_SHA1Update_binary(&ctx, (const unsigned char *) opaque,
			     strlen(opaque));
    ap_SHA1Final(sha1, &ctx);

    for (idx=0; idx<SHA_DIGESTSIZE; idx++) {
	*hash++ = hex[sha1[idx] >> 4];
	*hash++ = hex[sha1[idx] & 0xF];
    }

    *hash++ = '\0';
}


/* The nonce has the format b64(time)+hash .
 */
static const char *gen_nonce(pool *p, time_t now, const char *opaque,
			     const server_rec *server,
			     const digest_config_rec *conf)
{
    char *nonce = ap_palloc(p, NONCE_LEN+1);
    time_rec t;

    if (conf->nonce_lifetime != 0)
	t.time = now;
    else
#ifdef HAVE_SHMEM_MM
	/* this counter is not synch'd, because it doesn't really matter
	 * if it counts exactly.
	 */
	t.time = (*otn_counter)++;
#else	/* HAVE_SHMEM_MM */
	t.time = 42;
#endif	/* HAVE_SHMEM_MM */
    ap_base64encode_binary(nonce, t.arr, sizeof(t.arr));
    gen_nonce_hash(nonce+NONCE_TIME_LEN, nonce, opaque, server, conf);

    return nonce;
}


/*
 * Opaque and hash-table management
 */

#ifdef HAVE_SHMEM_MM
/*
 * Generate a new client entry, add it to the list, and return the
 * entry. Returns NULL if failed.
 */
static client_entry *gen_client(const request_rec *r)
{
    unsigned long op;
    client_entry new_entry = { 0, NULL, 0, "", "" }, *entry;

    if (!opaque_mm)  return 0;

    mm_lock(opaque_mm, MM_LOCK_RW);
    op = (*opaque_cntr)++;
    mm_unlock(opaque_mm);

    if (!(entry = add_client(op, &new_entry, r->server))) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		      "Digest: failed to allocate client entry - ignoring "
		      "client");
	return NULL;
    }

    return entry;
}
#else	/* HAVE_SHMEM_MM */
static client_entry *gen_client(const request_rec *r) { return NULL; }
#endif	/* HAVE_SHMEM_MM */



/*
 * MD5-sess code.
 *
 * If you want to use algorithm=MD5-sess you must write get_userpw_hash()
 * yourself (see below). The dummy provided here just uses the hash from
 * the auth-file, i.e. it is only useful for testing client implementations
 * of MD5-sess .
 */

/*
 * get_userpw_hash() will be called each time a new session needs to be
 * generated and is expected to return the equivalent of
 *
 * h_urp = ap_md5(r->pool,
 *         ap_pstrcat(r->pool, username, ":", ap_auth_name(r), ":", passwd))
 * ap_md5(r->pool,
 *         (unsigned char *) ap_pstrcat(r->pool, h_urp, ":", resp->nonce, ":",
 *                                      resp->cnonce, NULL));
 *
 * or put differently, it must return
 *
 *   MD5(MD5(username ":" realm ":" password) ":" nonce ":" cnonce)
 *
 * If something goes wrong, the failure must be logged and NULL returned.
 *
 * You must implement this yourself, which will probably consist of code
 * contacting the password server with the necessary information (typically
 * the username, realm, nonce, and cnonce) and receiving the hash from it.
 *
 * TBD: This function should probably be in a seperate source file so that
 * people need not modify mod_auth_digest.c each time they install a new
 * version of apache.
 */
static const char *get_userpw_hash(const request_rec *r,
				   const digest_header_rec *resp,
				   const digest_config_rec *conf)
{
    return ap_md5(r->pool,
	     (unsigned char *) ap_pstrcat(r->pool, conf->ha1, ":", resp->nonce,
					  ":", resp->cnonce, NULL));
}


/* Retrieve current session H(A1). If there is none and "generate" is
 * true then a new session for MD5-sess is generated and stored in the
 * client struct; if generate is false, or a new session could not be
 * generated then NULL is returned (in case of failure to generate the
 * failure reason will have been logged already).
 */
static const char *get_session_HA1(const request_rec *r,
				   digest_header_rec *resp,
				   const digest_config_rec *conf,
				   int generate)
{
    const char *ha1 = NULL;

    /* return the current sessions if there is one */
    if (resp->opaque && resp->client && resp->client->ha1[0])
	return resp->client->ha1;
    else if (!generate)
	return NULL;

    /* generate a new session */
    if (!resp->client)
	resp->client = gen_client(r);
    if (resp->client) {
	ha1 = get_userpw_hash(r, resp, conf);
	if (ha1)
	    memcpy(resp->client->ha1, ha1, sizeof(resp->client->ha1));
    }

    return ha1;
}


static void clear_session(const digest_header_rec *resp)
{
    if (resp->client)
	resp->client->ha1[0] = '\0';
}

/*
 * Authorization challenge generation code (for WWW-Authenticate)
 */

static const char *ltox(pool *p, unsigned long num)
{
    if (num != 0)
	return ap_psprintf(p, "%lx", num);
    else
	return "";
}

static void note_digest_auth_failure(request_rec *r,
				     const digest_config_rec *conf,
				     digest_header_rec *resp, int stale)
{
    const char   *qop, *opaque, *opaque_param, *domain, *nonce;
    int           cnt;


    /* Setup qop */

    if (conf->qop_list[0] == NULL)
	qop = ", qop=\"auth\"";
    else if (!strcasecmp(conf->qop_list[0], "none"))
	qop = "";
    else {
	qop = ap_pstrcat(r->pool, ", qop=\"", conf->qop_list[0], NULL);
	for (cnt=1; conf->qop_list[cnt] != NULL; cnt++)
	    qop = ap_pstrcat(r->pool, qop, ",", conf->qop_list[cnt], NULL);
	qop = ap_pstrcat(r->pool, qop, "\"", NULL);
    }

    /* Setup opaque */

    if (resp->opaque == NULL) {
	/* new client */
	if ((conf->check_nc || conf->nonce_lifetime == 0
	     || !strcasecmp(conf->algorithm, "MD5-sess"))
	    && (resp->client = gen_client(r)) != NULL)
	    opaque = ltox(r->pool, resp->client->key);
	else
	    opaque = "";		/* opaque not needed */
    }
    else if (resp->client == NULL) {
	/* client info was gc'd */
	resp->client = gen_client(r);
	if (resp->client != NULL) {
	    opaque = ltox(r->pool, resp->client->key);
	    stale = 1;
	    client_list->num_renewed++;
	}
	else
	    opaque = "";		/* ??? */
    }
    else {
	opaque = resp->opaque;
	/* we're generating a new nonce, so reset the nonce-count */
	resp->client->nonce_count = 0;
    }

    if (opaque[0])
	opaque_param = ap_pstrcat(r->pool, ", opaque=\"", opaque, "\"", NULL);
    else
	opaque_param = NULL;

    /* Setup nonce */

    nonce = gen_nonce(r->pool, r->request_time, opaque, r->server, conf);
    if (resp->client && conf->nonce_lifetime == 0)
	memcpy(resp->client->last_nonce, nonce, NONCE_LEN+1);

    /* Setup MD5-sess stuff. Note that we just clear out the session
     * info here, since we can't generate a new session until the request
     * from the client comes in with the cnonce.
     */

    if (!strcasecmp(conf->algorithm, "MD5-sess"))
	clear_session(resp);

    /* setup domain attribute. We want to send this attribute wherever
     * possible so that the client won't send the Authorization header
     * unneccessarily (it's usually > 200 bytes!).
     */

    /* don't send domain
     * - for proxy requests
     * - if it's no specified
     */
    if (r->proxyreq || !conf->uri_list) {
        domain = NULL;  
    }
    else {
        domain = conf->uri_list;
    }

    ap_table_mergen(r->err_headers_out,
		    r->proxyreq == STD_PROXY ? "Proxy-Authenticate"
					     : "WWW-Authenticate",
		    ap_psprintf(r->pool, "Digest realm=\"%s\", nonce=\"%s\", "
					 "algorithm=%s%s%s%s%s",
				ap_auth_name(r), nonce, conf->algorithm,
				opaque_param ? opaque_param : "",
				domain ? domain : "",
				stale ? ", stale=true" : "", qop));
}


/*
 * Authorization header verification code
 */

static const char *get_hash(request_rec *r, const char *user,
			    const char *realm, const char *auth_pwfile)
{
    configfile_t *f;
    char l[MAX_STRING_LEN];
    const char *rpw;
    char *w, *x;

    if (!(f = ap_pcfg_openfile(r->pool, auth_pwfile))) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		      "Digest: Could not open password file: %s", auth_pwfile);
	return NULL;
    }
    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
	if ((l[0] == '#') || (!l[0]))
	    continue;
	rpw = l;
	w = ap_getword(r->pool, &rpw, ':');
	x = ap_getword(r->pool, &rpw, ':');

	if (x && w && !strcmp(user, w) && !strcmp(realm, x)) {
	    ap_cfg_closefile(f);
	    return ap_pstrdup(r->pool, rpw);
	}
    }
    ap_cfg_closefile(f);
    return NULL;
}

static int check_nc(const request_rec *r, const digest_header_rec *resp,
		    const digest_config_rec *conf)
{
    unsigned long nc;
    const char *snc = resp->nonce_count;
    char *endptr;

    if (!conf->check_nc || !client_mm)
	return OK;

    nc = ap_strtol(snc, &endptr, 16);
    if (endptr < (snc+strlen(snc)) && !ap_isspace(*endptr)) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "Digest: invalid nc %s received - not a number", snc);
	return !OK;
    }

    if (!resp->client)
	return !OK;

    if (nc != resp->client->nonce_count) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "Digest: Warning, possible replay attack: nonce-count "
		      "check failed: %lu != %lu", nc,
		      resp->client->nonce_count);
	return !OK;
    }

    return OK;
}

static int check_nonce(request_rec *r, digest_header_rec *resp,
		       const digest_config_rec *conf)
{
    double dt;
    time_rec nonce_time;
    char tmp, hash[NONCE_HASH_LEN+1];

    if (strlen(resp->nonce) != NONCE_LEN) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "Digest: invalid nonce %s received - length is not %d",
		      resp->nonce, NONCE_LEN);
	note_digest_auth_failure(r, conf, resp, 1);
	return AUTH_REQUIRED;
    }

    tmp = resp->nonce[NONCE_TIME_LEN];
    resp->nonce[NONCE_TIME_LEN] = '\0';
    ap_base64decode_binary(nonce_time.arr, resp->nonce);
    gen_nonce_hash(hash, resp->nonce, resp->opaque, r->server, conf);
    resp->nonce[NONCE_TIME_LEN] = tmp;
    resp->nonce_time = nonce_time.time;

    if (strcmp(hash, resp->nonce+NONCE_TIME_LEN)) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "Digest: invalid nonce %s received - hash is not %s",
		      resp->nonce, hash);
	note_digest_auth_failure(r, conf, resp, 1);
	return AUTH_REQUIRED;
    }

    dt = difftime(r->request_time, nonce_time.time);
    if (conf->nonce_lifetime > 0 && dt < 0) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "Digest: invalid nonce %s received - user attempted "
		      "time travel", resp->nonce);
	note_digest_auth_failure(r, conf, resp, 1);
	return AUTH_REQUIRED;
    }

    if (conf->nonce_lifetime > 0) {
	if (dt > conf->nonce_lifetime) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r,
			  "Digest: user %s: nonce expired - sending new nonce",
			  r->connection->user);
	    note_digest_auth_failure(r, conf, resp, 1);
	    return AUTH_REQUIRED;
	}
    }
    else if (conf->nonce_lifetime == 0 && resp->client) {
	if (memcmp(resp->client->last_nonce, resp->nonce, NONCE_LEN)) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, r,
			  "Digest: user %s: one-time-nonce mismatch - sending "
			  "new nonce", r->connection->user);
	    note_digest_auth_failure(r, conf, resp, 1);
	    return AUTH_REQUIRED;
	}
    }
    /* else (lifetime < 0) => never expires */

    return OK;
}

/* The actual MD5 code... whee */

/* RFC-2069 */
static const char *old_digest(const request_rec *r,
			      const digest_header_rec *resp, const char *ha1)
{
    const char *ha2;

    ha2 = ap_md5(r->pool, (unsigned char *)ap_pstrcat(r->pool, r->method, ":",
						      resp->uri, NULL));
    return ap_md5(r->pool,
		  (unsigned char *)ap_pstrcat(r->pool, ha1, ":", resp->nonce,
					      ":", ha2, NULL));
}

/* RFC-2617 */
static const char *new_digest(const request_rec *r,
			      digest_header_rec *resp,
			      const digest_config_rec *conf)
{
    const char *ha1, *ha2, *a2;

    if (resp->algorithm && !strcasecmp(resp->algorithm, "MD5-sess")) {
	ha1 = get_session_HA1(r, resp, conf, 1);
	if (!ha1)
	    return NULL;
    }
    else
	ha1 = conf->ha1;

    if (resp->message_qop && !strcasecmp(resp->message_qop, "auth-int"))
	a2 = ap_pstrcat(r->pool, r->method, ":", resp->uri, ":",
			ap_md5(r->pool, (const unsigned char*) ""), NULL); /* TBD */
    else
	a2 = ap_pstrcat(r->pool, r->method, ":", resp->uri, NULL);
    ha2 = ap_md5(r->pool, (const unsigned char *)a2);

    return ap_md5(r->pool,
		  (unsigned char *)ap_pstrcat(r->pool, ha1, ":", resp->nonce,
					      ":", resp->nonce_count, ":",
					      resp->cnonce, ":",
					      resp->message_qop, ":", ha2,
					      NULL));
}


static void copy_uri_components(uri_components *dst, uri_components *src,
				request_rec *r)
{
    if (src->scheme && src->scheme[0] != '\0')
	dst->scheme = src->scheme;
    else
	dst->scheme = (char *) "http";

    if (src->hostname && src->hostname[0] != '\0') {
	dst->hostname = ap_pstrdup(r->pool, src->hostname);
	ap_unescape_url(dst->hostname);
    }
    else
	dst->hostname = (char *) ap_get_server_name(r);

    if (src->port_str && src->port_str[0] != '\0')
	dst->port = src->port;
    else
	dst->port = ap_get_server_port(r);

    if (src->path && src->path[0] != '\0') {
	dst->path = ap_pstrdup(r->pool, src->path);
	ap_unescape_url(dst->path);
    }
    else
	dst->path = src->path;

    if (src->query && src->query[0] != '\0') {
	dst->query = ap_pstrdup(r->pool, src->query);
	ap_unescape_url(dst->query);
    }
    else
	dst->query = src->query;
}

/* This handles non-FQDN's. If h1 is empty, the comparison succeeds. Else
 * if h1 is a FQDN (i.e. contains a '.') then normal strcasecmp() is done.
 * Else only the first part of h2 (up to the first '.') is compared.
 */
static int compare_hostnames(const char *h1, const char *h2)
{
    const char *dot;

    /* if no hostname given, then ok */
    if (!h1 || h1[0] == '\0')
	return 1;

    /* handle FQDN's in h1 */
    dot = strchr(h1, '.');
    if (dot != NULL)
	return !strcasecmp(h1, h2);

    /* handle non-FQDN's in h1 */
    dot = strchr(h2, '.');
    if (dot == NULL)
	return !strcasecmp(h1, h2);
    else
	return (strlen(h1) == (size_t) (dot - h2)) && !strncasecmp(h1, h2, dot-h2);
}

/* These functions return 0 if client is OK, and proper error status
 * if not... either AUTH_REQUIRED, if we made a check, and it failed, or
 * SERVER_ERROR, if things are so totally confused that we couldn't
 * figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

/* Determine user ID, and check if the attributes are correct, if it
 * really is that user, if the nonce is correct, etc.
 */

static int authenticate_digest_user(request_rec *r)
{
    digest_config_rec *conf;
    digest_header_rec *resp;
    request_rec       *mainreq;
    conn_rec          *conn = r->connection;
    const char        *t;
    int                res;


    /* do we require Digest auth for this URI? */

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Digest"))
	return DECLINED;

    if (!ap_auth_name(r)) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "Digest: need AuthName: %s", r->uri);
	return SERVER_ERROR;
    }


    /* get the client response and mark */

    mainreq = r;
    while (mainreq->main != NULL)  mainreq = mainreq->main;
    while (mainreq->prev != NULL)  mainreq = mainreq->prev;
    resp = (digest_header_rec *) ap_get_module_config(mainreq->request_config,
						      &digest_auth_module);
    resp->needed_auth = 1;


    /* get our conf */

    conf = (digest_config_rec *) ap_get_module_config(r->per_dir_config,
						      &digest_auth_module);


    /* check for existence and syntax of Auth header */

    if (resp->auth_hdr_sts != VALID) {
	if (resp->auth_hdr_sts == NOT_DIGEST)
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			  "Digest: client used wrong authentication scheme "
			  "`%s': %s", resp->scheme, r->uri);
	else if (resp->auth_hdr_sts == INVALID)
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			  "Digest: missing user, realm, nonce, uri, digest, "
			  "cnonce, or nonce_count in authorization header: %s",
			  r->uri);
	/* else (resp->auth_hdr_sts == NO_HEADER) */
	note_digest_auth_failure(r, conf, resp, 0);
	return AUTH_REQUIRED;
    }

    r->connection->user         = (char *) resp->username;
    r->connection->ap_auth_type = (char *) "Digest";


    /* check the auth attributes */

    if (strcmp(resp->uri, resp->raw_request_uri)) {
	/* Hmm, the simple match didn't work (probably a proxy modified the
	 * request-uri), so lets do a more sophisticated match
	 */
	uri_components r_uri, d_uri;

	copy_uri_components(&r_uri, resp->psd_request_uri, r);
	if (ap_parse_uri_components(r->pool, resp->uri, &d_uri) != HTTP_OK) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			  "Digest: invalid uri <%s> in Authorization header",
			  resp->uri);
	    return BAD_REQUEST;
	}

	if (d_uri.hostname)
	    ap_unescape_url(d_uri.hostname);
	if (d_uri.path)
	    ap_unescape_url(d_uri.path);
	if (d_uri.query)
	    ap_unescape_url(d_uri.query);

	if (r->method_number == M_CONNECT) {
	    if (strcmp(resp->uri, r_uri.hostinfo)) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			      "Digest: uri mismatch - <%s> does not match "
			      "request-uri <%s>", resp->uri, r_uri.hostinfo);
		return BAD_REQUEST;
	    }
	}
	else if (
	    /* check hostname matches, if present */
	    !compare_hostnames(d_uri.hostname, r_uri.hostname)
	    /* check port matches, if present */
	    || (d_uri.port_str && d_uri.port != r_uri.port)
	    /* check that server-port is default port if no port present */
	    || (d_uri.hostname && d_uri.hostname[0] != '\0'
		&& !d_uri.port_str && r_uri.port != ap_default_port(r))
	    /* check that path matches */
	    || (d_uri.path != r_uri.path
		/* either exact match */
	        && (!d_uri.path || !r_uri.path
		    || strcmp(d_uri.path, r_uri.path))
		/* or '*' matches empty path in scheme://host */
	        && !(d_uri.path && !r_uri.path && resp->psd_request_uri->hostname
		    && d_uri.path[0] == '*' && d_uri.path[1] == '\0'))
	    /* check that query matches */
	    || (d_uri.query != r_uri.query
		&& (!d_uri.query || !r_uri.query
		    || strcmp(d_uri.query, r_uri.query)))
	    ) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			  "Digest: uri mismatch - <%s> does not match "
			  "request-uri <%s>", resp->uri, resp->raw_request_uri);
	    return BAD_REQUEST;
	}
    }

    if (resp->opaque && resp->opaque_num == 0) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "Digest: received invalid opaque - got `%s'",
		      resp->opaque);
	note_digest_auth_failure(r, conf, resp, 0);
	return AUTH_REQUIRED;
    }

    if (strcmp(resp->realm, conf->realm)) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "Digest: realm mismatch - got `%s' but expected `%s'",
		      resp->realm, conf->realm);
	note_digest_auth_failure(r, conf, resp, 0);
	return AUTH_REQUIRED;
    }

    if (resp->algorithm != NULL
	&& strcasecmp(resp->algorithm, "MD5")
	&& strcasecmp(resp->algorithm, "MD5-sess")) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "Digest: unknown algorithm `%s' received: %s",
		      resp->algorithm, r->uri);
	note_digest_auth_failure(r, conf, resp, 0);
	return AUTH_REQUIRED;
    }

    if (!conf->pwfile)
	return DECLINED;

    if (!(conf->ha1 = get_hash(r, conn->user, conf->realm, conf->pwfile))) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		      "Digest: user `%s' in realm `%s' not found: %s",
		      conn->user, conf->realm, r->uri);
	note_digest_auth_failure(r, conf, resp, 0);
	return AUTH_REQUIRED;
    }

    if (resp->message_qop == NULL) {
	/* old (rfc-2069) style digest */
	if (strcmp(resp->digest, old_digest(r, resp, conf->ha1))) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			  "Digest: user %s: password mismatch: %s", conn->user,
			  r->uri);
	    note_digest_auth_failure(r, conf, resp, 0);
	    return AUTH_REQUIRED;
	}
    }
    else {
	const char *exp_digest;
	int match = 0, idx;
	for (idx=0; conf->qop_list[idx] != NULL; idx++) {
	    if (!strcasecmp(conf->qop_list[idx], resp->message_qop)) {
		match = 1;
		break;
	    }
	}

	if (!match
	    && !(conf->qop_list[0] == NULL
		 && !strcasecmp(resp->message_qop, "auth"))) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			  "Digest: invalid qop `%s' received: %s",
			  resp->message_qop, r->uri);
	    note_digest_auth_failure(r, conf, resp, 0);
	    return AUTH_REQUIRED;
	}

	if (check_nc(r, resp, conf) != OK) {
	    note_digest_auth_failure(r, conf, resp, 0);
	    return AUTH_REQUIRED;
	}

	exp_digest = new_digest(r, resp, conf);
	if (!exp_digest) {
	    /* we failed to allocate a client struct */
	    return SERVER_ERROR;
	}
	if (strcmp(resp->digest, exp_digest)) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			  "Digest: user %s: password mismatch: %s", conn->user,
			  r->uri);
	    note_digest_auth_failure(r, conf, resp, 0);
	    return AUTH_REQUIRED;
	}
    }

    /* Note: this check is done last so that a "stale=true" can be
       generated if the nonce is old */
    if ((res = check_nonce(r, resp, conf)))
	return res;

    return OK;
}


/*
 * Checking ID
 */

static table *groups_for_user(request_rec *r, const char *user,
			      const char *grpfile)
{
    configfile_t *f;
    table *grps = ap_make_table(r->pool, 15);
    pool *sp;
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;

    if (!(f = ap_pcfg_openfile(r->pool, grpfile))) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
		      "Digest: Could not open group file: %s", grpfile);
	return NULL;
    }

    sp = ap_make_sub_pool(r->pool);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
	if ((l[0] == '#') || (!l[0]))
	    continue;
	ll = l;
	ap_clear_pool(sp);

	group_name = ap_getword(sp, &ll, ':');

	while (ll[0]) {
	    w = ap_getword_conf(sp, &ll);
	    if (!strcmp(w, user)) {
		ap_table_setn(grps, ap_pstrdup(r->pool, group_name), "in");
		break;
	    }
	}
    }

    ap_cfg_closefile(f);
    ap_destroy_pool(sp);
    return grps;
}


static int digest_check_auth(request_rec *r)
{
    const digest_config_rec *conf =
		(digest_config_rec *) ap_get_module_config(r->per_dir_config,
							   &digest_auth_module);
    const char *user = r->connection->user;
    int m = r->method_number;
    int method_restricted = 0;
    register int x;
    const char *t, *w;
    table *grpstatus;
    const array_header *reqs_arr;
    require_line *reqs;

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Digest"))
	return DECLINED;

    reqs_arr = ap_requires(r);
    /* If there is no "requires" directive, then any user will do.
     */
    if (!reqs_arr)
	return OK;
    reqs = (require_line *) reqs_arr->elts;

    if (conf->grpfile)
	grpstatus = groups_for_user(r, user, conf->grpfile);
    else
	grpstatus = NULL;

    for (x = 0; x < reqs_arr->nelts; x++) {

	if (!(reqs[x].method_mask & (1 << m)))
	    continue;

	method_restricted = 1;

	t = reqs[x].requirement;
	w = ap_getword_white(r->pool, &t);
	if (!strcasecmp(w, "valid-user"))
	    return OK;
	else if (!strcasecmp(w, "user")) {
	    while (t[0]) {
		w = ap_getword_conf(r->pool, &t);
		if (!strcmp(user, w))
		    return OK;
	    }
	}
	else if (!strcasecmp(w, "group")) {
	    if (!grpstatus)
		return DECLINED;

	    while (t[0]) {
		w = ap_getword_conf(r->pool, &t);
		if (ap_table_get(grpstatus, w))
		    return OK;
	    }
	}
	else {
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		"Digest: access to %s failed, reason: unknown require "
		"directive \"%s\"", r->uri, reqs[x].requirement);
	    return DECLINED;
	}
    }

    if (!method_restricted)
	return OK;

    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
	"Digest: access to %s failed, reason: user %s not allowed access",
	r->uri, user);

    note_digest_auth_failure(r, conf,
	(digest_header_rec *) ap_get_module_config(r->request_config,
						   &digest_auth_module),
	0);
    return AUTH_REQUIRED;
}


/*
 * Authorization-Info header code
 */

#ifdef SEND_DIGEST
static const char *hdr(const table *tbl, const char *name)
{
    const char *val = ap_table_get(tbl, name);
    if (val)
	return val;
    else
	return "";
}
#endif

static int add_auth_info(request_rec *r)
{
    const digest_config_rec *conf =
		(digest_config_rec *) ap_get_module_config(r->per_dir_config,
							   &digest_auth_module);
    digest_header_rec *resp =
		(digest_header_rec *) ap_get_module_config(r->request_config,
							   &digest_auth_module);
    const char *ai = NULL, *digest = NULL, *nextnonce = "";

    if (resp == NULL || !resp->needed_auth || conf == NULL)
	return OK;


    /* rfc-2069 digest
     */
    if (resp->message_qop == NULL) {
	/* old client, so calc rfc-2069 digest */

#ifdef SEND_DIGEST
	/* most of this totally bogus because the handlers don't set the
	 * headers until the final handler phase (I wonder why this phase
	 * is called fixup when there's almost nothing you can fix up...)
	 *
	 * Because it's basically impossible to get this right (e.g. the
	 * Content-length is never set yet when we get here, and we can't
	 * calc the entity hash) it's best to just leave this #def'd out.
	 */
	char *entity_info =
	    ap_md5(r->pool,
		   (unsigned char *) ap_pstrcat(r->pool, resp->raw_request_uri,
		       ":",
		       r->content_type ? r->content_type : ap_default_type(r), ":",
		       hdr(r->headers_out, "Content-Length"), ":",
		       r->content_encoding ? r->content_encoding : "", ":",
		       hdr(r->headers_out, "Last-Modified"), ":",
		       r->no_cache && !ap_table_get(r->headers_out, "Expires") ?
			    ap_gm_timestr_822(r->pool, r->request_time) :
			    hdr(r->headers_out, "Expires"),
		       NULL));
	digest =
	    ap_md5(r->pool,
		   (unsigned char *)ap_pstrcat(r->pool, conf->ha1, ":",
					       resp->nonce, ":",
					       r->method, ":",
					       ap_gm_timestr_822(r->pool, r->request_time), ":",
					       entity_info, ":",
					       ap_md5(r->pool, (unsigned char *) ""), /* H(entity) - TBD */
					       NULL));
#endif
    }


    /* setup nextnonce
     */
    if (conf->nonce_lifetime > 0) {
	/* send nextnonce if current nonce will expire in less than 30 secs */
	if (difftime(r->request_time, resp->nonce_time) > (conf->nonce_lifetime-NEXTNONCE_DELTA)) {
	    nextnonce = ap_pstrcat(r->pool, ", nextnonce=\"",
				   gen_nonce(r->pool, r->request_time,
					     resp->opaque, r->server, conf),
				   "\"", NULL);
	    if (resp->client)
		resp->client->nonce_count = 0;
	}
    }
    else if (conf->nonce_lifetime == 0 && resp->client) {
        const char *nonce = gen_nonce(r->pool, 0, resp->opaque, r->server,
				      conf);
	nextnonce = ap_pstrcat(r->pool, ", nextnonce=\"", nonce, "\"", NULL);
	memcpy(resp->client->last_nonce, nonce, NONCE_LEN+1);
    }
    /* else nonce never expires, hence no nextnonce */


    /* do rfc-2069 digest
     */
    if (conf->qop_list[0] && !strcasecmp(conf->qop_list[0], "none")
	&& resp->message_qop == NULL) {
	/* use only RFC-2069 format */
	if (digest)
	    ai = ap_pstrcat(r->pool, "digest=\"", digest, "\"", nextnonce,NULL);
	else
	    ai = nextnonce;
    }
    else {
	const char *resp_dig, *ha1, *a2, *ha2;

	/* calculate rspauth attribute
	 */
	if (resp->algorithm && !strcasecmp(resp->algorithm, "MD5-sess")) {
	    ha1 = get_session_HA1(r, resp, conf, 0);
	    if (!ha1) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
			      "Digest: internal error: couldn't find session "
			      "info for user %s", resp->username);
		return !OK;
	    }
	}
	else
	    ha1 = conf->ha1;

	if (resp->message_qop && !strcasecmp(resp->message_qop, "auth-int"))
	    a2 = ap_pstrcat(r->pool, ":", resp->uri, ":",
			    ap_md5(r->pool, (const unsigned char *) ""), NULL); /* TBD */
	else
	    a2 = ap_pstrcat(r->pool, ":", resp->uri, NULL);
	ha2 = ap_md5(r->pool, (const unsigned char *)a2);

	resp_dig = ap_md5(r->pool,
		         (unsigned char *)ap_pstrcat(r->pool, ha1, ":",
						     resp->nonce, ":",
						     resp->nonce_count, ":",
						     resp->cnonce, ":",
						     resp->message_qop ?
							 resp->message_qop : "",
						     ":", ha2, NULL));

	/* assemble Authentication-Info header
	 */
	ai = ap_pstrcat(r->pool,
			"rspauth=\"", resp_dig, "\"",
			nextnonce,
		        resp->cnonce ? ", cnonce=\"" : "",
		        resp->cnonce ? ap_escape_quotes(r->pool, resp->cnonce) :
					"",
		        resp->cnonce ? "\"" : "",
		        resp->nonce_count ? ", nc=" : "",
		        resp->nonce_count ? resp->nonce_count : "",
		        resp->message_qop ? ", qop=" : "",
		        resp->message_qop ? resp->message_qop : "",
			digest ? "digest=\"" : "",
			digest ? digest : "",
			digest ? "\"" : "",
			NULL);
    }

    if (ai && ai[0])
	ap_table_mergen(r->headers_out,
			r->proxyreq == STD_PROXY ? "Proxy-Authentication-Info"
						 : "Authentication-Info",
			ai);
    return OK;
}


module MODULE_VAR_EXPORT digest_auth_module =
{
    STANDARD_MODULE_STUFF,
    initialize_module,		/* initializer */
    create_digest_dir_config,	/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server config */
    digest_cmds,		/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    authenticate_digest_user,	/* check_user_id */
    digest_check_auth,		/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    add_auth_info,		/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    update_nonce_count		/* post read-request */
};

