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
 * It is still fairly new and problems may turn up - submit problem
 * reports to the Apache bug-database, or send them directly to me
 * at ronald@innovation.ch.
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
 *   - expired nonces give amaya fits.  
 */

#include "apr_sha1.h"
#include "apr_base64.h"
#include "apr_lib.h"
#include "apr_time.h"
#include "apr_errno.h"
#include "apr_global_mutex.h"
#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"
#include "apr_uri.h"
#include "util_md5.h"
#include "apr_shm.h"
#include "apr_rmm.h"
#include "ap_provider.h"

#include "mod_auth.h"

/* Disable shmem until pools/init gets sorted out 
 * remove following two lines when fixed 
 */
#undef APR_HAS_SHARED_MEMORY
#define APR_HAS_SHARED_MEMORY 0

/* struct to hold the configuration info */

typedef struct digest_config_struct {
    const char  *dir_name;
    authn_provider_list *providers;
    const char  *realm;
    char **qop_list;
    apr_sha1_ctx_t  nonce_ctx;
    apr_time_t    nonce_lifetime;
    const char  *nonce_format;
    int          check_nc;
    const char  *algorithm;
    char        *uri_list;
    const char  *ha1;
} digest_config_rec;


#define DFLT_ALGORITHM  "MD5"

#define DFLT_NONCE_LIFE apr_time_from_sec(300)
#define NEXTNONCE_DELTA apr_time_from_sec(30)


#define NONCE_TIME_LEN  (((sizeof(apr_time_t)+2)/3)*4)
#define NONCE_HASH_LEN  (2*APR_SHA1_DIGESTSIZE)
#define NONCE_LEN       (int )(NONCE_TIME_LEN + NONCE_HASH_LEN)

#define SECRET_LEN      20


/* client list definitions */

typedef struct hash_entry {
    unsigned long      key;                     /* the key for this entry    */
    struct hash_entry *next;                    /* next entry in the bucket  */
    unsigned long      nonce_count;             /* for nonce-count checking  */
    char               ha1[2*APR_MD5_DIGESTSIZE+1]; /* for algorithm=MD5-sess    */
    char               last_nonce[NONCE_LEN+1]; /* for one-time nonce's      */
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
    apr_time_t            nonce_time;
    enum hdr_sts          auth_hdr_sts;
    const char           *raw_request_uri;
    apr_uri_t            *psd_request_uri;
    int                   needed_auth;
    client_entry         *client;
} digest_header_rec;


/* (mostly) nonce stuff */

typedef union time_union {
    apr_time_t    time;
    unsigned char arr[sizeof(apr_time_t)];
} time_rec;

static unsigned char secret[SECRET_LEN];

/* client-list, opaque, and one-time-nonce stuff */

static apr_shm_t      *client_shm =  NULL;
static apr_rmm_t      *client_rmm = NULL;
static unsigned long  *opaque_cntr;
static apr_time_t     *otn_counter;     /* one-time-nonce counter */
static apr_global_mutex_t *client_lock = NULL;
static apr_global_mutex_t *opaque_lock = NULL;
static char           client_lock_name[L_tmpnam];
static char           opaque_lock_name[L_tmpnam];

#define DEF_SHMEM_SIZE  1000L           /* ~ 12 entries */
#define DEF_NUM_BUCKETS 15L
#define HASH_DEPTH      5

static long shmem_size  = DEF_SHMEM_SIZE;
static long num_buckets = DEF_NUM_BUCKETS;


module AP_MODULE_DECLARE_DATA auth_digest_module;

/*
 * initialization code
 */

static apr_status_t cleanup_tables(void *not_used)
{
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                  "Digest: cleaning up shared memory");
    fflush(stderr);

    if (client_shm) {
        apr_shm_destroy(client_shm);
        client_shm = NULL;
    }

    if (client_lock) {
        apr_global_mutex_destroy(client_lock);
        client_lock = NULL;
    }

    if (opaque_lock) {
        apr_global_mutex_destroy(opaque_lock);
        opaque_lock = NULL;
    }

    return APR_SUCCESS;
}

static apr_status_t initialize_secret(server_rec *s)
{
    apr_status_t status;

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "Digest: generating secret for digest authentication ...");

#if APR_HAS_RANDOM
    status = apr_generate_random_bytes(secret, sizeof(secret));
#else
#error APR random number support is missing; you probably need to install the truerand library.
#endif

    if (status != APR_SUCCESS) {
        char buf[120];
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                     "Digest: error generating secret: %s", 
                     apr_strerror(status, buf, sizeof(buf)));
        return status;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Digest: done");

    return APR_SUCCESS;
}

static void log_error_and_cleanup(char *msg, apr_status_t sts, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, sts, s,
                 "Digest: %s - all nonce-count checking, one-time nonces, and "
                 "MD5-sess algorithm disabled", msg);

    cleanup_tables(NULL);
}

#if APR_HAS_SHARED_MEMORY

static void initialize_tables(server_rec *s, apr_pool_t *ctx)
{
    unsigned long idx;
    apr_status_t   sts;

    /* set up client list */

    sts = apr_shm_create(&client_shm, shmem_size, tmpnam(NULL), ctx);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to create shared memory segments", sts, s);
        return;
    }

    client_list = apr_rmm_malloc(client_rmm, sizeof(*client_list) +
                                            sizeof(client_entry*)*num_buckets);
    if (!client_list) {
        log_error_and_cleanup("failed to allocate shared memory", -1, s);
        return;
    }
    client_list->table = (client_entry**) (client_list + 1);
    for (idx = 0; idx < num_buckets; idx++) {
        client_list->table[idx] = NULL;
    }
    client_list->tbl_len     = num_buckets;
    client_list->num_entries = 0;

    tmpnam(client_lock_name);
    /* FIXME: get the client_lock_name from a directive so we're portable
     * to non-process-inheriting operating systems, like Win32. */
    sts = apr_global_mutex_create(&client_lock, client_lock_name,
                                  APR_LOCK_DEFAULT, ctx);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to create lock (client_lock)", sts, s);
        return;
    }


    /* setup opaque */

    opaque_cntr = apr_rmm_malloc(client_rmm, sizeof(*opaque_cntr));
    if (opaque_cntr == NULL) {
        log_error_and_cleanup("failed to allocate shared memory", -1, s);
        return;
    }
    *opaque_cntr = 1UL;

    tmpnam(opaque_lock_name);
    /* FIXME: get the opaque_lock_name from a directive so we're portable
     * to non-process-inheriting operating systems, like Win32. */
    sts = apr_global_mutex_create(&opaque_lock, opaque_lock_name,
                                  APR_LOCK_DEFAULT, ctx);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to create lock (opaque_lock)", sts, s);
        return;
    }


    /* setup one-time-nonce counter */

    otn_counter = apr_rmm_malloc(client_rmm, sizeof(*otn_counter));
    if (otn_counter == NULL) {
        log_error_and_cleanup("failed to allocate shared memory", -1, s);
        return;
    }
    *otn_counter = 0;
    /* no lock here */


    /* success */
    return;
}

#endif /* APR_HAS_SHARED_MEMORY */


static int initialize_module(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    void *data;
    const char *userdata_key = "auth_digest_init";

    /* initialize_module() will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call. */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                               apr_pool_cleanup_null, s->process->pool);
        return OK;
    }
    if (initialize_secret(s) != APR_SUCCESS) {
        return !OK;
    }

#if APR_HAS_SHARED_MEMORY
    /* Note: this stuff is currently fixed for the lifetime of the server,
     * i.e. even across restarts. This means that A) any shmem-size
     * configuration changes are ignored, and B) certain optimizations,
     * such as only allocating the smallest necessary entry for each
     * client, can't be done. However, the alternative is a nightmare:
     * we can't call apr_shm_destroy on a graceful restart because there
     * will be children using the tables, and we also don't know when the
     * last child dies. Therefore we can never clean up the old stuff,
     * creating a creeping memory leak.
     */
    initialize_tables(s, p);
    apr_pool_cleanup_register(p, NULL, cleanup_tables, apr_pool_cleanup_null);
#endif  /* APR_HAS_SHARED_MEMORY */
    return OK;
}

static void initialize_child(apr_pool_t *p, server_rec *s)
{
    apr_status_t sts;

    if (!client_shm) {
        return;
    }

    /* FIXME: get the client_lock_name from a directive so we're portable
     * to non-process-inheriting operating systems, like Win32. */
    sts = apr_global_mutex_child_init(&client_lock, client_lock_name, p);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to create lock (client_lock)", sts, s);
        return;
    }
    /* FIXME: get the opaque_lock_name from a directive so we're portable
     * to non-process-inheriting operating systems, like Win32. */
    sts = apr_global_mutex_child_init(&opaque_lock, opaque_lock_name, p);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to create lock (opaque_lock)", sts, s);
        return;
    }
}

/*
 * configuration code
 */

static void *create_digest_dir_config(apr_pool_t *p, char *dir)
{
    digest_config_rec *conf;

    if (dir == NULL) {
        return NULL;
    }

    conf = (digest_config_rec *) apr_pcalloc(p, sizeof(digest_config_rec));
    if (conf) {
        conf->qop_list       = apr_palloc(p, sizeof(char*));
        conf->qop_list[0]    = NULL;
        conf->nonce_lifetime = DFLT_NONCE_LIFE;
        conf->dir_name       = apr_pstrdup(p, dir);
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
    apr_sha1_init(&conf->nonce_ctx);
    apr_sha1_update_binary(&conf->nonce_ctx, secret, sizeof(secret));
    apr_sha1_update_binary(&conf->nonce_ctx, (const unsigned char *) realm,
                           strlen(realm));

    return DECLINE_CMD;
}

static const char *add_authn_provider(cmd_parms *cmd, void *config,
                                      const char *arg)
{
    digest_config_rec *conf = (digest_config_rec*)config;
    authn_provider_list *newp;
    const char *provider_name;
    
    if (strcasecmp(arg, "on") == 0) {
        provider_name = AUTHN_DEFAULT_PROVIDER;
    }
    else if (strcasecmp(arg, "off") == 0) {
        /* Clear all configured providers and return. */
        conf->providers = NULL; 
        return NULL;
    }
    else {
        provider_name = apr_pstrdup(cmd->pool, arg);
    }

    newp = apr_pcalloc(cmd->pool, sizeof(authn_provider_list));
    newp->provider_name = provider_name;

    /* lookup and cache the actual provider now */
    newp->provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP,
                                        newp->provider_name, "0");

    if (newp->provider == NULL) {
       /* by the time they use it, the provider should be loaded and
           registered with us. */
        return apr_psprintf(cmd->pool,
                            "Unknown Authn provider: %s",
                            newp->provider_name);
    }

    if (!newp->provider->get_realm_hash) {
        /* if it doesn't provide the appropriate function, reject it */
        return apr_psprintf(cmd->pool,
                            "The '%s' Authn provider doesn't support "
                            "Digest Authentication", provider_name);
    }

    /* Add it to the list now. */
    if (!conf->providers) {
        conf->providers = newp;
    }
    else {
        authn_provider_list *last = conf->providers;

        while (last->next) {
            last = last->next;
        }
        last->next = newp;
    }

    return NULL;
}

static const char *set_qop(cmd_parms *cmd, void *config, const char *op)
{
    digest_config_rec *conf = (digest_config_rec *) config;
    char **tmp;
    int cnt;

    if (!strcasecmp(op, "none")) {
        if (conf->qop_list[0] == NULL) {
            conf->qop_list = apr_palloc(cmd->pool, 2 * sizeof(char*));
            conf->qop_list[1] = NULL;
        }
        conf->qop_list[0] = "none";
        return NULL;
    }

    if (!strcasecmp(op, "auth-int")) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                     "Digest: WARNING: qop `auth-int' currently only works "
                     "correctly for responses with no entity");
    }
    else if (strcasecmp(op, "auth")) {
        return apr_pstrcat(cmd->pool, "Unrecognized qop: ", op, NULL);
    }

    for (cnt = 0; conf->qop_list[cnt] != NULL; cnt++)
        ;

    tmp = apr_palloc(cmd->pool, (cnt + 2) * sizeof(char*));
    memcpy(tmp, conf->qop_list, cnt*sizeof(char*));
    tmp[cnt]   = apr_pstrdup(cmd->pool, op);
    tmp[cnt+1] = NULL;
    conf->qop_list = tmp;

    return NULL;
}

static const char *set_nonce_lifetime(cmd_parms *cmd, void *config,
                                      const char *t)
{
    char *endptr;
    long  lifetime;

    lifetime = strtol(t, &endptr, 10); 
    if (endptr < (t+strlen(t)) && !apr_isspace(*endptr)) {
        return apr_pstrcat(cmd->pool,
                           "Invalid time in AuthDigestNonceLifetime: ",
                           t, NULL);
    }

    ((digest_config_rec *) config)->nonce_lifetime = apr_time_from_sec(lifetime);
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
    if (flag && !client_shm)
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                     cmd->server, "Digest: WARNING: nonce-count checking "
                     "is not supported on platforms without shared-memory "
                     "support - disabling check");

    ((digest_config_rec *) config)->check_nc = flag;
    return NULL;
}

static const char *set_algorithm(cmd_parms *cmd, void *config, const char *alg)
{
    if (!strcasecmp(alg, "MD5-sess")) {
        if (!client_shm) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                         cmd->server, "Digest: WARNING: algorithm `MD5-sess' "
                         "is not supported on platforms without shared-memory "
                         "support - reverting to MD5");
            alg = "MD5";
        }
    }
    else if (strcasecmp(alg, "MD5")) {
        return apr_pstrcat(cmd->pool, "Invalid algorithm in AuthDigestAlgorithm: ", alg, NULL);
    }

    ((digest_config_rec *) config)->algorithm = alg;
    return NULL;
}

static const char *set_uri_list(cmd_parms *cmd, void *config, const char *uri)
{
    digest_config_rec *c = (digest_config_rec *) config;
    if (c->uri_list) {
        c->uri_list[strlen(c->uri_list)-1] = '\0';
        c->uri_list = apr_pstrcat(cmd->pool, c->uri_list, " ", uri, "\"", NULL);
    }
    else {
        c->uri_list = apr_pstrcat(cmd->pool, ", domain=\"", uri, "\"", NULL);
    }
    return NULL;
}

static const char *set_shmem_size(cmd_parms *cmd, void *config,
                                  const char *size_str)
{
    char *endptr;
    long  size, min;

    size = strtol(size_str, &endptr, 10); 
    while (apr_isspace(*endptr)) endptr++;
    if (*endptr == '\0' || *endptr == 'b' || *endptr == 'B') {
        ;
    }
    else if (*endptr == 'k' || *endptr == 'K') {
        size *= 1024;
    }
    else if (*endptr == 'm' || *endptr == 'M') {
        size *= 1048576;
    }
    else {
        return apr_pstrcat(cmd->pool, "Invalid size in AuthDigestShmemSize: ",
                          size_str, NULL);
    }

    min = sizeof(*client_list) + sizeof(client_entry*) + sizeof(client_entry);
    if (size < min) {
        return apr_psprintf(cmd->pool, "size in AuthDigestShmemSize too small: "
                           "%ld < %ld", size, min);
    }

    shmem_size  = size;
    num_buckets = (size - sizeof(*client_list)) /
                  (sizeof(client_entry*) + HASH_DEPTH * sizeof(client_entry));
    if (num_buckets == 0) {
        num_buckets = 1;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "Digest: Set shmem-size: %ld, num-buckets: %ld", shmem_size,
                 num_buckets);

    return NULL;
}

static const command_rec digest_cmds[] =
{
    AP_INIT_TAKE1("AuthName", set_realm, NULL, OR_AUTHCFG, 
     "The authentication realm (e.g. \"Members Only\")"),
    AP_INIT_ITERATE("AuthDigestProvider", add_authn_provider, NULL, OR_AUTHCFG,
                     "specify the auth providers for a directory or location"),
    AP_INIT_ITERATE("AuthDigestQop", set_qop, NULL, OR_AUTHCFG, 
     "A list of quality-of-protection options"),
    AP_INIT_TAKE1("AuthDigestNonceLifetime", set_nonce_lifetime, NULL, OR_AUTHCFG, 
     "Maximum lifetime of the server nonce (seconds)"),
    AP_INIT_TAKE1("AuthDigestNonceFormat", set_nonce_format, NULL, OR_AUTHCFG, 
     "The format to use when generating the server nonce"),
    AP_INIT_FLAG("AuthDigestNcCheck", set_nc_check, NULL, OR_AUTHCFG, 
     "Whether or not to check the nonce-count sent by the client"),
    AP_INIT_TAKE1("AuthDigestAlgorithm", set_algorithm, NULL, OR_AUTHCFG, 
     "The algorithm used for the hash calculation"),
    AP_INIT_ITERATE("AuthDigestDomain", set_uri_list, NULL, OR_AUTHCFG, 
     "A list of URI's which belong to the same protection space as the current URI"),
    AP_INIT_TAKE1("AuthDigestShmemSize", set_shmem_size, NULL, RSRC_CONF, 
     "The amount of shared memory to allocate for keeping track of clients"),
    {NULL}
};


/*
 * client list code
 *
 * Each client is assigned a number, which is transfered in the opaque
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
 * or NULL if it's not found.
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


    if (!key || !client_shm)  return NULL;

    bucket = key % client_list->tbl_len;
    entry  = client_list->table[bucket];

    apr_global_mutex_lock(client_lock);

    while (entry && key != entry->key) {
        prev  = entry;
        entry = entry->next;
    }

    if (entry && prev) {                /* move entry to front of list */
        prev->next  = entry->next;
        entry->next = client_list->table[bucket];
        client_list->table[bucket] = entry;
    }

    apr_global_mutex_unlock(client_lock);

    if (entry) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "get_client(): client %lu found", key);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "get_client(): client %lu not found", key);
    }

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

    for (idx = 0; idx < client_list->tbl_len; idx++) {
        entry = client_list->table[idx];
        prev  = NULL;
        while (entry->next) {   /* find last entry */
            prev  = entry;
            entry = entry->next;
        }
        if (prev) {
            prev->next = NULL;   /* cut list */
        }
        else {
            client_list->table[idx] = NULL;
        }
        if (entry) {                    /* remove entry */
            apr_rmm_free(client_rmm, (apr_rmm_off_t)entry);
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


    if (!key || !client_shm) {
        return NULL;
    }

    bucket = key % client_list->tbl_len;
    entry  = client_list->table[bucket];

    apr_global_mutex_lock(client_lock);

    /* try to allocate a new entry */

    entry = (client_entry *)apr_rmm_malloc(client_rmm, sizeof(client_entry));
    if (!entry) {
        long num_removed = gc();
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "Digest: gc'd %ld client entries. Total new clients: "
                     "%ld; Total removed clients: %ld; Total renewed clients: "
                     "%ld", num_removed,
                     client_list->num_created - client_list->num_renewed,
                     client_list->num_removed, client_list->num_renewed);
        entry = (client_entry *)apr_rmm_malloc(client_rmm, sizeof(client_entry));
        if (!entry) {
            return NULL;       /* give up */
        }
    }

    /* now add the entry */

    memcpy(entry, info, sizeof(client_entry));
    entry->key  = key;
    entry->next = client_list->table[bucket];
    client_list->table[bucket] = entry;
    client_list->num_created++;
    client_list->num_entries++;

    apr_global_mutex_unlock(client_lock);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "allocated new client %lu", key);

    return entry;
}


/*
 * Authorization header parser code
 */

/* Parse the Authorization header, if it exists */
static int get_digest_rec(request_rec *r, digest_header_rec *resp)
{
    const char *auth_line;
    apr_size_t l;
    int vk = 0, vv = 0;
    char *key, *value;

    auth_line = apr_table_get(r->headers_in,
                             (PROXYREQ_PROXY == r->proxyreq)
                                 ? "Proxy-Authorization"
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

    key   = apr_palloc(r->pool, l+1);
    value = apr_palloc(r->pool, l+1);

    while (auth_line[0] != '\0') {

        /* find key */

        while (apr_isspace(auth_line[0])) {
            auth_line++;
        }
        vk = 0;
        while (auth_line[0] != '=' && auth_line[0] != ','
               && auth_line[0] != '\0' && !apr_isspace(auth_line[0])) {
            key[vk++] = *auth_line++;
        }
        key[vk] = '\0';
        while (apr_isspace(auth_line[0])) {
            auth_line++;
        }

        /* find value */

        if (auth_line[0] == '=') {
            auth_line++;
            while (apr_isspace(auth_line[0])) {
                auth_line++;
            }

            vv = 0;
            if (auth_line[0] == '\"') {         /* quoted string */
                auth_line++;
                while (auth_line[0] != '\"' && auth_line[0] != '\0') {
                    if (auth_line[0] == '\\' && auth_line[1] != '\0') {
                        auth_line++;            /* escaped char */
                    }
                    value[vv++] = *auth_line++;
                }
                if (auth_line[0] != '\0') {
                    auth_line++;
                }
            }
            else {                               /* token */
                while (auth_line[0] != ',' && auth_line[0] != '\0'
                       && !apr_isspace(auth_line[0])) {
                    value[vv++] = *auth_line++;
                }
            }
            value[vv] = '\0';
        }

        while (auth_line[0] != ',' && auth_line[0] != '\0') {
            auth_line++;
        }
        if (auth_line[0] != '\0') {
            auth_line++;
        }

        if (!strcasecmp(key, "username"))
            resp->username = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "realm"))
            resp->realm = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "nonce"))
            resp->nonce = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "uri"))
            resp->uri = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "response"))
            resp->digest = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "algorithm"))
            resp->algorithm = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "cnonce"))
            resp->cnonce = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "opaque"))
            resp->opaque = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "qop"))
            resp->message_qop = apr_pstrdup(r->pool, value);
        else if (!strcasecmp(key, "nc"))
            resp->nonce_count = apr_pstrdup(r->pool, value);
    }

    if (!resp->username || !resp->realm || !resp->nonce || !resp->uri
        || !resp->digest
        || (resp->message_qop && (!resp->cnonce || !resp->nonce_count))) {
        resp->auth_hdr_sts = INVALID;
        return !OK;
    }

    if (resp->opaque) {
        resp->opaque_num = (unsigned long) strtol(resp->opaque, NULL, 16);
    }

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
static int parse_hdr_and_update_nc(request_rec *r)
{
    digest_header_rec *resp;
    int res;

    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    resp = apr_pcalloc(r->pool, sizeof(digest_header_rec));
    resp->raw_request_uri = r->unparsed_uri;
    resp->psd_request_uri = &r->parsed_uri;
    resp->needed_auth = 0;
    ap_set_module_config(r->request_config, &auth_digest_module, resp);

    res = get_digest_rec(r, resp);
    resp->client = get_client(resp->opaque_num, r);
    if (res == OK && resp->client) {
        resp->client->nonce_count++;
    }

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
    unsigned char sha1[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t ctx;
    int idx;

    memcpy(&ctx, &conf->nonce_ctx, sizeof(ctx));
    /*
    apr_sha1_update_binary(&ctx, (const unsigned char *) server->server_hostname,
                         strlen(server->server_hostname));
    apr_sha1_update_binary(&ctx, (const unsigned char *) &server->port,
                         sizeof(server->port));
     */
    apr_sha1_update_binary(&ctx, (const unsigned char *) timestr, strlen(timestr));
    if (opaque) {
        apr_sha1_update_binary(&ctx, (const unsigned char *) opaque,
                             strlen(opaque));
    }
    apr_sha1_final(sha1, &ctx);

    for (idx=0; idx<APR_SHA1_DIGESTSIZE; idx++) {
        *hash++ = hex[sha1[idx] >> 4];
        *hash++ = hex[sha1[idx] & 0xF];
    }

    *hash++ = '\0';
}


/* The nonce has the format b64(time)+hash .
 */
static const char *gen_nonce(apr_pool_t *p, apr_time_t now, const char *opaque,
                             const server_rec *server,
                             const digest_config_rec *conf)
{
    char *nonce = apr_palloc(p, NONCE_LEN+1);
    int len;
    time_rec t;

    if (conf->nonce_lifetime != 0) {
        t.time = now;
    }
    else if (otn_counter) {
        /* this counter is not synch'd, because it doesn't really matter
         * if it counts exactly.
         */
        t.time = (*otn_counter)++;
    }
    else {
        /* XXX: WHAT IS THIS CONSTANT? */
        t.time = 42;
    }
    len = apr_base64_encode_binary(nonce, t.arr, sizeof(t.arr));
    gen_nonce_hash(nonce+NONCE_TIME_LEN, nonce, opaque, server, conf);

    return nonce;
}


/*
 * Opaque and hash-table management
 */

/*
 * Generate a new client entry, add it to the list, and return the
 * entry. Returns NULL if failed.
 */
static client_entry *gen_client(const request_rec *r)
{
    unsigned long op;
    client_entry new_entry = { 0, NULL, 0, "", "" }, *entry;

    if (!opaque_cntr) {
        return NULL;
    }

    apr_global_mutex_lock(opaque_lock);
    op = (*opaque_cntr)++;
    apr_global_mutex_lock(opaque_lock);

    if (!(entry = add_client(op, &new_entry, r->server))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Digest: failed to allocate client entry - ignoring "
                      "client");
        return NULL;
    }

    return entry;
}


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
 *         apr_pstrcat(r->pool, username, ":", ap_auth_name(r), ":", passwd))
 * ap_md5(r->pool,
 *         (unsigned char *) apr_pstrcat(r->pool, h_urp, ":", resp->nonce, ":",
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
             (unsigned char *) apr_pstrcat(r->pool, conf->ha1, ":", resp->nonce,
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
    if (resp->opaque && resp->client && resp->client->ha1[0]) {
        return resp->client->ha1;
    }
    else if (!generate) {
        return NULL;
    }

    /* generate a new session */
    if (!resp->client) {
        resp->client = gen_client(r);
    }
    if (resp->client) {
        ha1 = get_userpw_hash(r, resp, conf);
        if (ha1) {
            memcpy(resp->client->ha1, ha1, sizeof(resp->client->ha1));
        }
    }

    return ha1;
}


static void clear_session(const digest_header_rec *resp)
{
    if (resp->client) {
        resp->client->ha1[0] = '\0';
    }
}

/*
 * Authorization challenge generation code (for WWW-Authenticate)
 */

static const char *ltox(apr_pool_t *p, unsigned long num)
{
    if (num != 0) {
        return apr_psprintf(p, "%lx", num);
    }
    else {
        return "";
    }
}

static void note_digest_auth_failure(request_rec *r,
                                     const digest_config_rec *conf,
                                     digest_header_rec *resp, int stale)
{
    const char   *qop, *opaque, *opaque_param, *domain, *nonce;
    int           cnt;

    /* Setup qop */

    if (conf->qop_list[0] == NULL) {
        qop = ", qop=\"auth\"";
    }
    else if (!strcasecmp(conf->qop_list[0], "none")) {
        qop = "";
    }
    else {
        qop = apr_pstrcat(r->pool, ", qop=\"", conf->qop_list[0], NULL);
        for (cnt = 1; conf->qop_list[cnt] != NULL; cnt++) {
            qop = apr_pstrcat(r->pool, qop, ",", conf->qop_list[cnt], NULL);
        }
        qop = apr_pstrcat(r->pool, qop, "\"", NULL);
    }

    /* Setup opaque */

    if (resp->opaque == NULL) {
        /* new client */
        if ((conf->check_nc || conf->nonce_lifetime == 0
             || !strcasecmp(conf->algorithm, "MD5-sess"))
            && (resp->client = gen_client(r)) != NULL) {
            opaque = ltox(r->pool, resp->client->key);
        }
        else {
            opaque = "";                /* opaque not needed */
        }
    }
    else if (resp->client == NULL) {
        /* client info was gc'd */
        resp->client = gen_client(r);
        if (resp->client != NULL) {
            opaque = ltox(r->pool, resp->client->key);
            stale = 1;
            client_list->num_renewed++;
        }
        else {
            opaque = "";                /* ??? */
        }
    }
    else {
        opaque = resp->opaque;
        /* we're generating a new nonce, so reset the nonce-count */
        resp->client->nonce_count = 0;
    }

    if (opaque[0]) {
        opaque_param = apr_pstrcat(r->pool, ", opaque=\"", opaque, "\"", NULL);
    }
    else {
        opaque_param = NULL;
    }

    /* Setup nonce */

    nonce = gen_nonce(r->pool, r->request_time, opaque, r->server, conf);
    if (resp->client && conf->nonce_lifetime == 0) {
        memcpy(resp->client->last_nonce, nonce, NONCE_LEN+1);
    }

    /* Setup MD5-sess stuff. Note that we just clear out the session
     * info here, since we can't generate a new session until the request
     * from the client comes in with the cnonce.
     */

    if (!strcasecmp(conf->algorithm, "MD5-sess")) {
        clear_session(resp);
    }

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

    apr_table_mergen(r->err_headers_out,
                     (PROXYREQ_PROXY == r->proxyreq)
                         ? "Proxy-Authenticate" : "WWW-Authenticate",
                     apr_psprintf(r->pool, "Digest realm=\"%s\", "
                                  "nonce=\"%s\", algorithm=%s%s%s%s%s",
                                  ap_auth_name(r), nonce, conf->algorithm,
                                  opaque_param ? opaque_param : "",
                                  domain ? domain : "",
                                  stale ? ", stale=true" : "", qop));

}


/*
 * Authorization header verification code
 */

static const char *get_hash(request_rec *r, const char *user,
                            digest_config_rec *conf)
{
    authn_status auth_result;
    char *password;
    authn_provider_list *current_provider;

    current_provider = conf->providers;
    do {
        const authn_provider *provider;

        /* For now, if a provider isn't set, we'll be nice and use the file
         * provider.
         */
        if (!current_provider) {
            provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP,
                                          AUTHN_DEFAULT_PROVIDER, "0");

            if (!provider || !provider->get_realm_hash) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "No Authn provider configured");
                auth_result = AUTH_GENERAL_ERROR;
                break;
            }
        }
        else {
            provider = current_provider->provider;
        }

        /* We expect the password to be md5 hash of user:realm:password */
        auth_result = provider->get_realm_hash(r, user, conf->realm,
                                               &password);

        /* Something occured.  Stop checking. */
        if (auth_result != AUTH_USER_NOT_FOUND) {
            break;
        }

        /* If we're not really configured for providers, stop now. */
        if (!conf->providers) {
           break;
        }

        current_provider = current_provider->next;
    } while (current_provider);

    if (auth_result != AUTH_USER_FOUND) {
        return NULL;
    }
    else {
        return password;
    }
}

static int check_nc(const request_rec *r, const digest_header_rec *resp,
                    const digest_config_rec *conf)
{
    unsigned long nc;
    const char *snc = resp->nonce_count;
    char *endptr;

    if (!conf->check_nc || !client_shm) {
        return OK;
    }

    nc = strtol(snc, &endptr, 16);
    if (endptr < (snc+strlen(snc)) && !apr_isspace(*endptr)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Digest: invalid nc %s received - not a number", snc);
        return !OK;
    }

    if (!resp->client) {
        return !OK;
    }

    if (nc != resp->client->nonce_count) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
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
    apr_time_t dt;
    int len;
    time_rec nonce_time;
    char tmp, hash[NONCE_HASH_LEN+1];

    if (strlen(resp->nonce) != NONCE_LEN) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Digest: invalid nonce %s received - length is not %d",
                      resp->nonce, NONCE_LEN);
        note_digest_auth_failure(r, conf, resp, 1);
        return HTTP_UNAUTHORIZED;
    }

    tmp = resp->nonce[NONCE_TIME_LEN];
    resp->nonce[NONCE_TIME_LEN] = '\0';
    len = apr_base64_decode_binary(nonce_time.arr, resp->nonce);
    gen_nonce_hash(hash, resp->nonce, resp->opaque, r->server, conf);
    resp->nonce[NONCE_TIME_LEN] = tmp;
    resp->nonce_time = nonce_time.time;

    if (strcmp(hash, resp->nonce+NONCE_TIME_LEN)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Digest: invalid nonce %s received - hash is not %s",
                      resp->nonce, hash);
        note_digest_auth_failure(r, conf, resp, 1);
        return HTTP_UNAUTHORIZED;
    }

    dt = r->request_time - nonce_time.time;
    if (conf->nonce_lifetime > 0 && dt < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Digest: invalid nonce %s received - user attempted "
                      "time travel", resp->nonce);
        note_digest_auth_failure(r, conf, resp, 1);
        return HTTP_UNAUTHORIZED;
    }

    if (conf->nonce_lifetime > 0) {
        if (dt > conf->nonce_lifetime) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0,r,
                          "Digest: user %s: nonce expired (%.2f seconds old "
                          "- max lifetime %.2f) - sending new nonce", 
                          r->user, (double)apr_time_sec(dt),
                          (double)apr_time_sec(conf->nonce_lifetime));
            note_digest_auth_failure(r, conf, resp, 1);
            return HTTP_UNAUTHORIZED;
        }
    }
    else if (conf->nonce_lifetime == 0 && resp->client) {
        if (memcmp(resp->client->last_nonce, resp->nonce, NONCE_LEN)) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "Digest: user %s: one-time-nonce mismatch - sending "
                          "new nonce", r->user);
            note_digest_auth_failure(r, conf, resp, 1);
            return HTTP_UNAUTHORIZED;
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

    ha2 = ap_md5(r->pool, (unsigned char *)apr_pstrcat(r->pool, r->method, ":",
                                                       resp->uri, NULL));
    return ap_md5(r->pool,
                  (unsigned char *)apr_pstrcat(r->pool, ha1, ":", resp->nonce,
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
        if (!ha1) {
            return NULL;
        }
    }
    else {
        ha1 = conf->ha1;
    }

    if (resp->message_qop && !strcasecmp(resp->message_qop, "auth-int")) {
        a2 = apr_pstrcat(r->pool, r->method, ":", resp->uri, ":",
                         ap_md5(r->pool, (const unsigned char*) ""), NULL);
                         /* TBD */
    }
    else {
        a2 = apr_pstrcat(r->pool, r->method, ":", resp->uri, NULL);
    }
    ha2 = ap_md5(r->pool, (const unsigned char *)a2);

    return ap_md5(r->pool,
                  (unsigned char *)apr_pstrcat(r->pool, ha1, ":", resp->nonce,
                                               ":", resp->nonce_count, ":",
                                               resp->cnonce, ":",
                                               resp->message_qop, ":", ha2,
                                               NULL));
}


static void copy_uri_components(apr_uri_t *dst, 
                                apr_uri_t *src, request_rec *r) {
    if (src->scheme && src->scheme[0] != '\0') {
        dst->scheme = src->scheme;
    }
    else {
        dst->scheme = (char *) "http";
    }

    if (src->hostname && src->hostname[0] != '\0') {
        dst->hostname = apr_pstrdup(r->pool, src->hostname);
        ap_unescape_url(dst->hostname);
    }
    else {
        dst->hostname = (char *) ap_get_server_name(r);
    }

    if (src->port_str && src->port_str[0] != '\0') {
        dst->port = src->port;
    }
    else {
        dst->port = ap_get_server_port(r);
    }

    if (src->path && src->path[0] != '\0') {
        dst->path = apr_pstrdup(r->pool, src->path);
        ap_unescape_url(dst->path);
    }
    else {
        dst->path = src->path;
    }

    if (src->query && src->query[0] != '\0') {
        dst->query = apr_pstrdup(r->pool, src->query);
        ap_unescape_url(dst->query);
    }
    else {
        dst->query = src->query;
    }
}

/* These functions return 0 if client is OK, and proper error status
 * if not... either HTTP_UNAUTHORIZED, if we made a check, and it failed, or
 * HTTP_INTERNAL_SERVER_ERROR, if things are so totally confused that we
 * couldn't figure out how to tell if the client is authorized or not.
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
    const char        *t;
    int                res;

    /* do we require Digest auth for this URI? */

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Digest")) {
        return DECLINED;
    }

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Digest: need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }


    /* get the client response and mark */

    mainreq = r;
    while (mainreq->main != NULL) {
        mainreq = mainreq->main;
    }
    while (mainreq->prev != NULL) {
        mainreq = mainreq->prev;
    }
    resp = (digest_header_rec *) ap_get_module_config(mainreq->request_config,
                                                      &auth_digest_module);
    resp->needed_auth = 1;


    /* get our conf */

    conf = (digest_config_rec *) ap_get_module_config(r->per_dir_config,
                                                      &auth_digest_module);


    /* check for existence and syntax of Auth header */

    if (resp->auth_hdr_sts != VALID) {
        if (resp->auth_hdr_sts == NOT_DIGEST) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Digest: client used wrong authentication scheme "
                          "`%s': %s", resp->scheme, r->uri);
        }
        else if (resp->auth_hdr_sts == INVALID) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Digest: missing user, realm, nonce, uri, digest, "
                          "cnonce, or nonce_count in authorization header: %s",
                          r->uri);
        }
        /* else (resp->auth_hdr_sts == NO_HEADER) */
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    r->user         = (char *) resp->username;
    r->ap_auth_type = (char *) "Digest";

    /* check the auth attributes */

    if (strcmp(resp->uri, resp->raw_request_uri)) {
        /* Hmm, the simple match didn't work (probably a proxy modified the
         * request-uri), so lets do a more sophisticated match
         */
        apr_uri_t r_uri, d_uri;

        copy_uri_components(&r_uri, resp->psd_request_uri, r);
        if (apr_uri_parse(r->pool, resp->uri, &d_uri) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Digest: invalid uri <%s> in Authorization header",
                          resp->uri);
            return HTTP_BAD_REQUEST;
        }

        if (d_uri.hostname) {
            ap_unescape_url(d_uri.hostname);
        }
        if (d_uri.path) {
            ap_unescape_url(d_uri.path);
        }
        if (d_uri.query) {
            ap_unescape_url(d_uri.query);
        }

        if (r->method_number == M_CONNECT) {
            if (strcmp(resp->uri, r_uri.hostinfo)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Digest: uri mismatch - <%s> does not match "
                              "request-uri <%s>", resp->uri, r_uri.hostinfo);
                return HTTP_BAD_REQUEST;
            }
        }
        else if (
            /* check hostname matches, if present */
            (d_uri.hostname && d_uri.hostname[0] != '\0'
              && strcasecmp(d_uri.hostname, r_uri.hostname))
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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Digest: uri mismatch - <%s> does not match "
                          "request-uri <%s>", resp->uri, resp->raw_request_uri);
            return HTTP_BAD_REQUEST;
        }
    }

    if (resp->opaque && resp->opaque_num == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Digest: received invalid opaque - got `%s'",
                      resp->opaque);
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    if (strcmp(resp->realm, conf->realm)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Digest: realm mismatch - got `%s' but expected `%s'",
                      resp->realm, conf->realm);
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    if (resp->algorithm != NULL
        && strcasecmp(resp->algorithm, "MD5")
        && strcasecmp(resp->algorithm, "MD5-sess")) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Digest: unknown algorithm `%s' received: %s",
                      resp->algorithm, r->uri);
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    if (!(conf->ha1 = get_hash(r, r->user, conf))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Digest: user `%s' in realm `%s' not found: %s",
                      r->user, conf->realm, r->uri);
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    
    if (resp->message_qop == NULL) {
        /* old (rfc-2069) style digest */
        if (strcmp(resp->digest, old_digest(r, resp, conf->ha1))) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Digest: user %s: password mismatch: %s", r->user,
                          r->uri);
            note_digest_auth_failure(r, conf, resp, 0);
            return HTTP_UNAUTHORIZED;
        }
    }
    else {
        const char *exp_digest;
        int match = 0, idx;
        for (idx = 0; conf->qop_list[idx] != NULL; idx++) {
            if (!strcasecmp(conf->qop_list[idx], resp->message_qop)) {
                match = 1;
                break;
            }
        }

        if (!match
            && !(conf->qop_list[0] == NULL
                 && !strcasecmp(resp->message_qop, "auth"))) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Digest: invalid qop `%s' received: %s",
                          resp->message_qop, r->uri);
            note_digest_auth_failure(r, conf, resp, 0);
            return HTTP_UNAUTHORIZED;
        }

        exp_digest = new_digest(r, resp, conf);
        if (!exp_digest) {
            /* we failed to allocate a client struct */
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (strcmp(resp->digest, exp_digest)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Digest: user %s: password mismatch: %s", r->user,
                          r->uri);
            note_digest_auth_failure(r, conf, resp, 0);
            return HTTP_UNAUTHORIZED;
        }
    }

    if (check_nc(r, resp, conf) != OK) {
        note_digest_auth_failure(r, conf, resp, 0);
        return HTTP_UNAUTHORIZED;
    }

    /* Note: this check is done last so that a "stale=true" can be
       generated if the nonce is old */
    if ((res = check_nonce(r, resp, conf))) {
        return res;
    }

    return OK;
}

/*
 * Authorization-Info header code
 */

#ifdef SEND_DIGEST
static const char *hdr(const apr_table_t *tbl, const char *name)
{
    const char *val = apr_table_get(tbl, name);
    if (val) {
        return val;
    }
    else {
        return "";
    }
}
#endif

static int add_auth_info(request_rec *r)
{
    const digest_config_rec *conf =
                (digest_config_rec *) ap_get_module_config(r->per_dir_config,
                                                           &auth_digest_module);
    digest_header_rec *resp =
                (digest_header_rec *) ap_get_module_config(r->request_config,
                                                           &auth_digest_module);
    const char *ai = NULL, *digest = NULL, *nextnonce = "";

    if (resp == NULL || !resp->needed_auth || conf == NULL) {
        return OK;
    }


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
        char date[APR_RFC822_DATE_LEN];
        apr_rfc822_date(date, r->request_time);
        char *entity_info =
            ap_md5(r->pool,
                   (unsigned char *) apr_pstrcat(r->pool, resp->raw_request_uri,
                       ":",
                       r->content_type ? r->content_type : ap_default_type(r), ":",
                       hdr(r->headers_out, "Content-Length"), ":",
                       r->content_encoding ? r->content_encoding : "", ":",
                       hdr(r->headers_out, "Last-Modified"), ":",
                       r->no_cache && !apr_table_get(r->headers_out, "Expires") ?
                            date :
                            hdr(r->headers_out, "Expires"),
                       NULL));
        digest =
            ap_md5(r->pool,
                   (unsigned char *)apr_pstrcat(r->pool, conf->ha1, ":",
                                               resp->nonce, ":",
                                               r->method, ":",
                                               date, ":",
                                               entity_info, ":",
                                               ap_md5(r->pool, (unsigned char *) ""), /* H(entity) - TBD */
                                               NULL));
#endif
    }


    /* setup nextnonce
     */
    if (conf->nonce_lifetime > 0) {
        /* send nextnonce if current nonce will expire in less than 30 secs */
        if ((r->request_time - resp->nonce_time) > (conf->nonce_lifetime-NEXTNONCE_DELTA)) {
            nextnonce = apr_pstrcat(r->pool, ", nextnonce=\"",
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
        nextnonce = apr_pstrcat(r->pool, ", nextnonce=\"", nonce, "\"", NULL);
        memcpy(resp->client->last_nonce, nonce, NONCE_LEN+1);
    }
    /* else nonce never expires, hence no nextnonce */


    /* do rfc-2069 digest
     */
    if (conf->qop_list[0] && !strcasecmp(conf->qop_list[0], "none")
        && resp->message_qop == NULL) {
        /* use only RFC-2069 format */
        if (digest) {
            ai = apr_pstrcat(r->pool, "digest=\"", digest, "\"", nextnonce,NULL);
        }
        else {
            ai = nextnonce;
        }
    }
    else {
        const char *resp_dig, *ha1, *a2, *ha2;

        /* calculate rspauth attribute
         */
        if (resp->algorithm && !strcasecmp(resp->algorithm, "MD5-sess")) {
            ha1 = get_session_HA1(r, resp, conf, 0);
            if (!ha1) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Digest: internal error: couldn't find session "
                              "info for user %s", resp->username);
                return !OK;
            }
        }
        else {
            ha1 = conf->ha1;
        }

        if (resp->message_qop && !strcasecmp(resp->message_qop, "auth-int")) {
            a2 = apr_pstrcat(r->pool, ":", resp->uri, ":",
                             ap_md5(r->pool,(const unsigned char *) ""), NULL);
                             /* TBD */
        }
        else {
            a2 = apr_pstrcat(r->pool, ":", resp->uri, NULL);
        }
        ha2 = ap_md5(r->pool, (const unsigned char *)a2);

        resp_dig = ap_md5(r->pool,
                          (unsigned char *)apr_pstrcat(r->pool, ha1, ":",
                                                       resp->nonce, ":",
                                                       resp->nonce_count, ":",
                                                       resp->cnonce, ":",
                                                       resp->message_qop ?
                                                         resp->message_qop : "",
                                                       ":", ha2, NULL));

        /* assemble Authentication-Info header
         */
        ai = apr_pstrcat(r->pool,
                         "rspauth=\"", resp_dig, "\"",
                         nextnonce,
                         resp->cnonce ? ", cnonce=\"" : "",
                         resp->cnonce
                           ? ap_escape_quotes(r->pool, resp->cnonce)
                           : "",
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

    if (ai && ai[0]) {
        apr_table_mergen(r->headers_out,
                         (PROXYREQ_PROXY == r->proxyreq)
                             ? "Proxy-Authentication-Info"
                             : "Authentication-Info",
                         ai);
    }

    return OK;
}


static void register_hooks(apr_pool_t *p)
{
    static const char * const cfgPost[]={ "http_core.c", NULL };
    static const char * const parsePre[]={ "mod_proxy.c", NULL };

    ap_hook_post_config(initialize_module, NULL, cfgPost, APR_HOOK_MIDDLE);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(parse_hdr_and_update_nc, parsePre, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(authenticate_digest_user, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_fixups(add_auth_info, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_digest_module =
{
    STANDARD20_MODULE_STUFF,
    create_digest_dir_config,   /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    digest_cmds,                /* command table */
    register_hooks              /* register hooks */
};

