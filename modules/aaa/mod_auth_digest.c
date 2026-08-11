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
 * Open Issues:
 *   - qop=auth-int (when streams and trailer support available)
 *   - nonce-format configurability
 *   - Proxy-Authentication-Info header is set by this module, but is
 *     currently ignored by mod_proxy (needs patch to mod_proxy)
 *   - The source of the secret should be run-time directive (with server
 *     scope: RSRC_CONF)
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
 *   - MD5-sess and auth-int are not yet implemented. An incomplete
 *     implementation has been removed and can be retrieved from svn history.
 */

#include "apr_sha1.h"
#include "apr_base64.h"
#include "apr_lib.h"
#include "apr_time.h"
#include "apr_errno.h"
#include "apr_global_mutex.h"
#include "apr_strings.h"
#include "apr_atomic.h"

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
#include "util_mutex.h"
#include "apr_shm.h"
#include "apr_rmm.h"
#include "ap_provider.h"

#include "mod_auth.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* struct to hold the configuration info */

typedef struct digest_config_struct {
    authn_provider_list *providers;
    apr_time_t    nonce_lifetime;
    int          check_nc;
    const char  *algorithm; /* currently a constant (MD5). */
    char        *uri_list;
} digest_config_rec;


#define DFLT_ALGORITHM  "MD5"

#define DFLT_NONCE_LIFE apr_time_from_sec(300)
#define NEXTNONCE_DELTA apr_time_from_sec(30)

/* The server nonce has fixed length and is the concatenation of:
 *    base64(apr_time_t timestamp) + hex(SHA1(realm+time[+opaque])) */
#define NONCE_TIME_LEN  (((sizeof(apr_time_t)+2)/3)*4)
#define NONCE_HASH_LEN  (2*APR_SHA1_DIGESTSIZE)
#define NONCE_LEN       (int )(NONCE_TIME_LEN + NONCE_HASH_LEN)
/* Evaluates to true if nonce string is valid. Since the time part of
 * the nonce is a base64 encoding of an apr_time_t (8 bytes), it
 * must end with a '='.  */
#define VALID_NONCE(n_) ((n_) && strlen((n_)) == NONCE_LEN && (n_)[NONCE_TIME_LEN - 1] == '=')

#define MD5_DIGEST_LEN (2*APR_MD5_DIGESTSIZE) /* ignoring trailing \0 */

#define SECRET_LEN          20
#define RETAINED_DATA_ID    "mod_auth_digest"


/* client list definitions */

/* Identifies a client entry. This is the value sent to the client in the
 * opaque field of the challenge, and echoed back in its Authorization
 * header; zero is never a valid id, and means "no client". Ids are counted
 * out by client_id_counter, so this must remain the type which the atomics
 * used on it take, and the "%u"/"%x" formats below must match it. */
typedef apr_uint32_t client_id_t;

typedef struct hash_entry {
    client_id_t        key;                     /* the key for this entry    */
    struct hash_entry *next;                    /* next entry in the bucket  */
    unsigned long      nonce_count;             /* highest nonce-count seen
                                                 * for last_nonce_time       */
    apr_time_t         last_nonce_time;         /* nonce of the last request
                                                 * accepted for this client  */
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

/* Outcome of checking a request's nonce and nonce-count against the state
 * tracked for its client. */
enum nonce_state {
    NONCE_ACCEPTED,     /* recorded as the latest used by this client */
    NONCE_STALE,        /* already used, or the client is unknown */
    NONCE_BAD_COUNT     /* nonce-count did not increase: possible replay */
};

typedef struct digest_header_struct {
    const char           *scheme;
    const char           *realm;
    const char           *username;
          char           *nonce;
    const char           *uri;
    const char           *method;
    const char           *digest;
    const char           *algorithm;
    const char           *cnonce;
    const char           *opaque;
    client_id_t           opaque_num;
    const char           *message_qop;
    const char           *nonce_count;
    /* the following fields are not (directly) from the header */
    const char           *raw_request_uri;
    apr_uri_t            *psd_request_uri;
    apr_time_t            nonce_time;
    enum hdr_sts          auth_hdr_sts;
    int                   needed_auth;
    const char           *ha1;
} digest_header_rec;


/* (mostly) nonce stuff */

typedef union time_union {
    apr_time_t    time;
    unsigned char arr[sizeof(apr_time_t)];
} time_rec;

static unsigned char *secret;

/* client-list, opaque, and one-time-nonce stuff */

static apr_shm_t      *client_shm =  NULL;
static apr_rmm_t      *client_rmm = NULL;
static volatile client_id_t  *client_id_counter;
static volatile apr_uint32_t *otn_counter;     /* one-time-nonce counter */
static apr_global_mutex_t *client_lock = NULL;
static const char     *client_mutex_type = "authdigest-client";
static const char     *client_shm_filename;

#define DEF_SHMEM_SIZE  1000L           /* ~ 12 entries */
#define DEF_NUM_BUCKETS 15L
#define HASH_DEPTH      5

static apr_size_t shmem_size  = DEF_SHMEM_SIZE;
static unsigned long num_buckets = DEF_NUM_BUCKETS;


module AP_MODULE_DECLARE_DATA auth_digest_module;

/*
 * initialization code
 */

static apr_status_t cleanup_tables(void *not_used)
{
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL, APLOGNO(01756)
                  "cleaning up shared memory");

    if (client_rmm) {
        apr_rmm_destroy(client_rmm);
        client_rmm = NULL;
    }

    if (client_shm) {
        apr_shm_destroy(client_shm);
        client_shm = NULL;
    }

    if (client_lock) {
        apr_global_mutex_destroy(client_lock);
        client_lock = NULL;
    }

    client_list = NULL;

    return APR_SUCCESS;
}

static void log_error_and_cleanup(char *msg, apr_status_t sts, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, sts, s, APLOGNO(01760)
                 "%s - all nonce-count checking and one-time nonces "
                 "disabled", msg);

    cleanup_tables(NULL);
}

/* RMM helper functions that behave like single-step malloc/free. */

static void *rmm_malloc(apr_rmm_t *rmm, apr_size_t size)
{
    apr_rmm_off_t offset = apr_rmm_malloc(rmm, size);

    if (!offset) {
        return NULL;
    }

    return apr_rmm_addr_get(rmm, offset);
}

static apr_status_t rmm_free(apr_rmm_t *rmm, void *alloc)
{
    apr_rmm_off_t offset = apr_rmm_offset_get(rmm, alloc);

    return apr_rmm_free(rmm, offset);
}

static int initialize_tables(server_rec *s, apr_pool_t *ctx)
{
    unsigned long idx;
    apr_status_t   sts;

    /* set up client list */

    /* Create the shared memory segment */

    client_shm = NULL;
    client_rmm = NULL;
    client_lock = NULL;
    client_list = NULL;

    /*
     * Create a unique filename using our pid. This information is
     * stashed in the global variable so the children inherit it.
     */
    client_shm_filename = ap_runtime_dir_relative(ctx, "authdigest_shm");
    client_shm_filename = ap_append_pid(ctx, client_shm_filename, ".");

    /* Use anonymous shm by default, fall back on name-based. */
    sts = apr_shm_create(&client_shm, shmem_size, NULL, ctx);
    if (APR_STATUS_IS_ENOTIMPL(sts)) {
        /* For a name-based segment, remove it first in case of a
         * previous unclean shutdown. */
        apr_shm_remove(client_shm_filename, ctx);

        /* Now create that segment */
        sts = apr_shm_create(&client_shm, shmem_size,
                            client_shm_filename, ctx);
    }

    if (APR_SUCCESS != sts) {
        ap_log_error(APLOG_MARK, APLOG_ERR, sts, s, APLOGNO(01762)
                     "Failed to create shared memory segment on file %s",
                     client_shm_filename);
        log_error_and_cleanup("failed to initialize shm", sts, s);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    sts = apr_rmm_init(&client_rmm,
                       NULL, /* no lock, we'll do the locking ourselves */
                       apr_shm_baseaddr_get(client_shm),
                       shmem_size, ctx);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to initialize rmm", sts, s);
        return !OK;
    }

    client_list = rmm_malloc(client_rmm, sizeof(*client_list) +
                                         sizeof(client_entry *) * num_buckets);
    if (!client_list) {
        log_error_and_cleanup("failed to allocate shared memory", -1, s);
        return !OK;
    }
    client_list->table = (client_entry**) (client_list + 1);
    for (idx = 0; idx < num_buckets; idx++) {
        client_list->table[idx] = NULL;
    }
    client_list->tbl_len     = num_buckets;
    client_list->num_entries = 0;

    sts = ap_global_mutex_create(&client_lock, NULL, client_mutex_type, NULL,
                                 s, ctx, 0);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to create lock (client_lock)", sts, s);
        return !OK;
    }


    /* setup opaque */

    client_id_counter = rmm_malloc(client_rmm, sizeof *client_id_counter);
    if (client_id_counter == NULL) {
        log_error_and_cleanup("failed to allocate shared memory", -1, s);
        return !OK;
    }
    *client_id_counter = 1;

    /* setup one-time-nonce counter */

    otn_counter = rmm_malloc(client_rmm, sizeof(*otn_counter));
    if (otn_counter == NULL) {
        log_error_and_cleanup("failed to allocate shared memory", -1, s);
        return !OK;
    }
    *otn_counter = 0;
    /* no lock here */


    /* success */
    return OK;
}

static int pre_init(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    apr_status_t rv;
    void *retained;

    if (!APR_HAS_SHARED_MEMORY) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(10590)
                     "mod_auth_digest cannot be used on platforms without shared memory support");
        return !OK;
    }

    rv = ap_mutex_register(pconf, client_mutex_type, NULL, APR_LOCK_DEFAULT, 0);
    if (rv != APR_SUCCESS)
        return !OK;

    retained = ap_retained_data_get(RETAINED_DATA_ID);
    if (retained == NULL) {
        retained = ap_retained_data_create(RETAINED_DATA_ID, SECRET_LEN);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, APLOGNO(01757)
                     "generating secret for digest authentication");
#if APR_HAS_RANDOM
        rv = apr_generate_random_bytes(retained, SECRET_LEN);
#else
#error APR random number support is missing
#endif
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(01758)
                         "error generating secret");
            return !OK;
        }
    }
    secret = retained;
    return OK;
}

static int initialize_module(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    /* initialize_module() will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call. */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
        return OK;

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
    return initialize_tables(s, p);
}

static void initialize_child(apr_pool_t *p, server_rec *s)
{
    apr_status_t sts;

    /* Get access to rmm in child */
    sts = apr_rmm_attach(&client_rmm,
                         NULL,
                         apr_shm_baseaddr_get(client_shm),
                         p);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to attach to rmm", sts, s);
        return;
    }

    sts = apr_global_mutex_child_init(&client_lock,
                                      apr_global_mutex_lockfile(client_lock),
                                      p);
    if (sts != APR_SUCCESS) {
        log_error_and_cleanup("failed to create lock (client_lock)", sts, s);
        return;
    }
}

/*
 * configuration code
 */

static void *create_digest_dir_config(apr_pool_t *p, char *dir)
{
    digest_config_rec *conf = apr_pcalloc(p, sizeof *conf);

    conf->nonce_lifetime = DFLT_NONCE_LIFE;
    conf->algorithm      = DFLT_ALGORITHM;

    return conf;
}

static const char *add_authn_provider(cmd_parms *cmd, void *config,
                                      const char *arg)
{
    digest_config_rec *conf = (digest_config_rec*)config;
    authn_provider_list *newp;

    newp = apr_pcalloc(cmd->pool, sizeof(authn_provider_list));
    newp->provider_name = arg;

    /* lookup and cache the actual provider now */
    newp->provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP,
                                        newp->provider_name,
                                        AUTHN_PROVIDER_VERSION);

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
                            "Digest Authentication", newp->provider_name);
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
    if (ap_cstr_casecmp(op, "auth")) {
        return "AuthDigestQop is deprecated: only 'auth' is supported";
    }

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

static const char *set_nc_check(cmd_parms *cmd, void *config, int flag)
{
    ((digest_config_rec *) config)->check_nc = flag;
    return NULL;
}

static const char *set_algorithm(cmd_parms *cmd, void *config, const char *alg)
{
    if (ap_cstr_casecmp(alg, "MD5")) {
        return apr_pstrcat(cmd->pool, "Unsupported algorithm in AuthDigestAlgorithm: ", alg, NULL);
    }

    /* conf->algorithm remains the constant, "MD5". */
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
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server, APLOGNO(01763)
                 "Set shmem-size: %" APR_SIZE_T_FMT ", num-buckets: %ld",
                 shmem_size, num_buckets);

    return NULL;
}

static const command_rec digest_cmds[] =
{
    AP_INIT_ITERATE("AuthDigestProvider", add_authn_provider, NULL, OR_AUTHCFG,
                     "specify the auth providers for a directory or location"),
    AP_INIT_ITERATE("AuthDigestQop", set_qop, NULL, OR_AUTHCFG,
     "A list of quality-of-protection options"),
    AP_INIT_TAKE1("AuthDigestNonceLifetime", set_nonce_lifetime, NULL, OR_AUTHCFG,
     "Maximum lifetime of the server nonce (seconds)"),
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
 * out at each garbage collection run. Note that no attempt is made to
 * guarantee that num_renewed is correct in the face of clients spoofing
 * the opaque field; it is just an indicator, and whether it is off by a
 * few doesn't matter.
 */

/*
 * Find the client given its client number (the key), moving it to the
 * front of its bucket. Returns the entry, or NULL if it's not found.
 *
 * MUST be called with client_lock held, and the entry returned MUST NOT be
 * used outside that critical section: it lives in the shared memory
 * segment, where gc() can free it at any time on behalf of another
 * process. The accessors below are the only supported way to reach a
 * client entry; each looks it up afresh, so a client which has since been
 * garbage collected is simply reported as unknown and the caller goes on
 * to issue a new challenge for it.
 *
 * Note that this still gives no ordering guarantee for a client using
 * multiple simultaneous connections within the same protection space: the
 * requests can be processed in any order, so the nonce-count and one-time
 * nonce checks may reject some of them. That is not new.
 */
static client_entry *find_client(client_id_t key)
{
    int bucket;
    client_entry *entry, *prev = NULL;

    if (!key) {
        return NULL;
    }

    bucket = key % client_list->tbl_len;
    entry  = client_list->table[bucket];

    while (entry && key != entry->key) {
        prev  = entry;
        entry = entry->next;
    }

    if (entry && prev) {                /* move entry to front of list */
        prev->next  = entry->next;
        entry->next = client_list->table[bucket];
        client_list->table[bucket] = entry;
    }

    return entry;
}


/* Determine whether the client identified by key is still known. */
static int client_exists(client_id_t key, const request_rec *r)
{
    int found;

    apr_global_mutex_lock(client_lock);
    found = find_client(key) != NULL;
    apr_global_mutex_unlock(client_lock);

    if (found) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01764)
                      "client %u found", key);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01765)
                      "client %u not found", key);
    }

    return found;
}


/* Note that a client entry was created to replace one which had been
 * garbage collected. */
static void client_note_renewed(void)
{
    apr_global_mutex_lock(client_lock);
    client_list->num_renewed++;
    apr_global_mutex_unlock(client_lock);
}


/* Check the nonce generated at nonce_time, and the nonce-count nc sent
 * with it, against the state tracked for the client identified by key, and
 * record them if acceptable.
 *
 * Both nonce_time and the count are compared against what the client last
 * *used*, never against what was last issued to it: a nonce is issued
 * whenever a challenge is generated, and anything quoting the client's
 * opaque can provoke a challenge, so tracking what was issued lets an
 * unauthenticated request invalidate the nonce which the legitimate client
 * is holding.
 *
 * A one-time nonce (AuthDigestNonceLifetime 0) is therefore accepted iff
 * it is newer than the last nonce this client used, which permits it
 * exactly once. Otherwise, with AuthDigestNcCheck, a newer nonce starts a
 * new count and the same nonce must raise it.
 *
 * Must only be called for a request which is fully verified - both the
 * response digest and the nonce - so that a request which fails to
 * authenticate cannot alter the state tracked for the client whose opaque
 * it quotes. */
static enum nonce_state client_update_nonce(const request_rec *r,
                                            client_id_t key,
                                            const digest_config_rec *conf,
                                            apr_time_t nonce_time,
                                            unsigned long nc,
                                            const char *nonce)
{
    client_entry *client;
    unsigned long tracked = 0;
    enum nonce_state state;
    int known;

    apr_global_mutex_lock(client_lock);
    client = find_client(key);
    known = (client != NULL);
    if (!known) {
        state = NONCE_STALE;
    }
    else {
        tracked = client->nonce_count;
        if (conf->nonce_lifetime == 0) {
            /* one-time nonce: usable until it has been used */
            state = (nonce_time > client->last_nonce_time)
                    ? NONCE_ACCEPTED : NONCE_STALE;
        }
        else if (nonce_time > client->last_nonce_time
                 || (nonce_time == client->last_nonce_time && nc > tracked)) {
            state = NONCE_ACCEPTED;
        }
        else {
            state = NONCE_BAD_COUNT;
        }

        if (state == NONCE_ACCEPTED) {
            client->last_nonce_time = nonce_time;
            client->nonce_count     = nc;
        }
    }
    apr_global_mutex_unlock(client_lock);

    if (!known) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(10618)
                      "client %u is no longer known - sending new nonce",
                      key);
    }
    else if (state == NONCE_STALE) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01779)
                      "user %s: one-time-nonce %s already used - sending "
                      "new nonce", r->user, nonce);
    }
    else if (state == NONCE_BAD_COUNT) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01774)
                      "Warning, possible replay attack: nonce-count check "
                      "failed: %lu is not above %lu for nonce %s", nc,
                      tracked, nonce);
    }

    return state;
}


/* A simple garbage-collecter to remove unused clients. It removes the
 * last entry in each bucket and updates the counters. Returns the
 * number of removed entries.
 */
static long gc(server_rec *s)
{
    client_entry *entry, *prev;
    unsigned long num_removed = 0, idx;

    /* garbage collect all last entries */

    for (idx = 0; idx < client_list->tbl_len; idx++) {
        entry = client_list->table[idx];
        prev  = NULL;

        if (!entry) {
            /* This bucket is empty. */
            continue;
        }

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
            apr_status_t err;

            err = rmm_free(client_rmm, entry);
            num_removed++;

            if (err) {
                /* Nothing we can really do but log... */
                ap_log_error(APLOG_MARK, APLOG_ERR, err, s, APLOGNO(10007)
                             "Failed to free auth_digest client allocation");
            }
        }
    }

    /* update counters and log */

    client_list->num_entries -= num_removed;
    client_list->num_removed += num_removed;

    return num_removed;
}


/*
 * Add a new client to the list. Returns non-zero if successful, zero
 * otherwise. This triggers the garbage collection if memory is low. (The
 * new entry is not returned: see find_client().)
 */
static int add_client(client_id_t key, client_entry *info, server_rec *s)
{
    int bucket;
    client_entry *entry;

    if (!key) {
        return 0;
    }

    bucket = key % client_list->tbl_len;

    apr_global_mutex_lock(client_lock);

    /* try to allocate a new entry */

    entry = rmm_malloc(client_rmm, sizeof(client_entry));
    if (!entry) {
        long num_removed = gc(s);
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01766)
                     "gc'd %ld client entries. Total new clients: "
                     "%ld; Total removed clients: %ld; Total renewed clients: "
                     "%ld", num_removed,
                     client_list->num_created - client_list->num_renewed,
                     client_list->num_removed, client_list->num_renewed);
        entry = rmm_malloc(client_rmm, sizeof(client_entry));
        if (!entry) {
            apr_global_mutex_unlock(client_lock);
            return 0;          /* give up; the caller logs this */
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

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01768)
                 "allocated new client %u", key);

    return 1;
}


/*
 * Authorization header parser code
 */

/* Parse the Authorization header, if it exists, into resp; returns the
 * status of the header. */
static enum hdr_sts parse_digest_header(request_rec *r,
                                        digest_header_rec *resp)
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
        return NO_HEADER;
    }

    resp->scheme = ap_getword_white(r->pool, &auth_line);
    if (ap_cstr_casecmp(resp->scheme, "Digest")) {
        return NOT_DIGEST;
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

        vv = 0;
        if (auth_line[0] == '=') {
            auth_line++;
            while (apr_isspace(auth_line[0])) {
                auth_line++;
            }

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
        }
        value[vv] = '\0';

        while (auth_line[0] != ',' && auth_line[0] != '\0') {
            auth_line++;
        }
        if (auth_line[0] != '\0') {
            auth_line++;
        }

        if (!ap_cstr_casecmp(key, "username"))
            resp->username = apr_pstrdup(r->pool, value);
        else if (!ap_cstr_casecmp(key, "realm"))
            resp->realm = apr_pstrdup(r->pool, value);
        else if (!ap_cstr_casecmp(key, "nonce"))
            resp->nonce = apr_pstrdup(r->pool, value);
        else if (!ap_cstr_casecmp(key, "uri"))
            resp->uri = apr_pstrdup(r->pool, value);
        else if (!ap_cstr_casecmp(key, "response"))
            resp->digest = apr_pstrdup(r->pool, value);
        else if (!ap_cstr_casecmp(key, "algorithm"))
            resp->algorithm = apr_pstrdup(r->pool, value);
        else if (!ap_cstr_casecmp(key, "cnonce"))
            resp->cnonce = apr_pstrdup(r->pool, value);
        else if (!ap_cstr_casecmp(key, "opaque"))
            resp->opaque = apr_pstrdup(r->pool, value);
        else if (!ap_cstr_casecmp(key, "qop"))
            resp->message_qop = apr_pstrdup(r->pool, value);
        else if (!ap_cstr_casecmp(key, "nc"))
            resp->nonce_count = apr_pstrdup(r->pool, value);
    }

    if (!resp->username || !resp->realm || !resp->uri
        || !VALID_NONCE(resp->nonce)
        || !resp->digest || strlen(resp->digest) != MD5_DIGEST_LEN
        || (resp->message_qop && (!resp->cnonce || !resp->nonce_count))) {
        return INVALID;
    }

    if (resp->opaque) {
        char *endptr;
        long num;

        errno = 0;
        num = strtol(resp->opaque, &endptr, 16);
        if (errno == 0 && *endptr == '\0' && num > 0
            && num <= APR_UINT32_MAX)
            resp->opaque_num = (client_id_t)num;
    }

    return VALID;
}


/* Set up the per-request record: this is the place to get the request-uri
 * (before any subrequests etc are initiated), to initialize the
 * request_config, and to parse the Authorization header.
 *
 * Note that the nonce-count tracked for the client is deliberately NOT
 * updated here: the state of an authenticated client must not be altered
 * by a request which has not (yet) been authenticated, or a replayed or
 * bogus request quoting the client's opaque would be able to rewind that
 * state. See check_and_update_nc().
 *
 * Note that this must be called after mod_proxy had its go so that
 * r->proxyreq is set correctly.
 */
static int init_digest_request(request_rec *r)
{
    digest_header_rec *resp;

    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    resp = apr_pcalloc(r->pool, sizeof(digest_header_rec));
    resp->raw_request_uri = r->unparsed_uri;
    resp->psd_request_uri = &r->parsed_uri;
    resp->needed_auth = 0;
    resp->method = r->method;
    ap_set_module_config(r->request_config, &auth_digest_module, resp);

    resp->auth_hdr_sts = parse_digest_header(r, resp);

    return DECLINED;
}


/* Writes the hash part of the server nonce to hash, which must be of
 * minimum size (NONCE_HASH_LEN+1). */
static void gen_nonce_hash(char hash[NONCE_HASH_LEN+1], const char *timestr, const char *opaque,
                           const server_rec *server,
                           const digest_config_rec *conf, 
                           const char *realm)
{
    unsigned char sha1[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t ctx;

    apr_sha1_init(&ctx);
    apr_sha1_update_binary(&ctx, secret, SECRET_LEN);
    apr_sha1_update_binary(&ctx, (const unsigned char *) realm, strlen(realm));

    apr_sha1_update_binary(&ctx, (const unsigned char *) timestr, strlen(timestr));
    if (opaque) {
        apr_sha1_update_binary(&ctx, (const unsigned char *) opaque,
                             strlen(opaque));
    }
    apr_sha1_final(sha1, &ctx);

    ap_bin2hex(sha1, APR_SHA1_DIGESTSIZE, hash);
}


/* The nonce has the format b64(time)+hash .
 */
static const char *gen_nonce(apr_pool_t *p, apr_time_t now, const char *opaque,
                             const server_rec *server,
                             const digest_config_rec *conf,
                             const char *realm)
{
    char *nonce = apr_palloc(p, NONCE_LEN+1);
    time_rec t;

    if (conf->nonce_lifetime != 0) {
        t.time = now;
    }
    else {
        /* Nonces are ordered by this counter rather than by time; the +1
         * is because apr_atomic_inc32() returns the previous value, and a
         * nonce time of zero means "no nonce used yet" in a client entry. */
        t.time = apr_atomic_inc32(otn_counter) + 1;
    }
    apr_base64_encode_binary(nonce, t.arr, sizeof(t.arr));
    gen_nonce_hash(nonce+NONCE_TIME_LEN, nonce, opaque, server, conf, realm);

    return nonce;
}


/*
 * Opaque and hash-table management
 */

/*
 * Generate a new client entry and add it to the list. Returns the key of
 * the new entry, or 0 if it failed. (The entry itself is deliberately not
 * returned: see find_client().)
 */
static client_id_t client_generate(const request_rec *r)
{
    client_id_t op = apr_atomic_inc32(client_id_counter);
    client_entry new_entry = { 0, NULL, 0, 0 };

    /* The counter wraps after 2^32 clients: skip an id of zero, which means
     * "no client" and which add_client() would refuse. */
    if (op == 0) {
        op = apr_atomic_inc32(client_id_counter);
    }

    if (!add_client(op, &new_entry, r->server)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01769)
                      "unable to allocate a client entry - failing the "
                      "request, since this configuration needs one");
        return 0;
    }

    return op;
}


/*
 * Authorization challenge generation code (for WWW-Authenticate)
 */

/* Format a client id as the opaque sent to the client. Never called with
 * zero: the callers check client_generate() for failure first. */
static const char *ltox(apr_pool_t *p, client_id_t num)
{
    return apr_psprintf(p, "%x", num);
}

/* Generate a challenge for the client, and return the status which the
 * caller should return for this request: HTTP_UNAUTHORIZED normally, or
 * HTTP_SERVICE_UNAVAILABLE if the per-client state which this configuration
 * requires could not be allocated. No challenge is sent in that case: it
 * could only carry an opaque which identifies nothing, so the client would
 * be unable to authenticate through it however often it retried. */
static int note_digest_auth_failure(request_rec *r,
                                    const digest_config_rec *conf,
                                    digest_header_rec *resp, int stale)
{
    const char   *qop, *opaque = NULL, *opaque_param = "", *domain, *nonce;
    client_id_t   client_key = 0;

    /* Setup qop */
    qop = ", qop=\"auth\"";

    /* Setup opaque */

    if (resp->opaque == NULL) {
        /* new client */
        if (conf->check_nc || conf->nonce_lifetime == 0) {
            if ((client_key = client_generate(r)) == 0) {
                return HTTP_SERVICE_UNAVAILABLE;
            }
            opaque = ltox(r->pool, client_key);
        }
        /* else no opaque is needed, and none is sent */
    }
    else if (!client_exists(resp->opaque_num, r)) {
        /* client info was gc'd */
        if ((client_key = client_generate(r)) == 0) {
            return HTTP_SERVICE_UNAVAILABLE;
        }
        opaque = ltox(r->pool, client_key);
        stale = 1;
        client_note_renewed();
    }
    else {
        /* Note that the nonce-count tracked for this client is left alone
         * here: the client may not even see this challenge (it may have
         * been triggered by somebody else quoting its opaque), and it is
         * tied to the nonce it was counted for in any case. */
        client_key = resp->opaque_num;
        opaque = resp->opaque;
    }

    if (opaque) {
        opaque_param = apr_pstrcat(r->pool, ", opaque=\"", opaque, "\"", NULL);
    }

    /* Setup nonce */

    nonce = gen_nonce(r->pool, r->request_time, opaque, r->server, conf, ap_auth_name(r));

    /* setup domain attribute. We want to send this attribute wherever
     * possible so that the client won't send the Authorization header
     * unnecessarily (it's usually > 200 bytes!).
     */


    /* don't send domain
     * - for proxy requests
     * - if it's not specified
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
                                  opaque_param,
                                  domain ? domain : "",
                                  stale ? ", stale=true" : "", qop));

    return HTTP_UNAUTHORIZED;
}

static int hook_note_digest_auth_failure(request_rec *r, const char *auth_type)
{
    request_rec *mainreq;
    digest_header_rec *resp;
    digest_config_rec *conf;

    if (ap_cstr_casecmp(auth_type, "Digest"))
        return DECLINED;

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

    note_digest_auth_failure(r, conf, resp, 0);

    return OK;
}


/*
 * Authorization header verification code
 */

static authn_status get_hash(request_rec *r, const char *user,
                             digest_config_rec *conf, const char **rethash)
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
                                          AUTHN_DEFAULT_PROVIDER,
                                          AUTHN_PROVIDER_VERSION);

            if (!provider || !provider->get_realm_hash) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01770)
                              "No Authn provider configured");
                auth_result = AUTH_GENERAL_ERROR;
                break;
            }
            apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, AUTHN_DEFAULT_PROVIDER);
        }
        else {
            provider = current_provider->provider;
            apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, current_provider->provider_name);
        }


        /* We expect the password to be md5 hash of user:realm:password */
        auth_result = provider->get_realm_hash(r, user, ap_auth_name(r),
                                               &password);

        apr_table_unset(r->notes, AUTHN_PROVIDER_NAME_NOTE);

        /* Something occurred.  Stop checking. */
        if (auth_result != AUTH_USER_NOT_FOUND) {
            break;
        }

        /* If we're not really configured for providers, stop now. */
        if (!conf->providers) {
           break;
        }

        current_provider = current_provider->next;
    } while (current_provider);

    if (auth_result == AUTH_USER_FOUND) {
        *rethash = password;
    }

    return auth_result;
}

/* Check the nonce and nonce-count of a fully verified request against the
 * state tracked for its client, record them, and generate a new challenge
 * if they are not acceptable.
 *
 * The nonce-count is counted by the client per-nonce (RFC 7616 3.4.3), so
 * the count tracked here is tied to the nonce it was counted for: a request
 * using a newer nonce starts a new count. Within a single nonce the count
 * must strictly increase, but it need not increase by exactly one: the
 * client also counts the requests it sends to URIs in the protection space
 * which turn out not to need authentication, and this server never sees
 * those.
 */
static int check_and_record_nonce(request_rec *r, digest_header_rec *resp,
                                  const digest_config_rec *conf)
{
    unsigned long nc;
    const char *snc = resp->nonce_count;
    char *endptr;

    if (!conf->check_nc && conf->nonce_lifetime != 0) {
        return OK;              /* nothing is tracked per-client */
    }

    nc = strtol(snc, &endptr, 16);
    if (endptr < (snc+strlen(snc)) && !apr_isspace(*endptr)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01773)
                      "invalid nc %s received - not a number", snc);
        return note_digest_auth_failure(r, conf, resp, 0);
    }

    switch (client_update_nonce(r, resp->opaque_num, conf, resp->nonce_time,
                                nc, resp->nonce)) {
    case NONCE_ACCEPTED:
        return OK;

    case NONCE_STALE:
        /* the credentials were good, so the client can silently retry with
         * the nonce from this challenge */
        return note_digest_auth_failure(r, conf, resp, 1);

    default:
        return note_digest_auth_failure(r, conf, resp, 0);
    }
}

static int check_nonce(request_rec *r, digest_header_rec *resp,
                       const digest_config_rec *conf)
{
    apr_time_t dt;
    time_rec nonce_time;
    char tmp, hash[NONCE_HASH_LEN+1];

    tmp = resp->nonce[NONCE_TIME_LEN];
    resp->nonce[NONCE_TIME_LEN] = '\0';
    apr_base64_decode_binary(nonce_time.arr, resp->nonce);
    gen_nonce_hash(hash, resp->nonce, resp->opaque, r->server, conf, ap_auth_name(r));
    resp->nonce[NONCE_TIME_LEN] = tmp;
    resp->nonce_time = nonce_time.time;

    if (!ap_memeq_timingsafe(hash, resp->nonce+NONCE_TIME_LEN, NONCE_HASH_LEN)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01776)
                      "invalid nonce %s received - hash is not %s",
                      resp->nonce, hash);
        return note_digest_auth_failure(r, conf, resp, 1);
    }

    dt = r->request_time - nonce_time.time;
    if (conf->nonce_lifetime > 0 && dt < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01777)
                      "invalid nonce %s received - user attempted "
                      "time travel", resp->nonce);
        return note_digest_auth_failure(r, conf, resp, 1);
    }

    if (conf->nonce_lifetime > 0) {
        if (dt > conf->nonce_lifetime) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0,r, APLOGNO(01778)
                          "user %s: nonce expired (%.2f seconds old "
                          "- max lifetime %.2f) - sending new nonce",
                          r->user, (double)apr_time_sec(dt),
                          (double)apr_time_sec(conf->nonce_lifetime));
            return note_digest_auth_failure(r, conf, resp, 1);
        }
    }
    /* else (lifetime <= 0) => never expires by time; a one-time nonce is
     * retired by use, in check_and_record_nonce() */

    return OK;
}

/* The actual MD5 code... whee */

/* RFC-2617 */
static const char *new_digest(const request_rec *r,
                              digest_header_rec *resp)
{
    const char *ha1, *ha2, *a2;

    ha1 = resp->ha1;

    a2 = apr_pstrcat(r->pool, resp->method, ":", resp->uri, NULL);
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

    dst->hostinfo = src->hostinfo;
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
    authn_status       return_code;
    const char *realm;

    /* do we require Digest auth for this URI? */

    if (!(t = ap_auth_type(r)) || ap_cstr_casecmp(t, "Digest")) {
        return DECLINED;
    }

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01780)
                      "need AuthName: %s", r->uri);
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

    realm = ap_auth_name(r);

    /* get our conf */

    conf = (digest_config_rec *) ap_get_module_config(r->per_dir_config,
                                                      &auth_digest_module);


    /* check for existence and syntax of Auth header */

    if (resp->auth_hdr_sts != VALID) {
        if (resp->auth_hdr_sts == NOT_DIGEST) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01781)
                          "client used wrong authentication scheme `%s': %s",
                          resp->scheme, r->uri);
        }
        else if (resp->auth_hdr_sts == INVALID) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01782)
                          "missing user, realm, nonce, uri, digest, "
                          "cnonce, or nonce_count in authorization header: %s",
                          r->uri);
        }
        /* else (resp->auth_hdr_sts == NO_HEADER) */
        return note_digest_auth_failure(r, conf, resp, 0);
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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01783)
                          "invalid uri <%s> in Authorization header",
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
            if (!r_uri.hostinfo || strcmp(resp->uri, r_uri.hostinfo)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01785)
                              "uri mismatch - <%s> does not match "
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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01786)
                          "uri mismatch - <%s> does not match "
                          "request-uri <%s>", resp->uri, resp->raw_request_uri);
            return HTTP_BAD_REQUEST;
        }
    }

    if (resp->opaque && resp->opaque_num == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01787)
                      "received invalid opaque - got `%s'",
                      resp->opaque);
        return note_digest_auth_failure(r, conf, resp, 0);
    }
 
    

    if (!realm) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02533)
                      "realm mismatch - got `%s' but no realm specified",
                      resp->realm);
        return note_digest_auth_failure(r, conf, resp, 0);
    }

    if (!resp->realm || strcmp(resp->realm, realm)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01788)
                      "realm mismatch - got `%s' but expected `%s'",
                      resp->realm, realm);
        return note_digest_auth_failure(r, conf, resp, 0);
    }

    if (resp->algorithm != NULL
        && ap_cstr_casecmp(resp->algorithm, "MD5")) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01789)
                      "unknown algorithm `%s' received: %s",
                      resp->algorithm, r->uri);
        return note_digest_auth_failure(r, conf, resp, 0);
    }

    return_code = get_hash(r, r->user, conf, &resp->ha1);

    if (return_code == AUTH_USER_NOT_FOUND) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01790)
                      "user `%s' in realm `%s' not found: %s",
                      r->user, realm, r->uri);
        return note_digest_auth_failure(r, conf, resp, 0);
    }
    else if (return_code == AUTH_USER_FOUND) {
        /* we have a password, so continue */
    }
    else if (return_code == AUTH_DENIED) {
        /* authentication denied in the provider before attempting a match */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01791)
                      "user `%s' in realm `%s' denied by provider: %s",
                      r->user, realm, r->uri);
        return note_digest_auth_failure(r, conf, resp, 0);
    }
    else if (return_code == AUTH_HANDLED) {
        return r->status;
    }
    else {
        /* AUTH_GENERAL_ERROR (or worse)
         * We'll assume that the module has already said what its error
         * was in the logs.
         */
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (resp->message_qop == NULL
        || ap_cstr_casecmp(resp->message_qop, "auth")) {
        /* RFC 2069-style Digest is no longer supported. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10560)
                      "invalid or missing qop value '%s', RFC 2069 is "
                      "no longer supported: %s", resp->message_qop, r->uri);
        return note_digest_auth_failure(r, conf, resp, 0);
    }
    else {
        /* RFC 2617 (or 7616)-style Digest hash calculation. */
        const char *exp_digest = new_digest(r, resp);
        if (!exp_digest) {
            /* we failed to allocate a client struct */
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (!ap_memeq_timingsafe(exp_digest, resp->digest, MD5_DIGEST_LEN)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01794)
                          "user %s: password mismatch: %s", r->user,
                          r->uri);
            return note_digest_auth_failure(r, conf, resp, 0);
        }
    }

    /* Note: the nonce is checked before the nonce-count so that the
     * nonce-count state is only ever updated for a request which is using
     * a nonce this server issued, and so that a request using an expired
     * nonce gets a "stale=true" challenge (and hence a silent retry with a
     * fresh nonce-count) rather than being reported as a replay. */
    if ((res = check_nonce(r, resp, conf))) {
        return res;
    }

    return check_and_record_nonce(r, resp, conf);
}

/* Authentication-Info header code. */
static int add_auth_info(request_rec *r)
{
    const digest_config_rec *conf =
                (digest_config_rec *) ap_get_module_config(r->per_dir_config,
                                                           &auth_digest_module);
    digest_header_rec *resp =
                (digest_header_rec *) ap_get_module_config(r->request_config,
                                                           &auth_digest_module);
    const char *ai = NULL, *nextnonce = "";

    if (resp == NULL || !resp->needed_auth || conf == NULL) {
        return OK;
    }

    /* Don't add Authentication-Info for 401/407 responses. */
    if (apr_table_get(r->err_headers_out,
                      (r->proxyreq == PROXYREQ_PROXY)
                      ? "Proxy-Authenticate" : "WWW-Authenticate")) {
        return OK;
    }

    /* Set up nextnonce for one-time-nonces and expiring-nonce cases. */
    if (conf->nonce_lifetime > 0) {
        /* send nextnonce if current nonce will expire in less than 30 secs */
        if ((r->request_time - resp->nonce_time) > (conf->nonce_lifetime-NEXTNONCE_DELTA)) {
            nextnonce = apr_pstrcat(r->pool, ", nextnonce=\"",
                                   gen_nonce(r->pool, r->request_time,
                                             resp->opaque, r->server, conf, ap_auth_name(r)),
                                   "\"", NULL);
        }
    }
    else if (conf->nonce_lifetime == 0 && resp->opaque_num) {
        const char *nonce = gen_nonce(r->pool, 0, resp->opaque, r->server,
                                      conf, ap_auth_name(r));
        nextnonce = apr_pstrcat(r->pool, ", nextnonce=\"", nonce, "\"", NULL);
    }
    /* else nonce never expires, hence no nextnonce */


    {
        const char *resp_dig, *ha1, *a2, *ha2;

        /* calculate rspauth attribute
         */
        ha1 = resp->ha1;

        a2 = apr_pstrcat(r->pool, ":", resp->uri, NULL);
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

    ap_hook_pre_config(pre_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(initialize_module, NULL, cfgPost, APR_HOOK_MIDDLE);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(init_digest_request, parsePre, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_authn(authenticate_digest_user, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);

    ap_hook_fixups(add_auth_info, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_note_auth_failure(hook_note_digest_auth_failure, NULL, NULL,
                              APR_HOOK_MIDDLE);

}

AP_DECLARE_MODULE(auth_digest) =
{
    STANDARD20_MODULE_STUFF,
    create_digest_dir_config,   /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    digest_cmds,                /* command table */
    register_hooks              /* register hooks */
};

