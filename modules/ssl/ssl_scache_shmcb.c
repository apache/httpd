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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_scache_shmcb.c
 *  Session Cache via Shared Memory (Cyclic Buffer Variant)
 */

#include "ssl_private.h"

/* 
 * This shared memory based SSL session cache implementation was
 * originally written by Geoff Thorpe <geoff geoffthorpe.net> for C2Net
 * Europe as a contribution to Ralf Engelschall's mod_ssl project.
 *
 * Since rewritten by GT to not use alignment-fudging memcpys and reduce
 * complexity.
 */

/*
 * Header structure - the start of the shared-mem segment
 */
typedef struct {
    /* Stats for cache operations */
    unsigned long stat_stores;
    unsigned long stat_expiries;
    unsigned long stat_scrolled;
    unsigned long stat_retrieves_hit;
    unsigned long stat_retrieves_miss;
    unsigned long stat_removes_hit;
    unsigned long stat_removes_miss;
    /* Number of subcaches */
    unsigned int subcache_num;
    /* How many indexes each subcache's queue has */
    unsigned int index_num;
    /* How large each subcache is, including the queue and data */
    unsigned int subcache_size;
    /* How far into each subcache the data area is (optimisation) */
    unsigned int subcache_data_offset;
    /* How large the data area in each subcache is (optimisation) */
    unsigned int subcache_data_size;
} SHMCBHeader;

/* 
 * Subcache structure - the start of each subcache, followed by
 * indexes then data
 */
typedef struct {
    /* The start position and length of the cyclic buffer of indexes */
    unsigned int idx_pos, idx_used;
    /* Same for the data area */
    unsigned int data_pos, data_used;
} SHMCBSubcache;

/* 
 * Index structure - each subcache has an array of these
 */
typedef struct {
    /* absolute time this entry expires */
    time_t expires;
    /* location within the subcache's data area */
    unsigned int data_pos;
    /* size (most logic ignores this, we keep it only to minimise memcpy) */
    unsigned int data_used;
    /* Optimisation to prevent ASN decoding unless a match is likely */
    unsigned char s_id2;
    /* Used to mark explicitly-removed sessions */
    unsigned char removed;
} SHMCBIndex;


/* The SHM data segment is of fixed size and stores data as follows.
 *
 *   [ SHMCBHeader | Subcaches ]
 *
 * The SHMCBHeader header structure stores metadata concerning the
 * cache and the contained subcaches.
 *
 * Subcaches is a hash table of header->subcache_num SHMCBSubcache
 * structures.  The hash table is indexed by SHMCB_MASK(id). Each
 * SHMCBSubcache structure has a fixed size (header->subcache_size),
 * which is determined at creation time, and looks like the following:
 *
 *   [ SHMCBSubcache | Indexes | Data ]
 *
 * Each subcache is prefixed by the SHMCBSubcache structure.
 *
 * The subcache's "Data" segment is a single cyclic data buffer, of
 * total size header->subcache_data_size; data inside is referenced
 * using byte offsets. The offset marking the beginning of the cyclic
 * buffer is subcache->data_pos the buffer's length is
 * subcache->data_used.
 *
 * "Indexes" is an array of header->index_num SHMCBIndex structures,
 * which is used as a cyclic queue; subcache->idx_pos gives the array
 * index of the first in use, subcache->idx_used gives the number in
 * use.  Both ->idx_* values have a range of [0, header->index_num)
 *
 * Each in-use SHMCBIndex structure represents a single SSL session.
 */

/* This macro takes a pointer to the header and a zero-based index and returns
 * a pointer to the corresponding subcache. */
#define SHMCB_SUBCACHE(pHeader, num) \
                (SHMCBSubcache *)(((unsigned char *)(pHeader)) + \
                        sizeof(SHMCBHeader) + \
                        (num) * ((pHeader)->subcache_size))

/* This macro takes a pointer to the header and a session id and returns a
 * pointer to the corresponding subcache. */
#define SHMCB_MASK(pHeader, id) \
                SHMCB_SUBCACHE((pHeader), *(id) & ((pHeader)->subcache_num - 1))

/* This macro takes the same params as the last, generating two outputs for use
 * in ap_log_error(...). */
#define SHMCB_MASK_DBG(pHeader, id) \
                *(id), (*(id) & ((pHeader)->subcache_num - 1))

/* This macro takes a pointer to a subcache and a zero-based index and returns
 * a pointer to the corresponding SHMCBIndex. */
#define SHMCB_INDEX(pSubcache, num) \
                ((SHMCBIndex *)(((unsigned char *)pSubcache) + \
                                sizeof(SHMCBSubcache)) + num)

/* This macro takes a pointer to the header and a subcache and returns a
 * pointer to the corresponding data area. */
#define SHMCB_DATA(pHeader, pSubcache) \
                ((unsigned char *)(pSubcache) + (pHeader)->subcache_data_offset)

/*
 * Cyclic functions - assists in "wrap-around"/modulo logic
 */

/* Addition modulo 'mod' */
#define SHMCB_CYCLIC_INCREMENT(val,inc,mod) \
                (((val) + (inc)) % (mod))

/* Subtraction (or "distance between") modulo 'mod' */
#define SHMCB_CYCLIC_SPACE(val1,val2,mod) \
                ((val2) >= (val1) ? ((val2) - (val1)) : \
                        ((val2) + (mod) - (val1)))

/* A "normal-to-cyclic" memcpy. */
static void shmcb_cyclic_ntoc_memcpy(unsigned int buf_size, unsigned char *data,
                                     unsigned int dest_offset, unsigned char *src,
                                     unsigned int src_len)
{
    if (dest_offset + src_len < buf_size)
        /* It be copied all in one go */
        memcpy(data + dest_offset, src, src_len);
    else {
        /* Copy the two splits */
        memcpy(data + dest_offset, src, buf_size - dest_offset);
        memcpy(data, src + buf_size - dest_offset,
               src_len + dest_offset - buf_size);
    }
}

/* A "cyclic-to-normal" memcpy. */
static void shmcb_cyclic_cton_memcpy(unsigned int buf_size, unsigned char *dest,
                                     unsigned char *data, unsigned int src_offset,
                                     unsigned int src_len)
{
    if (src_offset + src_len < buf_size)
        /* It be copied all in one go */
        memcpy(dest, data + src_offset, src_len);
    else {
        /* Copy the two splits */
        memcpy(dest, data + src_offset, buf_size - src_offset);
        memcpy(dest + buf_size - src_offset, data,
               src_len + src_offset - buf_size);
    }
}

/* Prototypes for low-level subcache operations */
static void shmcb_subcache_expire(server_rec *, SHMCBHeader *, SHMCBSubcache *);
static BOOL shmcb_subcache_store(server_rec *, SHMCBHeader *, SHMCBSubcache *,
                                 UCHAR *, unsigned int, UCHAR *, time_t);
static SSL_SESSION *shmcb_subcache_retrieve(server_rec *, SHMCBHeader *, SHMCBSubcache *,
                                            UCHAR *, unsigned int);
static BOOL shmcb_subcache_remove(server_rec *, SHMCBHeader *, SHMCBSubcache *,
                                 UCHAR *, unsigned int);

/*
 * High-Level "handlers" as per ssl_scache.c
 * subcache internals are deferred to shmcb_subcache_*** functions lower down
 */

void ssl_scache_shmcb_init(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    void *shm_segment;
    apr_size_t shm_segsize;
    apr_status_t rv;
    SHMCBHeader *header;
    unsigned int num_subcache, num_idx, loop;

    /* Create shared memory segment */
    if (mc->szSessionCacheDataFile == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "SSLSessionCache required");
        ssl_die();
    }

    /* Use anonymous shm by default, fall back on name-based. */
    rv = apr_shm_create(&(mc->pSessionCacheDataMM), 
                        mc->nSessionCacheDataSize, 
                        NULL, mc->pPool);
    if (APR_STATUS_IS_ENOTIMPL(rv)) {
        /* For a name-based segment, remove it first in case of a
         * previous unclean shutdown. */
        apr_shm_remove(mc->szSessionCacheDataFile, mc->pPool);

        rv = apr_shm_create(&(mc->pSessionCacheDataMM),
                            mc->nSessionCacheDataSize,
                            mc->szSessionCacheDataFile,
                            mc->pPool);
    }

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "could not allocate shared memory for shmcb "
                     "session cache");
        ssl_die();
    }

    shm_segment = apr_shm_baseaddr_get(mc->pSessionCacheDataMM);
    shm_segsize = apr_shm_size_get(mc->pSessionCacheDataMM);
    if (shm_segsize < (5 * sizeof(SHMCBHeader))) {
        /* the segment is ridiculously small, bail out */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "shared memory segment too small");
        ssl_die();
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "shmcb_init allocated %" APR_SIZE_T_FMT
                 " bytes of shared memory",
                 shm_segsize);
    /* Discount the header */
    shm_segsize -= sizeof(SHMCBHeader);
    /* Select the number of subcaches to create and how many indexes each
     * should contain based on the size of the memory (the header has already
     * been subtracted). Typical non-client-auth sslv3/tlsv1 sessions are
     * around 150 bytes, so erring to division by 120 helps ensure we would
     * exhaust data storage before index storage (except sslv2, where it's
     * *slightly* the other way). From there, we select the number of subcaches
     * to be a power of two, such that the number of indexes per subcache at
     * least twice the number of subcaches. */
    num_idx = (shm_segsize) / 120;
    num_subcache = 256;
    while ((num_idx / num_subcache) < (2 * num_subcache))
        num_subcache /= 2;
    num_idx /= num_subcache;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "for %" APR_SIZE_T_FMT " bytes (%" APR_SIZE_T_FMT 
                 " including header), recommending %u subcaches, "
                 "%u indexes each", shm_segsize,
                 shm_segsize + sizeof(SHMCBHeader), num_subcache, num_idx);
    if (num_idx < 5) {
        /* we're still too small, bail out */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "shared memory segment too small");
        ssl_die();
    }
    /* OK, we're sorted */
    header = shm_segment;
    header->stat_stores = 0;
    header->stat_expiries = 0;
    header->stat_scrolled = 0;
    header->stat_retrieves_hit = 0;
    header->stat_retrieves_miss = 0;
    header->stat_removes_hit = 0;
    header->stat_removes_miss = 0;
    header->subcache_num = num_subcache;
    /* Convert the subcache size (in bytes) to a value that is suitable for
     * structure alignment on the host platform, by rounding down if necessary.
     * This assumes that sizeof(unsigned long) provides an appropriate
     * alignment unit.  */
    header->subcache_size = ((size_t)(shm_segsize / num_subcache) &
                             ~(size_t)(sizeof(unsigned long) - 1));
    header->subcache_data_offset = sizeof(SHMCBSubcache) +
                                   num_idx * sizeof(SHMCBIndex);
    header->subcache_data_size = header->subcache_size -
                                 header->subcache_data_offset;
    header->index_num = num_idx;

    /* Output trace info */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "shmcb_init_memory choices follow");
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "subcache_num = %u", header->subcache_num);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "subcache_size = %u", header->subcache_size);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "subcache_data_offset = %u", header->subcache_data_offset);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "subcache_data_size = %u", header->subcache_data_size);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "index_num = %u", header->index_num);
    /* The header is done, make the caches empty */
    for (loop = 0; loop < header->subcache_num; loop++) {
        SHMCBSubcache *subcache = SHMCB_SUBCACHE(header, loop);
        subcache->idx_pos = subcache->idx_used = 0;
        subcache->data_pos = subcache->data_used = 0;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "Shared memory session cache initialised");
    /* Success ... */
    mc->tSessionCacheDataTable = shm_segment;
}

void ssl_scache_shmcb_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->pSessionCacheDataMM != NULL) {
        apr_shm_destroy(mc->pSessionCacheDataMM);
        mc->pSessionCacheDataMM = NULL;
    }
    return;
}

BOOL ssl_scache_shmcb_store(server_rec *s, UCHAR *id, int idlen,
                           time_t timeout, SSL_SESSION * pSession)
{
    SSLModConfigRec *mc = myModConfig(s);
    BOOL to_return = FALSE;
    unsigned char encoded[SSL_SESSION_MAX_DER];
    unsigned char *ptr_encoded;
    unsigned int len_encoded;
    SHMCBHeader *header = mc->tSessionCacheDataTable;
    SHMCBSubcache *subcache = SHMCB_MASK(header, id);

    ssl_mutex_on(s);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "ssl_scache_shmcb_store (0x%02x -> subcache %d)",
                 SHMCB_MASK_DBG(header, id));
    if (idlen < 4) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "unusably short session_id provided "
                "(%u bytes)", idlen);
        goto done;
    }
    /* Serialise the session. */
    len_encoded = i2d_SSL_SESSION(pSession, NULL);
    if (len_encoded > SSL_SESSION_MAX_DER) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "session is too big (%u bytes)", len_encoded);
        goto done;
    }
    ptr_encoded = encoded;
    len_encoded = i2d_SSL_SESSION(pSession, &ptr_encoded);
    if (!shmcb_subcache_store(s, header, subcache, encoded,
                              len_encoded, id, timeout)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "can't store a session!");
        goto done;
    }
    header->stat_stores++;
    to_return = TRUE;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "leaving ssl_scache_shmcb_store successfully");
done:
    ssl_mutex_off(s);
    return to_return;
}

SSL_SESSION *ssl_scache_shmcb_retrieve(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig(s);
    SSL_SESSION *pSession = NULL;
    SHMCBHeader *header = mc->tSessionCacheDataTable;
    SHMCBSubcache *subcache = SHMCB_MASK(header, id);

    ssl_mutex_on(s);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "ssl_scache_shmcb_retrieve (0x%02x -> subcache %d)",
                 SHMCB_MASK_DBG(header, id));
    if (idlen < 4) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "unusably short session_id provided "
                "(%u bytes)", idlen);
        goto done;
    }
    /* Get the session corresponding to the session_id or NULL if it doesn't
     * exist (or is flagged as "removed"). */
    pSession = shmcb_subcache_retrieve(s, header, subcache, id, idlen);
    if (pSession)
        header->stat_retrieves_hit++;
    else
        header->stat_retrieves_miss++;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "leaving ssl_scache_shmcb_retrieve successfully");
done:
    ssl_mutex_off(s);
    return pSession;
}

void ssl_scache_shmcb_remove(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig(s);
    SHMCBHeader *header = mc->tSessionCacheDataTable;
    SHMCBSubcache *subcache = SHMCB_MASK(header, id);

    ssl_mutex_on(s);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "ssl_scache_shmcb_remove (0x%02x -> subcache %d)",
                 SHMCB_MASK_DBG(header, id));
    if (idlen < 4) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "unusably short session_id provided "
                "(%u bytes)", idlen);
        goto done;
    }
    if (shmcb_subcache_remove(s, header, subcache, id, idlen))
        header->stat_removes_hit++;
    else
        header->stat_removes_miss++;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "leaving ssl_scache_shmcb_remove successfully");
done:
    ssl_mutex_off(s);
}

void ssl_scache_shmcb_status(request_rec *r, int flags, apr_pool_t *p)
{
    server_rec *s = r->server;
    SSLModConfigRec *mc = myModConfig(s);
    void *shm_segment = apr_shm_baseaddr_get(mc->pSessionCacheDataMM);
    SHMCBHeader *header = shm_segment;
    unsigned int loop, total = 0, cache_total = 0, non_empty_subcaches = 0;
    time_t idx_expiry, min_expiry = 0, max_expiry = 0, average_expiry = 0;
    time_t now = time(NULL);
    double expiry_total = 0;
    int index_pct, cache_pct;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "inside shmcb_status");
    /* Perform the iteration inside the mutex to avoid corruption or invalid
     * pointer arithmetic. The rest of our logic uses read-only header data so
     * doesn't need the lock. */
    ssl_mutex_on(s);
    /* Iterate over the subcaches */
    for (loop = 0; loop < header->subcache_num; loop++) {
        SHMCBSubcache *subcache = SHMCB_SUBCACHE(header, loop);
        shmcb_subcache_expire(s, header, subcache);
        total += subcache->idx_used;
        cache_total += subcache->data_used;
        if (subcache->idx_used) {
            SHMCBIndex *idx = SHMCB_INDEX(subcache, subcache->idx_pos);
            non_empty_subcaches++;
            idx_expiry = idx->expires;
            expiry_total += (double)idx_expiry;
            max_expiry = ((idx_expiry > max_expiry) ? idx_expiry : max_expiry);
            if (!min_expiry)
                min_expiry = idx_expiry;
            else
                min_expiry = ((idx_expiry < min_expiry) ? idx_expiry : min_expiry);
        }
    }
    ssl_mutex_off(s);
    index_pct = (100 * total) / (header->index_num *
                                 header->subcache_num);
    cache_pct = (100 * cache_total) / (header->subcache_data_size *
                                       header->subcache_num);
    /* Generate HTML */
    ap_rprintf(r, "cache type: <b>SHMCB</b>, shared memory: <b>%d</b> "
               "bytes, current sessions: <b>%d</b><br>",
               mc->nSessionCacheDataSize, total);
    ap_rprintf(r, "subcaches: <b>%d</b>, indexes per subcache: <b>%d</b><br>",
               header->subcache_num, header->index_num);
    if (non_empty_subcaches) {
        average_expiry = (time_t)(expiry_total / (double)non_empty_subcaches);
        ap_rprintf(r, "time left on oldest entries' SSL sessions: ");
        if (now < average_expiry)
            ap_rprintf(r, "avg: <b>%d</b> seconds, (range: %d...%d)<br>",
                       (int)(average_expiry - now),
                       (int)(min_expiry - now),
                       (int)(max_expiry - now));
        else
            ap_rprintf(r, "expiry_threshold: <b>Calculation error!</b><br>");
    }

    ap_rprintf(r, "index usage: <b>%d%%</b>, cache usage: <b>%d%%</b><br>",
               index_pct, cache_pct);
    ap_rprintf(r, "total sessions stored since starting: <b>%lu</b><br>",
               header->stat_stores);
    ap_rprintf(r, "total sessions expired since starting: <b>%lu</b><br>",
               header->stat_expiries);
    ap_rprintf(r, "total (pre-expiry) sessions scrolled out of the cache: "
               "<b>%lu</b><br>", header->stat_scrolled);
    ap_rprintf(r, "total retrieves since starting: <b>%lu</b> hit, "
               "<b>%lu</b> miss<br>", header->stat_retrieves_hit,
               header->stat_retrieves_miss);
    ap_rprintf(r, "total removes since starting: <b>%lu</b> hit, "
               "<b>%lu</b> miss<br>", header->stat_removes_hit,
               header->stat_removes_miss);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "leaving shmcb_status");
}

/*
 * Subcache-level cache operations 
 */

static void shmcb_subcache_expire(server_rec *s, SHMCBHeader *header,
                                  SHMCBSubcache *subcache)
{
    time_t now = time(NULL);
    unsigned int loop = 0;
    unsigned int new_idx_pos = subcache->idx_pos;
    SHMCBIndex *idx = NULL;

    while (loop < subcache->idx_used) {
        idx = SHMCB_INDEX(subcache, new_idx_pos);
        if (idx->expires > now)
            /* it hasn't expired yet, we're done iterating */
            break;
        loop++;
        new_idx_pos = SHMCB_CYCLIC_INCREMENT(new_idx_pos, 1, header->index_num);
    }
    if (!loop)
        /* Nothing to do */
        return;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "will be expiring %u sessions", loop);
    if (loop == subcache->idx_used) {
        /* We're expiring everything, piece of cake */
        subcache->idx_used = 0;
        subcache->data_used = 0;
    } else {
        /* There remain other indexes, so we can use idx to adjust 'data' */
        unsigned int diff = SHMCB_CYCLIC_SPACE(subcache->data_pos,
                                               idx->data_pos,
                                               header->subcache_data_size);
        /* Adjust the indexes */
        subcache->idx_used -= loop;
        subcache->idx_pos = new_idx_pos;
        /* Adjust the data area */
        subcache->data_used -= diff;
        subcache->data_pos = idx->data_pos;
    }
    header->stat_expiries += loop;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "we now have %u sessions", subcache->idx_used);
}

static BOOL shmcb_subcache_store(server_rec *s, SHMCBHeader *header,
                                 SHMCBSubcache *subcache, 
                                 UCHAR *data, unsigned int data_len,
                                 UCHAR *id, time_t expiry)
{
    unsigned int new_offset, new_idx;
    SHMCBIndex *idx;

    /* Sanity check the input */
    if ((data_len > header->subcache_data_size) || (data_len > SSL_SESSION_MAX_DER)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "inserting session larger (%d) than subcache data area (%d)",
                     data_len, header->subcache_data_size);
        return FALSE;
    }

    /* If there are entries to expire, ditch them first. */
    shmcb_subcache_expire(s, header, subcache);

    /* Loop until there is enough space to insert */
    if (header->subcache_data_size - subcache->data_used < data_len
        || subcache->idx_used == header->index_num) {
        unsigned int loop = 0;

        idx = SHMCB_INDEX(subcache, subcache->idx_pos);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "about to force-expire, subcache: idx_used=%d, "
                     "data_used=%d", subcache->idx_used, subcache->data_used);
        do {
            SHMCBIndex *idx2;

            /* Adjust the indexes by one */
            subcache->idx_pos = SHMCB_CYCLIC_INCREMENT(subcache->idx_pos, 1,
                                                       header->index_num);
            subcache->idx_used--;
            if (!subcache->idx_used) {
                /* There's nothing left */
                subcache->data_used = 0;
                break;
            }
            /* Adjust the data */
            idx2 = SHMCB_INDEX(subcache, subcache->idx_pos);
            subcache->data_used -= SHMCB_CYCLIC_SPACE(idx->data_pos, idx2->data_pos,
                                                      header->subcache_data_size);
            subcache->data_pos = idx2->data_pos;
            /* Stats */
            header->stat_scrolled++;
            /* Loop admin */
            idx = idx2;
            loop++;
        } while (header->subcache_data_size - subcache->data_used < data_len);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "finished force-expire, subcache: idx_used=%d, "
                     "data_used=%d", subcache->idx_used, subcache->data_used);
    }

    /* HERE WE ASSUME THAT THE NEW SESSION SHOULD GO ON THE END! I'M NOT
     * CHECKING WHETHER IT SHOULD BE GENUINELY "INSERTED" SOMEWHERE.
     *
     * We either fix that, or find out at a "higher" (read "mod_ssl")
     * level whether it is possible to have distinct session caches for
     * any attempted tomfoolery to do with different session timeouts.
     * Knowing in advance that we can have a cache-wide constant timeout
     * would make this stuff *MUCH* more efficient. Mind you, it's very
     * efficient right now because I'm ignoring this problem!!!
     */
    /* Insert the data */
    new_offset = SHMCB_CYCLIC_INCREMENT(subcache->data_pos, subcache->data_used,
                                        header->subcache_data_size);
    shmcb_cyclic_ntoc_memcpy(header->subcache_data_size,
                             SHMCB_DATA(header, subcache), new_offset,
                             data, data_len);
    subcache->data_used += data_len;
    /* Insert the index */
    new_idx = SHMCB_CYCLIC_INCREMENT(subcache->idx_pos, subcache->idx_used,
                                     header->index_num);
    idx = SHMCB_INDEX(subcache, new_idx);
    idx->expires = expiry;
    idx->data_pos = new_offset;
    idx->data_used = data_len;
    idx->s_id2 = id[1];
    idx->removed = 0;
    subcache->idx_used++;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "insert happened at idx=%d, data=%d", new_idx, new_offset);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "finished insert, subcache: idx_pos/idx_used=%d/%d, "
                 "data_pos/data_used=%d/%d",
                 subcache->idx_pos, subcache->idx_used,
                 subcache->data_pos, subcache->data_used);
    return TRUE;
}

static SSL_SESSION *shmcb_subcache_retrieve(server_rec *s, SHMCBHeader *header,
                                            SHMCBSubcache *subcache, UCHAR *id,
                                            unsigned int idlen)
{
    unsigned int pos;
    unsigned int loop = 0;

    /* If there are entries to expire, ditch them first. */
    shmcb_subcache_expire(s, header, subcache);
    pos = subcache->idx_pos;

    while (loop < subcache->idx_used) {
        SHMCBIndex *idx = SHMCB_INDEX(subcache, pos);

        /* Only consider 'idx' if;
         * (a) the s_id2 byte matches
         * (b) the "removed" flag isn't set.
         */
        if ((idx->s_id2 == id[1]) && !idx->removed) {
            SSL_SESSION *pSession;
            unsigned char *s_id;
            unsigned int s_idlen;
            unsigned char tempasn[SSL_SESSION_MAX_DER];
            MODSSL_D2I_SSL_SESSION_CONST unsigned char *ptr = tempasn;

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "possible match at idx=%d, data=%d", pos, idx->data_pos);
            /* Copy the data */
            shmcb_cyclic_cton_memcpy(header->subcache_data_size,
                                     tempasn, SHMCB_DATA(header, subcache),
                                     idx->data_pos, idx->data_used);
            /* Decode the session */
            pSession = d2i_SSL_SESSION(NULL, &ptr, idx->data_used);
            if (!pSession) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "shmcb_subcache_retrieve internal error");
                return NULL;
            }
            s_id = SSL_SESSION_get_session_id(pSession);
            s_idlen = SSL_SESSION_get_session_id_length(pSession);
            if (s_idlen == idlen && memcmp(s_id, id, idlen) == 0) {
                /* Found the matching session */
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                             "shmcb_subcache_retrieve returning matching session");
                return pSession;
            }
            SSL_SESSION_free(pSession);
        }
        /* Increment */
        loop++;
        pos = SHMCB_CYCLIC_INCREMENT(pos, 1, header->index_num);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "shmcb_subcache_retrieve found no match");
    return NULL;
}

static BOOL shmcb_subcache_remove(server_rec *s, SHMCBHeader *header,
                                  SHMCBSubcache *subcache,
                                  UCHAR *id, unsigned int idlen)
{
    unsigned int pos;
    unsigned int loop = 0;
    BOOL to_return = FALSE;

    /* Unlike the others, we don't do an expire-run first. This is to keep
     * consistent statistics where a "remove" operation may actually be the
     * higher layer spotting an expiry issue prior to us. Our caller is
     * handling stats, so a failure return would be inconsistent if the
     * intended session was in fact removed by an expiry run. */

    pos = subcache->idx_pos;
    while (!to_return && (loop < subcache->idx_used)) {
        SHMCBIndex *idx = SHMCB_INDEX(subcache, pos);
        /* Only consider 'idx' if the s_id2 byte matches and it's not already
         * removed - easiest way to avoid costly ASN decodings. */
        if ((idx->s_id2 == id[1]) && !idx->removed) {
            SSL_SESSION *pSession;
            unsigned char *s_id;
            unsigned int s_idlen;
            unsigned char tempasn[SSL_SESSION_MAX_DER];
            MODSSL_D2I_SSL_SESSION_CONST unsigned char *ptr = tempasn;

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "possible match at idx=%d, data=%d", pos, idx->data_pos);
            /* Copy the data */
            shmcb_cyclic_cton_memcpy(header->subcache_data_size,
                                     tempasn, SHMCB_DATA(header, subcache),
                                     idx->data_pos, idx->data_used);
            /* Decode the session */
            pSession = d2i_SSL_SESSION(NULL, &ptr, idx->data_used);
            if (!pSession) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "shmcb_subcache_remove internal error");
                return FALSE;
            }
            s_id = SSL_SESSION_get_session_id(pSession);
            s_idlen = SSL_SESSION_get_session_id_length(pSession);
            if (s_idlen == idlen && memcmp(s_id, id, idlen) == 0) {
                /* Found the matching session, remove it quietly. */
                idx->removed = 1;
                to_return = TRUE;
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                             "shmcb_subcache_remove removing matching session");
            }
            SSL_SESSION_free(pSession);
        }
        /* Increment */
        loop++;
        pos = SHMCB_CYCLIC_INCREMENT(pos, 1, header->index_num);
    }

    return to_return;
}
