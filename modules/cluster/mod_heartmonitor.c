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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_time.h"
#include "ap_mpm.h"
#include "scoreboard.h"
#include "mod_watchdog.h"
#include "ap_slotmem.h"
#include "heartbeat.h"


#ifndef HM_UPDATE_SEC
/* How often we update the stats file */
/* TODO: Make a runtime config */
#define HM_UPDATE_SEC (5)
#endif

#define HM_WATHCHDOG_NAME ("_heartmonitor_")

static const ap_slotmem_provider_t *storage = NULL;
static ap_slotmem_instance_t *slotmem = NULL;
static int maxworkers = 0;

module AP_MODULE_DECLARE_DATA heartmonitor_module;

typedef struct hm_server_t
{
    const char *ip;
    int busy;
    int ready;
    unsigned int port;
    apr_time_t seen;
} hm_server_t;

typedef struct hm_ctx_t
{
    int active;
    const char *storage_path;
    ap_watchdog_t *watchdog;
    apr_interval_time_t interval;
    apr_sockaddr_t *mcast_addr;
    apr_status_t status;
    volatile int keep_running;
    apr_socket_t *sock;
    apr_pool_t *p;
    apr_hash_t *servers;
    server_rec *s;
} hm_ctx_t;

typedef struct hm_slot_server_ctx_t {
  hm_server_t *s;
  int found;
  unsigned int item_id;
} hm_slot_server_ctx_t;

static apr_status_t hm_listen(hm_ctx_t *ctx)
{
    apr_status_t rv;

    rv = apr_socket_create(&ctx->sock, ctx->mcast_addr->family,
                           SOCK_DGRAM, APR_PROTO_UDP, ctx->p);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Failed to create listening socket.");
        return rv;
    }

    rv = apr_socket_opt_set(ctx->sock, APR_SO_REUSEADDR, 1);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Failed to set APR_SO_REUSEADDR to 1 on socket.");
        return rv;
    }


    rv = apr_socket_opt_set(ctx->sock, APR_SO_NONBLOCK, 1);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Failed to set APR_SO_REUSEADDR to 1 on socket.");
        return rv;
    }

    rv = apr_socket_bind(ctx->sock, ctx->mcast_addr);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Failed to bind on socket.");
        return rv;
    }

    rv = apr_mcast_join(ctx->sock, ctx->mcast_addr, NULL, NULL);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Failed to join multicast group");
        return rv;
    }

    rv = apr_mcast_loopback(ctx->sock, 1);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Failed to accept localhost mulitcast on socket.");
        return rv;
    }

    return APR_SUCCESS;
}

/* XXX: The same exists in mod_lbmethod_heartbeat.c where it is named argstr_to_table */
static void qs_to_table(const char *input, apr_table_t *parms,
                        apr_pool_t *p)
{
    char *key;
    char *value;
    char *query_string;
    char *strtok_state;

    if (input == NULL) {
        return;
    }

    query_string = apr_pstrdup(p, input);

    key = apr_strtok(query_string, "&", &strtok_state);
    while (key) {
        value = strchr(key, '=');
        if (value) {
            *value = '\0';      /* Split the string in two */
            value++;            /* Skip passed the = */
        }
        else {
            value = "1";
        }
        ap_unescape_url(key);
        ap_unescape_url(value);
        apr_table_set(parms, key, value);
        /*
           ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
           "Found query arg: %s = %s", key, value);
         */
        key = apr_strtok(NULL, "&", &strtok_state);
    }
}


#define SEEN_TIMEOUT (30)

/* Store in the slotmem */
static apr_status_t hm_update(void* mem, void *data, apr_pool_t *p)
{
    hm_slot_server_t *old = (hm_slot_server_t *) mem;
    hm_slot_server_ctx_t *s = (hm_slot_server_ctx_t *) data;
    hm_server_t *new = s->s;
    if (strncmp(old->ip, new->ip, MAXIPSIZE)==0) {
        s->found = 1;
        old->busy = new->busy;
        old->ready = new->ready;
        old->seen = new->seen;
    }
    return APR_SUCCESS;
}
/* Read the id corresponding to the entry in the slotmem */
static apr_status_t hm_readid(void* mem, void *data, apr_pool_t *p)
{
    hm_slot_server_t *old = (hm_slot_server_t *) mem;
    hm_slot_server_ctx_t *s = (hm_slot_server_ctx_t *) data;
    hm_server_t *new = s->s;
    if (strncmp(old->ip, new->ip, MAXIPSIZE)==0) {
        s->found = 1;
        s->item_id = old->id;
    }
    return APR_SUCCESS;
}
/* update the entry or create it if not existing */
static  apr_status_t  hm_slotmem_update_stat(hm_server_t *s, apr_pool_t *pool)
{
    /* We call do_all (to try to update) otherwise grab + put */
    hm_slot_server_ctx_t ctx;
    ctx.s = s;
    ctx.found = 0;
    storage->doall(slotmem, hm_update, &ctx, pool);
    if (!ctx.found) {
        unsigned int i;
        hm_slot_server_t hmserver;
        memcpy(hmserver.ip, s->ip, MAXIPSIZE);
        hmserver.busy = s->busy;
        hmserver.ready = s->ready;
        hmserver.seen = s->seen;
        /* XXX locking for grab() / put() */
        storage->grab(slotmem, &i);
        hmserver.id = i;
        storage->put(slotmem, i, (unsigned char *)&hmserver, sizeof(hmserver));
    }
    return APR_SUCCESS;
}
static  apr_status_t  hm_slotmem_remove_stat(hm_server_t *s, apr_pool_t *pool)
{
    hm_slot_server_ctx_t ctx;
    ctx.s = s;
    ctx.found = 0;
    storage->doall(slotmem, hm_readid, &ctx, pool);
    if (ctx.found) {
        storage->release(slotmem, ctx.item_id);
    }
    return APR_SUCCESS;
}
static apr_status_t hm_file_update_stat(hm_ctx_t *ctx, hm_server_t *s, apr_pool_t *pool)
{
    apr_status_t rv;
    apr_file_t *fp;
    apr_file_t *fpin;
    apr_time_t now;
    unsigned int fage;
    apr_finfo_t fi;
    int updated = 0;
    char *path = apr_pstrcat(pool, ctx->storage_path, ".tmp.XXXXXX", NULL);


    /* TODO: Update stats file (!) */
    rv = apr_file_mktemp(&fp, path, APR_CREATE | APR_WRITE, pool);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Unable to open tmp file: %s", path);
        return rv;
    }
    rv = apr_file_open(&fpin, ctx->storage_path, APR_READ|APR_BINARY|APR_BUFFERED,
                       APR_OS_DEFAULT, pool);

    now = apr_time_now();
    if (rv == APR_SUCCESS) {
        char *t;
        apr_table_t *hbt = apr_table_make(pool, 10);
        apr_bucket_alloc_t *ba = apr_bucket_alloc_create(pool);
        apr_bucket_brigade *bb = apr_brigade_create(pool, ba);
        apr_bucket_brigade *tmpbb = apr_brigade_create(pool, ba);
        rv = apr_file_info_get(&fi, APR_FINFO_SIZE | APR_FINFO_MTIME, fpin);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                         "Heartmonitor: Unable to read file: %s", ctx->storage_path);
            return rv;
        }

        /* Read the file and update the line corresponding to the node */
        ba = apr_bucket_alloc_create(pool);
        bb = apr_brigade_create(pool, ba);
        apr_brigade_insert_file(bb, fpin, 0, fi.size, pool);
        tmpbb = apr_brigade_create(pool, ba);
        fage = (unsigned int) apr_time_sec(now - fi.mtime);
        do {
            char buf[4096];
            const char *ip;
            apr_size_t bsize = sizeof(buf);
            apr_brigade_cleanup(tmpbb);
            if (APR_BRIGADE_EMPTY(bb)) {
                break;
            } 
            rv = apr_brigade_split_line(tmpbb, bb,
                                        APR_BLOCK_READ, sizeof(buf));
       
            if (rv) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                             "Heartmonitor: Unable to read from file: %s", ctx->storage_path);
                return rv;
            }

            apr_brigade_flatten(tmpbb, buf, &bsize);
            if (bsize == 0) {
                break;
            }
            buf[bsize - 1] = 0;
            t = strchr(buf, ' ');
            if (t) {
                ip = apr_pstrndup(pool, buf, t - buf);
            } else {
                ip = NULL;
            }
            if (!ip || buf[0] == '#') {
                /* copy things we can't process */
                apr_file_printf(fp, "%s\n", buf);
            } else if (strcmp(ip, s->ip) !=0 ) {
                hm_server_t node; 
                unsigned int seen;
                /* Update seen time according to the last file modification */
                apr_table_clear(hbt);
                qs_to_table(apr_pstrdup(pool, t), hbt, pool);
                if (apr_table_get(hbt, "busy")) {
                    node.busy = atoi(apr_table_get(hbt, "busy"));
                } else {
                    node.busy = 0;
                }

                if (apr_table_get(hbt, "ready")) {
                    node.ready = atoi(apr_table_get(hbt, "ready"));
                } else {
                    node.ready = 0;
                }

                if (apr_table_get(hbt, "lastseen")) {
                    node.seen = atoi(apr_table_get(hbt, "lastseen"));
                } else {
                    node.seen = SEEN_TIMEOUT; 
                }
                seen = fage + node.seen;

                if (apr_table_get(hbt, "port")) {
                    node.port = atoi(apr_table_get(hbt, "port"));
                } else {
                    node.port = 80; 
                }
                apr_file_printf(fp, "%s &ready=%u&busy=%u&lastseen=%u&port=%u\n",
                                ip, node.ready, node.busy, (unsigned int) seen, node.port);
            } else {
                apr_time_t seen;
                seen = apr_time_sec(now - s->seen);
                apr_file_printf(fp, "%s &ready=%u&busy=%u&lastseen=%u&port=%u\n",
                                s->ip, s->ready, s->busy, (unsigned int) seen, s->port);
                updated = 1;
            }
        } while (1);
    }

    if (!updated) {
        apr_time_t seen;
        seen = apr_time_sec(now - s->seen);
        apr_file_printf(fp, "%s &ready=%u&busy=%u&lastseen=%u&port=%u\n",
                        s->ip, s->ready, s->busy, (unsigned int) seen, s->port);
    }

    rv = apr_file_flush(fp);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                   "Heartmonitor: Unable to flush file: %s", path);
      return rv;
    }

    rv = apr_file_close(fp);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                   "Heartmonitor: Unable to close file: %s", path);
      return rv;
    }
  
    rv = apr_file_perms_set(path,
                            APR_FPROT_UREAD | APR_FPROT_GREAD |
                            APR_FPROT_WREAD);
    if (rv && rv != APR_INCOMPLETE) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Unable to set file permssions on %s",
                     path);
        return rv;
    }

    rv = apr_file_rename(path, ctx->storage_path, pool);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Unable to move file: %s -> %s", path,
                     ctx->storage_path);
        return rv;
    }

    return APR_SUCCESS;
}
static  apr_status_t  hm_update_stat(hm_ctx_t *ctx, hm_server_t *s, apr_pool_t *pool)
{
    if (slotmem)
        return hm_slotmem_update_stat(s, pool);
    else
        return hm_file_update_stat(ctx, s, pool);
}

/* Store in a file */
static apr_status_t hm_file_update_stats(hm_ctx_t *ctx, apr_pool_t *p)
{
    apr_status_t rv;
    apr_file_t *fp;
    apr_hash_index_t *hi;
    apr_time_t now;
    char *path = apr_pstrcat(p, ctx->storage_path, ".tmp.XXXXXX", NULL);
    /* TODO: Update stats file (!) */
    rv = apr_file_mktemp(&fp, path, APR_CREATE | APR_WRITE, p);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Unable to open tmp file: %s", path);
        return rv;
    }

    now = apr_time_now();
    for (hi = apr_hash_first(p, ctx->servers);
         hi != NULL; hi = apr_hash_next(hi)) {
        hm_server_t *s = NULL;
        apr_time_t seen;
        apr_hash_this(hi, NULL, NULL, (void **) &s);
        seen = apr_time_sec(now - s->seen);
        if (seen > SEEN_TIMEOUT) {
            /*
             * Skip this entry from the heartbeat file -- when it comes back,
             * we will reuse the memory...
             */
        }
        else {
            apr_file_printf(fp, "%s &ready=%u&busy=%u&lastseen=%u&port=%u\n",
                            s->ip, s->ready, s->busy, (unsigned int) seen, s->port);
        }
    }

    rv = apr_file_flush(fp);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                   "Heartmonitor: Unable to flush file: %s", path);
      return rv;
    }

    rv = apr_file_close(fp);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                   "Heartmonitor: Unable to close file: %s", path);
      return rv;
    }
  
    rv = apr_file_perms_set(path,
                            APR_FPROT_UREAD | APR_FPROT_GREAD |
                            APR_FPROT_WREAD);
    if (rv && rv != APR_INCOMPLETE) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Unable to set file permssions on %s",
                     path);
        return rv;
    }

    rv = apr_file_rename(path, ctx->storage_path, p);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: Unable to move file: %s -> %s", path,
                     ctx->storage_path);
        return rv;
    }

    return APR_SUCCESS;
}
/* Store in a slotmem */
static apr_status_t hm_slotmem_update_stats(hm_ctx_t *ctx, apr_pool_t *p)
{
    apr_status_t rv;
    apr_time_t now;
    apr_hash_index_t *hi;
    now = apr_time_now();
    for (hi = apr_hash_first(p, ctx->servers);
         hi != NULL; hi = apr_hash_next(hi)) {
        hm_server_t *s = NULL;
        apr_time_t seen;
        apr_hash_this(hi, NULL, NULL, (void **) &s);
        seen = apr_time_sec(now - s->seen);
        if (seen > SEEN_TIMEOUT) {
            /* remove it */
            rv = hm_slotmem_remove_stat(s, p);
        } else {
            /* update it */
            rv = hm_slotmem_update_stat(s, p);
        }
        if (rv !=APR_SUCCESS)
            return rv;
    }
    return APR_SUCCESS;
}
/* Store/update the stats */
static apr_status_t hm_update_stats(hm_ctx_t *ctx, apr_pool_t *p)
{
    if (slotmem)
        return hm_slotmem_update_stats(ctx, p);
    else
        return hm_file_update_stats(ctx, p);
}

static hm_server_t *hm_get_server(hm_ctx_t *ctx, const char *ip, const int port)
{
    hm_server_t *s;

    s = apr_hash_get(ctx->servers, ip, APR_HASH_KEY_STRING);

    if (s == NULL) {
        s = apr_palloc(ctx->p, sizeof(hm_server_t));
        s->ip = apr_pstrdup(ctx->p, ip);
        s->port = port;
        s->ready = 0;
        s->busy = 0;
        s->seen = 0;
        apr_hash_set(ctx->servers, s->ip, APR_HASH_KEY_STRING, s);
    }

    return s;
}

/* Process a message received from a backend node */
static void hm_processmsg(hm_ctx_t *ctx, apr_pool_t *p,
                                  apr_sockaddr_t *from, char *buf, int len)
{
    apr_table_t *tbl;

    buf[len] = '\0';

    tbl = apr_table_make(p, 10);

    qs_to_table(buf, tbl, p);

    if (apr_table_get(tbl, "v") != NULL &&
        apr_table_get(tbl, "busy") != NULL &&
        apr_table_get(tbl, "ready") != NULL) {
        char *ip;
        int port = 80;
        hm_server_t *s;
        /* TODO: REMOVE ME BEFORE PRODUCTION (????) */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s,
                     "Heartmonitor: %pI busy=%s ready=%s", from,
                     apr_table_get(tbl, "busy"), apr_table_get(tbl, "ready"));

        apr_sockaddr_ip_get(&ip, from);

        if (apr_table_get(tbl, "port") != NULL)
            port = atoi(apr_table_get(tbl, "port"));
           
        s = hm_get_server(ctx, ip, port);

        s->busy = atoi(apr_table_get(tbl, "busy"));
        s->ready = atoi(apr_table_get(tbl, "ready"));
        s->seen = apr_time_now();
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, ctx->s,
                     "Heartmonitor: malformed message from %pI",
                     from);
    }

}
/* Read message from multicast socket */
#define MAX_MSG_LEN (1000)
static apr_status_t hm_recv(hm_ctx_t *ctx, apr_pool_t *p)
{
    char buf[MAX_MSG_LEN + 1];
    apr_sockaddr_t from;
    apr_size_t len = MAX_MSG_LEN;
    apr_status_t rv;

    from.pool = p;

    rv = apr_socket_recvfrom(&from, ctx->sock, 0, buf, &len);

    if (APR_STATUS_IS_EAGAIN(rv)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: would block");
        return APR_SUCCESS;
    }
    else if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                     "Heartmonitor: recvfrom failed");
        return rv;
    }

    hm_processmsg(ctx, p, &from, buf, len);

    return rv;
}

static apr_status_t hm_watchdog_callback(int state, void *data,
                                         apr_pool_t *pool)
{
    apr_status_t rv = APR_SUCCESS;
    apr_time_t cur, now;
    hm_ctx_t *ctx = (hm_ctx_t *)data;

    if (!ctx->active) {
        return rv;
    }

    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            rv = hm_listen(ctx);
            if (rv) {
                ctx->status = rv;
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ctx->s,
                             "Heartmonitor: Unable to listen for connections!");
            }
            else {
                ctx->keep_running = 1;
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s,
                             "Heartmonitor: %s listener started.",
                             HM_WATHCHDOG_NAME);
            }
        break;
        case AP_WATCHDOG_STATE_RUNNING:
            /* store in the slotmem or in the file depending on configuration */
            hm_update_stats(ctx, pool);
            cur = now = apr_time_sec(apr_time_now());
            /* TODO: Insted HN_UPDATE_SEC use
             * the ctx->interval
             */
            while ((now - cur) < apr_time_sec(ctx->interval)) {
                int n;
                apr_status_t rc;
                apr_pool_t *p;
                apr_pollfd_t pfd;
                apr_interval_time_t timeout;

                apr_pool_create(&p, pool);

                pfd.desc_type = APR_POLL_SOCKET;
                pfd.desc.s = ctx->sock;
                pfd.p = p;
                pfd.reqevents = APR_POLLIN;

                timeout = apr_time_from_sec(1);

                rc = apr_poll(&pfd, 1, &n, timeout);

                if (!ctx->keep_running) {
                    apr_pool_destroy(p);
                    break;
                }
                if (rc == APR_SUCCESS && (pfd.rtnevents & APR_POLLIN)) {
                    hm_recv(ctx, p);
                }
                now = apr_time_sec(apr_time_now());
                apr_pool_destroy(p);
            }
        break;
        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s,
                         "Heartmonitor: stopping %s listener.",
                         HM_WATHCHDOG_NAME);

            ctx->keep_running = 0;
            if (ctx->sock) {
                apr_socket_close(ctx->sock);
                ctx->sock = NULL;
            }
        break;
    }
    return rv;
}

static int hm_post_config(apr_pool_t *p, apr_pool_t *plog,
                          apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    const char *userdata_key = "mod_heartmonitor_init";
    void *data;
    hm_ctx_t *ctx = ap_get_module_config(s->module_config,
                                         &heartmonitor_module);
    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *hm_watchdog_get_instance;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *hm_watchdog_register_callback;

    hm_watchdog_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    hm_watchdog_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    if (!hm_watchdog_get_instance || !hm_watchdog_register_callback) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "Heartmonitor: mod_watchdog is required");
        return !OK;
    }

    /* Create the slotmem */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        /* first call do nothing */
        apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);
    } else {
        if (maxworkers) {
            storage = ap_lookup_provider(AP_SLOTMEM_PROVIDER_GROUP, "shared", "0");
            if (!storage) {
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, 0, s, "ap_lookup_provider %s failed", AP_SLOTMEM_PROVIDER_GROUP);
                return !OK;
            }
            storage->create(&slotmem, "mod_heartmonitor", sizeof(hm_slot_server_t), maxworkers, AP_SLOTMEM_TYPE_PREGRAB, p);
            if (!slotmem) {
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, 0, s, "slotmem_create for status failed");
                return !OK;
            }
        }
    }

    if (!ctx->active) {
        return OK;
    }
    rv = hm_watchdog_get_instance(&ctx->watchdog,
                                  HM_WATHCHDOG_NAME,
                                  0, 1, p);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "Heartmonitor: Failed to create watchdog "
                     "instance (%s)", HM_WATHCHDOG_NAME);
        return !OK;
    }
    /* Register a callback with zero interval. */
    rv = hm_watchdog_register_callback(ctx->watchdog,
                                       0,
                                       ctx,
                                       hm_watchdog_callback);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "Heartmonitor: Failed to register watchdog "
                     "callback (%s)", HM_WATHCHDOG_NAME);
        return !OK;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "Heartmonitor: wd callback %s", HM_WATHCHDOG_NAME);
    return OK;
}

static int hm_handler(request_rec *r)
{
    apr_bucket_brigade *input_brigade;
    apr_size_t len=MAX_MSG_LEN;
    char *buf;
    apr_status_t status;
    apr_table_t *tbl;
    hm_server_t hmserver;
    char *ip;
    hm_ctx_t *ctx = ap_get_module_config(r->server->module_config,
                                         &heartmonitor_module);

    if (strcmp(r->handler, "hearthbeat")) {
        return DECLINED;
    }
    if (r->method_number != M_POST) {
        return HTTP_METHOD_NOT_ALLOWED;
    }
    buf = apr_pcalloc(r->pool, MAX_MSG_LEN);
    input_brigade = apr_brigade_create(r->connection->pool, r->connection->bucket_alloc);
    status = ap_get_brigade(r->input_filters, input_brigade, AP_MODE_READBYTES, APR_BLOCK_READ, MAX_MSG_LEN);
    if (status != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_brigade_flatten(input_brigade, buf, &len);

    /* we can't use hm_processmsg because it uses hm_get_server() */
    buf[len] = '\0';
    tbl = apr_table_make(r->pool, 10);
    qs_to_table(buf, tbl, r->pool);
    apr_sockaddr_ip_get(&ip, r->connection->remote_addr);
    hmserver.ip = ip;
    hmserver.port = 80;
    if (apr_table_get(tbl, "port") != NULL)
        hmserver.port = atoi(apr_table_get(tbl, "port"));
    hmserver.busy = atoi(apr_table_get(tbl, "busy"));
    hmserver.ready = atoi(apr_table_get(tbl, "ready"));
    hmserver.seen = apr_time_now();
    hm_update_stat(ctx, &hmserver, r->pool);

    ap_set_content_type(r, "text/plain");
    ap_set_content_length(r, 2);
    ap_rprintf(r, "OK");
    ap_rflush(r);

    return OK;
}

static void hm_register_hooks(apr_pool_t *p)
{
    static const char * const aszSucc[]={ "mod_proxy.c", NULL };
    ap_hook_post_config(hm_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_handler(hm_handler, NULL, aszSucc, APR_HOOK_FIRST);
}

static void *hm_create_config(apr_pool_t *p, server_rec *s)
{
    hm_ctx_t *ctx = (hm_ctx_t *) apr_palloc(p, sizeof(hm_ctx_t));

    ctx->active = 0;
    ctx->storage_path = ap_server_root_relative(p, "logs/hb.dat");
    /* TODO: Add directive for tuning the update interval
     */
    ctx->interval = apr_time_from_sec(HM_UPDATE_SEC);
    ctx->s = s;
    apr_pool_create(&ctx->p, p);
    ctx->servers = apr_hash_make(ctx->p);

    return ctx;
}

static const char *cmd_hm_storage(cmd_parms *cmd,
                                  void *dconf, const char *path)
{
    apr_pool_t *p = cmd->pool;
    hm_ctx_t *ctx =
        (hm_ctx_t *) ap_get_module_config(cmd->server->module_config,
                                          &heartmonitor_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    ctx->storage_path = ap_server_root_relative(p, path);

    return NULL;
}

static const char *cmd_hm_listen(cmd_parms *cmd,
                                 void *dconf, const char *mcast_addr)
{
    apr_status_t rv;
    char *host_str;
    char *scope_id;
    apr_port_t port = 0;
    apr_pool_t *p = cmd->pool;
    hm_ctx_t *ctx =
        (hm_ctx_t *) ap_get_module_config(cmd->server->module_config,
                                          &heartmonitor_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    if (!ctx->active) {
        ctx->active = 1;
    }
    else {
        return "HeartbeatListen: May only be specified once.";
    }

    rv = apr_parse_addr_port(&host_str, &scope_id, &port, mcast_addr, cmd->temp_pool);

    if (rv) {
        return "HeartbeatListen: Unable to parse multicast address.";
    }

    if (host_str == NULL) {
        return "HeartbeatListen: No host provided in multicast address";
    }

    if (port == 0) {
        return "HeartbeatListen: No port provided in multicast address";
    }

    rv = apr_sockaddr_info_get(&ctx->mcast_addr, host_str, APR_INET, port, 0,
                               p);

    if (rv) {
        return
            "HeartbeatListen: apr_sockaddr_info_get failed on multicast address";
    }

    return NULL;
}

static const char *cmd_hm_maxworkers(cmd_parms *cmd,
                                  void *dconf, const char *data)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    maxworkers = atoi(data);
    if (maxworkers <= 10)
        return "HeartbeatMaxServers: Should be bigger than 10"; 

    return NULL;
}

static const command_rec hm_cmds[] = {
    AP_INIT_TAKE1("HeartbeatListen", cmd_hm_listen, NULL, RSRC_CONF,
                  "Address to listen for heartbeat requests"),
    AP_INIT_TAKE1("HeartbeatStorage", cmd_hm_storage, NULL, RSRC_CONF,
                  "Path to store heartbeat data."),
    AP_INIT_TAKE1("HeartbeatMaxServers", cmd_hm_maxworkers, NULL, RSRC_CONF,
                  "Max number of servers when using slotmem (instead file) to store heartbeat data."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA heartmonitor_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    hm_create_config,           /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    hm_cmds,                    /* command apr_table_t */
    hm_register_hooks
};
