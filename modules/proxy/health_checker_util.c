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
 * Internal routine of the default httpd part of a health checker
 */
#define CORE_PRIVATE

#include "apr.h"
#include "apr_pools.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include "mod_proxy.h"
#include "slotmem.h"
#include "mod_proxy_health_checker.h"

#include "ajp.h"

static const slotmem_storage_method *checkstorage = NULL;
static ap_slotmem_t *myscore = NULL;

/* Check a AJP back-end server.
 * Send a cing message and wait for the answer
 */
static apr_status_t pingc_backend(apr_socket_t *sock, apr_pool_t *pool)
{
    ajp_msg_t *msg;
    apr_status_t rc;
    apr_byte_t result;

    rc = ajp_msg_create(pool,  &msg);
    if (rc != APR_SUCCESS)
        return rc;
    ajp_msg_serialize_cping(msg);
    rc = ajp_ilink_send(sock, msg);
    if (rc != APR_SUCCESS)
        return rc;
    ajp_msg_reuse(msg);
    rc = ajp_ilink_receive(sock, msg);
    if (rc != APR_SUCCESS)
        return rc;
    rc = ajp_msg_peek_uint8(msg, &result);
    if (rc != APR_SUCCESS)
        return rc;
    return APR_SUCCESS;
}

/*
 * Build a connection to the backend server and check it
 */
static apr_status_t test_backend(char *scheme, char *hostname, int port, apr_pool_t *pool)
{
    apr_socket_t *newsock;
    apr_sockaddr_t *epsv_addr;
    apr_status_t rv;

    /* Note that AJP requires a new apr-util (29-07-2006) */
    if (!port)
        port  = (int) apr_uri_port_of_scheme(scheme);
    rv = apr_socket_create(&newsock, APR_INET, SOCK_STREAM, APR_PROTO_TCP, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                    "apr_socket_create failed");
        return rv;
    }
    rv = apr_sockaddr_info_get(&epsv_addr, hostname, APR_INET, port, 0, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                     "apr_sockaddr_info_get failed");
        apr_socket_close(newsock);
        return rv;
    }

    rv = apr_socket_timeout_set(newsock, 10);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, NULL,
                    "apr_socket_timeout_set");
        apr_socket_close(newsock);
        return rv;
    }
    rv = apr_socket_connect(newsock, epsv_addr);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, NULL,
                    "apr_socket_connect failed");
        apr_socket_close(newsock);
        return rv;
    }

    /* XXX: Something is needed for http/https */
    if (strcasecmp(scheme, "ajp") == 0) {
        /* The connection is etablished send a ping and read the answer */
        apr_socket_timeout_set(newsock, 10000);
        rv = pingc_backend(newsock, pool);  
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, NULL,
                        "pingc_backend failed");
            apr_socket_close(newsock);
            return rv;
        }
    }
    apr_socket_close(newsock);
    return APR_SUCCESS;
}

/* read the size of the entry: to create the shared area */
static int getentrysize()
{
    return sizeof(struct proxy_worker_conf);
}
/* copy the worker information in the shared area so the health-checker can extract the part it need */
static apr_status_t add_entry(proxy_worker *worker, const char *balancer_name, int id)
{
    struct proxy_worker_conf *workerconf = NULL;
    apr_status_t rv;

    if (myscore == NULL)
        return APR_ENOSHMAVAIL;
    rv = checkstorage->ap_slotmem_mem(myscore, worker->id, (void *) &workerconf);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if (balancer_name)
        strncpy(workerconf->balancer_name, balancer_name, sizeof(workerconf->balancer_name));
    workerconf->id = worker->id;
    workerconf->retry = worker->retry;
    workerconf->lbfactor = worker->lbfactor;
    if (worker->name)
        strncpy(workerconf->name, worker->name, sizeof(workerconf->name));
    if (worker->scheme)
        strncpy(workerconf->scheme, worker->scheme, sizeof(workerconf->scheme));
    if (worker->hostname)
        strncpy(workerconf->hostname, worker->hostname, sizeof(workerconf->hostname));
    if (worker->route)
        strncpy(workerconf->route, worker->route, sizeof(workerconf->route));
    if (worker->redirect)
        strncpy(workerconf->redirect, worker->redirect, sizeof(workerconf->redirect));
    workerconf->status = worker->status;
    workerconf->port = worker->port;
    workerconf->min = worker->min;
    workerconf->smax = worker->smax;
    workerconf->hmax = worker->hmax;
    workerconf->ttl = worker->ttl;
    workerconf->timeout = worker->timeout;
    workerconf->acquire = worker->acquire;
    workerconf->acquire_set = worker->acquire_set;
    workerconf->recv_buffer_size = worker->recv_buffer_size;
    workerconf->recv_buffer_size_set = worker->recv_buffer_size_set;
    workerconf->io_buffer_size = worker->io_buffer_size;
    workerconf->io_buffer_size_set = worker->io_buffer_size_set;
    workerconf->keepalive = worker->keepalive;
    workerconf->keepalive_set = worker->keepalive_set;
    workerconf->flush_packets = worker->flush_packets;
    workerconf->flush_wait = worker->flush_wait;
    workerconf->health = 0;
    workerconf->used = 1;
    return APR_SUCCESS;
}
/* Remove the entry: TO BE DONE */
static apr_status_t del_entry(int id)
{
    return APR_SUCCESS;
}
/* read the health of the entry: for httpd */
static apr_status_t get_health(int id, int *health)
{
    struct proxy_worker_conf *workerconf = NULL;
    apr_status_t rv;

    if (myscore == NULL)
        return APR_ENOSHMAVAIL;
    rv = checkstorage->ap_slotmem_mem(myscore, id, (void *) &workerconf);
    if (rv != APR_SUCCESS)
        return rv;
    *health = workerconf->health;
    return APR_SUCCESS;
}
/* set the health of the entry: for the health-checker */
static apr_status_t set_health(int id, int value)
{
    struct proxy_worker_conf *workerconf = NULL;
    apr_status_t rv;

    if (myscore == NULL)
        return APR_ENOSHMAVAIL;
    rv = checkstorage->ap_slotmem_mem(myscore, id, (void *) &workerconf);
    if (rv != APR_SUCCESS)
        return rv;
    workerconf->health = value;
    workerconf->time_checked = apr_time_now();
    return APR_SUCCESS;
}
/* read the entry stored in the shared area and build the corresponding worker structure */
static apr_status_t get_entry(int id, proxy_worker **worker, char **balancer_name, apr_pool_t *pool)
{
    struct proxy_worker_conf *workerconf = NULL;
    char *ptr;
    apr_status_t rv;

    if (myscore == NULL)
        return APR_ENOSHMAVAIL;
    rv = checkstorage->ap_slotmem_mem(myscore, id, (void *) &workerconf);
    if (rv != APR_SUCCESS)
        return rv;

    /* allocate the data */
    *worker = apr_pcalloc(pool, sizeof(proxy_worker));
    if (workerconf->balancer_name) {
        *balancer_name = apr_pcalloc(pool, strlen(workerconf->balancer_name) + 1);
        strcpy(*balancer_name, workerconf->balancer_name);
    }
    else
        *balancer_name = NULL;

    /* The httpstatus is handle by httpd don't touch it here */
    (* worker)->id = workerconf->id;
    // XXX: what to do (* worker)->s = workerconf;
    (* worker)->retry = workerconf->retry;
    (* worker)->lbfactor = workerconf->lbfactor;
    if (workerconf->name) {
        ptr = apr_pcalloc(pool, strlen(workerconf->name) + 1);
        strcpy(ptr, workerconf->name);
        (* worker)->name = ptr;
    }
    if (workerconf->scheme) {
        ptr = apr_pcalloc(pool, strlen(workerconf->scheme) + 1);
        strcpy(ptr, workerconf->scheme);
        (* worker)->scheme = ptr;
    }
    if (workerconf->hostname) {
        ptr = apr_pcalloc(pool, strlen(workerconf->hostname) + 1);
        strcpy(ptr, workerconf->hostname);
        (* worker)->hostname = ptr;
    }
    if (workerconf->route) {
        ptr = apr_pcalloc(pool, strlen(workerconf->route) + 1);
        strcpy(ptr, workerconf->route);
        (* worker)->route = ptr;
    }
    if (workerconf->redirect) {
        ptr = apr_pcalloc(pool, strlen(workerconf->redirect) + 1);
        strcpy(ptr, workerconf->redirect);
        (* worker)->redirect = ptr;
    }
    (* worker)->status = workerconf->status;
    (* worker)->port = workerconf->port;
    (* worker)->min = workerconf->min;
    (* worker)->smax = workerconf->smax;
    (* worker)->hmax = workerconf->hmax;
    (* worker)->ttl = workerconf->ttl;
    (* worker)->timeout = workerconf->timeout;
    (* worker)->acquire = workerconf->acquire;
    (* worker)->acquire_set = workerconf->acquire_set;
    (* worker)->recv_buffer_size = workerconf->recv_buffer_size;
    (* worker)->recv_buffer_size_set = workerconf->recv_buffer_size_set;
    (* worker)->io_buffer_size = workerconf->io_buffer_size;
    (* worker)->io_buffer_size_set = workerconf->io_buffer_size_set;
    (* worker)->keepalive = workerconf->keepalive;
    (* worker)->keepalive_set = workerconf->keepalive_set;
    (* worker)->flush_packets = workerconf->flush_packets;
    (* worker)->flush_wait = workerconf->flush_wait;
    return APR_SUCCESS;
}
/* read the entry stored in the shared area */
static apr_status_t get_entryconf(int id, struct proxy_worker_conf **workerconf, char **balancer_name, apr_pool_t *pool)
{
    apr_status_t rv;

    if (myscore == NULL)
        return APR_ENOSHMAVAIL;
    rv = checkstorage->ap_slotmem_mem(myscore, id, (void **) workerconf);
    if (rv != APR_SUCCESS)
        return rv;
    *balancer_name = (*workerconf)->balancer_name;
    return APR_SUCCESS;
}

/* Test the corresponding back-end server */
static apr_status_t check_entryhealth(int id, apr_pool_t *pool) {
    apr_status_t rv;
    struct proxy_worker_conf *workerconf;

    if (myscore == NULL)
        return APR_ENOSHMAVAIL;
    rv = checkstorage->ap_slotmem_mem(myscore, id, (void **) &workerconf);
    if (rv != APR_SUCCESS)
        return rv;
    /* If the error is not initialized to the worker to be removed keep it */
    if (workerconf->used != VALID)
        return APR_SUCCESS;
    rv = test_backend(workerconf->scheme, workerconf->hostname, workerconf->port, pool);
    if (rv != APR_SUCCESS)
        workerconf->health = HEALTH_NO;
    else
        workerconf->health = HEALTH_OK;
    workerconf->time_checked = apr_time_now();
    return rv;
}

/* check the connection pool used by the worker */
static apr_status_t check_poolhealth(proxy_worker *worker, int id, apr_pool_t *pool)
{
    /* XXX: The code is missing */
    return APR_SUCCESS;
}

/* The stuff we provide */
static const health_worker_method worker_storage = {
    &getentrysize,
    &add_entry,
    &del_entry,
    &get_health,
    &set_health,
    &get_entry,
    &get_entryconf,
    &check_entryhealth
};

/* make the module usuable from outside */
const health_worker_method *health_checker_get_storage()
{
    return(&worker_storage);
}

/* handle the slotmem storage */
void health_checker_init_slotmem_storage(const slotmem_storage_method * storage)
{
    checkstorage = storage;
}
const slotmem_storage_method * health_checker_get_slotmem_storage()
{
    return(checkstorage);
}

/* handle the slotmen itself */
void health_checker_init_slotmem(ap_slotmem_t *score)
{
     myscore = score;
}
ap_slotmem_t *health_checker_get_slotmem()
{
    return(myscore);
}
