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

/* health checker routines for proxies */
#define HEALTH_OK      1
#define HEALTH_NO      2
#define HEALTH_UNKNOWN 0

/* Validity of the entry */
#define VALID          1
#define REMOVED        2
#define UNINITIALIZED  0

typedef struct proxy_worker_conf proxy_worker_conf;

/* allow health check method on workers in a non httpd process */
struct health_worker_method {
    /* read the size of the entry: to create the shared area */
    int (* getentrysize)();
    /* copy the worker information in the shared area so the health-checker can extract the part it need */
    apr_status_t (*add_entry)(proxy_worker *worker, char *balancer_name, int id);
    /* XXX : Remove the entry */
    apr_status_t (*del_entry)(int id);
    /* read the health of the entry: for httpd */
    apr_status_t (*get_health)(int id, int *health);
    /* set the health of the entry: for the health-checker */
    apr_status_t (*set_health)(int id, int value);
    /* read the entry stored in the shared area */
    apr_status_t (*get_entry)(proxy_worker **worker, char **balancer_name, apr_pool_t *pool);
    /* read the conf part. */
    apr_status_t (*get_entryconf)(int id, proxy_worker_conf **worker, char **balancer_name, apr_pool_t *pool);
    /* check the back-end server health */
    apr_status_t (*check_entryhealth)(int id, apr_pool_t *pool);
    /* check the pool of sockets (are they still connected) */
    apr_status_t (*check_poolhealth)(int id, proxy_worker *worker, apr_pool_t *pool);
};

/* To store the configuration of the balancers and workers.
 */
struct proxy_balancer_conf {
    char name[32];
    char sticky[32];
    int sticky_force;
    apr_interval_time_t timeout;
    int max_attempts;
    char max_attempts_set;
    char lbmethod_name[32];
};

struct proxy_worker_conf {
    proxy_worker_stat httpstatus;      /* httpd private */
    char balancer_name[32];
    int             id;            /* scoreboard id */
    apr_interval_time_t retry;     /* retry interval */
    int             lbfactor;      /* initial load balancing factor */
    char            name[64];
    char            scheme[6];     /* scheme to use ajp|http|https */
    char            hostname[64];  /* remote backend address */
    char            route[128];    /* balancing route */
    char            redirect[128]; /* temporary balancing redirection route */
    int             status;        /* temporary worker status */
    apr_port_t      port;
    int             min;           /* Desired minimum number of available connections */
    int             smax;          /* Soft maximum on the total number of connections */
    int             hmax;          /* Hard maximum on the total number of connections */
    apr_interval_time_t ttl;       /* maximum amount of time in seconds a connection
                                    * may be available while exceeding the soft limit */
    apr_interval_time_t timeout;   /* connection timeout */
    char                timeout_set;
    apr_interval_time_t acquire; /* acquire timeout when the maximum number of connections is exceeded */
    char                acquire_set;
    apr_size_t          recv_buffer_size;
    char                recv_buffer_size_set;
    apr_size_t          io_buffer_size;
    char                io_buffer_size_set;
    char                keepalive;
    char                keepalive_set;
    int                 is_address_reusable;
    int                 flush_packets;
    int                 flush_wait;  /* poll wait time in microseconds if flush_auto */
    int                 health;
    int                 used;  /* 1 : valid entry 2 : remove 0 : free slot */
    apr_time_t          time_checked;
};

