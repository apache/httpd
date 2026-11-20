/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

#ifndef FCGID_TABLE_H
#define FCGID_TABLE_H
#include <limits.h>
#include "httpd.h"
#include "apr_thread_proc.h"
#include "fcgid_global.h"
#include "fcgid_conf.h"

/* Increase it if necessary */
#define FCGID_MAX_APPLICATION (1024)

/* FCGID_MAX_APPLICATION + 4 list headers */
#define FCGID_PROC_TABLE_SIZE (FCGID_MAX_APPLICATION+4)

/*
    nNextIndex is for making a node list, there are four kind of list:
    1) free list: no process associate to this node
    2) busy list: a process is associated, and it's handling request
    3) idle list: a process is associated, and it's waiting request
    4) error list: a process is associated, and killing the process now
*/
typedef struct {
    /* only one of next_index or node_type is used, depending on context */
    int next_index;             /* the next array index in the list */
    int node_type;              /* the type of this node, used in fcgid_status_hook() only */
    apr_pool_t *proc_pool;      /* pool for process */
    apr_proc_t proc_id;         /* the process id */
    char executable_path[FCGID_PATH_MAX]; /* executable file path */
    char socket_path[FCGID_PATH_MAX]; /* cgi application socket path */
    apr_ino_t inode;            /* cgi file inode */
    apr_dev_t deviceid;         /* cgi file device id */
    char cmdline[FCGID_CMDLINE_MAX]; /* entire command line */
    gid_t gid;                  /* for suEXEC */
    uid_t uid;                  /* for suEXEC */
    int vhost_id;               /* the vhost to which this process belongs (the server_rec
                                 * addr fails with some mass-vhost mods which allocate
                                 * them per-request) */
    apr_time_t start_time;      /* the time of this process create */
    apr_time_t last_active_time;    /* the time this process last active */
    int requests_handled;       /* number of requests process has handled */
    char diewhy;                /* why it die */
    fcgid_cmd_options cmdopts;  /* context-specific configuration */
} fcgid_procnode;

/* Macros for diewhy */
#define FCGID_DIE_KILLSELF  0
#define FCGID_DIE_IDLE_TIMEOUT 1
#define FCGID_DIE_LIFETIME_EXPIRED 2
#define FCGID_DIE_BUSY_TIMEOUT 3
#define FCGID_DIE_CONNECT_ERROR 4
#define FCGID_DIE_COMM_ERROR 5
#define FCGID_DIE_SHUTDOWN 6

typedef struct {
    int must_exit;              /* All processes using this share memory must exit */
} fcgid_global_share;

typedef struct {
    fcgid_global_share global;
    fcgid_procnode procnode_array[FCGID_PROC_TABLE_SIZE];
} fcgid_share;

apr_status_t proctable_child_init(server_rec * main_server,
                                  apr_pool_t * pchild);
apr_status_t proctable_pre_config(apr_pool_t *p, apr_pool_t *plog,
                                  apr_pool_t *ptemp);
apr_status_t proctable_post_config(server_rec * main_server,
                                   apr_pool_t * pconf);

fcgid_procnode *proctable_get_free_list(void);
fcgid_procnode *proctable_get_busy_list(void);
fcgid_procnode *proctable_get_idle_list(void);
fcgid_procnode *proctable_get_error_list(void);
fcgid_procnode *proctable_get_table_array(void);
size_t proctable_get_table_size(void);
fcgid_global_share *proctable_get_globalshare(void);

void proctable_pm_lock(server_rec *s);
void proctable_pm_unlock(server_rec *s);
void proctable_lock(request_rec *r);
void proctable_unlock(request_rec *r);

/* Just for debug */
void proctable_print_debug_info(server_rec * main_server);

#endif
