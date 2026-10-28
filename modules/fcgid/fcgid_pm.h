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

#ifndef FCGID_PM_H
#define FCGID_PM_H
#include "fcgid_global.h"
#include "fcgid_conf.h"

typedef struct {
    char cgipath[FCGID_PATH_MAX];
    char cmdline[FCGID_CMDLINE_MAX];
    apr_ino_t inode;
    dev_t deviceid;
    /* can't reference these via server_rec because some mass vhost
     * module may have copied it for per-request customization
     */
    int vhost_id;
    char server_hostname[32];   /* for logging only; ok to truncate */
    uid_t uid;                  /* For suEXEC */
    gid_t gid;                  /* For suEXEC */
    int userdir;                /* For suEXEC */
    fcgid_cmd_options cmdopts;  /* context-specific configuration, other than
                                 * envvars
                                 */
    fcgid_cmd_env cmdenv;       /* start the command with these env settings */
} fcgid_command;

void procmgr_init_spawn_cmd(fcgid_command * command, request_rec * r,
                            fcgid_cmd_conf *cmd_conf);
apr_status_t procmgr_send_spawn_cmd(fcgid_command * command,
                                    request_rec * r);
apr_status_t procmgr_fetch_cmd(fcgid_command * command,
                              server_rec * main_server);
apr_status_t procmgr_finish_notify(server_rec * main_server);

apr_status_t procmgr_child_init(server_rec * main_server,
                                apr_pool_t * pchild);
apr_status_t procmgr_pre_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp);
apr_status_t procmgr_post_config(server_rec * main_server,
                                 apr_pool_t * pconf);

apr_status_t procmgr_stop_procmgr(void *dummy);
int procmgr_must_exit(void);

#endif
