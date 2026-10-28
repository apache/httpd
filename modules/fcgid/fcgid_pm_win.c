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

#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "apr_queue.h"
#include "fcgid_pm.h"
#include "fcgid_pm_main.h"
#include "fcgid_conf.h"
#include "fcgid_spawn_ctl.h"
#define FCGID_MSGQUEUE_SIZE 10

static apr_thread_t *g_thread = NULL;
static apr_queue_t *g_msgqueue = NULL;
static apr_queue_t *g_notifyqueue = NULL;
static apr_thread_mutex_t *g_reqlock = NULL;
static apr_thread_t *g_wakeup_thread = NULL;
static int g_must_exit = 0;
static int g_wakeup_timeout = 0;

static void *APR_THREAD_FUNC wakeup_thread(apr_thread_t * thd, void *data)
{
    while (!g_must_exit) {
        /* Wake up every second to check g_must_exit flag */
        int i;

        for (i = 0; i < g_wakeup_timeout; i++) {
            if (g_must_exit)
                break;
            apr_sleep(apr_time_from_sec(1));
        }

        /* Send a wake up message to procmgr_fetch_cmd() */
        if (!g_must_exit && g_msgqueue)
            apr_queue_trypush(g_msgqueue, NULL);
    }
    return NULL;
}

static void *APR_THREAD_FUNC worker_thread(apr_thread_t * thd, void *data)
{
    server_rec *main_server = data;

    pm_main(main_server, main_server->process->pconf);
    return NULL;
}

apr_status_t procmgr_pre_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp)
{
    return APR_SUCCESS;
}

apr_status_t
procmgr_post_config(server_rec * main_server, apr_pool_t * pconf)
{
    apr_status_t rv;
    fcgid_server_conf *sconf = ap_get_module_config(main_server->module_config,
                                                    &fcgid_module);

    /* Initialize spawn controler */
    spawn_control_init(main_server, pconf);

    /* Create a message queues */
    if ((rv = apr_queue_create(&g_msgqueue, FCGID_MSGQUEUE_SIZE,
                               pconf)) != APR_SUCCESS
        || (rv = apr_queue_create(&g_notifyqueue, FCGID_MSGQUEUE_SIZE,
                                  pconf)) != APR_SUCCESS) {
        /* Fatal error */
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: can't create message queue");
        exit(1);
    }

    /* Create request lock */
    if ((rv = apr_thread_mutex_create(&g_reqlock,
                                      APR_THREAD_MUTEX_DEFAULT,
                                      pconf)) != APR_SUCCESS) {
        /* Fatal error */
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: Can't create request mutex");
        exit(1);
    }

    /* Calculate procmgr_fetch_cmd wake up interval */
    g_wakeup_timeout = min(sconf->error_scan_interval,
                           sconf->busy_scan_interval);
    g_wakeup_timeout = min(sconf->idle_scan_interval,
                           g_wakeup_timeout);
    if (g_wakeup_timeout == 0)
        g_wakeup_timeout = 1;   /* Make it reasonable */

    /* Create process manager worker thread */
    if ((rv = apr_thread_create(&g_thread, NULL, worker_thread,
                                main_server, pconf)) != APR_SUCCESS) {
        /* It's a fatal error */
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: can't create process manager thread");
        exit(1);
    }

    /* Create wake up thread */
    /* XXX If there was a function such like apr_queue_pop_timedwait(),
       then I don't need such an ugly thread to do the wake up job */
    if ((rv = apr_thread_create(&g_wakeup_thread, NULL, wakeup_thread,
                                NULL, pconf)) != APR_SUCCESS) {
        /* It's a fatal error */
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: can't create wake up thread");
        exit(1);
    }

    apr_pool_cleanup_register(pconf, main_server, procmgr_stop_procmgr,
                              apr_pool_cleanup_null);

    return APR_SUCCESS;
}

void procmgr_init_spawn_cmd(fcgid_command * command, request_rec * r,
                            fcgid_cmd_conf *cmd_conf)
{
    fcgid_server_conf *sconf =
        ap_get_module_config(r->server->module_config, &fcgid_module);

    /* no truncation should ever occur */
    AP_DEBUG_ASSERT(sizeof command->cgipath > strlen(cmd_conf->cgipath));
    apr_cpystrn(command->cgipath, cmd_conf->cgipath, sizeof command->cgipath);
    AP_DEBUG_ASSERT(sizeof command->cmdline > strlen(cmd_conf->cmdline));
    apr_cpystrn(command->cmdline, cmd_conf->cmdline, sizeof command->cmdline);

    command->inode = (apr_ino_t) -1;
    command->deviceid = (dev_t) -1;
    command->uid = (uid_t) - 1;
    command->gid = (gid_t) - 1;
    command->userdir = 0;
    command->vhost_id = sconf->vhost_id;
    if (r->server->server_hostname) {
        apr_cpystrn(command->server_hostname, r->server->server_hostname,
                    sizeof command->server_hostname);
    }
    else {
        command->server_hostname[0] = '\0';
    }

    get_cmd_options(r, command->cgipath, &command->cmdopts, &command->cmdenv);
}

apr_status_t procmgr_send_spawn_cmd(fcgid_command * command,
                                    request_rec * r)
{
    if (g_thread && g_msgqueue && !g_must_exit
        && g_reqlock && g_notifyqueue) {
        apr_status_t rv;

        /*
           Prepare the message send to another thread
           destroy the message if I can't push to message
         */
        fcgid_command *postcmd =
            (fcgid_command *) malloc(sizeof(fcgid_command));
        if (!postcmd)
            return APR_ENOMEM;
        memcpy(postcmd, command, sizeof(*command));

        /* Get request lock first */
        if ((rv = apr_thread_mutex_lock(g_reqlock)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, rv, r,
                          "mod_fcgid: can't get request lock");
            return rv;
        }

        /* Try push the message */
        if ((rv = apr_queue_push(g_msgqueue, postcmd)) != APR_SUCCESS) {
            apr_thread_mutex_unlock(g_reqlock);
            free(postcmd);
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, rv, r,
                          "mod_fcgid: can't push request message");
            return rv;
        } else {
            /* Wait the respond from process manager */
            char *notifybyte = NULL;

            if ((rv =
                 apr_queue_pop(g_notifyqueue,
                               (void **)&notifybyte)) != APR_SUCCESS) {
                apr_thread_mutex_unlock(g_reqlock);
                ap_log_rerror(APLOG_MARK, APLOG_EMERG, rv, r,
                              "mod_fcgid: can't pop notify message");
                return rv;
            }
        }

        /* Release the lock now */
        if ((rv = apr_thread_mutex_unlock(g_reqlock)) != APR_SUCCESS) {
            /* It's a fatal error */
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, rv, r,
                          "mod_fcgid: can't release request lock");
            exit(1);
        }
    }

    return APR_SUCCESS;
}

apr_status_t procmgr_finish_notify(server_rec * main_server)
{
    apr_status_t rv;
    char *notify = NULL;

    if ((rv = apr_queue_push(g_notifyqueue, notify)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: can't send spawn notify");
    }

    return rv;
}

apr_status_t procmgr_fetch_cmd(fcgid_command * command,
                              server_rec * main_server)
{
    fcgid_command *peakcmd = NULL;

    if (!g_must_exit && g_msgqueue) {
        if (apr_queue_pop(g_msgqueue, (void **)&peakcmd) == APR_SUCCESS) {
            if (!peakcmd)
                return APR_TIMEUP;  /* This a wake up message */
            else {
                /* Copy the command, and then free the memory */
                memcpy(command, peakcmd, sizeof(*peakcmd));
                free(peakcmd);

                return APR_SUCCESS;
            }
        }
    }

    return APR_TIMEUP;
}

apr_status_t
procmgr_child_init(server_rec * main_server, apr_pool_t * pchild)
{
    /* Noop on windows, but used by unix */

    return APR_SUCCESS;
}

int procmgr_must_exit()
{
    return g_must_exit;
}

apr_status_t procmgr_stop_procmgr(void *server)
{
    apr_status_t status;
    fcgid_server_conf *conf;

    /* Tell the world to die */
    g_must_exit = 1;
    if (g_msgqueue)
        apr_queue_push(g_msgqueue, NULL);

    /* Wait */
    if (g_thread && apr_thread_join(&status, g_thread) == APR_SUCCESS) {
        /* Free the memory left in queue */
        fcgid_command *peakcmd = NULL;

        while (apr_queue_trypop(g_msgqueue, (void **)&peakcmd) == APR_SUCCESS) {
            if (peakcmd)
                free(peakcmd);
        }
    }

    /* Clean up the Job object if present */
    conf = ap_get_module_config(((server_rec*)server)->module_config,
                                &fcgid_module);

    if (conf->hJobObjectForAutoCleanup != NULL) {
        CloseHandle(conf->hJobObjectForAutoCleanup);
    }

    if (g_wakeup_thread)
        return apr_thread_join(&status, g_wakeup_thread);

    return APR_SUCCESS;
}
