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

/* For DEFAULT_PATH */
#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "apr_strings.h"

#include "fcgid_pm.h"
#include "fcgid_pm_main.h"
#include "fcgid_conf.h"
#include "fcgid_proctbl.h"
#include "fcgid_proc.h"
#include "fcgid_spawn_ctl.h"

#define HAS_GRACEFUL_KILL "Gracefulkill"

static void
link_node_to_list(server_rec * main_server,
                  fcgid_procnode * header,
                  fcgid_procnode * node, fcgid_procnode * table_array)
{
    proctable_pm_lock(main_server);
    node->next_index = header->next_index;
    header->next_index = node - table_array;
    proctable_pm_unlock(main_server);
}

static apr_time_t lastidlescan = 0;
static void scan_idlelist(server_rec * main_server)
{
    /*
       Scan the idle list
       1. move all processes idle timeout to error list
       2. move all processes lifetime expired to error list
     */
    fcgid_procnode *previous_node, *current_node, *next_node;
    fcgid_procnode *error_list_header;
    fcgid_procnode *proc_table;
    apr_time_t last_active_time, start_time;
    apr_time_t now = apr_time_now();
    int idle_timeout, proc_lifetime;
    fcgid_server_conf *sconf =
        ap_get_module_config(main_server->module_config,
                             &fcgid_module);

    /* Should I check the idle list now? */
    if (procmgr_must_exit()
        || apr_time_sec(now) - apr_time_sec(lastidlescan) <=
        sconf->idle_scan_interval)
        return;
    lastidlescan = now;

    /* Check the list */
    proc_table = proctable_get_table_array();
    previous_node = proctable_get_idle_list();
    error_list_header = proctable_get_error_list();

    proctable_pm_lock(main_server);
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];
        last_active_time = current_node->last_active_time;
        start_time = current_node->start_time;
        idle_timeout = current_node->cmdopts.idle_timeout;
        proc_lifetime = current_node->cmdopts.proc_lifetime;
        if (((idle_timeout &&
              (apr_time_sec(now) - apr_time_sec(last_active_time) >
               idle_timeout))
             || (proc_lifetime
                 && (apr_time_sec(now) - apr_time_sec(start_time) >
                     proc_lifetime)))
            && is_kill_allowed(main_server, current_node)) {
            /* Set die reason for log */
            if (idle_timeout &&
                (apr_time_sec(now) - apr_time_sec(last_active_time) >
                 idle_timeout))
                current_node->diewhy = FCGID_DIE_IDLE_TIMEOUT;
            else if (proc_lifetime &&
                     (apr_time_sec(now) - apr_time_sec(start_time) >
                      proc_lifetime))
                current_node->diewhy = FCGID_DIE_LIFETIME_EXPIRED;

            /* Unlink from idle list */
            previous_node->next_index = current_node->next_index;

            /* Link to error list */
            current_node->next_index = error_list_header->next_index;
            error_list_header->next_index = current_node - proc_table;
        }
        else
            previous_node = current_node;

        current_node = next_node;
    }
    proctable_pm_unlock(main_server);
}

static apr_time_t lastbusyscan = 0;
static void scan_busylist(server_rec * main_server)
{
    fcgid_procnode *current_node;
    fcgid_procnode *proc_table;
    apr_time_t last_active_time;
    apr_time_t now = apr_time_now();
    fcgid_server_conf *sconf =
        ap_get_module_config(main_server->module_config,
                             &fcgid_module);

    /* Should I check the busy list? */
    if (procmgr_must_exit()
        || apr_time_sec(now) - apr_time_sec(lastbusyscan) <=
        sconf->busy_scan_interval)
        return;
    lastbusyscan = now;

    /* Check busy list */
    proc_table = proctable_get_table_array();

    proctable_pm_lock(main_server);
    current_node = &proc_table[proctable_get_busy_list()->next_index];
    while (current_node != proc_table) {
        last_active_time = current_node->last_active_time;
        if (apr_time_sec(now) - apr_time_sec(last_active_time) >
            (current_node->cmdopts.busy_timeout)) {
            /* Protocol:
               1. diewhy init with FCGID_DIE_KILLSELF
               2. Process manager set diewhy to FCGID_DIE_BUSY_TIMEOUT and gracefully kill process while busy timeout
               3. Process manager forced kill process while busy timeout and diewhy is FCGID_DIE_BUSY_TIMEOUT
             */
            if (current_node->diewhy == FCGID_DIE_BUSY_TIMEOUT)
                proc_kill_force(current_node, main_server);
            else {
                current_node->diewhy = FCGID_DIE_BUSY_TIMEOUT;
                proc_kill_gracefully(current_node, main_server);
            }
        }
        current_node = &proc_table[current_node->next_index];
    }
    proctable_pm_unlock(main_server);
}

static apr_time_t lastzombiescan = 0;
static void scan_idlelist_zombie(server_rec * main_server)
{
    /*
       Scan the idle list
       1. pick up the node for scan(now-last_activ>g_zombie_scan_interval)
       2. check if it's zombie process
       3. if it's zombie process, wait() and return to free list
       4. return to idle list if it's not zombie process
     */
    pid_t thepid;
    fcgid_procnode *previous_node, *current_node, *next_node;
    fcgid_procnode *check_list_header;
    fcgid_procnode *proc_table;
    apr_time_t last_active_time;
    apr_time_t now = apr_time_now();
    fcgid_procnode temp_header;
    fcgid_server_conf *sconf =
        ap_get_module_config(main_server->module_config,
                             &fcgid_module);

    memset(&temp_header, 0, sizeof(temp_header));

    /* Should I check zombie processes in idle list now? */
    if (procmgr_must_exit()
        || apr_time_sec(now) - apr_time_sec(lastzombiescan) <=
        sconf->zombie_scan_interval)
        return;
    lastzombiescan = now;

    /*
       Check the list
     */
    proc_table = proctable_get_table_array();
    previous_node = proctable_get_idle_list();
    check_list_header = &temp_header;

    proctable_pm_lock(main_server);
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];

        /* Is it time for zombie check? */
        last_active_time = current_node->last_active_time;
        if (apr_time_sec(now) - apr_time_sec(last_active_time) >
            sconf->zombie_scan_interval) {
            /* Unlink from idle list */
            previous_node->next_index = current_node->next_index;

            /* Link to check list */
            current_node->next_index = check_list_header->next_index;
            check_list_header->next_index = current_node - proc_table;
        }
        else
            previous_node = current_node;

        current_node = next_node;
    }
    proctable_pm_unlock(main_server);

    /*
       Now check every node in check list
       1) If it's zombie process, wait() and return to free list
       2) If it's not zombie process, link it to the tail of idle list
     */
    previous_node = check_list_header;
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];

        /* Is it zombie process? */
        thepid = current_node->proc_id.pid;
        if (proc_wait_process(main_server, current_node) == APR_CHILD_DONE) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
                         "mod_fcgid: cleanup zombie process %"
                         APR_PID_T_FMT, thepid);

            /* Unlink from check list */
            previous_node->next_index = current_node->next_index;

            /* Link to free list */
            link_node_to_list(main_server, proctable_get_free_list(),
                              current_node, proc_table);
        }
        else
            previous_node = current_node;

        current_node = next_node;
    }

    /*
       Now link the check list back to the tail of idle list
     */
    if (check_list_header->next_index) {
        proctable_pm_lock(main_server);
        previous_node = proctable_get_idle_list();
        current_node = &proc_table[previous_node->next_index];

        /* Find the tail of idle list */
        while (current_node != proc_table) {
            previous_node = current_node;
            current_node = &proc_table[current_node->next_index];
        }

        /* Link check list to the tail of idle list */
        previous_node->next_index = check_list_header->next_index;
        proctable_pm_unlock(main_server);
    }
}

static apr_time_t lasterrorscan = 0;
static void scan_errorlist(server_rec * main_server)
{
    /*
       kill() and wait() every node in error list
       put them back to free list after that
     */
    void *dummy;
    fcgid_procnode *previous_node, *current_node, *next_node;
    apr_time_t now = apr_time_now();
    fcgid_procnode *error_list_header = proctable_get_error_list();
    fcgid_procnode *free_list_header = proctable_get_free_list();
    fcgid_procnode *proc_table = proctable_get_table_array();
    fcgid_procnode temp_error_header;
    fcgid_server_conf *sconf =
        ap_get_module_config(main_server->module_config,
                             &fcgid_module);
    int graceful_terminations = 0;

    /* Should I check the busy list? */
    if (procmgr_must_exit()
        || apr_time_sec(now) - apr_time_sec(lasterrorscan) <=
        sconf->error_scan_interval)
        return;
    lasterrorscan = now;

    /* Try wait dead processes, restore to free list */
    /* Note: I can't keep the lock during the scan */
    proctable_pm_lock(main_server);
    temp_error_header.next_index = error_list_header->next_index;
    error_list_header->next_index = 0;
    proctable_pm_unlock(main_server);

    previous_node = &temp_error_header;
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];

        if (proc_wait_process(main_server, current_node) != APR_CHILD_NOTDONE) {
            /* Unlink from error list */
            previous_node->next_index = current_node->next_index;

            /* Link to free list */
            current_node->next_index = free_list_header->next_index;
            free_list_header->next_index = current_node - proc_table;
        }
        else
            previous_node = current_node;

        current_node = next_node;
    }

    /* Kill the left processes, wait() them in the next round */
    for (current_node = &proc_table[temp_error_header.next_index];
         current_node != proc_table;
         current_node = &proc_table[current_node->next_index]) {
        /* Try gracefully first */
        dummy = NULL;
        apr_pool_userdata_get(&dummy, HAS_GRACEFUL_KILL,
                              current_node->proc_pool);
        if (!dummy) {
            proc_kill_gracefully(current_node, main_server);
            ++graceful_terminations;
            apr_pool_userdata_set("set", HAS_GRACEFUL_KILL,
                                  apr_pool_cleanup_null,
                                  current_node->proc_pool);
        }
        else {
#ifndef WIN32
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
#else
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
#endif
                         "mod_fcgid: process %" APR_PID_T_FMT
                         " graceful kill fail, sending SIGKILL",
                         current_node->proc_id.pid);
            proc_kill_force(current_node, main_server);
        }
    }

    /* Link the temp error list back */
    proctable_pm_lock(main_server);
    /* Find the tail of error list */
    previous_node = error_list_header;
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        previous_node = current_node;
        current_node = &proc_table[current_node->next_index];
    }
    previous_node->next_index = temp_error_header.next_index;
    proctable_pm_unlock(main_server);

    if (graceful_terminations) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, main_server,
                     "mod_fcgid: gracefully terminated %d processes",
                     graceful_terminations);
    }
}

typedef enum action_t {DO_NOTHING, KILL_GRACEFULLY, KILL_FORCEFULLY,
                       HARD_WAIT} action_t;

static int reclaim_one_pid(server_rec *main_server, fcgid_procnode *proc,
                           action_t action)
{
    int exitcode;
    apr_exit_why_e exitwhy;
    apr_wait_how_e wait_how = action == HARD_WAIT ? APR_WAIT : APR_NOWAIT;

    if (apr_proc_wait(&proc->proc_id, &exitcode, &exitwhy,
                      wait_how) != APR_CHILD_NOTDONE) {
        proc->diewhy = FCGID_DIE_SHUTDOWN;
        proc_print_exit_info(proc, exitcode, exitwhy,
                             main_server);
        proc->proc_pool = NULL;
        return 1;
    }

    switch(action) {
    case DO_NOTHING:
    case HARD_WAIT:
        break;

    case KILL_GRACEFULLY:
        proc_kill_gracefully(proc, main_server);
        break;

    case KILL_FORCEFULLY:
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server,
                     "FastCGI process %" APR_PID_T_FMT
                     " still did not exit, "
                     "terminating forcefully",
                     proc->proc_id.pid);
        proc_kill_force(proc, main_server);
        break;
    }

    return 0;
}

static void kill_all_subprocess(server_rec *main_server)
{
    apr_time_t waittime = 1024 * 16;
    size_t i, table_size = proctable_get_table_size();
    int not_dead_yet;
    int cur_action, next_action;
    apr_time_t starttime = apr_time_now();
    struct {
        action_t action;
        apr_time_t action_time;
    } action_table[] = {
        {DO_NOTHING,      0}, /* dummy entry for iterations where
                              * we reap children but take no action
                              * against stragglers
                              */
        {KILL_GRACEFULLY, apr_time_from_sec(0)},
        {KILL_GRACEFULLY, apr_time_from_sec(1)},
        {KILL_FORCEFULLY, apr_time_from_sec(8)},
        {HARD_WAIT,       apr_time_from_sec(8)}
    };
    fcgid_procnode *proc_table = proctable_get_table_array();

    next_action = 1;
    do {
        apr_sleep(waittime);
        /* don't let waittime get longer than 1 second; otherwise, we don't
         * react quickly to the last child exiting, and taking action can
         * be delayed
         */
        waittime = waittime * 4;
        if (waittime > apr_time_from_sec(1)) {
            waittime = apr_time_from_sec(1);
        }

        /* see what action to take, if any */
        if (action_table[next_action].action_time <= apr_time_now() - starttime) {
            cur_action = next_action;
            ++next_action;
        }
        else {
            cur_action = 0; /* index of DO_NOTHING entry */
        }

        /* now see who is done */
        not_dead_yet = 0;
        for (i = 0; i < table_size; i++) {
            if (!proc_table[i].proc_pool) {
                continue; /* unused */
            }

            if (!reclaim_one_pid(main_server, &proc_table[i],
                                 action_table[cur_action].action)) {
                ++not_dead_yet;
            }
        }

    } while (not_dead_yet &&
             action_table[cur_action].action != HARD_WAIT);
}

/* This should be proposed as a stand-alone improvement to the httpd module,
 * either in the arch/ platform-specific modules or util_script.c from whence
 * it came.
 */
static void default_proc_env(apr_table_t * e)
{
    const char *env_temp;

    if (!(env_temp = getenv("PATH"))) {
        env_temp = DEFAULT_PATH;
    }
    apr_table_addn(e, "PATH", env_temp);

#ifdef WIN32
    if ((env_temp = getenv("SYSTEMROOT"))) {
        apr_table_addn(e, "SYSTEMROOT", env_temp);
    }
    if ((env_temp = getenv("COMSPEC"))) {
        apr_table_addn(e, "COMSPEC", env_temp);
    }
    if ((env_temp = getenv("PATHEXT"))) {
        apr_table_addn(e, "PATHEXT", env_temp);
    }
    if ((env_temp = getenv("WINDIR"))) {
        apr_table_addn(e, "WINDIR", env_temp);
    }
#elif defined(OS2)
    if ((env_temp = getenv("COMSPEC")) != NULL) {
        apr_table_addn(e, "COMSPEC", env_temp);
    }
    if ((env_temp = getenv("ETC")) != NULL) {
        apr_table_addn(e, "ETC", env_temp);
    }
    if ((env_temp = getenv("DPATH")) != NULL) {
        apr_table_addn(e, "DPATH", env_temp);
    }
    if ((env_temp = getenv("PERLLIB_PREFIX")) != NULL) {
        apr_table_addn(e, "PERLLIB_PREFIX", env_temp);
    }
#elif defined(BEOS)
    if ((env_temp = getenv("LIBRARY_PATH")) != NULL) {
        apr_table_addn(e, "LIBRARY_PATH", env_temp);
    }
#elif defined (AIX)
    if ((env_temp = getenv("LIBPATH"))) {
        apr_table_addn(e, "LIBPATH", env_temp);
    }
#else
/* DARWIN, HPUX vary depending on circumstance */
#if defined (DARWIN)
    if ((env_temp = getenv("DYLD_LIBRARY_PATH"))) {
        apr_table_addn(e, "DYLD_LIBRARY_PATH", env_temp);
    }
#elif defined (HPUX11) || defined (HPUX10) || defined (HPUX)
    if ((env_temp = getenv("SHLIB_PATH"))) {
        apr_table_addn(e, "SHLIB_PATH", env_temp);
    }
#endif
    if ((env_temp = getenv("LD_LIBRARY_PATH"))) {
        apr_table_addn(e, "LD_LIBRARY_PATH", env_temp);
    }
#endif
}

/* End of common to util_script.c */

static void
fastcgi_spawn(fcgid_command * command, server_rec * main_server,
              apr_pool_t * configpool)
{
    fcgid_procnode *free_list_header, *proctable_array,
        *procnode, *idle_list_header;
    fcgid_proc_info procinfo;
    apr_status_t rv;
    int i;

    free_list_header = proctable_get_free_list();
    idle_list_header = proctable_get_idle_list();
    proctable_array = proctable_get_table_array();

    /* Apply a slot from free list */
    proctable_pm_lock(main_server);
    if (free_list_header->next_index == 0) {
        proctable_pm_unlock(main_server);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
                     "mod_fcgid: too much processes, please increase FCGID_MAX_APPLICATION");
        return;
    }
    procnode = &proctable_array[free_list_header->next_index];
    free_list_header->next_index = procnode->next_index;
    procnode->next_index = 0;
    proctable_pm_unlock(main_server);

    /* Prepare to spawn */
    procnode->deviceid = command->deviceid;
    procnode->inode = command->inode;

    /* no truncation should ever occur */
    AP_DEBUG_ASSERT(sizeof procnode->cmdline > strlen(command->cmdline));
    apr_cpystrn(procnode->cmdline, command->cmdline, sizeof procnode->cmdline);

    procnode->vhost_id = command->vhost_id;
    procnode->uid = command->uid;
    procnode->gid = command->gid;
    procnode->start_time = procnode->last_active_time = apr_time_now();
    procnode->requests_handled = 0;
    procnode->diewhy = FCGID_DIE_KILLSELF;
    procnode->proc_pool = NULL;
    procnode->cmdopts = command->cmdopts;

    procinfo.cgipath = command->cgipath;
    procinfo.configpool = configpool;
    procinfo.main_server = main_server;
    procinfo.uid = command->uid;
    procinfo.gid = command->gid;
    procinfo.userdir = command->userdir;
    if ((rv =
         apr_pool_create(&procnode->proc_pool, configpool)) != APR_SUCCESS
        || (procinfo.proc_environ =
            apr_table_make(procnode->proc_pool, INITENV_CNT)) == NULL) {
        /* Link the node back to free list in this case */
        if (procnode->proc_pool)
            apr_pool_destroy(procnode->proc_pool);
        link_node_to_list(main_server, free_list_header, procnode,
                          proctable_array);

        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, main_server,
                     "mod_fcgid: can't create pool for process");
        return;
    }
    /* Set up longer, system defaults before falling into parsing fixed-limit
     * request-by-request variables, so if any are overriden, they preempt
     * any system default assumptions
     */
    default_proc_env(procinfo.proc_environ);
    for (i = 0; i < INITENV_CNT; i++) {
        if (command->cmdenv.initenv_key[i][0] == '\0')
            break;
        apr_table_set(procinfo.proc_environ, command->cmdenv.initenv_key[i],
                      command->cmdenv.initenv_val[i]);
    }

    /* Spawn the process now */
    /* XXX Spawn uses wrapper_cmdline, but log uses cgipath ? */
    if ((rv =
         proc_spawn_process(command->cmdline, &procinfo,
                            procnode)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, main_server,
                     "mod_fcgid: spawn process %s error", command->cgipath);

        apr_pool_destroy(procnode->proc_pool);
        link_node_to_list(main_server, free_list_header,
                          procnode, proctable_array);
        return;
    }
    else {
        /* The job done */
        link_node_to_list(main_server, idle_list_header,
                          procnode, proctable_array);
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, main_server,
                     "mod_fcgid: server %s:%s(%" APR_PID_T_FMT ") started",
                     command->server_hostname[0] ?
                         command->server_hostname : "(unknown)",
                     command->cgipath,
                     procnode->proc_id.pid);
        register_spawn(main_server, procnode);
    }
}

apr_status_t pm_main(server_rec * main_server, apr_pool_t * configpool)
{
    fcgid_command command;

    while (1) {
        if (procmgr_must_exit())
            break;

        /* Wait for command */
        if (procmgr_fetch_cmd(&command, main_server) == APR_SUCCESS) {
            if (is_spawn_allowed(main_server, &command))
                fastcgi_spawn(&command, main_server, configpool);

            procmgr_finish_notify(main_server);
        }

        /* Move matched node to error list */
        scan_idlelist_zombie(main_server);
        scan_idlelist(main_server);
        scan_busylist(main_server);

        /* Kill() and wait() nodes in error list */
        scan_errorlist(main_server);
    }

    /* Stop all processes */
    kill_all_subprocess(main_server);

    return APR_SUCCESS;
}
