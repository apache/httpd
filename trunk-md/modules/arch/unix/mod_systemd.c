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
 * 
 */

#include <stdint.h>
#include <ap_config.h>
#include "ap_mpm.h"
#include <http_core.h>
#include <httpd.h>
#include <http_log.h>
#include <apr_version.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include "unixd.h"
#include "scoreboard.h"
#include "mpm_common.h"

#include "systemd/sd-daemon.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

static int shutdown_timer = 0;
static int shutdown_counter = 0;
static unsigned long bytes_served;
static pid_t mainpid;

static int systemd_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp)
{
    sd_notify(0,
              "RELOADING=1\n"
              "STATUS=Reading configuration...\n");
    ap_extended_status = 1;
    return OK;
}

static int systemd_pre_mpm(apr_pool_t *p, ap_scoreboard_e sb_type)
{
    int rv;

    mainpid = getpid();

    rv = sd_notifyf(0, "READY=1\n"
                    "STATUS=Processing requests...\n"
                    "MAINPID=%" APR_PID_T_FMT, mainpid);
    if (rv < 0) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p, APLOGNO(02395)
                     "sd_notifyf returned an error %d", rv);
    }

    return OK;
}

static int systemd_monitor(apr_pool_t *p, server_rec *s)
{
    ap_sload_t sload;
    apr_interval_time_t up_time;
    char bps[5];
    int rv;

    if (!ap_extended_status) {
        /* Nothing useful to report with ExtendedStatus disabled. */
        return DECLINED;
    }
    
    ap_get_sload(&sload);
    /* up_time in seconds */
    up_time = (apr_uint32_t) apr_time_sec(apr_time_now() -
                               ap_scoreboard_image->global->restart_time);

    apr_strfsize((unsigned long)((float) (sload.bytes_served)
                                 / (float) up_time), bps);

    rv = sd_notifyf(0, "READY=1\n"
                    "STATUS=Total requests: %lu; Idle/Busy workers %d/%d;"
                    "Requests/sec: %.3g; Bytes served/sec: %sB/sec\n",
                    sload.access_count, sload.idle, sload.busy,
                    ((float) sload.access_count) / (float) up_time, bps);

    if (rv < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02396)
                     "sd_notifyf returned an error %d", rv);
    }

    /* Shutdown httpd when nothing is sent for shutdown_timer seconds. */
    if (sload.bytes_served == bytes_served) {
        /* mpm_common.c: INTERVAL_OF_WRITABLE_PROBES is 10 */
        shutdown_counter += 10;
        if (shutdown_timer > 0 && shutdown_counter >= shutdown_timer) {
            rv = sd_notifyf(0, "READY=1\n"
                            "STATUS=Stopped as result of IdleShutdown "
                            "timeout.");
            if (rv < 0) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02804)
                            "sd_notifyf returned an error %d", rv);
            }
            kill(mainpid, AP_SIG_GRACEFUL);
        }
    }
    else {
        shutdown_counter = 0;
    }

    bytes_served = sload.bytes_served;

    return DECLINED;
}

static void systemd_register_hooks(apr_pool_t *p)
{
    /* Enable ap_extended_status. */
    ap_hook_pre_config(systemd_pre_config, NULL, NULL, APR_HOOK_LAST);
    /* We know the PID in this hook ... */
    ap_hook_pre_mpm(systemd_pre_mpm, NULL, NULL, APR_HOOK_LAST);
    /* Used to update httpd's status line using sd_notifyf */
    ap_hook_monitor(systemd_monitor, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *set_shutdown_timer(cmd_parms *cmd, void *dummy,
                                      const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    shutdown_timer = atoi(arg);
    return NULL;
}

static const command_rec systemd_cmds[] =
{
AP_INIT_TAKE1("IdleShutdown", set_shutdown_timer, NULL, RSRC_CONF,
     "Number of seconds in idle-state after which httpd is shutdown"),
    {NULL}
};

AP_DECLARE_MODULE(systemd) = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    systemd_cmds,
    systemd_register_hooks,
};
