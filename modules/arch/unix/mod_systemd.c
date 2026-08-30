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
#include <time.h>
#include <ap_config.h>
#include "ap_mpm.h"
#include "ap_listen.h"
#include <http_core.h>
#include <httpd.h>
#include <http_log.h>
#include <apr_version.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include "unixd.h"
#include "scoreboard.h"
#include "mpm_common.h"

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "systemd/sd-daemon.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Microseconds on the clock systemd compares RELOADING=1 against, or
 * zero if it cannot be read. */
static apr_uint64_t monotonic_usec(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (apr_uint64_t)ts.tv_sec * APR_USEC_PER_SEC + ts.tv_nsec / 1000;
}

/* ap_run_monitor() is called once every INTERVAL_OF_WRITABLE_PROBES turns
 * of the parent's one second loop in ap_wait_or_timeout(), so that is how
 * often a keep-alive notification can be sent, and the shortest watchdog
 * timeout which can be met is twice that: sd_watchdog_enabled(3) asks for
 * a notification every half of the configured timeout. */
#define WATCHDOG_INTERVAL_SEC (10)

/* The WatchdogSec= of the service in microseconds, or zero if the service
 * manager is not watching.  Set in pre_config, before the first
 * notification which could carry a keep-alive. */
static apr_uint64_t watchdog_usec;

/* A keep-alive assignment to paste into a notification, or nothing while
 * the service manager is not asking for one.  Sending WATCHDOG=1 when it
 * is not expected is harmless, but saying so only when asked keeps what
 * httpd reports the same as what the service was configured for. */
static const char *watchdog_ping(void)
{
    return watchdog_usec ? "WATCHDOG=1\n" : "";
}

static int systemd_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp)
{
    apr_uint64_t usec = monotonic_usec(), wd_usec;

    /* Read afresh on each configuration load, since a restart unloads and
     * loads the module again, and without unsetting it as server/listen.c
     * does for $LISTEN_FDS, which would stop the keep-alive at the first
     * reload. */
    watchdog_usec = sd_watchdog_enabled(0, &wd_usec) > 0 ? wd_usec : 0;

    /* A Type=notify-reload service ignores a reload notification which
     * does not say when it was sent. */
    if (usec) {
        sd_notifyf(0,
                   "RELOADING=1\n"
                   "MONOTONIC_USEC=%" APR_UINT64_T_FMT "\n"
                   "%s"
                   "STATUS=Reading configuration...\n", usec, watchdog_ping());
    }
    else {
        sd_notifyf(0,
                   "RELOADING=1\n"
                   "%s"
                   "STATUS=Reading configuration...\n", watchdog_ping());
    }
    ap_extended_status = 1;
    return OK;
}

#ifdef HAVE_SELINUX
static void log_selinux_context(void)
{
    char *con;

    if (is_selinux_enabled() && getcon(&con) == 0) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                     APLOGNO(10497) "SELinux is enabled; "
                     "httpd running as context %s", con);
        freecon(con);
    }
}
#endif

/* pconf is also cleared on a restart, where the service is not stopping
 * at all, so distinguish the two by the state of the process. */
static apr_status_t systemd_stopping(void *unused)
{
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_EXITING) {
        sd_notify(0, "STOPPING=1\n"
                  "STATUS=Shutting down.\n");
    }
    return APR_SUCCESS;
}

/* Report the service is ready in post_config, which could be during
 * startup or after a reload.  The server could still hit a fatal
 * startup error after this point during ap_run_mpm(), so this is
 * perhaps too early, but by post_config listen() has been called on
 * the TCP ports so new connections will not be rejected.  There will
 * always be a possible async failure event simultaneous to the
 * service reporting "ready", so this should be good enough. */
static int systemd_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *main_server)
{
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
        return OK;

#ifdef HAVE_SELINUX
    log_selinux_context();
#endif

    /* Not reached by "httpd -k stop" and friends, which signal the
     * running server and exit before post_config. */
    apr_pool_cleanup_register(pconf, NULL, systemd_stopping,
                              apr_pool_cleanup_null);

    /* A timeout the parent cannot meet would have the service manager
     * killing a healthy server every WatchdogSec, so say so rather than
     * leaving nothing in the log to explain it. */
    if (watchdog_usec
        && watchdog_usec / 2 < (apr_uint64_t)WATCHDOG_INTERVAL_SEC
                               * APR_USEC_PER_SEC) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server, APLOGNO(10621)
                     "WatchdogSec is %" APR_UINT64_T_FMT "us, but keep-alive "
                     "notifications are sent from the parent process only "
                     "every %ds; configure a WatchdogSec of at least %ds or "
                     "the service will be killed while it is healthy",
                     watchdog_usec, WATCHDOG_INTERVAL_SEC,
                     2 * WATCHDOG_INTERVAL_SEC);
    }

    /* The keep-alive rides along with the notification which ends a
     * reload: the configuration is read outside the parent's monitor loop,
     * so nothing reports while it is being parsed, and the service manager
     * keeps the timeout armed throughout. */
    sd_notifyf(0, "READY=1\n"
               "%s"
               "STATUS=Configuration loaded.\n", watchdog_ping());
    return OK;
}

static int systemd_pre_mpm(apr_pool_t *p, ap_scoreboard_e sb_type)
{
    sd_notifyf(0, "READY=1\n"
               "STATUS=Processing requests...\n"
               "MAINPID=%" APR_PID_T_FMT, getpid());

    return OK;
}

static int systemd_monitor(apr_pool_t *p, server_rec *s)
{
    ap_sload_t sload;
    apr_interval_time_t up_time;
    char bps[5];

    /* Before anything which might decline: reporting the server is alive
     * does not depend on there being a status line to report with it. */
    if (watchdog_usec) {
        sd_notify(0, "WATCHDOG=1\n");
    }

    if (!ap_extended_status) {
        /* Nothing useful to report with ExtendedStatus disabled. */
        return DECLINED;
    }
    
    ap_get_sload(&sload);
    /* up_time in seconds, and never zero: a restart resets restart_time,
     * so this hook can run in the same second it was set. */
    up_time = apr_time_sec(apr_time_now() -
                           ap_scoreboard_image->global->restart_time);
    if (up_time < 1) {
        up_time = 1;
    }

    apr_strfsize(sload.bytes_served / up_time, bps);

    /* ap_get_sload() gives idle and busy as percentages of the workers
     * available, not as counts. */
    sd_notifyf(0, "READY=1\n"
               "STATUS=Total requests: %lu; Idle/Busy workers %d%%/%d%%; "
               "Requests/sec: %.3g; Bytes served/sec: %sB/sec\n",
               sload.access_count, sload.idle, sload.busy,
               ((float) sload.access_count) / (float) up_time, bps);

    return DECLINED;
}

/* The number of sockets passed by the service manager has to be
 * remembered: the configuration is read again on restart, by which time
 * the environment sd_listen_fds() reads has been cleared, and the module
 * itself has been unloaded and loaded again.  Hence retained data rather
 * than a static. */
static const char *const retained_key = "mod_systemd_listen_fds";

static int ap_systemd_listen_fds(int unset_environment)
{
    int *fds = ap_retained_data_get(retained_key);

    if (fds == NULL) {
        fds = ap_retained_data_create(retained_key, sizeof(*fds));
        *fds = sd_listen_fds(0);
    }
    if (unset_environment) {
        /* Take the variables out of the environment, keeping the count. */
        sd_listen_fds(1);
    }
    return *fds;
}

static int ap_find_systemd_socket(process_rec * process, apr_port_t port) {
    int fd;
    int sdc = ap_systemd_listen_fds(0);

    if (sdc < 0) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, sdc, process->pool, APLOGNO(02486)
                      "find_systemd_socket: Error parsing enviroment, sd_listen_fds returned %d",
                      sdc);
        return -1;
    }

    if (sdc == 0) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, sdc, process->pool, APLOGNO(02487)
                      "find_systemd_socket: At least one socket must be set.");
        return -1;
    }

    for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + sdc; fd++) {
        if (sd_is_socket_inet(fd, 0, 0, -1, port) > 0) {
            return fd;
        }
    }

    return -1;
}

static void systemd_register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(ap_systemd_listen_fds);
    APR_REGISTER_OPTIONAL_FN(ap_find_systemd_socket);

    /* Enable ap_extended_status. */
    ap_hook_pre_config(systemd_pre_config, NULL, NULL, APR_HOOK_LAST);
    /* Signal service is ready. */
    ap_hook_post_config(systemd_post_config, NULL, NULL, APR_HOOK_REALLY_LAST);
    /* We know the PID in this hook ... */
    ap_hook_pre_mpm(systemd_pre_mpm, NULL, NULL, APR_HOOK_LAST);
    /* Used to update httpd's status line using sd_notifyf */
    ap_hook_monitor(systemd_monitor, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(systemd) = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    systemd_register_hooks,
};
