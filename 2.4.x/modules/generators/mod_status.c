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

/* Status Module.  Display lots of internal data about how Apache is
 * performing and the state of all children processes.
 *
 * To enable this, add the following lines into any config file:
 *
 * <Location /server-status>
 * SetHandler server-status
 * </Location>
 *
 * You may want to protect this location by password or domain so no one
 * else can look at it.  Then you can access the statistics with a URL like:
 *
 * http://your_server_name/server-status
 *
 * /server-status - Returns page using tables
 * /server-status?notable - Returns page for browsers without table support
 * /server-status?refresh - Returns page with 1 second refresh
 * /server-status?refresh=6 - Returns page with refresh every 6 seconds
 * /server-status?auto - Returns page with data for automatic parsing
 *
 * Mark Cox, mark@ukweb.com, November 1995
 *
 * 12.11.95 Initial version for www.telescope.org
 * 13.3.96  Updated to remove rprintf's [Mark]
 * 18.3.96  Added CPU usage, process information, and tidied [Ben Laurie]
 * 18.3.96  Make extra Scoreboard variables #definable
 * 25.3.96  Make short report have full precision [Ben Laurie suggested]
 * 25.3.96  Show uptime better [Mark/Ben Laurie]
 * 29.3.96  Better HTML and explanation [Mark/Rob Hartill suggested]
 * 09.4.96  Added message for non-STATUS compiled version
 * 18.4.96  Added per child and per slot counters [Jim Jagielski]
 * 01.5.96  Table format, cleanup, even more spiffy data [Chuck Murcko/Jim J.]
 * 18.5.96  Adapted to use new rprintf() routine, incidentally fixing a missing
 *          piece in short reports [Ben Laurie]
 * 21.5.96  Additional Status codes (DNS and LOGGING only enabled if
 *          extended STATUS is enabled) [George Burgyan/Jim J.]
 * 10.8.98  Allow for extended status info at runtime (no more STATUS)
 *          [Jim J.]
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "ap_mpm.h"
#include "util_script.h"
#include <time.h>
#include "scoreboard.h"
#include "http_log.h"
#include "mod_status.h"
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"

#define STATUS_MAXLINE 64

#define KBYTE 1024
#define MBYTE 1048576L
#define GBYTE 1073741824L

#ifndef DEFAULT_TIME_FORMAT
#define DEFAULT_TIME_FORMAT "%A, %d-%b-%Y %H:%M:%S %Z"
#endif

#define STATUS_MAGIC_TYPE "application/x-httpd-status"

module AP_MODULE_DECLARE_DATA status_module;

static int server_limit, thread_limit, threads_per_child, max_servers,
           is_async;

/* Implement 'ap_run_status_hook'. */
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap, STATUS, int, status_hook,
                                    (request_rec *r, int flags),
                                    (r, flags),
                                    OK, DECLINED)

#ifdef HAVE_TIMES
/* ugh... need to know if we're running with a pthread implementation
 * such as linuxthreads that treats individual threads as distinct
 * processes; that affects how we add up CPU time in a process
 */
static pid_t child_pid;
#endif

/* Format the number of bytes nicely */
static void format_byte_out(request_rec *r, apr_off_t bytes)
{
    if (bytes < (5 * KBYTE))
        ap_rprintf(r, "%d B", (int) bytes);
    else if (bytes < (MBYTE / 2))
        ap_rprintf(r, "%.1f kB", (float) bytes / KBYTE);
    else if (bytes < (GBYTE / 2))
        ap_rprintf(r, "%.1f MB", (float) bytes / MBYTE);
    else
        ap_rprintf(r, "%.1f GB", (float) bytes / GBYTE);
}

static void format_kbyte_out(request_rec *r, apr_off_t kbytes)
{
    if (kbytes < KBYTE)
        ap_rprintf(r, "%d kB", (int) kbytes);
    else if (kbytes < MBYTE)
        ap_rprintf(r, "%.1f MB", (float) kbytes / KBYTE);
    else
        ap_rprintf(r, "%.1f GB", (float) kbytes / MBYTE);
}

static void show_time(request_rec *r, apr_uint32_t tsecs)
{
    int days, hrs, mins, secs;

    secs = (int)(tsecs % 60);
    tsecs /= 60;
    mins = (int)(tsecs % 60);
    tsecs /= 60;
    hrs = (int)(tsecs % 24);
    days = (int)(tsecs / 24);

    if (days)
        ap_rprintf(r, " %d day%s", days, days == 1 ? "" : "s");

    if (hrs)
        ap_rprintf(r, " %d hour%s", hrs, hrs == 1 ? "" : "s");

    if (mins)
        ap_rprintf(r, " %d minute%s", mins, mins == 1 ? "" : "s");

    if (secs)
        ap_rprintf(r, " %d second%s", secs, secs == 1 ? "" : "s");
}

/* Main handler for x-httpd-status requests */

/* ID values for command table */

#define STAT_OPT_END     -1
#define STAT_OPT_REFRESH  0
#define STAT_OPT_NOTABLE  1
#define STAT_OPT_AUTO     2

struct stat_opt {
    int id;
    const char *form_data_str;
    const char *hdr_out_str;
};

static const struct stat_opt status_options[] = /* see #defines above */
{
    {STAT_OPT_REFRESH, "refresh", "Refresh"},
    {STAT_OPT_NOTABLE, "notable", NULL},
    {STAT_OPT_AUTO, "auto", NULL},
    {STAT_OPT_END, NULL, NULL}
};

/* add another state for slots above the MaxRequestWorkers setting */
#define SERVER_DISABLED SERVER_NUM_STATUS
#define MOD_STATUS_NUM_STATUS (SERVER_NUM_STATUS+1)

static char status_flags[MOD_STATUS_NUM_STATUS];

static int status_handler(request_rec *r)
{
    const char *loc;
    apr_time_t nowtime;
    apr_uint32_t up_time;
    ap_loadavg_t t;
    int j, i, res, written;
    int ready;
    int busy;
    unsigned long count;
    unsigned long lres, my_lres, conn_lres;
    apr_off_t bytes, my_bytes, conn_bytes;
    apr_off_t bcount, kbcount;
    long req_time;
    apr_time_t duration_global;
    apr_time_t duration_slot;
    int short_report;
    int no_table_report;
    global_score *global_record;
    worker_score *ws_record;
    process_score *ps_record;
    char *stat_buffer;
    pid_t *pid_buffer, worker_pid;
    int *thread_idle_buffer = NULL;
    int *thread_busy_buffer = NULL;
    clock_t tu, ts, tcu, tcs;
    clock_t gu, gs, gcu, gcs;
    ap_generation_t mpm_generation, worker_generation;
#ifdef HAVE_TIMES
    float tick;
    int times_per_thread;
#endif

    if (strcmp(r->handler, STATUS_MAGIC_TYPE) && strcmp(r->handler,
            "server-status")) {
        return DECLINED;
    }

#ifdef HAVE_TIMES
    times_per_thread = getpid() != child_pid;
#endif

    ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);

#ifdef HAVE_TIMES
#ifdef _SC_CLK_TCK
    tick = sysconf(_SC_CLK_TCK);
#else
    tick = HZ;
#endif
#endif

    ready = 0;
    busy = 0;
    count = 0;
    bcount = 0;
    kbcount = 0;
    duration_global = 0;
    short_report = 0;
    no_table_report = 0;

    if (!ap_exists_scoreboard_image()) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01237)
                      "Server status unavailable in inetd mode");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    pid_buffer = apr_palloc(r->pool, server_limit * sizeof(pid_t));
    stat_buffer = apr_palloc(r->pool, server_limit * thread_limit * sizeof(char));
    if (is_async) {
        thread_idle_buffer = apr_palloc(r->pool, server_limit * sizeof(int));
        thread_busy_buffer = apr_palloc(r->pool, server_limit * sizeof(int));
    }

    nowtime = apr_time_now();
#ifdef HAVE_TIMES
    global_record = ap_get_scoreboard_global();
    gu = global_record->times.tms_utime;
    gs = global_record->times.tms_stime;
    gcu = global_record->times.tms_cutime;
    gcs = global_record->times.tms_cstime;
#else
    gu = gs = gcu = gcs = 0;
#endif
    tu = ts = tcu = tcs = 0;

    r->allowed = (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET)
        return DECLINED;

    ap_set_content_type(r, "text/html; charset=ISO-8859-1");

    /*
     * Simple table-driven form data set parser that lets you alter the header
     */

    if (r->args) {
        i = 0;
        while (status_options[i].id != STAT_OPT_END) {
            if ((loc = ap_strstr_c(r->args,
                                   status_options[i].form_data_str)) != NULL) {
                switch (status_options[i].id) {
                case STAT_OPT_REFRESH: {
                    apr_size_t len = strlen(status_options[i].form_data_str);
                    long t = 0;

                    if (*(loc + len ) == '=') {
                        t = atol(loc + len + 1);
                    }
                    apr_table_setn(r->headers_out,
                                   status_options[i].hdr_out_str,
                                   apr_ltoa(r->pool, t < 1 ? 10 : t));
                    break;
                }
                case STAT_OPT_NOTABLE:
                    no_table_report = 1;
                    break;
                case STAT_OPT_AUTO:
                    ap_set_content_type(r, "text/plain; charset=ISO-8859-1");
                    short_report = 1;
                    break;
                }
            }

            i++;
        }
    }

    ws_record = apr_palloc(r->pool, sizeof *ws_record);

    for (i = 0; i < server_limit; ++i) {
#ifdef HAVE_TIMES
        clock_t proc_tu = 0, proc_ts = 0, proc_tcu = 0, proc_tcs = 0;
        clock_t tmp_tu, tmp_ts, tmp_tcu, tmp_tcs;
#endif

        ps_record = ap_get_scoreboard_process(i);
        if (is_async) {
            thread_idle_buffer[i] = 0;
            thread_busy_buffer[i] = 0;
        }
        for (j = 0; j < thread_limit; ++j) {
            int indx = (i * thread_limit) + j;

            ap_copy_scoreboard_worker(ws_record, i, j);
            res = ws_record->status;

            if ((i >= max_servers || j >= threads_per_child)
                && (res == SERVER_DEAD))
                stat_buffer[indx] = status_flags[SERVER_DISABLED];
            else
                stat_buffer[indx] = status_flags[res];

            if (!ps_record->quiescing
                && ps_record->pid) {
                if (res == SERVER_READY) {
                    if (ps_record->generation == mpm_generation)
                        ready++;
                    if (is_async)
                        thread_idle_buffer[i]++;
                }
                else if (res != SERVER_DEAD &&
                         res != SERVER_STARTING &&
                         res != SERVER_IDLE_KILL) {
                    busy++;
                    if (is_async) {
                        if (res == SERVER_GRACEFUL)
                            thread_idle_buffer[i]++;
                        else
                            thread_busy_buffer[i]++;
                    }
                }
            }

            /* XXX what about the counters for quiescing/seg faulted
             * processes?  should they be counted or not?  GLA
             */
            if (ap_extended_status) {
                lres = ws_record->access_count;
                bytes = ws_record->bytes_served;

                if (lres != 0 || (res != SERVER_READY && res != SERVER_DEAD)) {
#ifdef HAVE_TIMES
                    tmp_tu = ws_record->times.tms_utime;
                    tmp_ts = ws_record->times.tms_stime;
                    tmp_tcu = ws_record->times.tms_cutime;
                    tmp_tcs = ws_record->times.tms_cstime;

                    if (times_per_thread) {
                        proc_tu += tmp_tu;
                        proc_ts += tmp_ts;
                        proc_tcu += tmp_tcu;
                        proc_tcs += tmp_tcs;
                    }
                    else {
                        if (tmp_tu > proc_tu ||
                            tmp_ts > proc_ts ||
                            tmp_tcu > proc_tcu ||
                            tmp_tcs > proc_tcs) {
                            proc_tu = tmp_tu;
                            proc_ts = tmp_ts;
                            proc_tcu = tmp_tcu;
                            proc_tcs = tmp_tcs;
                        }
                    }
#endif /* HAVE_TIMES */

                    count += lres;
                    bcount += bytes;
                    duration_global += ws_record->duration;

                    if (bcount >= KBYTE) {
                        kbcount += (bcount >> 10);
                        bcount = bcount & 0x3ff;
                    }
                }
            }
        }
#ifdef HAVE_TIMES
        tu += proc_tu;
        ts += proc_ts;
        tcu += proc_tcu;
        tcs += proc_tcs;
#endif
        pid_buffer[i] = ps_record->pid;
    }

    /* up_time in seconds */
    up_time = (apr_uint32_t) apr_time_sec(nowtime -
                               ap_scoreboard_image->global->restart_time);
    ap_get_loadavg(&t);

    if (!short_report) {
        ap_rputs(DOCTYPE_HTML_3_2
                 "<html><head>\n"
                 "<title>Apache Status</title>\n"
                 "</head><body>\n"
                 "<h1>Apache Server Status for ", r);
        ap_rvputs(r, ap_escape_html(r->pool, ap_get_server_name(r)),
                  " (via ", r->connection->local_ip,
                  ")</h1>\n\n", NULL);
        ap_rvputs(r, "<dl><dt>Server Version: ",
                  ap_get_server_description(), "</dt>\n", NULL);
        ap_rvputs(r, "<dt>Server MPM: ",
                  ap_show_mpm(), "</dt>\n", NULL);
        ap_rvputs(r, "<dt>Server Built: ",
                  ap_get_server_built(), "\n</dt></dl><hr /><dl>\n", NULL);
        ap_rvputs(r, "<dt>Current Time: ",
                  ap_ht_time(r->pool, nowtime, DEFAULT_TIME_FORMAT, 0),
                             "</dt>\n", NULL);
        ap_rvputs(r, "<dt>Restart Time: ",
                  ap_ht_time(r->pool,
                             ap_scoreboard_image->global->restart_time,
                             DEFAULT_TIME_FORMAT, 0),
                  "</dt>\n", NULL);
        ap_rprintf(r, "<dt>Parent Server Config. Generation: %d</dt>\n",
                   ap_state_query(AP_SQ_CONFIG_GEN));
        ap_rprintf(r, "<dt>Parent Server MPM Generation: %d</dt>\n",
                   (int)mpm_generation);
        ap_rputs("<dt>Server uptime: ", r);
        show_time(r, up_time);
        ap_rputs("</dt>\n", r);
        ap_rprintf(r, "<dt>Server load: %.2f %.2f %.2f</dt>\n",
                   t.loadavg, t.loadavg5, t.loadavg15);
    }
    else {
        ap_rvputs(r, ap_get_server_name(r), "\n", NULL);
        ap_rvputs(r, "ServerVersion: ",
                  ap_get_server_description(), "\n", NULL);
        ap_rvputs(r, "ServerMPM: ",
                  ap_show_mpm(), "\n", NULL);
        ap_rvputs(r, "Server Built: ",
                  ap_get_server_built(), "\n", NULL);
        ap_rvputs(r, "CurrentTime: ",
                  ap_ht_time(r->pool, nowtime, DEFAULT_TIME_FORMAT, 0),
                             "\n", NULL);
        ap_rvputs(r, "RestartTime: ",
                  ap_ht_time(r->pool,
                             ap_scoreboard_image->global->restart_time,
                             DEFAULT_TIME_FORMAT, 0),
                  "\n", NULL);
        ap_rprintf(r, "ParentServerConfigGeneration: %d\n",
                   ap_state_query(AP_SQ_CONFIG_GEN));
        ap_rprintf(r, "ParentServerMPMGeneration: %d\n",
                   (int)mpm_generation);
        ap_rprintf(r, "ServerUptimeSeconds: %u\n",
                   up_time);
        ap_rputs("ServerUptime:", r);
        show_time(r, up_time);
        ap_rputs("\n", r);
        ap_rprintf(r, "Load1: %.2f\nLoad5: %.2f\nLoad15: %.2f\n",
                   t.loadavg, t.loadavg5, t.loadavg15);
    }

    if (ap_extended_status) {
        clock_t cpu = gu + gs + gcu + gcs + tu + ts + tcu + tcs;
        if (short_report) {
            ap_rprintf(r, "Total Accesses: %lu\nTotal kBytes: %"
                       APR_OFF_T_FMT "\nTotal Duration: %"
                       APR_TIME_T_FMT "\n",
                       count, kbcount, apr_time_as_msec(duration_global));

#ifdef HAVE_TIMES
            /* Allow for OS/2 not having CPU stats */
            ap_rprintf(r, "CPUUser: %g\nCPUSystem: %g\nCPUChildrenUser: %g\nCPUChildrenSystem: %g\n",
                       (gu + tu) / tick, (gs + ts) / tick, (gcu + tcu) / tick, (gcs + tcs) / tick);

            if (cpu)
                ap_rprintf(r, "CPULoad: %g\n",
                           cpu / tick / up_time * 100.);
#endif

            ap_rprintf(r, "Uptime: %ld\n", (long) (up_time));
            if (up_time > 0) {
                ap_rprintf(r, "ReqPerSec: %g\n",
                           (float) count / (float) up_time);

                ap_rprintf(r, "BytesPerSec: %g\n",
                           KBYTE * (float) kbcount / (float) up_time);
            }
            if (count > 0) {
                ap_rprintf(r, "BytesPerReq: %g\n",
                           KBYTE * (float) kbcount / (float) count);
                ap_rprintf(r, "DurationPerReq: %g\n",
                           (float) apr_time_as_msec(duration_global) / (float) count);
            }
        }
        else { /* !short_report */
            ap_rprintf(r, "<dt>Total accesses: %lu - Total Traffic: ", count);
            format_kbyte_out(r, kbcount);
            ap_rprintf(r, " - Total Duration: %" APR_TIME_T_FMT "</dt>\n",
                       apr_time_as_msec(duration_global));

#ifdef HAVE_TIMES
            /* Allow for OS/2 not having CPU stats */
            ap_rprintf(r, "<dt>CPU Usage: u%g s%g cu%g cs%g",
                       (gu + tu) / tick, (gs + ts) / tick, (gcu + tcu) / tick, (gcs + tcs) / tick);

            if (cpu)
                ap_rprintf(r, " - %.3g%% CPU load</dt>\n",
                           cpu / tick / up_time * 100.);
            else
                ap_rputs("</dt>\n", r);
#endif

            ap_rputs("<dt>", r);
            if (up_time > 0) {
                ap_rprintf(r, "%.3g requests/sec - ",
                           (float) count / (float) up_time);

                format_byte_out(r, (unsigned long)(KBYTE * (float) kbcount
                                                   / (float) up_time));
                ap_rputs("/second", r);
            }

            if (count > 0) {
                if (up_time > 0)
                    ap_rputs(" - ", r);
                format_byte_out(r, (unsigned long)(KBYTE * (float) kbcount
                                                   / (float) count));
                ap_rprintf(r, "/request - %g ms/request",
                (float) apr_time_as_msec(duration_global) / (float) count);
            }

            ap_rputs("</dt>\n", r);
        } /* short_report */
    } /* ap_extended_status */

    if (!short_report)
        ap_rprintf(r, "<dt>%d requests currently being processed, "
                      "%d idle workers</dt>\n", busy, ready);
    else
        ap_rprintf(r, "BusyWorkers: %d\nIdleWorkers: %d\n", busy, ready);

    if (!short_report)
        ap_rputs("</dl>", r);

    if (is_async) {
        int write_completion = 0, lingering_close = 0, keep_alive = 0,
            connections = 0, stopping = 0, procs = 0;
        /*
         * These differ from 'busy' and 'ready' in how gracefully finishing
         * threads are counted. XXX: How to make this clear in the html?
         */
        int busy_workers = 0, idle_workers = 0;
        if (!short_report)
            ap_rputs("\n\n<table rules=\"all\" cellpadding=\"1%\">\n"
                     "<tr><th rowspan=\"2\">Slot</th>"
                         "<th rowspan=\"2\">PID</th>"
                         "<th rowspan=\"2\">Stopping</th>"
                         "<th colspan=\"2\">Connections</th>\n"
                         "<th colspan=\"2\">Threads</th>"
                         "<th colspan=\"3\">Async connections</th></tr>\n"
                     "<tr><th>total</th><th>accepting</th>"
                         "<th>busy</th><th>idle</th>"
                         "<th>writing</th><th>keep-alive</th><th>closing</th></tr>\n", r);
        for (i = 0; i < server_limit; ++i) {
            ps_record = ap_get_scoreboard_process(i);
            if (ps_record->pid) {
                connections      += ps_record->connections;
                write_completion += ps_record->write_completion;
                keep_alive       += ps_record->keep_alive;
                lingering_close  += ps_record->lingering_close;
                busy_workers     += thread_busy_buffer[i];
                idle_workers     += thread_idle_buffer[i];
                procs++;
                if (ps_record->quiescing) {
                    stopping++;
                }
                if (!short_report) {
                    const char *dying = "no";
                    const char *old = "";
                    if (ps_record->quiescing) {
                        dying = "yes";
                    }
                    if (ps_record->generation != mpm_generation)
                        old = " (old gen)";
                    ap_rprintf(r, "<tr><td>%u</td><td>%" APR_PID_T_FMT "</td>"
                                      "<td>%s%s</td>"
                                      "<td>%u</td><td>%s</td>"
                                      "<td>%u</td><td>%u</td>"
                                      "<td>%u</td><td>%u</td><td>%u</td>"
                                      "</tr>\n",
                               i, ps_record->pid,
                               dying, old,
                               ps_record->connections,
                               ps_record->not_accepting ? "no" : "yes",
                               thread_busy_buffer[i],
                               thread_idle_buffer[i],
                               ps_record->write_completion,
                               ps_record->keep_alive,
                               ps_record->lingering_close);
                }
            }
        }
        if (!short_report) {
            ap_rprintf(r, "<tr><td>Sum</td>"
                          "<td>%d</td><td>%d</td>"
                          "<td>%d</td><td>&nbsp;</td>"
                          "<td>%d</td><td>%d</td>"
                          "<td>%d</td><td>%d</td><td>%d</td>"
                          "</tr>\n</table>\n",
                          procs, stopping,
                          connections,
                          busy_workers, idle_workers,
                          write_completion, keep_alive, lingering_close);
        }
        else {
            ap_rprintf(r, "Processes: %d\n"
                          "Stopping: %d\n"
                          "BusyWorkers: %d\n"
                          "IdleWorkers: %d\n"
                          "ConnsTotal: %d\n"
                          "ConnsAsyncWriting: %d\n"
                          "ConnsAsyncKeepAlive: %d\n"
                          "ConnsAsyncClosing: %d\n",
                          procs, stopping,
                          busy_workers, idle_workers,
                          connections,
                          write_completion, keep_alive, lingering_close);
        }
    }

    /* send the scoreboard 'table' out */
    if (!short_report)
        ap_rputs("<pre>", r);
    else
        ap_rputs("Scoreboard: ", r);

    written = 0;
    for (i = 0; i < server_limit; ++i) {
        for (j = 0; j < thread_limit; ++j) {
            int indx = (i * thread_limit) + j;
            if (stat_buffer[indx] != status_flags[SERVER_DISABLED]) {
                ap_rputc(stat_buffer[indx], r);
                if ((written % STATUS_MAXLINE == (STATUS_MAXLINE - 1))
                    && !short_report)
                    ap_rputs("\n", r);
                written++;
            }
        }
    }


    if (short_report)
        ap_rputs("\n", r);
    else {
        ap_rputs("</pre>\n"
                 "<p>Scoreboard Key:<br />\n"
                 "\"<b><code>_</code></b>\" Waiting for Connection, \n"
                 "\"<b><code>S</code></b>\" Starting up, \n"
                 "\"<b><code>R</code></b>\" Reading Request,<br />\n"
                 "\"<b><code>W</code></b>\" Sending Reply, \n"
                 "\"<b><code>K</code></b>\" Keepalive (read), \n"
                 "\"<b><code>D</code></b>\" DNS Lookup,<br />\n"
                 "\"<b><code>C</code></b>\" Closing connection, \n"
                 "\"<b><code>L</code></b>\" Logging, \n"
                 "\"<b><code>G</code></b>\" Gracefully finishing,<br /> \n"
                 "\"<b><code>I</code></b>\" Idle cleanup of worker, \n"
                 "\"<b><code>.</code></b>\" Open slot with no current process<br />\n"
                 "</p>\n", r);
        if (!ap_extended_status) {
            int j;
            int k = 0;
            ap_rputs("PID Key: <br />\n"
                     "<pre>\n", r);
            for (i = 0; i < server_limit; ++i) {
                for (j = 0; j < thread_limit; ++j) {
                    int indx = (i * thread_limit) + j;

                    if (stat_buffer[indx] != '.') {
                        ap_rprintf(r, "   %" APR_PID_T_FMT
                                   " in state: %c ", pid_buffer[i],
                                   stat_buffer[indx]);

                        if (++k >= 3) {
                            ap_rputs("\n", r);
                            k = 0;
                        } else
                            ap_rputs(",", r);
                    }
                }
            }

            ap_rputs("\n"
                     "</pre>\n", r);
        }
    }

    if (ap_extended_status && !short_report) {
        if (no_table_report)
            ap_rputs("<hr /><h2>Server Details</h2>\n\n", r);
        else
            ap_rputs("\n\n<table border=\"0\"><tr>"
                     "<th>Srv</th><th>PID</th><th>Acc</th>"
                     "<th>M</th>"
#ifdef HAVE_TIMES
                     "<th>CPU\n</th>"
#endif
                     "<th>SS</th><th>Req</th><th>Dur</th>"
                     "<th>Conn</th><th>Child</th><th>Slot</th>"
                     "<th>Client</th><th>Protocol</th><th>VHost</th>"
                     "<th>Request</th></tr>\n\n", r);

        for (i = 0; i < server_limit; ++i) {
            for (j = 0; j < thread_limit; ++j) {
                ap_copy_scoreboard_worker(ws_record, i, j);

                if (ws_record->access_count == 0 &&
                    (ws_record->status == SERVER_READY ||
                     ws_record->status == SERVER_DEAD)) {
                    continue;
                }

                ps_record = ap_get_scoreboard_process(i);

                if (ws_record->start_time == 0L)
                    req_time = 0L;
                else
                    req_time = (long)
                        apr_time_as_msec(ws_record->stop_time -
                          ws_record->start_time);
                if (req_time < 0L)
                    req_time = 0L;

                lres = ws_record->access_count;
                my_lres = ws_record->my_access_count;
                conn_lres = ws_record->conn_count;
                bytes = ws_record->bytes_served;
                my_bytes = ws_record->my_bytes_served;
                conn_bytes = ws_record->conn_bytes;
                duration_slot = ws_record->duration;
                if (ws_record->pid) { /* MPM sets per-worker pid and generation */
                    worker_pid = ws_record->pid;
                    worker_generation = ws_record->generation;
                }
                else {
                    worker_pid = ps_record->pid;
                    worker_generation = ps_record->generation;
                }

                if (no_table_report) {
                    if (ws_record->status == SERVER_DEAD)
                        ap_rprintf(r,
                                   "<b>Server %d-%d</b> (-): %d|%lu|%lu [",
                                   i, (int)worker_generation,
                                   (int)conn_lres, my_lres, lres);
                    else
                        ap_rprintf(r,
                                   "<b>Server %d-%d</b> (%"
                                   APR_PID_T_FMT "): %d|%lu|%lu [",
                                   i, (int) worker_generation,
                                   worker_pid,
                                   (int)conn_lres, my_lres, lres);

                    switch (ws_record->status) {
                    case SERVER_READY:
                        ap_rputs("Ready", r);
                        break;
                    case SERVER_STARTING:
                        ap_rputs("Starting", r);
                        break;
                    case SERVER_BUSY_READ:
                        ap_rputs("<b>Read</b>", r);
                        break;
                    case SERVER_BUSY_WRITE:
                        ap_rputs("<b>Write</b>", r);
                        break;
                    case SERVER_BUSY_KEEPALIVE:
                        ap_rputs("<b>Keepalive</b>", r);
                        break;
                    case SERVER_BUSY_LOG:
                        ap_rputs("<b>Logging</b>", r);
                        break;
                    case SERVER_BUSY_DNS:
                        ap_rputs("<b>DNS lookup</b>", r);
                        break;
                    case SERVER_CLOSING:
                        ap_rputs("<b>Closing</b>", r);
                        break;
                    case SERVER_DEAD:
                        ap_rputs("Dead", r);
                        break;
                    case SERVER_GRACEFUL:
                        ap_rputs("Graceful", r);
                        break;
                    case SERVER_IDLE_KILL:
                        ap_rputs("Dying", r);
                        break;
                    default:
                        ap_rputs("?STATE?", r);
                        break;
                    }

                    ap_rprintf(r, "] "
#ifdef HAVE_TIMES
                               "u%g s%g cu%g cs%g"
#endif
                               "\n %ld %ld %" APR_TIME_T_FMT "(",
#ifdef HAVE_TIMES
                               ws_record->times.tms_utime / tick,
                               ws_record->times.tms_stime / tick,
                               ws_record->times.tms_cutime / tick,
                               ws_record->times.tms_cstime / tick,
#endif
                               (long)apr_time_sec(nowtime -
                                                  ws_record->last_used),
                               (long) req_time, apr_time_as_msec(duration_slot));

                    format_byte_out(r, conn_bytes);
                    ap_rputs("|", r);
                    format_byte_out(r, my_bytes);
                    ap_rputs("|", r);
                    format_byte_out(r, bytes);
                    ap_rputs(")\n", r);
                    ap_rprintf(r,
                               " <i>%s {%s}</i> <i>(%s)</i> <b>[%s]</b><br />\n\n",
                               ap_escape_html(r->pool,
                                              ws_record->client64),
                               ap_escape_html(r->pool,
                                              ap_escape_logitem(r->pool,
                                                                ws_record->request)),
                               ap_escape_html(r->pool,
                                              ws_record->protocol),
                               ap_escape_html(r->pool,
                                              ws_record->vhost));
                }
                else { /* !no_table_report */
                    if (ws_record->status == SERVER_DEAD)
                        ap_rprintf(r,
                                   "<tr><td><b>%d-%d</b></td><td>-</td><td>%d/%lu/%lu",
                                   i, (int)worker_generation,
                                   (int)conn_lres, my_lres, lres);
                    else
                        ap_rprintf(r,
                                   "<tr><td><b>%d-%d</b></td><td>%"
                                   APR_PID_T_FMT
                                   "</td><td>%d/%lu/%lu",
                                   i, (int)worker_generation,
                                   worker_pid,
                                   (int)conn_lres,
                                   my_lres, lres);

                    switch (ws_record->status) {
                    case SERVER_READY:
                        ap_rputs("</td><td>_", r);
                        break;
                    case SERVER_STARTING:
                        ap_rputs("</td><td><b>S</b>", r);
                        break;
                    case SERVER_BUSY_READ:
                        ap_rputs("</td><td><b>R</b>", r);
                        break;
                    case SERVER_BUSY_WRITE:
                        ap_rputs("</td><td><b>W</b>", r);
                        break;
                    case SERVER_BUSY_KEEPALIVE:
                        ap_rputs("</td><td><b>K</b>", r);
                        break;
                    case SERVER_BUSY_LOG:
                        ap_rputs("</td><td><b>L</b>", r);
                        break;
                    case SERVER_BUSY_DNS:
                        ap_rputs("</td><td><b>D</b>", r);
                        break;
                    case SERVER_CLOSING:
                        ap_rputs("</td><td><b>C</b>", r);
                        break;
                    case SERVER_DEAD:
                        ap_rputs("</td><td>.", r);
                        break;
                    case SERVER_GRACEFUL:
                        ap_rputs("</td><td>G", r);
                        break;
                    case SERVER_IDLE_KILL:
                        ap_rputs("</td><td>I", r);
                        break;
                    default:
                        ap_rputs("</td><td>?", r);
                        break;
                    }

                    ap_rprintf(r,
                               "\n</td>"
#ifdef HAVE_TIMES
                               "<td>%.2f</td>"
#endif
                               "<td>%ld</td><td>%ld</td><td>%" APR_TIME_T_FMT,
#ifdef HAVE_TIMES
                               (ws_record->times.tms_utime +
                                ws_record->times.tms_stime +
                                ws_record->times.tms_cutime +
                                ws_record->times.tms_cstime) / tick,
#endif
                               (long)apr_time_sec(nowtime -
                                                  ws_record->last_used),
                               (long)req_time, apr_time_as_msec(duration_slot));

                    ap_rprintf(r, "</td><td>%-1.1f</td><td>%-2.2f</td><td>%-2.2f\n",
                               (float)conn_bytes / KBYTE, (float) my_bytes / MBYTE,
                               (float)bytes / MBYTE);

                    ap_rprintf(r, "</td><td>%s</td><td>%s</td><td nowrap>%s</td>"
                                  "<td nowrap>%s</td></tr>\n\n",
                               ap_escape_html(r->pool,
                                              ws_record->client64),
                               ap_escape_html(r->pool,
                                              ws_record->protocol),
                               ap_escape_html(r->pool,
                                              ws_record->vhost),
                               ap_escape_html(r->pool,
                                              ap_escape_logitem(r->pool,
                                                      ws_record->request)));
                } /* no_table_report */
            } /* for (j...) */
        } /* for (i...) */

        if (!no_table_report) {
            ap_rputs("</table>\n \
<hr /> \
<table>\n \
<tr><th>Srv</th><td>Child Server number - generation</td></tr>\n \
<tr><th>PID</th><td>OS process ID</td></tr>\n \
<tr><th>Acc</th><td>Number of accesses this connection / this child / this slot</td></tr>\n \
<tr><th>M</th><td>Mode of operation</td></tr>\n"

#ifdef HAVE_TIMES
"<tr><th>CPU</th><td>CPU usage, number of seconds</td></tr>\n"
#endif

"<tr><th>SS</th><td>Seconds since beginning of most recent request</td></tr>\n \
<tr><th>Req</th><td>Milliseconds required to process most recent request</td></tr>\n \
<tr><th>Dur</th><td>Sum of milliseconds required to process all requests</td></tr>\n \
<tr><th>Conn</th><td>Kilobytes transferred this connection</td></tr>\n \
<tr><th>Child</th><td>Megabytes transferred this child</td></tr>\n \
<tr><th>Slot</th><td>Total megabytes transferred this slot</td></tr>\n \
</table>\n", r);
        }
    } /* if (ap_extended_status && !short_report) */
    else {

        if (!short_report) {
            ap_rputs("<hr />To obtain a full report with current status "
                     "information you need to use the "
                     "<code>ExtendedStatus On</code> directive.\n", r);
        }
    }

    {
        /* Run extension hooks to insert extra content. */
        int flags =
            (short_report ? AP_STATUS_SHORT : 0) |
            (no_table_report ? AP_STATUS_NOTABLE : 0) |
            (ap_extended_status ? AP_STATUS_EXTENDED : 0);

        ap_run_status_hook(r, flags);
    }

    if (!short_report) {
        ap_rputs(ap_psignature("<hr />\n",r), r);
        ap_rputs("</body></html>\n", r);
    }

    return 0;
}

static int status_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    /* When mod_status is loaded, default our ExtendedStatus to 'on'
     * other modules which prefer verbose scoreboards may play a similar game.
     * If left to their own requirements, mpm modules can make do with simple
     * scoreboard entries.
     */
    ap_extended_status = 1;
    return OK;
}

static int status_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                       server_rec *s)
{
    status_flags[SERVER_DEAD] = '.';  /* We don't want to assume these are in */
    status_flags[SERVER_READY] = '_'; /* any particular order in scoreboard.h */
    status_flags[SERVER_STARTING] = 'S';
    status_flags[SERVER_BUSY_READ] = 'R';
    status_flags[SERVER_BUSY_WRITE] = 'W';
    status_flags[SERVER_BUSY_KEEPALIVE] = 'K';
    status_flags[SERVER_BUSY_LOG] = 'L';
    status_flags[SERVER_BUSY_DNS] = 'D';
    status_flags[SERVER_CLOSING] = 'C';
    status_flags[SERVER_GRACEFUL] = 'G';
    status_flags[SERVER_IDLE_KILL] = 'I';
    status_flags[SERVER_DISABLED] = ' ';
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &threads_per_child);
    /* work around buggy MPMs */
    if (threads_per_child == 0)
        threads_per_child = 1;
    ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_servers);
    ap_mpm_query(AP_MPMQ_IS_ASYNC, &is_async);
    return OK;
}

#ifdef HAVE_TIMES
static void status_child_init(apr_pool_t *p, server_rec *s)
{
    child_pid = getpid();
}
#endif

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(status_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(status_pre_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_post_config(status_init, NULL, NULL, APR_HOOK_MIDDLE);
#ifdef HAVE_TIMES
    ap_hook_child_init(status_child_init, NULL, NULL, APR_HOOK_MIDDLE);
#endif
}

AP_DECLARE_MODULE(status) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    NULL,                       /* command table */
    register_hooks              /* register_hooks */
};
