/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
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

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_conf_globals.h"	/* for ap_extended_status */
#include "http_main.h"
#include "util_script.h"
#include <time.h>
#include "scoreboard.h"
#include "http_log.h"

#ifdef NEXT
#if (NX_CURRENT_COMPILER_RELEASE == 410)
#ifdef m68k
#define HZ 64
#else
#define HZ 100
#endif
#else
#include <machine/param.h>
#endif
#endif /* NEXT */

#define STATUS_MAXLINE		64

#define KBYTE			1024
#define	MBYTE			1048576L
#define	GBYTE			1073741824L

#ifndef DEFAULT_TIME_FORMAT 
#define DEFAULT_TIME_FORMAT "%A, %d-%b-%Y %H:%M:%S %Z"
#endif

module MODULE_VAR_EXPORT status_module;

/*
 *command-related code. This is here to prevent use of ExtendedStatus
 * without status_module included.
 */
static const char *set_extended_status(cmd_parms *cmd, void *dummy, int arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    ap_extended_status = arg;
    return NULL;
}

static const command_rec status_module_cmds[] =
{
    { "ExtendedStatus", set_extended_status, NULL, RSRC_CONF, FLAG,
      "\"On\" to enable extended status information, \"Off\" to disable" },
    {NULL}
};

/* Format the number of bytes nicely */
static void format_byte_out(request_rec *r, unsigned long bytes)
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

static void format_kbyte_out(request_rec *r, unsigned long kbytes)
{
    if (kbytes < KBYTE)
	ap_rprintf(r, "%d kB", (int) kbytes);
    else if (kbytes < MBYTE)
	ap_rprintf(r, "%.1f MB", (float) kbytes / KBYTE);
    else
	ap_rprintf(r, "%.1f GB", (float) kbytes / MBYTE);
}

static void show_time(request_rec *r, time_t tsecs)
{
    long days, hrs, mins, secs;

    secs = tsecs % 60;
    tsecs /= 60;
    mins = tsecs % 60;
    tsecs /= 60;
    hrs = tsecs % 24;
    days = tsecs / 24;
    if (days)
	ap_rprintf(r, " %ld day%s", days, days == 1 ? "" : "s");
    if (hrs)
	ap_rprintf(r, " %ld hour%s", hrs, hrs == 1 ? "" : "s");
    if (mins)
	ap_rprintf(r, " %ld minute%s", mins, mins == 1 ? "" : "s");
    if (secs)
	ap_rprintf(r, " %ld second%s", secs, secs == 1 ? "" : "s");
}

/* Main handler for x-httpd-status requests */

/* ID values for command table */

#define STAT_OPT_END		-1
#define STAT_OPT_REFRESH	0
#define STAT_OPT_NOTABLE	1
#define STAT_OPT_AUTO		2

struct stat_opt {
    int id;
    const char *form_data_str;
    const char *hdr_out_str;
};

static const struct stat_opt status_options[] =	/* see #defines above */
{
    {STAT_OPT_REFRESH, "refresh", "Refresh"},
    {STAT_OPT_NOTABLE, "notable", NULL},
    {STAT_OPT_AUTO, "auto", NULL},
    {STAT_OPT_END, NULL, NULL}
};

static char status_flags[SERVER_NUM_STATUS];

static int status_handler(request_rec *r)
{
    char *loc;
    time_t nowtime = time(NULL);
    time_t up_time;
    int i, res;
    int ready = 0;
    int busy = 0;
    unsigned long count = 0;
    unsigned long lres, bytes;
    unsigned long my_lres, my_bytes, conn_bytes;
    unsigned short conn_lres;
    unsigned long bcount = 0;
    unsigned long kbcount = 0;
    long req_time;
#ifndef NO_TIMES
#ifdef _SC_CLK_TCK
    float tick = sysconf(_SC_CLK_TCK);
#else
    float tick = HZ;
#endif
#endif
    int short_report = 0;
    int no_table_report = 0;
    short_score score_record;
    parent_score ps_record;
    char stat_buffer[HARD_SERVER_LIMIT];
    int pid_buffer[HARD_SERVER_LIMIT];
    clock_t tu, ts, tcu, tcs;
    server_rec *vhost;

    tu = ts = tcu = tcs = 0;

    if (!ap_exists_scoreboard_image()) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		    "Server status unavailable in inetd mode");
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    r->allowed = (1 << M_GET);
    if (r->method_number != M_GET)
	return DECLINED;

    r->content_type = "text/html";

    /*
     * Simple table-driven form data set parser that lets you alter the header
     */

    if (r->args) {
	i = 0;
	while (status_options[i].id != STAT_OPT_END) {
	    if ((loc = strstr(r->args, status_options[i].form_data_str)) != NULL) {
		switch (status_options[i].id) {
		case STAT_OPT_REFRESH:
		    if (*(loc + strlen(status_options[i].form_data_str)) == '='
                        && atol(loc + strlen(status_options[i].form_data_str) 
                                    + 1) > 0)
			ap_table_set(r->headers_out,
			      status_options[i].hdr_out_str,
			      loc + strlen(status_options[i].hdr_out_str) + 1);
		    else
			ap_table_set(r->headers_out,
			      status_options[i].hdr_out_str, "1");
		    break;
		case STAT_OPT_NOTABLE:
		    no_table_report = 1;
		    break;
		case STAT_OPT_AUTO:
		    r->content_type = "text/plain";
		    short_report = 1;
		    break;
		}
	    }
	    i++;
	}
    }

    ap_send_http_header(r);
#ifdef CHARSET_EBCDIC
    /* Server-generated response, converted */
    ap_bsetflag(r->connection->client, B_EBCDIC2ASCII, r->ebcdic.conv_out = 1);
#endif

    if (r->header_only)
	return 0;

    ap_sync_scoreboard_image();
    for (i = 0; i < HARD_SERVER_LIMIT; ++i) {
	score_record = ap_scoreboard_image->servers[i];
	ps_record = ap_scoreboard_image->parent[i];
	res = score_record.status;
	stat_buffer[i] = status_flags[res];
	pid_buffer[i] = (int) ps_record.pid;
	if (res == SERVER_READY)
	    ready++;
	else if (res != SERVER_DEAD)
	    busy++;
	if (ap_extended_status) {
	    lres = score_record.access_count;
	    bytes = score_record.bytes_served;
	    if (lres != 0 || (res != SERVER_READY && res != SERVER_DEAD)) {
#ifndef NO_TIMES
		tu += score_record.times.tms_utime;
		ts += score_record.times.tms_stime;
		tcu += score_record.times.tms_cutime;
		tcs += score_record.times.tms_cstime;
#endif /* NO_TIMES */
		count += lres;
		bcount += bytes;
		if (bcount >= KBYTE) {
		    kbcount += (bcount >> 10);
		    bcount = bcount & 0x3ff;
		}
	    }
	}
    }

    up_time = nowtime - ap_restart_time;

    ap_hard_timeout("send status info", r);

    if (!short_report) {
	ap_rputs(DOCTYPE_HTML_3_2
		 "<HTML><HEAD>\n<TITLE>Apache Status</TITLE>\n</HEAD><BODY>\n",
		 r);
	ap_rputs("<H1>Apache Server Status for ", r);
	ap_rvputs(r, ap_get_server_name(r), "</H1>\n\n", NULL);
	ap_rvputs(r, "Server Version: ",
	  ap_get_server_version(), "<br>\n", NULL);
	ap_rvputs(r, "Server Built: ",
	  ap_get_server_built(), "<br>\n<hr>\n", NULL);
	ap_rvputs(r, "Current Time: ",
	  ap_ht_time(r->pool, nowtime, DEFAULT_TIME_FORMAT, 0), "<br>\n", NULL);
	ap_rvputs(r, "Restart Time: ",
	  ap_ht_time(r->pool, ap_restart_time, DEFAULT_TIME_FORMAT, 0), 
	  "<br>\n", NULL);
	ap_rprintf(r, "Parent Server Generation: %d <br>\n", (int) ap_my_generation);
	ap_rputs("Server uptime: ", r);
	show_time(r, up_time);
	ap_rputs("<br>\n", r);
    }

    if (ap_extended_status) {
	if (short_report) {
	    ap_rprintf(r, "Total Accesses: %lu\nTotal kBytes: %lu\n",
		count, kbcount);

#ifndef NO_TIMES
	    /* Allow for OS/2 not having CPU stats */
	    if (ts || tu || tcu || tcs)
		ap_rprintf(r, "CPULoad: %g\n",
		    (tu + ts + tcu + tcs) / tick / up_time * 100.);
#endif

	    ap_rprintf(r, "Uptime: %ld\n", (long) (up_time));
	    if (up_time > 0)
		ap_rprintf(r, "ReqPerSec: %g\n",
		    (float) count / (float) up_time);

	    if (up_time > 0)
		ap_rprintf(r, "BytesPerSec: %g\n",
		    KBYTE * (float) kbcount / (float) up_time);

	    if (count > 0)
		ap_rprintf(r, "BytesPerReq: %g\n",
		    KBYTE * (float) kbcount / (float) count);
	}
	else {			/* !short_report */
	    ap_rprintf(r, "Total accesses: %lu - Total Traffic: ", count);
	    format_kbyte_out(r, kbcount);

#ifndef NO_TIMES
	    /* Allow for OS/2 not having CPU stats */
	    ap_rputs("<br>\n", r);
	    ap_rprintf(r, "CPU Usage: u%g s%g cu%g cs%g",
		    tu / tick, ts / tick, tcu / tick, tcs / tick);

	    if (ts || tu || tcu || tcs)
		ap_rprintf(r, " - %.3g%% CPU load",
		    (tu + ts + tcu + tcs) / tick / up_time * 100.);
#endif

	    ap_rputs("<br>\n", r);

	    if (up_time > 0)
		ap_rprintf(r, "%.3g requests/sec - ",
			(float) count / (float) up_time);

	    if (up_time > 0) {
		format_byte_out(r, (unsigned long) (KBYTE * (float) kbcount 
                                                          / (float) up_time));
		ap_rputs("/second - ", r);
	    }

	    if (count > 0) {
		format_byte_out(r, (unsigned long) (KBYTE * (float) kbcount 
                                                          / (float) count));
		ap_rputs("/request", r);
	    }

	    ap_rputs("<br>\n", r);
	}				/* short_report */
    }					/* ap_extended_status */

    if (!short_report)
	ap_rprintf(r, "\n%d requests currently being processed, %d idle servers\n"
		,busy, ready);
    else
	ap_rprintf(r, "BusyServers: %d\nIdleServers: %d\n", busy, ready);

    /* send the scoreboard 'table' out */

    if (!short_report)
	ap_rputs("<PRE>", r);
    else
	ap_rputs("Scoreboard: ", r);

    for (i = 0; i < HARD_SERVER_LIMIT; ++i) {
	ap_rputc(stat_buffer[i], r);
	if ((i % STATUS_MAXLINE == (STATUS_MAXLINE - 1)) && !short_report)
	    ap_rputs("\n", r);
    }

    if (short_report)
	ap_rputs("\n", r);
    else {
	ap_rputs("</PRE>\n", r);
	ap_rputs("Scoreboard Key: <br>\n", r);
	ap_rputs("\"<B><code>_</code></B>\" Waiting for Connection, \n", r);
	ap_rputs("\"<B><code>S</code></B>\" Starting up, \n", r);
	ap_rputs("\"<B><code>R</code></B>\" Reading Request,<BR>\n", r);
	ap_rputs("\"<B><code>W</code></B>\" Sending Reply, \n", r);
	ap_rputs("\"<B><code>K</code></B>\" Keepalive (read), \n", r);
	ap_rputs("\"<B><code>D</code></B>\" DNS Lookup,<BR>\n", r);
	ap_rputs("\"<B><code>L</code></B>\" Logging, \n", r);
	ap_rputs("\"<B><code>G</code></B>\" Gracefully finishing, \n", r);
	ap_rputs("\"<B><code>.</code></B>\" Open slot with no current process<P>\n", r);
	ap_rputs("<P>\n", r);
	if (!ap_extended_status) {
	    int j = 0;
	    ap_rputs("PID Key: <br>\n", r);
	    ap_rputs("<PRE>\n", r);
	    for (i = 0; i < HARD_SERVER_LIMIT; ++i) {
		if (stat_buffer[i] != '.') {
		    ap_rprintf(r, "   %d in state: %c ", pid_buffer[i],
		     stat_buffer[i]);
		    if (++j >= 3) {
		    	ap_rputs("\n", r);
			j = 0;
		    } else
		    	ap_rputs(",", r);
		}
	    }
	    ap_rputs("\n", r);
	    ap_rputs("</PRE>\n", r);
	}
    }

    if (ap_extended_status) {
	if (!short_report) {
	    if (no_table_report)
		ap_rputs("<p><hr><h2>Server Details</h2>\n\n", r);
	    else
#ifdef NO_TIMES
		/* Allow for OS/2 not having CPU stats */
		ap_rputs("<p>\n\n<table border=0><tr><th>Srv<th>PID<th>Acc<th>M\n<th>SS<th>Req<th>Conn<th>Child<th>Slot<th>Client<th>VHost<th>Request</tr>\n\n", r);
#else
		ap_rputs("<p>\n\n<table border=0><tr><th>Srv<th>PID<th>Acc<th>M<th>CPU\n<th>SS<th>Req<th>Conn<th>Child<th>Slot<th>Client<th>VHost<th>Request</tr>\n\n", r);
#endif
	}

	for (i = 0; i < HARD_SERVER_LIMIT; ++i) {
	    score_record = ap_scoreboard_image->servers[i];
	    ps_record = ap_scoreboard_image->parent[i];
	    vhost = score_record.vhostrec;
	    if (ps_record.generation != ap_my_generation) {
		vhost = NULL;
	    }

#if defined(NO_GETTIMEOFDAY)
#ifndef NO_TIMES
	    if (score_record.start_time == (clock_t) 0)
#endif /* NO_TIMES */
		req_time = 0L;
#ifndef NO_TIMES
	    else {
		req_time = score_record.stop_time - score_record.start_time;
		req_time = (req_time * 1000) / (int) tick;
	    }
#endif /* NO_TIMES */
#else
	    if (score_record.start_time.tv_sec == 0L &&
		score_record.start_time.tv_usec == 0L)
		req_time = 0L;
	    else
		req_time =
		    ((score_record.stop_time.tv_sec - score_record.start_time.tv_sec) * 1000) +
		    ((score_record.stop_time.tv_usec - score_record.start_time.tv_usec) / 1000);
#endif
	    if (req_time < 0L)
		req_time = 0L;

	    lres = score_record.access_count;
	    my_lres = score_record.my_access_count;
	    conn_lres = score_record.conn_count;
	    bytes = score_record.bytes_served;
	    my_bytes = score_record.my_bytes_served;
	    conn_bytes = score_record.conn_bytes;
	    if (lres != 0 || (score_record.status != SERVER_READY
			      && score_record.status != SERVER_DEAD)) {
		if (!short_report) {
		    if (no_table_report) {
			if (score_record.status == SERVER_DEAD)
#ifdef TPF
                            if (kill(ps_record.pid, 0) == 0) {
                                /* on TPF show PIDs of the living dead */
                                ap_rprintf(r,
                                "<b>Server %d-%d</b> (%d): %d|%lu|%lu [",
                                i, (int) ps_record.generation,
                                (int)ps_record.pid, (int) conn_lres,
                                my_lres, lres);
                            } else
#endif /* TPF */
			    ap_rprintf(r,
				"<b>Server %d-%d</b> (-): %d|%lu|%lu [",
				i, (int) ps_record.generation, (int) conn_lres,
				my_lres, lres);
			else
			    ap_rprintf(r,
				"<b>Server %d-%d</b> (%d): %d|%lu|%lu [",
				i, (int) ps_record.generation,
				(int) ps_record.pid,
				(int) conn_lres, my_lres, lres);

			switch (score_record.status) {
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
			case SERVER_DEAD:
			    ap_rputs("Dead", r);
			    break;
			case SERVER_GRACEFUL:
			    ap_rputs("Graceful", r);
			    break;
			default:
			    ap_rputs("?STATE?", r);
			    break;
			}
#ifdef NO_TIMES
			/* Allow for OS/2 not having CPU stats */
			ap_rprintf(r, "]\n %.0f %ld (",
#else

			ap_rprintf(r, "] u%g s%g cu%g cs%g\n %.0f %ld (",
			    score_record.times.tms_utime / tick,
			    score_record.times.tms_stime / tick,
			    score_record.times.tms_cutime / tick,
			    score_record.times.tms_cstime / tick,
#endif
#ifdef OPTIMIZE_TIMEOUTS
			    difftime(nowtime, ps_record.last_rtime),
#else
			    difftime(nowtime, score_record.last_used),
#endif
			    (long) req_time);
			format_byte_out(r, conn_bytes);
			ap_rputs("|", r);
			format_byte_out(r, my_bytes);
			ap_rputs("|", r);
			format_byte_out(r, bytes);
			ap_rputs(")\n", r);
			ap_rprintf(r, " <i>%s {%s}</i> <b>[%s]</b><br>\n\n",
			    ap_escape_html(r->pool, score_record.client),
			    ap_escape_html(r->pool, score_record.request),
			    vhost ? ap_escape_html(r->pool, 
				vhost->server_hostname) : "(unavailable)");
		    }
		    else {		/* !no_table_report */
			if (score_record.status == SERVER_DEAD)
#ifdef TPF
                            if (kill(ps_record.pid, 0) == 0) {
                                /* on TPF show PIDs of the living dead */
                                ap_rprintf(r,
                                    "<tr><td><b>%d-%d</b><td>%d<td>%d/%lu/%lu",
                                    i, (int) ps_record.generation,
                                    (int) ps_record.pid,
                                    (int) conn_lres, my_lres, lres);
                            } else
#endif /* TPF */
			    ap_rprintf(r,
				"<tr><td><b>%d-%d</b><td>-<td>%d/%lu/%lu",
				i, (int) ps_record.generation,
				(int) conn_lres, my_lres, lres);
			else
			    ap_rprintf(r,
				"<tr><td><b>%d-%d</b><td>%d<td>%d/%lu/%lu",
				i, (int) ps_record.generation,
				(int) ps_record.pid, (int) conn_lres,
				my_lres, lres);

			switch (score_record.status) {
			case SERVER_READY:
			    ap_rputs("<td>_", r);
			    break;
			case SERVER_STARTING:
			    ap_rputs("<td><b>S</b>", r);
			    break;
			case SERVER_BUSY_READ:
			    ap_rputs("<td><b>R</b>", r);
			    break;
			case SERVER_BUSY_WRITE:
			    ap_rputs("<td><b>W</b>", r);
			    break;
			case SERVER_BUSY_KEEPALIVE:
			    ap_rputs("<td><b>K</b>", r);
			    break;
			case SERVER_BUSY_LOG:
			    ap_rputs("<td><b>L</b>", r);
			    break;
			case SERVER_BUSY_DNS:
			    ap_rputs("<td><b>D</b>", r);
			    break;
			case SERVER_DEAD:
			    ap_rputs("<td>.", r);
			    break;
			case SERVER_GRACEFUL:
			    ap_rputs("<td>G", r);
			    break;
			default:
			    ap_rputs("<td>?", r);
			    break;
			}
#ifdef NO_TIMES
			/* Allow for OS/2 not having CPU stats */
			ap_rprintf(r, "\n<td>%.0f<td>%ld",
#else
			ap_rprintf(r, "\n<td>%.2f<td>%.0f<td>%ld",
			    (score_record.times.tms_utime +
			     score_record.times.tms_stime +
			     score_record.times.tms_cutime +
			     score_record.times.tms_cstime) / tick,
#endif
#ifdef OPTIMIZE_TIMEOUTS
			    difftime(nowtime, ps_record.last_rtime),
#else
			    difftime(nowtime, score_record.last_used),
#endif
			    (long) req_time);
			ap_rprintf(r, "<td>%-1.1f<td>%-2.2f<td>%-2.2f\n",
			   (float) conn_bytes / KBYTE, (float) my_bytes / MBYTE,
			    (float) bytes / MBYTE);
			if (score_record.status == SERVER_BUSY_READ)
			    ap_rprintf(r,
			     "<td>?<td nowrap>?<td nowrap>..reading.. </tr>\n\n");
			else
			    ap_rprintf(r,
			     "<td>%s<td nowrap>%s<td nowrap>%s</tr>\n\n",
			     ap_escape_html(r->pool, score_record.client),
			     vhost ? ap_escape_html(r->pool, 
				vhost->server_hostname) : "(unavailable)",
			     ap_escape_html(r->pool, score_record.request));
		    }		/* no_table_report */
		}			/* !short_report */
	    }			/* if (<active child>) */
	}				/* for () */

	if (!(short_report || no_table_report)) {
#ifdef NO_TIMES
	    ap_rputs("</table>\n \
<hr> \
<table>\n \
<tr><th>Srv<td>Child Server number - generation\n \
<tr><th>PID<td>OS process ID\n \
<tr><th>Acc<td>Number of accesses this connection / this child / this slot\n \
<tr><th>M<td>Mode of operation\n \
<tr><th>SS<td>Seconds since beginning of most recent request\n \
<tr><th>Req<td>Milliseconds required to process most recent request\n \
<tr><th>Conn<td>Kilobytes transferred this connection\n \
<tr><th>Child<td>Megabytes transferred this child\n \
<tr><th>Slot<td>Total megabytes transferred this slot\n \
</table>\n", r);
#else
	    ap_rputs("</table>\n \
<hr> \
<table>\n \
<tr><th>Srv<td>Child Server number - generation\n \
<tr><th>PID<td>OS process ID\n \
<tr><th>Acc<td>Number of accesses this connection / this child / this slot\n \
<tr><th>M<td>Mode of operation\n \
<tr><th>CPU<td>CPU usage, number of seconds\n \
<tr><th>SS<td>Seconds since beginning of most recent request\n \
<tr><th>Req<td>Milliseconds required to process most recent request\n \
<tr><th>Conn<td>Kilobytes transferred this connection\n \
<tr><th>Child<td>Megabytes transferred this child\n \
<tr><th>Slot<td>Total megabytes transferred this slot\n \
</table>\n", r);
#endif
	}

    } else {

	if (!short_report) {
	    ap_rputs("<hr>To obtain a full report with current status information ", r);
	    ap_rputs("you need to use the <code>ExtendedStatus On</code> directive. \n", r);
	}

    }

    if (!short_report) {
	ap_rputs(ap_psignature("<HR>\n",r), r);
	ap_rputs("</BODY></HTML>\n", r);
    }

    ap_kill_timeout(r);
    return 0;
}


static void status_init(server_rec *s, pool *p)
{
    status_flags[SERVER_DEAD] = '.';	/* We don't want to assume these are in */
    status_flags[SERVER_READY] = '_';	/* any particular order in scoreboard.h */
    status_flags[SERVER_STARTING] = 'S';
    status_flags[SERVER_BUSY_READ] = 'R';
    status_flags[SERVER_BUSY_WRITE] = 'W';
    status_flags[SERVER_BUSY_KEEPALIVE] = 'K';
    status_flags[SERVER_BUSY_LOG] = 'L';
    status_flags[SERVER_BUSY_DNS] = 'D';
    status_flags[SERVER_GRACEFUL] = 'G';
}

static const handler_rec status_handlers[] =
{
    {STATUS_MAGIC_TYPE, status_handler},
    {"server-status", status_handler},
    {NULL}
};

module MODULE_VAR_EXPORT status_module =
{
    STANDARD_MODULE_STUFF,
    status_init,		/* initializer */
    NULL,			/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server config */
    status_module_cmds,		/* command table */
    status_handlers,		/* handlers */
    NULL,			/* filename translation */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};

