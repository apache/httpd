/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
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
             extended STATUS is enabled) [George Burgyan/Jim J.]  */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "util_script.h"
#include <time.h>
#include "scoreboard.h"
#include "http_log.h"

#ifdef NEXT
#include <machine/param.h>
#endif

#define STATUS_MAXLINE		64

#define KBYTE			1024
#define	MBYTE			1048576L
#define	GBYTE			1073741824L

module status_module;

/* Format the number of bytes nicely */

void format_byte_out(request_rec *r,unsigned long bytes)
{
    if (bytes < (5 * KBYTE))
	rprintf(r,"%d B",(int)bytes);
    else if (bytes < (MBYTE / 2))
	rprintf(r,"%.1f kB",(float)bytes/KBYTE);
    else if (bytes < (GBYTE / 2))
	rprintf(r,"%.1f MB",(float)bytes/MBYTE);
    else
	rprintf(r,"%.1f GB",(float)bytes/GBYTE);
}

void format_kbyte_out(request_rec *r,unsigned long kbytes)
{
    if (kbytes < KBYTE)
	rprintf(r,"%d kB",(int)kbytes);
    else if (kbytes < MBYTE)
	rprintf(r,"%.1f MB",(float)kbytes/KBYTE);
    else
	rprintf(r,"%.1f GB",(float)kbytes/MBYTE);
}

void show_time(request_rec *r,time_t tsecs)
{
    long days,hrs,mins,secs;
    char buf[100];
    char *s;

    secs=tsecs%60;
    tsecs/=60;
    mins=tsecs%60;
    tsecs/=60;
    hrs=tsecs%24;
    days=tsecs/24;
    s=buf;
    *s='\0';
    if(days)
	rprintf(r," %ld day%s",days,days==1?"":"s");
    if(hrs)
	rprintf(r," %ld hour%s",hrs,hrs==1?"":"s");
    if(mins)
	rprintf(r," %ld minute%s",mins,mins==1?"":"s");
    if(secs)
	rprintf(r," %ld second%s",secs,secs==1?"":"s");
}

#if defined(SUNOS4)
double
difftime(time1, time0)
        time_t time1, time0;
{   
        return(time1 - time0);
}   
#endif
    
/* Main handler for x-httpd-status requests */

/* ID values for command table */

#define STAT_OPT_END		-1
#define STAT_OPT_REFRESH	0
#define STAT_OPT_NOTABLE	1
#define STAT_OPT_AUTO		2

struct stat_opt
{
    int id;
    char *form_data_str;
    char *hdr_out_str;
};

int status_handler (request_rec *r)
{
    struct stat_opt options[] =        /* see #defines above */
    {
	{ STAT_OPT_REFRESH, "refresh", "Refresh" },
        { STAT_OPT_NOTABLE, "notable", NULL },
        { STAT_OPT_AUTO, "auto", NULL },
	{ STAT_OPT_END, NULL, NULL }
    };
    char *loc;
    time_t nowtime=time(NULL);
    time_t up_time;
    int i,res;
    int ready=0;
    int busy=0;
#if defined(STATUS)
    unsigned long count=0;
    unsigned long lres,bytes;
    unsigned long my_lres,my_bytes,conn_bytes;
    unsigned short conn_lres;
    unsigned long bcount=0;
    unsigned long kbcount=0;
#ifdef NEXT
    float tick=HZ;
#else
    float tick=sysconf(_SC_CLK_TCK);
#endif
#endif /* STATUS */
    int short_report=0;
    int no_table_report=0;
    server_rec *server = r->server;
    short_score score_record;
    char status[]="??????????";
    char stat_buffer[HARD_SERVER_LIMIT];
    clock_t tu,ts,tcu,tcs;

    tu=ts=tcu=tcs=0;

    status[SERVER_DEAD]='.';  /* We don't want to assume these are in */
    status[SERVER_READY]='_'; /* any particular order in scoreboard.h */
    status[SERVER_STARTING]='S';
    status[SERVER_BUSY_READ]='R';
    status[SERVER_BUSY_WRITE]='W';
    status[SERVER_BUSY_KEEPALIVE]='K';
    status[SERVER_BUSY_LOG]='L';
    status[SERVER_BUSY_DNS]='D';
    status[SERVER_GRACEFUL]='G';

    if (!exists_scoreboard_image()) {
         log_printf(r->server, "Server status unavailable in inetd mode");
         return HTTP_NOT_IMPLEMENTED;
     }
    r->allowed = (1 << M_GET) | (1 << M_TRACE);
    if (r->method_number != M_GET) return HTTP_METHOD_NOT_ALLOWED;

    r->content_type = "text/html";

    /*
     * Simple table-driven form data set parser that lets you alter the header
     */

    if (r->args)
    {
	i = 0;
        while (options[i].id != STAT_OPT_END)
        {
            if ((loc = strstr(r->args,options[i].form_data_str)) != NULL)
	    {
                switch (options[i].id)
                {
                  case STAT_OPT_REFRESH:
                      if(*(loc + strlen(options[i].form_data_str)) == '=')
                          table_set(r->headers_out,options[i].hdr_out_str,
			    loc+strlen(options[i].hdr_out_str)+1);
                      else
                          table_set(r->headers_out,options[i].hdr_out_str,"1");
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

    send_http_header(r);

    if (r->header_only) 
	return 0;

    sync_scoreboard_image();
    for (i = 0; i<HARD_SERVER_LIMIT; ++i)
    {
        score_record = get_scoreboard_info(i);
        res = score_record.status;
	stat_buffer[i] = status[res];
        if (res == SERVER_READY)
	    ready++;
        else if (res == SERVER_BUSY_READ || res==SERVER_BUSY_WRITE || 
		 res == SERVER_STARTING || res==SERVER_BUSY_KEEPALIVE ||
		 res == SERVER_BUSY_LOG || res==SERVER_BUSY_DNS ||
		 res == SERVER_GRACEFUL)
	    busy++;
#if defined(STATUS)
        lres = score_record.access_count;
	bytes= score_record.bytes_served;
        if (lres!=0 || (score_record.status != SERVER_READY
	  && score_record.status != SERVER_DEAD))
	{
	    tu+=score_record.times.tms_utime;
	    ts+=score_record.times.tms_stime;
	    tcu+=score_record.times.tms_cutime;
	    tcs+=score_record.times.tms_cstime;
            count+=lres;
	    bcount+=bytes;
	    if (bcount>=KBYTE) {
	    	kbcount += (bcount >> 10);
		bcount = bcount & 0x3ff;
	    }
	}
#endif /* STATUS */
    }

    up_time=nowtime-restart_time;

    hard_timeout("send status info", r);

    if (!short_report)
    {
        rputs("<HTML><HEAD>\n<TITLE>Apache Status</TITLE>\n</HEAD><BODY>\n",r);
        rputs("<H1>Apache Server Status for ",r);
	rvputs(r,server->server_hostname,"</H1>\n\n",NULL);
	rvputs(r,"Current Time: ",asctime(localtime(&nowtime)),"<br>\n",NULL);
	rvputs(r,"Restart Time: ",asctime(localtime(&restart_time)),"<br>\n",
	       NULL);
	rputs("Server uptime: ",r);
	show_time(r,up_time);
	rputs("<br>\n",r);
    }

#if defined(STATUS)
    if (short_report)
    {
        rprintf(r,"Total Accesses: %lu\nTotal kBytes: %lu\n",count,kbcount);

#ifndef __EMX__
    /* Allow for OS/2 not having CPU stats */
	if(ts || tu || tcu || tcs)
	    rprintf(r,"CPULoad: %g\n",(tu+ts+tcu+tcs)/tick/up_time*100.);
#endif

	rprintf(r,"Uptime: %ld\n",(long)(up_time));
	if (up_time>0)
	    rprintf(r,"ReqPerSec: %g\n",(float)count/(float)up_time);

	if (up_time>0)
	    rprintf(r,"BytesPerSec: %g\n",KBYTE*(float)kbcount/(float)up_time);

	if (count>0)
	    rprintf(r,"BytesPerReq: %g\n",KBYTE*(float)kbcount/(float)count);
    } else /* !short_report */
    {
	rprintf(r,"Total accesses: %lu - Total Traffic: ", count);
	format_kbyte_out(r,kbcount);

#ifndef __EMX__
	/* Allow for OS/2 not having CPU stats */
	rputs("<br>\n",r);
        rprintf(r,"CPU Usage: u%g s%g cu%g cs%g",
		tu/tick,ts/tick,tcu/tick,tcs/tick);

	if(ts || tu || tcu || tcs)
	    rprintf(r," - %.3g%% CPU load",(tu+ts+tcu+tcs)/tick/up_time*100.);
#endif

	rputs("<br>\n",r);

	if (up_time>0)
	    rprintf(r,"%.3g requests/sec - ",
		    (float)count/(float)up_time);

	if (up_time>0)
	{
	    format_byte_out(r,KBYTE*(float)kbcount/(float)up_time);
	    rputs("/second - ",r);
	}

	if (count>0)
	{
	    format_byte_out(r,KBYTE*(float)kbcount/(float)count);
	    rputs("/request",r);
	}

	rputs("<br>\n",r);
    } /* short_report */
#endif /* STATUS */

    if (!short_report)
        rprintf(r,"\n%d requests currently being processed, %d idle servers\n"
		,busy,ready);
    else
        rprintf(r,"BusyServers: %d\nIdleServers: %d\n",busy,ready);

    /* send the scoreboard 'table' out */

    if(!short_report)
	rputs("<PRE>",r);
    else
        rputs("Scoreboard: ",r);

    for (i = 0; i<HARD_SERVER_LIMIT; ++i)
    {
	rputc(stat_buffer[i], r);
	if((i%STATUS_MAXLINE == (STATUS_MAXLINE - 1))&&!short_report)
	    rputs("\n",r);
    }

    if (short_report)
        rputs("\n",r);
    else {
	rputs("</PRE>\n",r);
	rputs("Scoreboard Key: <br>\n",r);
	rputs("\"<B><code>_</code></B>\" Waiting for Connection, \n",r);
	rputs("\"<B><code>S</code></B>\" Starting up, \n",r);
	rputs("\"<B><code>R</code></B>\" Reading Request,<BR>\n",r);
	rputs("\"<B><code>W</code></B>\" Sending Reply, \n",r);
	rputs("\"<B><code>K</code></B>\" Keepalive (read), \n",r);
	rputs("\"<B><code>D</code></B>\" DNS Lookup,<BR>\n",r);
	rputs("\"<B><code>L</code></B>\" Logging, \n",r);
	rputs("\"<B><code>G</code></B>\" Gracefully finishing, \n",r);
	rputs("\"<B><code>.</code></B>\" Open slot with no current process<P>\n",r);
    }

#if defined(STATUS)
    if (!short_report)
    	if(no_table_report)
            rputs("<p><hr><h2>Server Details</h2>\n\n",r);
	else
#ifdef __EMX__
            /* Allow for OS/2 not having CPU stats */
            rputs("<p>\n\n<table border=0><tr><th>Srv<th>PID<th>Acc<th>M\n<th>SS<th>Conn<th>Child<th>Slot<th>Host<th>VHost<th>Request</tr>\n\n",r);
#else
            rputs("<p>\n\n<table border=0><tr><th>Srv<th>PID<th>Acc<th>M<th>CPU\n<th>SS<th>Conn<th>Child<th>Slot<th>Host<th>VHost<th>Request</tr>\n\n",r);
#endif


    for (i = 0; i<HARD_SERVER_LIMIT; ++i)
    {
        score_record=get_scoreboard_info(i);
        lres = score_record.access_count;
        my_lres = score_record.my_access_count;
	conn_lres = score_record.conn_count;
	bytes= score_record.bytes_served;
	my_bytes = score_record.my_bytes_served;
	conn_bytes = score_record.conn_bytes;
        if (lres!=0 || (score_record.status != SERVER_READY
		&& score_record.status != SERVER_DEAD))
	{
	    if (!short_report)
	    {
		if (no_table_report)
		{
	            rprintf(r,"<b>Server %d</b> (%d): %d|%lu|%lu [",
		     i,(int)score_record.pid,(int)conn_lres,my_lres,lres);

		    switch (score_record.status)
		    {
		        case SERVER_READY:
		            rputs("Ready",r);
		            break;
		        case SERVER_STARTING:
		            rputs("Starting",r);
		            break;
		        case SERVER_BUSY_READ:
		            rputs("<b>Read</b>",r);
		            break;
		        case SERVER_BUSY_WRITE:
		            rputs("<b>Write</b>",r);
		            break;
		        case SERVER_BUSY_KEEPALIVE:
		            rputs("<b>Keepalive</b>",r);
		            break;
		        case SERVER_BUSY_LOG:
		            rputs("<b>Logging</b>",r);
		            break;
		        case SERVER_BUSY_DNS:
		            rputs("<b>DNS lookup</b>",r);
		            break;
		        case SERVER_DEAD:
		            rputs("Dead",r);
		            break;
			case SERVER_GRACEFUL:
			    rputs("Graceful",r);
			    break;
			default:
			    rputs("?STATE?",r);
			    break;
		    }
#ifdef __EMX__
                    /* Allow for OS/2 not having CPU stats */
                    rprintf(r,"]\n %s (",
#else

		    rprintf(r,"] u%g s%g cu%g cs%g\n %s (",
			    score_record.times.tms_utime/tick,
			    score_record.times.tms_stime/tick,
			    score_record.times.tms_cutime/tick,
			    score_record.times.tms_cstime/tick,
#endif
			    asctime(localtime(&score_record.last_used)));
		    format_byte_out(r,conn_bytes);
		    rputs("|",r);
		    format_byte_out(r,my_bytes);
		    rputs("|",r);
		    format_byte_out(r,bytes);
		    rputs(")\n",r);
		    rprintf(r," <i>%s {%s}</i><br>\n\n",
			    score_record.client,
			    escape_html(r->pool, score_record.request));
		}
		else /* !no_table_report */
		{
	            rprintf(r,"<tr><td><b>%d</b><td>%d<td>%d/%lu/%lu",
		     i,(int)score_record.pid,(int)conn_lres,my_lres,lres);

		    switch (score_record.status)
		    {
		        case SERVER_READY:
		            rputs("<td>_",r);
		            break;
		        case SERVER_STARTING:
		            rputs("<td><b>S</b>",r);
		            break;
		        case SERVER_BUSY_READ:
		            rputs("<td><b>R</b>",r);
		            break;
		        case SERVER_BUSY_WRITE:
		            rputs("<td><b>W</b>",r);
		            break;
		        case SERVER_BUSY_KEEPALIVE:
		            rputs("<td><b>K</b>",r);
		            break;
		        case SERVER_BUSY_LOG:
		            rputs("<td><b>L</b>",r);
		            break;
		        case SERVER_BUSY_DNS:
		            rputs("<td><b>D</b>",r);
		            break;
		        case SERVER_DEAD:
		            rputs("<td>.",r);
		            break;
			case SERVER_GRACEFUL:
			    rputs("<td>G",r);
			    break;
			default:
			    rputs("<td>?",r);
			    break;
		    }
#ifdef __EMX__
	            /* Allow for OS/2 not having CPU stats */
        	    rprintf(r,"\n<td>%.0f",
#else
		    rprintf(r,"\n<td>%.2f<td>%.0f",
			    (score_record.times.tms_utime +
			    score_record.times.tms_stime +
			    score_record.times.tms_cutime +
			    score_record.times.tms_cstime)/tick,
#endif
			    difftime(nowtime, score_record.last_used));
		    rprintf(r,"<td>%-1.1f<td>%-2.2f<td>%-2.2f\n",
			(float)conn_bytes/KBYTE, (float)my_bytes/MBYTE,
			(float)bytes/MBYTE);
		    rprintf(r,"<td>%s<td nowrap>%s<td nowrap>%s</tr>\n\n",
			    score_record.client, score_record.vhost,
			    escape_html(r->pool, score_record.request));
		}	/* no_table_report */
	    }		/* !short_report */
	}		/* if (<active child>) */
    }			/* for () */

    if (!(short_report || no_table_report))
    {
#ifdef __EMX__
	rputs("</table>\n \
<hr> \
<table>\n \
<tr><th>Srv<td>Server number\n \
<tr><th>PID<td>OS process ID\n \
<tr><th>Acc<td>Number of accesses this connection / this child / this slot\n \
<tr><th>M<td>Mode of operation\n \
<tr><th>SS<td>Seconds since beginning of most recent request\n \
<tr><th>Conn<td>Kilobytes transferred this connection\n \
<tr><th>Child<td>Megabytes transferred this child\n \
<tr><th>Slot<td>Total megabytes transferred this slot\n \
</table>\n",r);
#else
	rputs("</table>\n \
<hr> \
<table>\n \
<tr><th>Srv<td>Server number\n \
<tr><th>PID<td>OS process ID\n \
<tr><th>Acc<td>Number of accesses this connection / this child / this slot\n \
<tr><th>M<td>Mode of operation\n \
<tr><th>CPU<td>CPU usage, number of seconds\n \
<tr><th>SS<td>Seconds since beginning of most recent request\n \
<tr><th>Conn<td>Kilobytes transferred this connection\n \
<tr><th>Child<td>Megabytes transferred this child\n \
<tr><th>Slot<td>Total megabytes transferred this slot\n \
</table>\n",r);
#endif
    }

#else /* !defined(STATUS) */

    rputs("<hr>To obtain a full report with current status information and",r);
    rputs(" DNS and LOGGING status codes \n",r);
    rputs("you need to recompile Apache after adding the line <pre>",r);
    rputs("Rule STATUS=yes</pre>into the file <code>Configuration</code>\n",r);

#endif /* STATUS */

    if (!short_report)
        rputs("</BODY></HTML>\n",r);

    kill_timeout(r);
    return 0;
}

handler_rec status_handlers[] =
{
{ STATUS_MAGIC_TYPE, status_handler },
{ "server-status", status_handler },
{ NULL }
};

module status_module =
{
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   NULL,			/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   NULL,			/* command table */
   status_handlers,		/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL,			/* logger */
   NULL				/* header parser */
};
