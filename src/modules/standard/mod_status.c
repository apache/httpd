/* ====================================================================
 * Copyright (c) 1995, 1996 The Apache Group.  All rights reserved.
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

/* Status Module.  Provide a way of getting at the internal Apache
 * status information without having to worry where the scoreboard is
 * held.
 *
 * AddType application/x-httpd-status .status
 * You might like to do this in a .htaccess in a protected directory only
 *
 * GET /.status - Returns pretty page for system admin user
 * GET /.status?refresh - Returns page with 1 second refresh
 * GET /.status?refresh=6 - Returns page with refresh every 6 seconds
 * GET /.status?auto - Returns page with data for automatic parsing
 *
 * Mark Cox, mark@ukweb.com, November 1995
 *
 * 12.11.95 Initial version for telescope.org
 * 13.3.96  Updated to remove rprintf's [Mark]
 * 18.3.96  Added CPU usage, process information, and tidied [Ben Laurie]
 * 18.3.96  Make extra Scoreboard variables #definable
 * 25.3.96  Make short report have full precision [Ben Laurie suggested]
 * 25.3.96  Show uptime better [Mark/Ben Laurie]
 * 29.3.96  Better HTML and explanation [Mark/Rob Hartill suggested]
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "util_script.h"
#include <time.h>
#include "scoreboard.h"

module status_module;

/* Format the number of bytes nicely */

void format_byte_out(request_rec *r,long bytes) {
    char ss[20];

    if (bytes<5196)
        sprintf(ss,"%dB",(int)bytes);
    else if (bytes<524288)
	sprintf(ss,"%.1fkB",(float)bytes/1024);
    else if (bytes<536870912)
	sprintf(ss,"%.1fMB",(float)bytes/1048576);
    else
	sprintf(ss,"%.1fGB",(float)bytes/1073741824);
    rputs(ss,r);
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
      s+=sprintf(s," %ld day%s",days,days==1?"":"s");
    if(hrs)
      s+=sprintf(s," %ld hour%s",hrs,hrs==1?"":"s");
    if(mins)
      s+=sprintf(s," %ld minute%s",mins,mins==1?"":"s");
    if(secs)
      s+=sprintf(s," %ld second%s",secs,secs==1?"":"s");
    rputs(buf,r);
}

/* Main handler for x-httpd-status requests */

int status_handler (request_rec *r)
{
    time_t nowtime=time(NULL);
    time_t up_time;
    int i,res;
    int ready=0;
    int busy=0;
    long count=0;
    long lres,bytes;
    long my_lres,my_bytes;
    long bcount=0;
    int short_report=0;
    server_rec *server = r->server;
    short_score score_record;
    char status[]="???????";
    char buffer[200];
    clock_t tu,ts,tcu,tcs;
    float tick=sysconf(_SC_CLK_TCK);

    tu=ts=tcu=tcs=0;

    status[SERVER_DEAD]='.';  /* We don't want to assume these are in */
    status[SERVER_READY]='_'; /* any particular order in scoreboard.h */
    status[SERVER_STARTING]='S';
    status[SERVER_BUSY_READ]='R';
    status[SERVER_BUSY_WRITE]='W';

    if (r->method_number != M_GET) return NOT_IMPLEMENTED;
    r->content_type = "text/html";

    if (r->args) {
        if (!strncmp(r->args,"refresh",7))
	  if(r->args[7] == '=')
	    table_set(r->headers_out,"Refresh",r->args+8);
	  else
	    table_set(r->headers_out,"Refresh","1");
        else if (!strncmp(r->args,"auto",4)) {
	  r->content_type = "text/plain";
	  short_report=1;
	}
    }
    soft_timeout ("send status info", r);
    send_http_header(r);

    if (r->header_only) 
	return 0;

    up_time=nowtime-restart_time;

    if (!short_report) {
        rputs("<html><head><title>Apache Status</title></head><body>",r);
        rputs("<h1>Apache Server Status</h1>\n\n",r);
	rvputs(r,"Hostname: ",server->server_hostname,"<br>",NULL);
	rvputs(r,"Current Time: ",asctime(localtime(&nowtime)),"<br>",NULL);
	rvputs(r,"Restart Time: ",asctime(localtime(&restart_time)),"<br>",
	       NULL);
	rputs("Server up for: ",r);
	show_time(r,up_time);
	rputs("<p>",r);
    }

    sync_scoreboard_image();
    rputs("Scoreboard: ",r);
    if(!short_report)
	rputs("<PRE>",r);
    for (i = 0; i<HARD_SERVER_MAX; ++i) {
        score_record = get_scoreboard_info(i);
        res = score_record.status;
	rputc(status[res],r);
        if (res == SERVER_READY)
	    ready++;
        else if (res == SERVER_BUSY_READ || res==SERVER_BUSY_WRITE || 
		 res == SERVER_STARTING)
	    busy++;
	if(!short_report && i%25 == 24)
	    rputs("\r\n",r);
    }
    if(!short_report) {
	rputs("</PRE>",r);
	rputs("Key: ",r);
	rputs("\"<code>_</code>\" Waiting for Connection, ",r);
	rputs("\"<code>S</code>\" Starting up, ",r);
	rputs("\"<code>R</code>\" Reading Request, ",r);
	rputs("\"<code>W</code>\" Sending Reply<p>",r);
    }
    if (short_report)
        sprintf(buffer,"\nBusyServers: %d\nIdleServers: %d\n",busy,ready);
    else 
        sprintf(buffer,"\n%d requests currently being processed,\n %d idle servers\n",busy,ready);
    rputs(buffer,r);

#ifdef STATUS_INSTRUMENTATION
    if (!short_report)
      rputs("<hr><h2>Server Details</h2>",r);
    for (i = 0; i<HARD_SERVER_MAX; ++i) {
        score_record=get_scoreboard_info(i);
        lres = score_record.access_count;
        my_lres = score_record.my_access_count;
	bytes= score_record.bytes_served;
	my_bytes= score_record.my_bytes_served;
        if (lres!=0 || (score_record.status != SERVER_READY && score_record.status != SERVER_DEAD)) {
	    if (!short_report) {
	        sprintf(buffer,"<b>Server %d</b> (%d): %ld|%ld [",
		 i,(int)score_record.pid,my_lres,lres);
		rputs(buffer,r);

		switch (score_record.status) {
		case SERVER_READY:
		    rputs("Ready",r);
		    break;
		case SERVER_STARTING:
		    rputs("Starting",r);
		    break;
		case SERVER_BUSY_READ:
		    rputs("Read",r);
		    break;
		case SERVER_BUSY_WRITE:
		    rputs("Write",r);
		    break;
		case SERVER_DEAD:
		    rputs("Dead",r);
		    break;
		}
		sprintf(buffer,"] u%g s%g cu%g cs%g %s (",
			score_record.times.tms_utime/tick,
			score_record.times.tms_stime/tick,
			score_record.times.tms_cutime/tick,
			score_record.times.tms_cstime/tick,
			asctime(localtime(&score_record.last_used)));
		rputs(buffer,r);
		format_byte_out(r,my_bytes);
		rputs("|",r);
		format_byte_out(r,bytes);
		rputs(")",r);
		sprintf(buffer," <i>%s {%s}</i><br>", score_record.client,
			score_record.request);
		rputs(buffer,r);
	    }
	    tu+=score_record.times.tms_utime;
	    ts+=score_record.times.tms_stime;
	    tcu+=score_record.times.tms_cutime;
	    tcs+=score_record.times.tms_cstime;
            count+=lres;
	    bcount+=bytes;
	}
    }
    if (short_report) {
        sprintf(buffer,"Total Accesses: %ld\nTotal Bytes: %ld\n",count,bcount);
	rputs(buffer,r);
    } else {
        sprintf(buffer,"<p>Total accesses: %ld u%g s%g cu%g cs%g (",
		count,tu/tick,ts/tick,tcu/tick,tcs/tick);
	rputs(buffer,r);
	format_byte_out(r,bcount);
	rputs(")",r);
    }
    if (!short_report) {
        rputs("<hr><h2>Averages</h2>",r);
	if (up_time>0) {
	    sprintf(buffer,"%.3g request per second<br>\n",
		    (float)count/(float)up_time);
	    rputs(buffer,r);
	}
	if (up_time>0) {
	    format_byte_out(r,(float)bcount/(float)up_time);
	    rputs(" per second<br>\n",r);
	}
	if (count>0)  {
	    format_byte_out(r,(float)bcount/(float)count);
	    rputs(" per request<br>\n",r);
	}
	if(ts || tu || tcu || tcs)
	    {
	    sprintf(buffer,"%.3g%% CPU load<br>\n",(tu+ts+tcu+tcs)/tick/up_time*100.);
	    rputs(buffer,r);
	    }
    } else {
	sprintf(buffer,"Uptime: %ld\n",(long)(up_time));
	rputs(buffer,r);
	if (up_time>0) { 
	    sprintf(buffer,"ReqPerSec: %g\n",
		    (float)count/(float)up_time);
	    rputs(buffer,r);
	}
	if (up_time>0) {
	    sprintf(buffer,"BytesPerSec: %g\n",
		(float)bcount/(float)up_time);
	    rputs(buffer,r);
	}
	if (count>0) {
	    sprintf(buffer,"BytesPerReq: %g\n",
		(float)bcount/(float)count);
	    rputs(buffer,r);
	}
	if(ts || tu || tcu || tcs)
	    {
	    sprintf(buffer,"CPULoad: %g\n",(tu+ts+tcu+tcs)/tick/up_time*100.);
	    rputs(buffer,r);
	    }
    }
#endif
    if (!short_report)
        rputs("</body></html>",r);
    return 0;
}

handler_rec status_handlers[] = {
{ STATUS_MAGIC_TYPE, status_handler },
{ "server-status", status_handler },
{ NULL }
};

module status_module = {
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
   NULL				/* logger */
};

































