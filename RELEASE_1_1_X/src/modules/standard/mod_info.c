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

/* 
 * Info Module.  Display configuration information for the server and
 * all included modules.
 *
 * <Location /info>
 * SetHandler server-info
 * </Location>
 *
 * GET /info - Returns full configuration page for server and all modules
 * GET /info?server - Returns server configuration only
 * GET /info?module_name - Returns configuration for a single module
 * GET /info?list - Returns quick list of included modules
 *
 * Rasmus Lerdorf <rasmus@vex.net>, May 1996
 *
 * 05.01.96 Initial Version
 * 
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"

typedef struct mod_info_config_lines {
	char *cmd;
	char *line;
	struct mod_info_config_lines *next;
} mod_info_config_lines;

module info_module;
extern module *top_module;

char *mod_info_html_cmd_string(char *string) {
	char *s,*t;
	static char ret[64];  /* What is the max size of a command? */

	ret[0]='\0';
	s = string;
	t=ret;	
	while(*s) {
		if(*s=='<') { strcat(t,"&lt;"); t+=4*sizeof(char); }
		else if(*s=='>') { strcat(t,"&gt;"); t+=4*sizeof(char); }
		else *t++=*s;
		s++;
		*t='\0';
	}
	return(ret);
}

mod_info_config_lines *mod_info_load_config(pool *p, char *filename) {
	char s[MAX_STRING_LEN];
	FILE *fp;
	mod_info_config_lines *new, *ret=NULL, *prev=NULL;
	char *t,*tt,o;
	
	fp = pfopen(p,filename,"r");
	if(!fp) return NULL;
	while(!cfg_getline(s,MAX_STRING_LEN,fp)) {
		if(*s=='#') continue; /* skip comments */
		new = palloc(p,sizeof(struct mod_info_config_lines));
		new->next = NULL;
		if(!ret) ret=new;
		if(prev) prev->next=new;
		t=strchr(s,' ');	
		tt=strchr(s,'\t');
		if(t && tt) t = (t<tt)?t:tt;
		else if(tt) t=tt;
		if(t) {
			o=*t;
			*t='\0';
			new->cmd = pstrdup(p,s);
			new->line = pstrdup(p,t+1);
			*t=o;
		} else {
			new->cmd = pstrdup(p,s);
			new->line = NULL;
		}
		prev=new;	
	}
	pfclose(p,fp);
	return(ret);
}

void mod_info_module_cmds(request_rec *r, mod_info_config_lines *cfg, command_rec *cmds,char *label) {
	command_rec *cmd=cmds;
	mod_info_config_lines *li=cfg,*li_st=NULL,*li_se=NULL,*block_start=NULL;
	int lab=0, nest=0;

	while(li) {
		if(!strncasecmp(li->cmd,"<directory",10) || !strncasecmp(li->cmd,"<location",9) ||
		  !strncasecmp(li->cmd,"<limit",6)) { 
			if(nest) li_se=li;
			else li_st=li; 
			li=li->next; 
			nest++;
			continue; 
		} else if(nest && (!strncasecmp(li->cmd,"</limit",7) ||
		  !strncasecmp(li->cmd,"</location",10) || !strncasecmp(li->cmd,"</directory",11))) { 
			if(block_start) {
				if((nest==1 && block_start==li_st) || (nest==2 && block_start==li_se)) {
					rputs("<dd><tt>",r);
					if(nest==2) rputs("&nbsp;&nbsp;",r);
					rputs(mod_info_html_cmd_string(li->cmd),r);
					rputs(" ",r);
					if(li->line) rputs(mod_info_html_cmd_string(li->line),r);
					rputs("</tt>\n",r);
					nest--;
					if(!nest) {
						block_start=NULL;
						li_st=NULL;
					} else {
						block_start=li_st;
					}
					li_se=NULL; 
				} else {
					nest--;	
					if(!nest) {
						li_st=NULL;
					}
					li_se=NULL; 
				}
			} else {
				nest--;	
				if(!nest) {
					li_st=NULL;
				}
				li_se=NULL; 
			}
			li=li->next;
			continue;
		}
		cmd = cmds;
		while(cmd) {
			if(cmd->name) {
				if(!strcasecmp(cmd->name,li->cmd)) {
					if(!lab) {
						rputs("<dt><strong>",r);
						rputs(label,r);
						rputs("</strong>\n",r);
						lab=1;
					}
					if(((nest && block_start==NULL) || (nest==2 && block_start==li_st))
					  && (strncasecmp(li->cmd,"<directory",10) &&
					  strncasecmp(li->cmd,"<location",9) && strncasecmp(li->cmd,"<limit",6) &&
					  strncasecmp(li->cmd,"</limit",7) && strncasecmp(li->cmd,"</location",10) &&
					  strncasecmp(li->cmd,"</directory",11))) {
						rputs("<dd><tt>",r);
						rputs(mod_info_html_cmd_string(li_st->cmd),r);
						rputs(" ",r);
						if(li_st->line) rputs(mod_info_html_cmd_string(li_st->line),r);
						rputs("</tt>\n",r);
						block_start=li_st;
						if(li_se) {
							rputs("<dd><tt>&nbsp;&nbsp;",r);
							rputs(mod_info_html_cmd_string(li_se->cmd),r);
							rputs(" ",r);
							if(li_se->line) rputs(mod_info_html_cmd_string(li_se->line),r);
							rputs("</tt>\n",r);
							block_start=li_se;
						}
					}	
					rputs("<dd><tt>",r);
					if(nest) rputs("&nbsp;&nbsp;",r);
					if(nest==2) rputs("&nbsp;&nbsp;",r);
					rputs(mod_info_html_cmd_string(li->cmd),r);
					if(li->line) {
						rputs(" <i>",r);
						rputs(mod_info_html_cmd_string(li->line),r);
						rputs("</i></tt>",r);
					}
				}
			} else break;
			cmd++;
		}
		li = li->next;
	}
}

int display_info(request_rec *r) {
	module *modp = NULL;
	char buf[256];
    extern char *module_names[];
    char **names = module_names;
	command_rec *cmd=NULL;
	handler_rec *hand=NULL;
	server_rec *serv = r->server;
	int comma=0;
	mod_info_config_lines *mod_info_cfg_httpd=NULL;
	mod_info_config_lines *mod_info_cfg_srm=NULL;
	mod_info_config_lines *mod_info_cfg_access=NULL;
	extern int standalone;
	extern uid_t user_id;
	extern char *user_name;
	extern gid_t group_id;
	extern int max_requests_per_child;
	extern char *pid_fname;
	extern char *scoreboard_fname;
	extern int daemons_to_start;
	extern int daemons_min_free;
	extern int daemons_max_free;
	extern int daemons_limit;
	extern char server_root[MAX_STRING_LEN];
	extern char server_confname[MAX_STRING_LEN];

	/* Init timeout */
	soft_timeout ("send server info", r);
	r->content_type = "text/html";		
	send_http_header(r);
	if(r->header_only) {
		return 0;
    }
	
	rputs("<html><head><title>Server Information</title></head>\n",r);
	rputs("<body><h1 align=center>Apache Server Information</h1>\n",r);
	if(!r->args || strcasecmp(r->args,"list")) {
		sprintf(buf,"%s/%s",server_root,server_confname);
		mod_info_cfg_httpd = mod_info_load_config(r->pool,buf);
		sprintf(buf,"%s/%s",server_root,serv->srm_confname);
		mod_info_cfg_srm = mod_info_load_config(r->pool,buf);
		sprintf(buf,"%s/%s",server_root,serv->access_confname);
		mod_info_cfg_access = mod_info_load_config(r->pool,buf);
		if(!r->args) {
			rputs("<tt><a href=\"#server\">Server Settings</a>, ",r);
			for(modp = top_module, names=module_names; modp; modp = modp->next, names++) {
				sprintf(buf,"<a href=\"#%s\">%s</a>",*names,*names);
				rputs(buf, r);
				if(modp->next) rputs(", ",r);
			}
			rputs("</tt><hr>",r);

		}
		if(!r->args || !strcasecmp(r->args,"server")) {	
			sprintf(buf,"<a name=\"server\"><strong>Server Version:</strong> <font size=+1><tt>%s</tt></a></font><br>\n",SERVER_VERSION);
			rputs(buf,r);
			sprintf(buf,"<strong>API Version:</strong> <tt>%d</tt><br>\n",MODULE_MAGIC_NUMBER);
			rputs(buf,r);
			sprintf(buf,"<strong>Run Mode:</strong> <tt>%s</tt><br>\n",standalone?"standalone":"inetd");
			rputs(buf,r);
			sprintf(buf,"<strong>User/Group:</strong> <tt>%s(%d)/%d</tt><br>\n",user_name,(int)user_id,(int)group_id);
			rputs(buf,r);
			sprintf(buf,"<strong>Hostname/port:</strong> <tt>%s:%d</tt><br>\n",serv->server_hostname,serv->port);
			rputs(buf,r);
			sprintf(buf,"<strong>Daemons:</strong> <tt>start: %d &nbsp;&nbsp; min idle: %d &nbsp;&nbsp; max idle: %d &nbsp;&nbsp; max: %d</tt><br>\n",daemons_to_start,daemons_min_free,daemons_max_free,daemons_limit);
			rputs(buf,r);
			sprintf(buf,"<strong>Max Requests:</strong> <tt>per child: %d &nbsp;&nbsp; per connection: %d</tt><br>\n",max_requests_per_child,serv->keep_alive);
			rputs(buf,r);
			sprintf(buf,"<strong>Timeouts:</strong> <tt>connection: %d &nbsp;&nbsp; keep-alive: %d</tt><br>",serv->timeout,serv->keep_alive_timeout);
			rputs(buf,r);
			sprintf(buf,"<strong>Server Root:</strong> <tt>%s</tt><br>\n",server_root);
			rputs(buf,r);
			sprintf(buf,"<strong>Config File:</strong> <tt>%s</tt><br>\n",server_confname);
			rputs(buf,r);
			sprintf(buf,"<strong>PID File:</strong> <tt>%s</tt><br>\n",pid_fname);
			rputs(buf,r);
			sprintf(buf,"<strong>Scoreboard File:</strong> <tt>%s</tt><br>\n",scoreboard_fname);
			rputs(buf,r);
		}
		rputs("<hr><dl>",r);
		for(modp = top_module, names=module_names; modp; modp = modp->next, names++) {
			if(!r->args || !strcasecmp(*names,r->args)) {	
				sprintf(buf,"<dt><a name=\"%s\"><strong>Module Name:</strong> <font size=+1><tt>%s</tt></a></font>\n",*names,*names);
				rputs(buf,r);
				rputs("<dt><strong>Content-types affected:</strong>",r);	
				hand = modp->handlers;
				if(hand) {
					while(hand) {
						if(hand->content_type) {
							sprintf(buf," <tt>%s</tt>\n",hand->content_type);	
							rputs(buf,r);
						} else break;
						hand++;
						if(hand && hand->content_type) rputs(",",r);
					}
				} else {
					rputs("<tt> none</tt>",r);
				}
				rputs("<dt><strong>Module Groups:</strong> \n",r);
				if(modp->translate_handler) {
					rputs("<tt>Translate Handler</tt>\n",r);
					comma=1;
				}
				if(modp->check_user_id) {
					if(comma) rputs(", ",r);
					rputs("<tt>User ID Checking</tt>\n",r);
					comma=1;
				}
				if(modp->auth_checker) {
					if(comma) rputs(", ",r);
					rputs("<tt>Authentication Checking</tt>\n",r);
					comma=1;
				}
				if(modp->access_checker) {
					if(comma) rputs(", ",r);
					rputs("<tt>Access Checking</tt>\n",r);
					comma=1;
				}
				if(modp->type_checker) {
					if(comma) rputs(", ",r);
					rputs("<tt>Type Checking</tt>\n",r);
					comma=1;
				}
				if(modp->fixer_upper) {
					if(comma) rputs(", ",r);
					rputs("<tt>Header Fixer</tt>\n",r);
					comma=1;
				}
				if(modp->logger) {
					if(comma) rputs(", ",r);
					rputs("<tt>Logging</tt>\n",r);
					comma=1;
				}
				if(!comma) rputs("<tt> none</tt>",r);
				comma=0;
				rputs("<dt><strong>Module Configuration Commands:</strong> ",r);
				cmd = modp->cmds;
				if(cmd) {
					while(cmd) {
						if(cmd->name) {
							sprintf(buf,"<dd><tt>%s - <i>",mod_info_html_cmd_string(cmd->name));	
							rputs(buf,r);
							if(cmd->errmsg) rputs(cmd->errmsg,r);
							rputs("</i></tt>\n",r);
						} else break;
						cmd++;
					}
					rputs("<dt><strong>Current Configuration:</strong>\n",r);
					mod_info_module_cmds(r,mod_info_cfg_httpd,modp->cmds,"httpd.conf");	
					mod_info_module_cmds(r,mod_info_cfg_srm,modp->cmds,"srm.conf");
					mod_info_module_cmds(r,mod_info_cfg_access,modp->cmds,"access.conf");
				} else {
					rputs("<tt> none</tt>\n",r);
				}
				rputs("<dt><hr>\n",r);
				if(r->args) break;
			}
		}
		if(!modp && r->args && strcasecmp(r->args,"server")) rputs("<b>No such module</b>\n",r);
	} else {
		for(modp = top_module; modp; modp = modp->next, names++) {
			rputs(*names,r);
			if(modp->next) rputs("<br>",r);
		}	
	}	
	rputs("</dl></body></html>\n",r);
	/* Done, turn off timeout, close file and return */
	return 0;
}

handler_rec info_handlers[] = {
	{ "server-info", display_info },
	{ NULL }
};

module info_module = {
	STANDARD_MODULE_STUFF,
	NULL,				/* initializer */
	NULL,				/* dir config creater */
	NULL,				/* dir merger --- default is to override */
	NULL,				/* server config */
	NULL,				/* merge server config */
	NULL,				/* command table */
	info_handlers,		/* handlers */
	NULL,				/* filename translation */
	NULL,				/* check_user_id */
	NULL,				/* check auth */
	NULL,				/* check access */
	NULL,				/* type_checker */
	NULL,				/* fixups */
	NULL				/* logger */
};
