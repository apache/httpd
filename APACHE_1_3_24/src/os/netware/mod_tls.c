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

/*
 * mod_tls.c - Apache SSL/TLS module for NetWare by Mike Gardiner.
 *
 * This module gives Apache the ability to do SSL/TLS with a minimum amount
 * of effort.  All of the SSL/TLS logic is already on NetWare versions 5 and
 * above and is interfaced through WinSock on NetWare.  As you can see in
 * the code below SSL/TLS sockets can be created with three WinSock calls.
 *
 * To load, simply place the module in the modules directory under the main
 * apache tree.  Then add a "SecureListen" with two arguments.  The first
 * argument is an address and/or port.  The second argument is the key pair
 * name as created in ConsoleOne.
 *
 *  Examples:
 *
 *          SecureListen 443 "SSL CertificateIP"  
 *          SecureListen 123.45.67.89:443 mycert
 */

#define CORE_PRIVATE
#define WS_SSL

#define  MAX_ADDRESS  512
#define  MAX_KEY       80

#include "httpd.h"
#include "http_config.h"
#include "http_conf_globals.h"
#include "http_log.h"
#include "http_main.h"

module MODULE_VAR_EXPORT tls_module;

typedef struct TLSSrvConfigRec TLSSrvConfigRec;
typedef struct seclisten_rec seclisten_rec;
static fd_set listenfds;

struct seclisten_rec {
    seclisten_rec *next;
    struct sockaddr_in local_addr;	/* local IP address and port */
    int fd;
    int used;			            /* Only used during restart */
    char key[MAX_KEY];
    int mutual;
};

struct TLSSrvConfigRec {
    table *sltable;
};

static seclisten_rec* ap_seclisteners = NULL;

#define get_tls_cfg(srv) (TLSSrvConfigRec *) ap_get_module_config(srv->module_config, &tls_module)


static int find_secure_listener(seclisten_rec *lr)
{
    seclisten_rec *sl;

    for (sl = ap_seclisteners; sl; sl = sl->next) {
        if (!memcmp(&sl->local_addr, &lr->local_addr, sizeof(sl->local_addr))) {
            sl->used = 1;
            return sl->fd;
        }
    }    
    return -1;
}


static int make_secure_socket(pool *p, const struct sockaddr_in *server,
                              char* key, int mutual, server_rec *server_conf)
{
    int s;
    int one = 1;
    char addr[MAX_ADDRESS];
    struct sslserveropts opts;
    struct linger li;
    unsigned int optParam;
    WSAPROTOCOL_INFO SecureProtoInfo;
    int no = 1;
    
    if (server->sin_addr.s_addr != htonl(INADDR_ANY))
        ap_snprintf(addr, sizeof(addr), "address %s port %d",
            inet_ntoa(server->sin_addr), ntohs(server->sin_port));
    else
        ap_snprintf(addr, sizeof(addr), "port %d", ntohs(server->sin_port));

    /* note that because we're about to slack we don't use psocket */
    ap_block_alarms();
    memset(&SecureProtoInfo, 0, sizeof(WSAPROTOCOL_INFO));

    SecureProtoInfo.iAddressFamily = AF_INET;
    SecureProtoInfo.iSocketType = SOCK_STREAM;
    SecureProtoInfo.iProtocol = IPPROTO_TCP;   
    SecureProtoInfo.iSecurityScheme = SECURITY_PROTOCOL_SSL;

    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP,
            (LPWSAPROTOCOL_INFO)&SecureProtoInfo, 0, 0);
            
    if (s == INVALID_SOCKET) {
        errno = WSAGetLastError();
        ap_log_error(APLOG_MARK, APLOG_CRIT, server_conf,
            "make_secure_socket: failed to get a socket for %s", addr);
        ap_unblock_alarms();
        return -1;
    }
        
    if (!mutual) {
        optParam = SO_SSL_ENABLE | SO_SSL_SERVER;
		    
        if (WSAIoctl(s, SO_SSL_SET_FLAGS, (char *)&optParam,
            sizeof(optParam), NULL, 0, NULL, NULL, NULL)) {
            errno = WSAGetLastError();
            ap_log_error(APLOG_MARK, APLOG_CRIT, server_conf,
                "make_secure_socket: for %s, WSAIoctl: (SO_SSL_SET_FLAGS)", addr);
            ap_unblock_alarms();
            return -1;
        }
    }

    opts.cert = key;
    opts.certlen = strlen(key);
    opts.sidtimeout = 0;
    opts.sidentries = 0;
    opts.siddir = NULL;

    if (WSAIoctl(s, SO_SSL_SET_SERVER, (char *)&opts, sizeof(opts),
        NULL, 0, NULL, NULL, NULL) != 0) {
        errno = WSAGetLastError();
        ap_log_error(APLOG_MARK, APLOG_CRIT, server_conf,
            "make_secure_socket: for %s, WSAIoctl: (SO_SSL_SET_SERVER)", addr);
        ap_unblock_alarms();
        return -1;
    }

    if (mutual) {
        optParam = 0x07;               // SO_SSL_AUTH_CLIENT

        if(WSAIoctl(s, SO_SSL_SET_FLAGS, (char*)&optParam,
            sizeof(optParam), NULL, 0, NULL, NULL, NULL)) {
            errno = WSAGetLastError();
            ap_log_error( APLOG_MARK, APLOG_CRIT, server_conf,
                "make_secure_socket: for %s, WSAIoctl: (SO_SSL_SET_FLAGS)", addr );
            ap_unblock_alarms();
            return -1;
        }
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(int)) < 0) {
        errno = WSAGetLastError();
        ap_log_error(APLOG_MARK, APLOG_CRIT, server_conf,
            "make_secure_socket: for %s, setsockopt: (SO_REUSEADDR)", addr);
        ap_unblock_alarms();
        return -1;
    }

    one = 1;
#ifdef SO_KEEPALIVE
    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(int)) < 0) {
        errno = WSAGetLastError();
        ap_log_error(APLOG_MARK, APLOG_CRIT, server_conf,
            "make_secure_socket: for %s, setsockopt: (SO_KEEPALIVE)", addr);
#endif
        ap_unblock_alarms();
        return -1;
    }

    if (server_conf->send_buffer_size) {
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
            (char *) &server_conf->send_buffer_size, sizeof(int)) < 0) {
            errno = WSAGetLastError();
            ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf,
                "make_secure_socket: failed to set SendBufferSize for %s, "
			    "using default", addr);
			ap_unblock_alarms();
	        return -1;
        }
    }

    if (bind(s, (struct sockaddr *) server, sizeof(struct sockaddr_in)) == -1) {
        errno = WSAGetLastError();
        ap_log_error(APLOG_MARK, APLOG_CRIT, server_conf,
            "make_secure_socket: could not bind to %s", addr);
        ap_unblock_alarms();
        return -1;
    }

    if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &no, sizeof(int)) < 0) {
        errno = WSAGetLastError();
        ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf,
            "setsockopt: (TCP_NODELAY)");
    }

    if (listen(s, ap_listenbacklog) == -1) {
        errno = WSAGetLastError();
        ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
            "make_secure_socket: unable to listen for connections on %s", addr);
        ap_unblock_alarms();
        return -1;
    }

    ap_unblock_alarms();
    return s;
}

static const char *set_secure_listener(cmd_parms *cmd, void *dummy, char *ips, char* key, char* mutual)
{
    TLSSrvConfigRec* sc = get_tls_cfg(cmd->server);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    char *ports;
    unsigned short port;
    seclisten_rec *new;

    
    if (err != NULL) 
        return err;

    ports = strchr(ips, ':');
    
    if (ports != NULL) {    
	    if (ports == ips)
	        return "Missing IP address";
	    else if (ports[1] == '\0')
	        return "Address must end in :<port-number>";
	        
	    *(ports++) = '\0';
    }
    else {
	    ports = ips;
    }
    
    new = ap_pcalloc(cmd->pool, sizeof(seclisten_rec)); 
    new->local_addr.sin_family = AF_INET;
    
    if (ports == ips)
	    new->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
	    new->local_addr.sin_addr.s_addr = ap_get_virthost_addr(ips, NULL);
    
    port = atoi(ports);
    
    if (!port) 
	    return "Port must be numeric";
	    
    ap_table_set(sc->sltable, ports, "T");
    
    new->local_addr.sin_port = htons(port);
    new->fd = -1;
    new->used = 0;
    new->next = ap_seclisteners;
    strcpy(new->key, key);
    new->mutual = (mutual) ? 1 : 0;
    ap_seclisteners = new;
    return NULL;
}

static void InitTLS(server_rec *s, pool *p)
{
    seclisten_rec* sl;
    listen_rec* lr;
    
    for (sl = ap_seclisteners; sl != NULL; sl = sl->next) {
        sl->fd = find_secure_listener(sl);

        if (sl->fd < 0)
            sl->fd = make_secure_socket(p, &sl->local_addr, sl->key, sl->mutual, s);            
        else
            ap_note_cleanups_for_socket(p, sl->fd);
            
        if (sl->fd >= 0) {
            FD_SET(sl->fd, &listenfds);
            ap_note_cleanups_for_socket(p, sl->fd);
            
            lr = ap_pcalloc(p, sizeof(listen_rec));
        
            if (lr) {
                lr->local_addr = sl->local_addr;
                lr->used = 0;
                lr->fd = sl->fd;
                lr->next = ap_listeners;
                ap_listeners = lr;
            }                        
        } else {
            clean_parent_exit(1);
        }
    } 
}

void *tls_config_server_create(pool *p, server_rec *s)
{
    TLSSrvConfigRec *new = ap_palloc(p, sizeof(TLSSrvConfigRec));
    new->sltable = ap_make_table(p, 5);
    return new;
}

void *tls_config_server_merge(pool *p, void *basev, void *addv)
{
    TLSSrvConfigRec *base = (TLSSrvConfigRec *)basev;
    TLSSrvConfigRec *add  = (TLSSrvConfigRec *)addv;
    TLSSrvConfigRec *merged  = (TLSSrvConfigRec *)ap_palloc(p, sizeof(TLSSrvConfigRec));
    return merged;
}

int tls_hook_Fixup(request_rec *r)
{
    TLSSrvConfigRec *sc = get_tls_cfg(r->server);
    table *e = r->subprocess_env;    
    const char *s_secure;
    char port[8];
    
    
    /* For some reason r->server->port always return 80 rather than
     * the current port.  So for now we will get it straight from
     * the horses mouth.
     */
    /*  itoa(r->server->port, port, 10); */
    itoa(ntohs(((r->connection)->local_addr).sin_port), port, 10);
    s_secure = ap_table_get(sc->sltable, port);    
    
    if (!s_secure)
        return DECLINED;
    
    ap_table_set(e, "HTTPS", "on");
    
    return DECLINED;
}

static const command_rec tls_module_cmds[] = {
    { "SecureListen", set_secure_listener, NULL, RSRC_CONF, TAKE23,
      "specify an address and/or port with a key pair name.\n"
      "Optional third parameter of MUTUAL configures the port for mutual authentication."},
    { NULL }
};

module MODULE_VAR_EXPORT tls_module =
{
    STANDARD_MODULE_STUFF,
    InitTLS,                  /* initializer */
    NULL,                     /* dir config creater */
    NULL,                     /* dir merger --- default is to override */
    tls_config_server_create, /* server config */
    tls_config_server_merge,  /* merge server config */
    tls_module_cmds,          /* command table */
    NULL,                     /* handlers */
    NULL,                     /* filename translation */
    NULL,                     /* check_user_id */
    NULL,                     /* check auth */
    NULL,                     /* check access */
    NULL,                     /* type_checker */    
    NULL,			          /* fixups */
    NULL,                     /* logger */
    NULL,               	  /* header parser */
    NULL,               	  /* child_init */
    NULL,			       	  /* child_exit */
    tls_hook_Fixup         	  /* post read request */
};


