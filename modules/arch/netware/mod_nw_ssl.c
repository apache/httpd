/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

#define WS_SSL

#define  MAX_ADDRESS  512
#define  MAX_KEY       80


#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "ap_listen.h"
#include "apr_strings.h"
#include "apr_portable.h"

module AP_MODULE_DECLARE_DATA nwssl_module;

typedef struct NWSSLSrvConfigRec NWSSLSrvConfigRec;
typedef struct seclisten_rec seclisten_rec;

struct seclisten_rec {
    seclisten_rec *next;
    struct sockaddr_in local_addr;	/* local IP address and port */
    int fd;
    int used;			            /* Only used during restart */
    char key[MAX_KEY];
    int mutual;
    char *addr;
    int port;
};

struct NWSSLSrvConfigRec {
    apr_table_t *sltable;
};

static seclisten_rec* ap_seclisteners = NULL;

#define get_nwssl_cfg(srv) (NWSSLSrvConfigRec *) ap_get_module_config(srv->module_config, &nwssl_module)

/*
 * Parses a host of the form <address>[:port]
 * :port is permitted if 'port' is not NULL
 */
static unsigned long parse_addr(const char *w, unsigned short *ports)
{
    struct hostent *hep;
    unsigned long my_addr;
    char *p;

    p = strchr(w, ':');
    if (ports != NULL) {
        *ports = 0;
    if (p != NULL && strcmp(p + 1, "*") != 0)
        *ports = atoi(p + 1);
    }

    if (p != NULL)
        *p = '\0';
    if (strcmp(w, "*") == 0) {
        if (p != NULL)
            *p = ':';
        return htonl(INADDR_ANY);
    }

    my_addr = apr_inet_addr((char *)w);
    if (my_addr != INADDR_NONE) {
        if (p != NULL)
            *p = ':';
        return my_addr;
    }

    hep = gethostbyname(w);

    if ((!hep) || (hep->h_addrtype != AF_INET || !hep->h_addr_list[0])) {
        /* XXX Should be echoing by r_errno the actual failure, no? 
         * ap_log_error would be good here.
         */
        fprintf(stderr, "Cannot resolve host name %s --- exiting!\n", w);
        exit(1);
    }

    if (hep->h_addr_list[1]) {
        fprintf(stderr, "Host %s has multiple addresses ---\n", w);
        fprintf(stderr, "you must choose one explicitly for use as\n");
        fprintf(stderr, "a secure port.  Exiting!!!\n");
        exit(1);
    }

    if (p != NULL)
        *p = ':';

    return ((struct in_addr *) (hep->h_addr))->s_addr;
}

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


static int make_secure_socket(apr_pool_t *pconf, const struct sockaddr_in *server,
                              char* key, int mutual, server_rec *sconf)
{
    int s;
    int one = 1;
    char addr[MAX_ADDRESS];
    struct sslserveropts opts;
    unsigned int optParam;
    WSAPROTOCOL_INFO SecureProtoInfo;
    int no = 1;
    
    if (server->sin_addr.s_addr != htonl(INADDR_ANY))
        apr_snprintf(addr, sizeof(addr), "address %s port %d",
            inet_ntoa(server->sin_addr), ntohs(server->sin_port));
    else
        apr_snprintf(addr, sizeof(addr), "port %d", ntohs(server->sin_port));

    /* note that because we're about to slack we don't use psocket */
    memset(&SecureProtoInfo, 0, sizeof(WSAPROTOCOL_INFO));

    SecureProtoInfo.iAddressFamily = AF_INET;
    SecureProtoInfo.iSocketType = SOCK_STREAM;
    SecureProtoInfo.iProtocol = IPPROTO_TCP;   
    SecureProtoInfo.iSecurityScheme = SECURITY_PROTOCOL_SSL;

    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP,
            (LPWSAPROTOCOL_INFO)&SecureProtoInfo, 0, 0);
            
    if (s == INVALID_SOCKET) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_netos_error(), sconf,
                     "make_secure_socket: failed to get a socket for %s", 
                     addr);
        return -1;
    }
        
    if (!mutual) {
        optParam = SO_SSL_ENABLE | SO_SSL_SERVER;
		    
        if (WSAIoctl(s, SO_SSL_SET_FLAGS, (char *)&optParam,
            sizeof(optParam), NULL, 0, NULL, NULL, NULL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_netos_error(), sconf,
                         "make_secure_socket: for %s, WSAIoctl: "
                         "(SO_SSL_SET_FLAGS)", addr);
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
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_netos_error(), sconf,
                     "make_secure_socket: for %s, WSAIoctl: "
                     "(SO_SSL_SET_SERVER)", addr);
        return -1;
    }

    if (mutual) {
        optParam = 0x07;               // SO_SSL_AUTH_CLIENT

        if(WSAIoctl(s, SO_SSL_SET_FLAGS, (char*)&optParam,
            sizeof(optParam), NULL, 0, NULL, NULL, NULL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_netos_error(), sconf,
                         "make_secure_socket: for %s, WSAIoctl: "
                         "(SO_SSL_SET_FLAGS)", addr);
            return -1;
        }
    }

    return s;
}

static const char *set_secure_listener(cmd_parms *cmd, void *dummy, 
                                       const char *ips, const char* key, 
                                       const char* mutual)
{
    NWSSLSrvConfigRec* sc = get_nwssl_cfg(cmd->server);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    char *ports, *addr;
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
	    ports = (char*)ips;
    }
    
    new = apr_pcalloc(cmd->pool, sizeof(seclisten_rec)); 
    new->local_addr.sin_family = AF_INET;
    
    if (ports == ips) {
	    new->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr = apr_pstrdup(cmd->pool, "0.0.0.0");
    }
    else {
	    new->local_addr.sin_addr.s_addr = parse_addr(ips, NULL);
        addr = apr_pstrdup(cmd->pool, ips);
    }
    
    port = atoi(ports);
    
    if (!port) 
	    return "Port must be numeric";
	    
    apr_table_set(sc->sltable, ports, "T");
    
    new->local_addr.sin_port = htons(port);
    new->fd = -1;
    new->used = 0;
    new->next = ap_seclisteners;
    strcpy(new->key, key);
    new->mutual = (mutual) ? 1 : 0;
    new->addr = addr;
    new->port = port;
    ap_seclisteners = new;
    return NULL;
}

static apr_status_t nwssl_socket_cleanup(void *data)
{
    ap_listen_rec* slr = (ap_listen_rec*)data;
    ap_listen_rec* lr;

    /* Remove our secure listener from the listener list */
    for (lr = ap_listeners; lr; lr = lr->next) {
        /* slr is at the head of the list */
        if (lr == slr) {
            ap_listeners = slr->next;
            break;
        }
        /* slr is somewhere in between or at the end*/
        if (lr->next == slr) {
            lr->next = slr->next;
            break;
        }
    }
    return APR_SUCCESS;
}

static int nwssl_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                         apr_pool_t *ptemp)
{
    ap_seclisteners = NULL;

    return OK;
}

static int nwssl_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                          apr_pool_t *ptemp, server_rec *s)
{
    seclisten_rec* sl;
    ap_listen_rec* lr;
    apr_socket_t*  sd;
    apr_status_t status;
    
    for (sl = ap_seclisteners; sl != NULL; sl = sl->next) {
        sl->fd = find_secure_listener(sl);

        if (sl->fd < 0)
            sl->fd = make_secure_socket(pconf, &sl->local_addr, sl->key, sl->mutual, s);            
            
        if (sl->fd >= 0) {
            apr_os_sock_info_t sock_info;

            sock_info.os_sock = &(sl->fd);
            sock_info.local = (struct sockaddr*)&(sl->local_addr);
            sock_info.remote = NULL;
            sock_info.family = APR_INET;
            sock_info.type = SOCK_STREAM;

            apr_os_sock_make(&sd, &sock_info, pconf);

            lr = apr_pcalloc(pconf, sizeof(ap_listen_rec));
        
            if (lr) {
				lr->sd = sd;
                if ((status = apr_sockaddr_info_get(&lr->bind_addr, sl->addr, APR_UNSPEC, sl->port, 0, 
                                              pconf)) != APR_SUCCESS) {
                    ap_log_perror(APLOG_MARK, APLOG_CRIT, status, pconf,
                                 "alloc_listener: failed to set up sockaddr for %s:%d", sl->addr, sl->port);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                lr->next = ap_listeners;
                ap_listeners = lr;
                apr_pool_cleanup_register(pconf, lr, nwssl_socket_cleanup, apr_pool_cleanup_null);
            }                        
        } else {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    } 
    return OK;
}

static void *nwssl_config_server_create(apr_pool_t *p, server_rec *s)
{
    NWSSLSrvConfigRec *new = apr_palloc(p, sizeof(NWSSLSrvConfigRec));
    new->sltable = apr_table_make(p, 5);
    return new;
}

static void *nwssl_config_server_merge(apr_pool_t *p, void *basev, void *addv)
{
    NWSSLSrvConfigRec *base = (NWSSLSrvConfigRec *)basev;
    NWSSLSrvConfigRec *add  = (NWSSLSrvConfigRec *)addv;
    NWSSLSrvConfigRec *merged  = (NWSSLSrvConfigRec *)apr_palloc(p, sizeof(NWSSLSrvConfigRec));
    return merged;
}

static int isSecure (const request_rec *r)
{
    NWSSLSrvConfigRec *sc = get_nwssl_cfg(r->server);
    const char *s_secure = NULL;
    char port[8];
    int ret = 0;

    itoa(((r->connection)->local_addr)->port, port, 10);
    s_secure = apr_table_get(sc->sltable, port);    
    if (s_secure)
        ret = 1;

    return ret;
}

static int nwssl_hook_Fixup(request_rec *r)
{
    apr_table_t *e = r->subprocess_env;    
    if (!isSecure(r))
        return DECLINED;

    apr_table_set(e, "HTTPS", "on");
    
    return DECLINED;
}

static const char *nwssl_hook_http_method (const request_rec *r)
{
    if (isSecure(r))
        return "https";

    return NULL;
}

static const command_rec nwssl_module_cmds[] =
{
    AP_INIT_TAKE23("SecureListen", set_secure_listener, NULL, RSRC_CONF,
      "specify an address and/or port with a key pair name.\n"
      "Optional third parameter of MUTUAL configures the port for mutual authentication."),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(nwssl_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(nwssl_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(nwssl_hook_Fixup, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_http_method(nwssl_hook_http_method,   NULL,NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA nwssl_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    nwssl_config_server_create, /* server config */
    nwssl_config_server_merge,  /* merge server config */
    nwssl_module_cmds,          /* command apr_table_t */
    register_hooks
};

