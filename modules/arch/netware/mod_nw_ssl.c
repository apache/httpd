/* Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
#include "http_protocol.h"
#include "http_core.h"
#include "ap_listen.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_optional.h"

#ifndef SO_TLS_UNCLEAN_SHUTDOWN
#define SO_TLS_UNCLEAN_SHUTDOWN 0
#endif

/* The ssl_var_lookup() optional function retrieves SSL environment
 * variables. */
APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *,
                         char *));

/* An optional function which returns non-zero if the given connection
 * is using SSL/TLS. */
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

/* The ssl_proxy_enable() and ssl_engine_disable() optional functions
 * are used by mod_proxy to enable use of SSL for outgoing
 * connections. */
APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));

#define strEQ(s1,s2)     (strcmp(s1,s2)        == 0)
#define strNE(s1,s2)     (strcmp(s1,s2)        != 0)
#define strEQn(s1,s2,n)  (strncmp(s1,s2,n)     == 0)
#define strNEn(s1,s2,n)  (strncmp(s1,s2,n)     != 0)

#define strcEQ(s1,s2)    (strcasecmp(s1,s2)    == 0)
#define strcNE(s1,s2)    (strcasecmp(s1,s2)    != 0)
#define strcEQn(s1,s2,n) (strncasecmp(s1,s2,n) == 0)
#define strcNEn(s1,s2,n) (strncasecmp(s1,s2,n) != 0)

#define strIsEmpty(s)    (s == NULL || s[0] == NUL)


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
	apr_pool_t *pPool;
};

static apr_array_header_t *certlist = NULL;
static unicode_t** certarray = NULL;
static int numcerts = 0;
static seclisten_rec* ap_seclisteners = NULL;

#define get_nwssl_cfg(srv) (NWSSLSrvConfigRec *) ap_get_module_config(srv->module_config, &nwssl_module)


static void build_cert_list (apr_pool_t *p)
{
    int i;
    char **rootcerts = (char **)certlist->elts;

    numcerts = certlist->nelts;
    certarray = apr_palloc(p, sizeof(unicode_t*)*numcerts);

    for (i = 0; i < numcerts; ++i) {
        unicode_t *unistr;
        unistr = (unicode_t*)apr_palloc(p, strlen(rootcerts[i])*4);
        loc2uni (UNI_LOCAL_DEFAULT, unistr, rootcerts[i], 0, 2);
        certarray[i] = unistr;
    }
}

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
        /* XXX Should be echoing by h_errno the actual failure, no? 
         * ap_log_error would be good here.  Better yet - APRize.
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
        optParam = 0x07;  // SO_SSL_AUTH_CLIENT

        if(WSAIoctl(s, SO_SSL_SET_FLAGS, (char*)&optParam,
            sizeof(optParam), NULL, 0, NULL, NULL, NULL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_netos_error(), sconf,
                         "make_secure_socket: for %s, WSAIoctl: "
                         "(SO_SSL_SET_FLAGS)", addr);
            return -1;
        }
    }

    optParam = SO_TLS_UNCLEAN_SHUTDOWN;
    WSAIoctl(s, SO_SSL_SET_FLAGS, (char *)&optParam, sizeof(optParam), 
             NULL, 0, NULL, NULL, NULL);

    return s;
}

int convert_secure_socket(conn_rec *c, apr_socket_t *csd)
{
	int rcode;
	struct tlsclientopts sWS2Opts;
	struct nwtlsopts sNWTLSOpts;
   	struct sslserveropts opts;
    unsigned long ulFlags;
    SOCKET sock;
    unicode_t keyFileName[60];

    apr_os_sock_get(&sock, csd);

    /* zero out buffers */
	memset((char *)&sWS2Opts, 0, sizeof(struct tlsclientopts));
	memset((char *)&sNWTLSOpts, 0, sizeof(struct nwtlsopts));

    /* turn on ssl for the socket */
	ulFlags = (numcerts ? SO_TLS_ENABLE : SO_TLS_ENABLE | SO_TLS_BLIND_ACCEPT);
	rcode = WSAIoctl(sock, SO_TLS_SET_FLAGS, &ulFlags, sizeof(unsigned long),
                     NULL, 0, NULL, NULL, NULL);
	if (SOCKET_ERROR == rcode)
	{
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->base_server,
                     "Error: %d with ioctlsocket(flag SO_TLS_ENABLE)", WSAGetLastError());
		return rcode;
	}

    ulFlags = SO_TLS_UNCLEAN_SHUTDOWN;
	WSAIoctl(sock, SO_TLS_SET_FLAGS, &ulFlags, sizeof(unsigned long),
                     NULL, 0, NULL, NULL, NULL);

    /* setup the socket for SSL */
    memset (&sWS2Opts, 0, sizeof(sWS2Opts));
    memset (&sNWTLSOpts, 0, sizeof(sNWTLSOpts));
    sWS2Opts.options = &sNWTLSOpts;

    if (numcerts) {
    	sNWTLSOpts.walletProvider 		= WAL_PROV_DER;	//the wallet provider defined in wdefs.h
    	sNWTLSOpts.TrustedRootList 		= certarray;	//array of certs in UNICODE format
    	sNWTLSOpts.numElementsInTRList 	= numcerts;     //number of certs in TRList
    }
    else {
        /* setup the socket for SSL */
    	unicpy(keyFileName, L"SSL CertificateIP");
    	sWS2Opts.wallet = keyFileName;    /* no client certificate */
    	sWS2Opts.walletlen = unilen(keyFileName);
    
    	sNWTLSOpts.walletProvider 		= WAL_PROV_KMO;	//the wallet provider defined in wdefs.h
    }

    /* make the IOCTL call */
    rcode = WSAIoctl(sock, SO_TLS_SET_CLIENT, &sWS2Opts,
                     sizeof(struct tlsclientopts), NULL, 0, NULL,
                     NULL, NULL);

    /* make sure that it was successfull */
	if(SOCKET_ERROR == rcode ){
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->base_server,
                     "Error: %d with ioctl (SO_TLS_SET_CLIENT)", WSAGetLastError());
	}		
	return rcode;
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

static const char *set_trusted_certs(cmd_parms *cmd, void *dummy, char *arg)
{
    char **ptr = (char **)apr_array_push(certlist);

    *ptr = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static int nwssl_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                         apr_pool_t *ptemp)
{
    ap_seclisteners = NULL;
    certlist = apr_array_make(pconf, 1, sizeof(char *));

    return OK;
}

static int nwssl_pre_connection(conn_rec *c, void *csd)
{
    
    if (apr_table_get(c->notes, "nwconv-ssl")) {
        convert_secure_socket(c, (apr_socket_t*)csd);
    }
    
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
    build_cert_list(pconf);

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

static int isSecureConn (const server_rec *s, const conn_rec *c)
{
    NWSSLSrvConfigRec *sc = get_nwssl_cfg(s);
    const char *s_secure = NULL;
    char port[8];
    int ret = 0;

    itoa((c->local_addr)->port, port, 10);
    s_secure = apr_table_get(sc->sltable, port);    
    if (s_secure)
        ret = 1;

    return ret;
}

static int isSecure (const request_rec *r)
{
	return isSecureConn (r->server, r->connection);
}

static int nwssl_hook_Fixup(request_rec *r)
{
    int i;

    if (!isSecure(r))
        return DECLINED;

    apr_table_set(r->subprocess_env, "HTTPS", "on");

    return DECLINED;
}

static const char *nwssl_hook_http_method (const request_rec *r)
{
    if (isSecure(r))
        return "https";

    return NULL;
}

static apr_port_t nwssl_hook_default_port(const request_rec *r)
{
    if (isSecure(r))
        return DEFAULT_HTTPS_PORT;

    return 0;
}

int ssl_proxy_enable(conn_rec *c)
{
    apr_table_set(c->notes, "nwconv-ssl", "Y");

    return 1;
}

int ssl_engine_disable(conn_rec *c)
{
    return 1;
}

static int ssl_is_https(conn_rec *c)
{
    return isSecureConn (c->base_server, c);
}

/* This function must remain safe to use for a non-SSL connection. */
char *ssl_var_lookup(apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, char *var)
{
    NWSSLSrvConfigRec *mc = get_nwssl_cfg(s);
    const char *result;
    BOOL resdup;
    apr_time_exp_t tm;

    result = NULL;
    resdup = TRUE;

    /*
     * When no pool is given try to find one
     */
    if (p == NULL) {
        if (r != NULL)
            p = r->pool;
        else if (c != NULL)
            p = c->pool;
        else
            p = mc->pPool;
    }

    /*
     * Request dependent stuff
     */
    if (r != NULL) {
        switch (var[0]) {
        case 'H':
        case 'h':
            if (strcEQ(var, "HTTP_USER_AGENT"))
                result = apr_table_get(r->headers_in, "User-Agent");
            else if (strcEQ(var, "HTTP_REFERER"))
                result = apr_table_get(r->headers_in, "Referer");
            else if (strcEQ(var, "HTTP_COOKIE"))
                result = apr_table_get(r->headers_in, "Cookie");
            else if (strcEQ(var, "HTTP_FORWARDED"))
                result = apr_table_get(r->headers_in, "Forwarded");
            else if (strcEQ(var, "HTTP_HOST"))
                result = apr_table_get(r->headers_in, "Host");
            else if (strcEQ(var, "HTTP_PROXY_CONNECTION"))
                result = apr_table_get(r->headers_in, "Proxy-Connection");
            else if (strcEQ(var, "HTTP_ACCEPT"))
                result = apr_table_get(r->headers_in, "Accept");
            else if (strlen(var) > 5 && strcEQn(var, "HTTP:", 5))
                /* all other headers from which we are still not know about */
                result = apr_table_get(r->headers_in, var+5);
            break;

        case 'R':
        case 'r':
            if (strcEQ(var, "REQUEST_METHOD")) 
                result = r->method;
            else if (strcEQ(var, "REQUEST_SCHEME"))
                result = ap_http_method(r);
            else if (strcEQ(var, "REQUEST_URI"))
                result = r->uri;
            else if (strcEQ(var, "REQUEST_FILENAME"))
                result = r->filename;
            else if (strcEQ(var, "REMOTE_HOST"))
                result = ap_get_remote_host(r->connection, r->per_dir_config, 
                                            REMOTE_NAME, NULL);
            else if (strcEQ(var, "REMOTE_IDENT"))
                result = ap_get_remote_logname(r);
            else if (strcEQ(var, "REMOTE_USER"))
                result = r->user;
            break;

        case 'S':
        case 's':
            if (strcEQn(var, "SSL", 3)) break; /* shortcut common case */
            
            if (strcEQ(var, "SERVER_ADMIN"))
                result = r->server->server_admin;
            else if (strcEQ(var, "SERVER_NAME"))
                result = ap_get_server_name(r);
            else if (strcEQ(var, "SERVER_PORT"))
                result = apr_psprintf(p, "%u", ap_get_server_port(r));
            else if (strcEQ(var, "SERVER_PROTOCOL"))
                result = r->protocol;
            else if (strcEQ(var, "SCRIPT_FILENAME"))
                result = r->filename;
            break;
            
        default:
            if (strcEQ(var, "PATH_INFO"))
                result = r->path_info;
            else if (strcEQ(var, "QUERY_STRING"))
                result = r->args;
            else if (strcEQ(var, "IS_SUBREQ"))
                result = (r->main != NULL ? "true" : "false");
            else if (strcEQ(var, "DOCUMENT_ROOT"))
                result = ap_document_root(r);
            else if (strcEQ(var, "AUTH_TYPE"))
                result = r->ap_auth_type;
            else if (strcEQ(var, "THE_REQUEST"))
                result = r->the_request;
            break;
        }
    }

    /*
     * Connection stuff
     */
    if (result == NULL && c != NULL) {

		/* XXX-Can't get specific SSL info from NetWare */
        /* SSLConnRec *sslconn = myConnConfig(c);
        if (strlen(var) > 4 && strcEQn(var, "SSL_", 4) 
            && sslconn && sslconn->ssl)
            result = ssl_var_lookup_ssl(p, c, var+4);*/

		if (strlen(var) > 4 && strcEQn(var, "SSL_", 4))
			result = NULL;
        else if (strcEQ(var, "REMOTE_ADDR"))
            result = c->remote_ip;
        else if (strcEQ(var, "HTTPS")) {
			if (isSecureConn (s, c))
                result = "on";
            else
                result = "off";
        }
    }

    /*
     * Totally independent stuff
     */
    if (result == NULL) {
        if (strlen(var) > 12 && strcEQn(var, "SSL_VERSION_", 12))
			result = NULL;
            /* XXX-Can't get specific SSL info from NetWare */
            /*result = ssl_var_lookup_ssl_version(p, var+12);*/
        else if (strcEQ(var, "SERVER_SOFTWARE"))
            result = ap_get_server_version();
        else if (strcEQ(var, "API_VERSION")) {
            result = apr_itoa(p, MODULE_MAGIC_NUMBER);
            resdup = FALSE;
        }
        else if (strcEQ(var, "TIME_YEAR")) {
            apr_time_exp_lt(&tm, apr_time_now());
            result = apr_psprintf(p, "%02d%02d",
                                 (tm.tm_year / 100) + 19, tm.tm_year % 100);
            resdup = FALSE;
        }
#define MKTIMESTR(format, tmfield) \
            apr_time_exp_lt(&tm, apr_time_now()); \
            result = apr_psprintf(p, format, tm.tmfield); \
            resdup = FALSE;
        else if (strcEQ(var, "TIME_MON")) {
            MKTIMESTR("%02d", tm_mon+1)
        }
        else if (strcEQ(var, "TIME_DAY")) {
            MKTIMESTR("%02d", tm_mday)
        }
        else if (strcEQ(var, "TIME_HOUR")) {
            MKTIMESTR("%02d", tm_hour)
        }
        else if (strcEQ(var, "TIME_MIN")) {
            MKTIMESTR("%02d", tm_min)
        }
        else if (strcEQ(var, "TIME_SEC")) {
            MKTIMESTR("%02d", tm_sec)
        }
        else if (strcEQ(var, "TIME_WDAY")) {
            MKTIMESTR("%d", tm_wday)
        }
        else if (strcEQ(var, "TIME")) {
            apr_time_exp_lt(&tm, apr_time_now());
            result = apr_psprintf(p,
                        "%02d%02d%02d%02d%02d%02d%02d", (tm.tm_year / 100) + 19,
                        (tm.tm_year % 100), tm.tm_mon+1, tm.tm_mday,
                        tm.tm_hour, tm.tm_min, tm.tm_sec);
            resdup = FALSE;
        }
        /* all other env-variables from the parent Apache process */
        else if (strlen(var) > 4 && strcEQn(var, "ENV:", 4)) {
            result = apr_table_get(r->notes, var+4);
            if (result == NULL)
                result = apr_table_get(r->subprocess_env, var+4);
            if (result == NULL)
                result = getenv(var+4);
        }
    }

    if (result != NULL && resdup)
        result = apr_pstrdup(p, result);
    if (result == NULL)
        result = "";
    return (char *)result;
}


static const command_rec nwssl_module_cmds[] =
{
    AP_INIT_TAKE23("SecureListen", set_secure_listener, NULL, RSRC_CONF,
      "specify an address and/or port with a key pair name.\n"
      "Optional third parameter of MUTUAL configures the port for mutual authentication."),
    AP_INIT_ITERATE("NWSSLTrustedCerts", set_trusted_certs, NULL, RSRC_CONF,
        "Adds trusted certificates that are used to create secure connections to proxied servers"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(nwssl_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(nwssl_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(nwssl_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(nwssl_hook_Fixup, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_http_method(nwssl_hook_http_method,   NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port  (nwssl_hook_default_port,  NULL,NULL, APR_HOOK_MIDDLE);

    APR_REGISTER_OPTIONAL_FN(ssl_is_https);
    APR_REGISTER_OPTIONAL_FN(ssl_var_lookup);
    
    APR_REGISTER_OPTIONAL_FN(ssl_proxy_enable);
    APR_REGISTER_OPTIONAL_FN(ssl_engine_disable);
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

