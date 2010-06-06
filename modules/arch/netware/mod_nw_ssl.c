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

#include <unilib.h>

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
typedef struct seclistenup_rec seclistenup_rec;
typedef struct secsocket_data secsocket_data;

struct seclisten_rec {
    seclisten_rec *next;
    struct sockaddr_in local_addr;   /* local IP address and port */
    int fd;
    int used;                        /* Only used during restart */
    char key[MAX_KEY];
    int mutual;
    char *addr;
    apr_port_t port;
};

struct seclistenup_rec {
    seclistenup_rec *next;
    char key[MAX_KEY];
    char *addr;
    apr_port_t port;
};

struct NWSSLSrvConfigRec {
    apr_table_t *sltable;
    apr_table_t *slutable;
        apr_pool_t *pPool;
};

struct secsocket_data {
    apr_socket_t* csd;
    int is_secure;
};

static apr_array_header_t *certlist = NULL;
static unicode_t** certarray = NULL;
static int numcerts = 0;
static seclisten_rec* ap_seclisteners = NULL;
static seclistenup_rec* ap_seclistenersup = NULL;

static ap_listen_rec *nw_old_listeners;

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

static char *get_port_key(conn_rec *c)
{
    seclistenup_rec *sl;

    for (sl = ap_seclistenersup; sl; sl = sl->next) {
        if ((sl->port == (c->local_addr)->port) &&
            ((strcmp(sl->addr, "0.0.0.0") == 0) || (strcmp(sl->addr, c->local_ip) == 0))) {
            return sl->key;
        }
    }
    return NULL;
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
        ap_log_error(APLOG_MARK, APLOG_CRIT, WSAGetLastError(), sconf,
                     "make_secure_socket: failed to get a socket for %s",
                     addr);
        return -1;
    }

    if (!mutual) {
        optParam = SO_SSL_ENABLE | SO_SSL_SERVER;

        if (WSAIoctl(s, SO_SSL_SET_FLAGS, (char *)&optParam,
            sizeof(optParam), NULL, 0, NULL, NULL, NULL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, WSAGetLastError(), sconf,
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
        ap_log_error(APLOG_MARK, APLOG_CRIT, WSAGetLastError(), sconf,
                     "make_secure_socket: for %s, WSAIoctl: "
                     "(SO_SSL_SET_SERVER)", addr);
        return -1;
    }

    if (mutual) {
        optParam = 0x07;  // SO_SSL_AUTH_CLIENT

        if(WSAIoctl(s, SO_SSL_SET_FLAGS, (char*)&optParam,
            sizeof(optParam), NULL, 0, NULL, NULL, NULL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, WSAGetLastError(), sconf,
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
        sNWTLSOpts.walletProvider = WAL_PROV_DER;   //the wallet provider defined in wdefs.h
        sNWTLSOpts.TrustedRootList = certarray;     //array of certs in UNICODE format
        sNWTLSOpts.numElementsInTRList = numcerts;  //number of certs in TRList
    }
    else {
        /* setup the socket for SSL */
        unicpy(keyFileName, L"SSL CertificateIP");
        sWS2Opts.wallet = keyFileName;    /* no client certificate */
        sWS2Opts.walletlen = unilen(keyFileName);

        sNWTLSOpts.walletProvider = WAL_PROV_KMO;  //the wallet provider defined in wdefs.h
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

int SSLize_Socket(SOCKET socketHnd, char *key, request_rec *r)
{
    int rcode;
    struct tlsserveropts sWS2Opts;
    struct nwtlsopts    sNWTLSOpts;
    unicode_t SASKey[512];
    unsigned long ulFlag;

    memset((char *)&sWS2Opts, 0, sizeof(struct tlsserveropts));
    memset((char *)&sNWTLSOpts, 0, sizeof(struct nwtlsopts));


    ulFlag = SO_TLS_ENABLE;
    rcode = WSAIoctl(socketHnd, SO_TLS_SET_FLAGS, &ulFlag, sizeof(unsigned long), NULL, 0, NULL, NULL, NULL);
    if(rcode)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "Error: %d with WSAIoctl(SO_TLS_SET_FLAGS, SO_TLS_ENABLE)", WSAGetLastError());
        goto ERR;
    }


    ulFlag = SO_TLS_SERVER;
    rcode = WSAIoctl(socketHnd, SO_TLS_SET_FLAGS, &ulFlag, sizeof(unsigned long),NULL, 0, NULL, NULL, NULL);

    if(rcode)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "Error: %d with WSAIoctl(SO_TLS_SET_FLAGS, SO_TLS_SERVER)", WSAGetLastError());
        goto ERR;
    }

    loc2uni(UNI_LOCAL_DEFAULT, SASKey, key, 0, 0);

    //setup the tlsserveropts struct
    sWS2Opts.wallet = SASKey;
    sWS2Opts.walletlen = unilen(SASKey);
    sWS2Opts.sidtimeout = 0;
    sWS2Opts.sidentries = 0;
    sWS2Opts.siddir = NULL;
    sWS2Opts.options = &sNWTLSOpts;

    //setup the nwtlsopts structure

    sNWTLSOpts.walletProvider               = WAL_PROV_KMO;
    sNWTLSOpts.keysList                     = NULL;
    sNWTLSOpts.numElementsInKeyList         = 0;
    sNWTLSOpts.reservedforfutureuse         = NULL;
    sNWTLSOpts.reservedforfutureCRL         = NULL;
    sNWTLSOpts.reservedforfutureCRLLen      = 0;
    sNWTLSOpts.reserved1                    = NULL;
    sNWTLSOpts.reserved2                    = NULL;
    sNWTLSOpts.reserved3                    = NULL;


    rcode = WSAIoctl(socketHnd,
                     SO_TLS_SET_SERVER,
                     &sWS2Opts,
                     sizeof(struct tlsserveropts),
                     NULL,
                     0,
                     NULL,
                     NULL,
                     NULL);
    if(SOCKET_ERROR == rcode) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "Error: %d with WSAIoctl(SO_TLS_SET_SERVER)", WSAGetLastError());
        goto ERR;
    }

ERR:
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
    ap_listen_rec **walk;
    apr_sockaddr_t *sa;
    int found_listener = 0;


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

    new = apr_pcalloc(cmd->server->process->pool, sizeof(seclisten_rec));
    new->local_addr.sin_family = AF_INET;

    if (ports == ips) {
        new->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr = apr_pstrdup(cmd->server->process->pool, "0.0.0.0");
    }
    else {
        new->local_addr.sin_addr.s_addr = parse_addr(ips, NULL);
        addr = apr_pstrdup(cmd->server->process->pool, ips);
    }

    port = atoi(ports);

    if (!port)
        return "Port must be numeric";

    /* If the specified addr:port was created previously, put the listen
       socket record back on the ap_listeners list so that the socket
       will be reused rather than recreated */
    for (walk = &nw_old_listeners; *walk;) {
        sa = (*walk)->bind_addr;
        if (sa) {
            ap_listen_rec *new;
            apr_port_t oldport;

            oldport = sa->port;
            /* If both ports are equivalent, then if their names are equivalent,
             * then we will re-use the existing record.
             */
            if (port == oldport &&
                ((!addr && !sa->hostname) ||
                 ((addr && sa->hostname) && !strcmp(sa->hostname, addr)))) {
                new = *walk;
                *walk = new->next;
                new->next = ap_listeners;
                ap_listeners = new;
                found_listener = 1;
                continue;
            }
        }

        walk = &(*walk)->next;
    }

    apr_table_add(sc->sltable, ports, addr);

    /* If we found a pre-existing listen socket record, then there
       is no need to create a new secure listen socket record. */
    if (found_listener) {
        return NULL;
    }

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

static const char *set_secure_upgradeable_listener(cmd_parms *cmd, void *dummy,
                                       const char *ips, const char* key)
{
    NWSSLSrvConfigRec* sc = get_nwssl_cfg(cmd->server);
    seclistenup_rec *listen_node;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    char *ports, *addr;
    unsigned short port;
    seclistenup_rec *new;

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

    if (ports == ips) {
        addr = apr_pstrdup(cmd->pool, "0.0.0.0");
    }
    else {
        addr = apr_pstrdup(cmd->pool, ips);
    }

    port = atoi(ports);

    if (!port)
        return "Port must be numeric";

    apr_table_set(sc->slutable, ports, addr);

    new = apr_pcalloc(cmd->pool, sizeof(seclistenup_rec));
    new->next = ap_seclistenersup;
    strcpy(new->key, key);
    new->addr = addr;
    new->port = port;
    ap_seclistenersup = new;

    return err;
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
    seclisten_rec* ap_old_seclisteners;
    char *ports, *addr;
    unsigned short port;
    ap_listen_rec **walk;
    seclisten_rec **secwalk;
    apr_sockaddr_t *sa;
    int found;

  /* Pull all of the listeners that were created by mod_nw_ssl out of the
     ap_listeners list so that the normal listen socket processing does
     automatically close them */
    nw_old_listeners = NULL;
    ap_old_seclisteners = NULL;

    for (secwalk = &ap_seclisteners; *secwalk;) {
        found = 0;
        for (walk = &ap_listeners; *walk;) {
            sa = (*walk)->bind_addr;
            if (sa) {
                ap_listen_rec *new;
                seclisten_rec *secnew;
                apr_port_t oldport;

                oldport = sa->port;
                /* If both ports are equivalent, then if their names are equivalent,
                 * then we will re-use the existing record.
                 */
                if ((*secwalk)->port == oldport &&
                    ((!(*secwalk)->addr && !sa->hostname) ||
                     (((*secwalk)->addr && sa->hostname) && !strcmp(sa->hostname, (*secwalk)->addr)))) {
                    /* Move the listen socket from ap_listeners to nw_old_listeners */
                    new = *walk;
                    *walk = new->next;
                    new->next = nw_old_listeners;
                    nw_old_listeners = new;

                    /* Move the secure socket record to ap_old_seclisterners */
                    secnew = *secwalk;
                    *secwalk = secnew->next;
                    secnew->next = ap_old_seclisteners;
                    ap_old_seclisteners = secnew;
                    found = 1;
                    break;
                }
            }

            walk = &(*walk)->next;
        }
        if (!found && &(*secwalk)->next) {
            secwalk = &(*secwalk)->next;
        }
    }

    /* Restore the secure socket records list so that the post config can
       process all of the sockets normally */
    ap_seclisteners = ap_old_seclisteners;
    ap_seclistenersup = NULL;
    certlist = apr_array_make(pconf, 1, sizeof(char *));

    /* Now that we have removed all of the mod_nw_ssl created socket records,
       allow the normal listen socket handling to occur.
       NOTE: If for any reason mod_nw_ssl is removed as a built-in module,
       the following call must be put back into the pre-config handler of the
       MPM.  It is only here to ensure that mod_nw_ssl fixes up the listen
       socket list before anything else looks at it. */
    ap_listen_pre_config();

    return OK;
}

static int nwssl_pre_connection(conn_rec *c, void *csd)
{

    if (apr_table_get(c->notes, "nwconv-ssl")) {
        convert_secure_socket(c, (apr_socket_t*)csd);
    }
    else {
        secsocket_data *csd_data = apr_palloc(c->pool, sizeof(secsocket_data));

        csd_data->csd = (apr_socket_t*)csd;
        csd_data->is_secure = 0;
        ap_set_module_config(c->conn_config, &nwssl_module, (void*)csd_data);
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
    seclistenup_rec *slu;
    int found;
    ap_listen_rec *walk;
    seclisten_rec *secwalk, *lastsecwalk;
    apr_sockaddr_t *sa;
    int found_listener = 0;

    /* Walk the old listeners list and compare it to the secure
       listeners list and remove any secure listener records that
       are not being reused */
    for (walk = nw_old_listeners; walk; walk = walk->next) {
        sa = walk->bind_addr;
        if (sa) {
            ap_listen_rec *new;
            apr_port_t oldport;

            oldport = sa->port;
            for (secwalk = ap_seclisteners, lastsecwalk = ap_seclisteners; secwalk; secwalk = lastsecwalk->next) {
                unsigned short port = secwalk->port;
                char *addr = secwalk->addr;
                /* If both ports are equivalent, then if their names are equivalent,
                 * then we will re-use the existing record.
                 */
                if (port == oldport &&
                    ((!addr && !sa->hostname) ||
                     ((addr && sa->hostname) && !strcmp(sa->hostname, addr)))) {
                    if (secwalk == ap_seclisteners) {
                        ap_seclisteners = secwalk->next;
                    }
                    else {
                        lastsecwalk->next = secwalk->next;
                    }
                    apr_socket_close(walk->sd);
                    walk->active = 0;
                    break;
                }
                else {
                    lastsecwalk = secwalk;
                }
            }
        }
    }

    for (sl = ap_seclisteners; sl != NULL; sl = sl->next) {
        /* If we find a pre-existing listen socket and it has already been
           created, then no neeed to go any further, just reuse it. */
        if (((sl->fd = find_secure_listener(sl)) >= 0) && (sl->used)) {
            continue;
        }

        if (sl->fd < 0)
            sl->fd = make_secure_socket(s->process->pool, &sl->local_addr, sl->key, sl->mutual, s);

        if (sl->fd >= 0) {
            apr_os_sock_info_t sock_info;

            sock_info.os_sock = &(sl->fd);
            sock_info.local = (struct sockaddr*)&(sl->local_addr);
            sock_info.remote = NULL;
            sock_info.family = APR_INET;
            sock_info.type = SOCK_STREAM;

            apr_os_sock_make(&sd, &sock_info, s->process->pool);

            lr = apr_pcalloc(s->process->pool, sizeof(ap_listen_rec));

            if (lr) {
                lr->sd = sd;
                if ((status = apr_sockaddr_info_get(&lr->bind_addr, sl->addr, APR_UNSPEC, sl->port, 0,
                                              s->process->pool)) != APR_SUCCESS) {
                    ap_log_perror(APLOG_MARK, APLOG_CRIT, status, pconf,
                                 "alloc_listener: failed to set up sockaddr for %s:%d", sl->addr, sl->port);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                lr->next = ap_listeners;
                ap_listeners = lr;
                apr_pool_cleanup_register(s->process->pool, lr, nwssl_socket_cleanup, apr_pool_cleanup_null);
            }
        } else {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    for (slu = ap_seclistenersup; slu; slu = slu->next) {
        /* Check the listener list for a matching upgradeable listener */
        found = 0;
        for (lr = ap_listeners; lr; lr = lr->next) {
            if (slu->port == lr->bind_addr->port) {
                found = 1;
                break;
            }
        }
        if (!found) {
            ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, plog,
                         "No Listen directive found for upgradeable listener %s:%d", slu->addr, slu->port);
        }
    }

    build_cert_list(s->process->pool);

    return OK;
}

static void *nwssl_config_server_create(apr_pool_t *p, server_rec *s)
{
    NWSSLSrvConfigRec *new = apr_palloc(p, sizeof(NWSSLSrvConfigRec));
    new->sltable = apr_table_make(p, 5);
    new->slutable = apr_table_make(p, 5);
    return new;
}

static void *nwssl_config_server_merge(apr_pool_t *p, void *basev, void *addv)
{
    NWSSLSrvConfigRec *base = (NWSSLSrvConfigRec *)basev;
    NWSSLSrvConfigRec *add  = (NWSSLSrvConfigRec *)addv;
    NWSSLSrvConfigRec *merged  = (NWSSLSrvConfigRec *)apr_palloc(p, sizeof(NWSSLSrvConfigRec));
    return merged;
}

static int compare_ipports(void *rec, const char *key, const char *value)
{
    conn_rec *c = (conn_rec*)rec;

    if (value &&
        ((strcmp(value, "0.0.0.0") == 0) || (strcmp(value, c->local_ip) == 0)))
    {
        return 0;
    }
    return 1;
}

static int isSecureConnEx (const server_rec *s, const conn_rec *c, const apr_table_t *t)
{
    char port[8];

    itoa((c->local_addr)->port, port, 10);
    if (!apr_table_do(compare_ipports, (void*)c, t, port, NULL))
    {
        return 1;
    }

    return 0;
}

static int isSecureConn (const server_rec *s, const conn_rec *c)
{
    NWSSLSrvConfigRec *sc = get_nwssl_cfg(s);

    return isSecureConnEx (s, c, sc->sltable);
}

static int isSecureConnUpgradeable (const server_rec *s, const conn_rec *c)
{
    NWSSLSrvConfigRec *sc = get_nwssl_cfg(s);

    return isSecureConnEx (s, c, sc->slutable);
}

static int isSecure (const request_rec *r)
{
        return isSecureConn (r->server, r->connection);
}

static int isSecureUpgradeable (const request_rec *r)
{
        return isSecureConnUpgradeable (r->server, r->connection);
}

static int isSecureUpgraded (const request_rec *r)
{
    secsocket_data *csd_data = (secsocket_data*)ap_get_module_config(r->connection->conn_config, &nwssl_module);

        return csd_data->is_secure;
}

static int nwssl_hook_Fixup(request_rec *r)
{
    int i;

    if (!isSecure(r) && !isSecureUpgraded(r))
        return DECLINED;

    apr_table_set(r->subprocess_env, "HTTPS", "on");

    return DECLINED;
}

static const char *nwssl_hook_http_scheme(const request_rec *r)
{
    if (isSecure(r) && !isSecureUpgraded(r))
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
    secsocket_data *csd_data = (secsocket_data*)ap_get_module_config(c->conn_config, &nwssl_module);

    return isSecureConn (c->base_server, c) || (csd_data && csd_data->is_secure);
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
            else if (strcEQ(var, "HTTPS")) {
                if (isSecure(r) || isSecureUpgraded(r))
                    result = "on";
                else
                    result = "off";
            }
            else if (strlen(var) > 5 && strcEQn(var, "HTTP:", 5))
                /* all other headers from which we are still not know about */
                result = apr_table_get(r->headers_in, var+5);
            break;

        case 'R':
        case 'r':
            if (strcEQ(var, "REQUEST_METHOD"))
                result = r->method;
            else if (strcEQ(var, "REQUEST_SCHEME"))
                result = ap_http_scheme(r);
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
            result = ap_get_server_banner();
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

#define SWITCH_STATUS_LINE "HTTP/1.1 101 Switching Protocols"
#define UPGRADE_HEADER "Upgrade: TLS/1.0, HTTP/1.1"
#define CONNECTION_HEADER "Connection: Upgrade"

static apr_status_t ssl_io_filter_Upgrade(ap_filter_t *f,
                                         apr_bucket_brigade *bb)

{
    const char *upgrade;
    apr_bucket_brigade *upgradebb;
    request_rec *r = f->r;
    apr_socket_t *csd = NULL;
    char *key;
    int ret;
    secsocket_data *csd_data;
    apr_bucket *b;
    apr_status_t rv;

    /* Just remove the filter, if it doesn't work the first time, it won't
     * work at all for this request.
     */
    ap_remove_output_filter(f);

    /* No need to ensure that this is a server with optional SSL, the filter
     * is only inserted if that is true.
     */

    upgrade = apr_table_get(r->headers_in, "Upgrade");
    if (upgrade == NULL
        || strcmp(ap_getword(r->pool, &upgrade, ','), "TLS/1.0")) {
            /* "Upgrade: TLS/1.0, ..." header not found, don't do Upgrade */
        return ap_pass_brigade(f->next, bb);
    }

    apr_table_unset(r->headers_out, "Upgrade");

    if (r) {
        csd_data = (secsocket_data*)ap_get_module_config(r->connection->conn_config, &nwssl_module);
        csd = csd_data->csd;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "Unable to get upgradeable socket handle");
        return ap_pass_brigade(f->next, bb);
    }


    /* Send the interim 101 response. */
    upgradebb = apr_brigade_create(r->pool, f->c->bucket_alloc);

    ap_fputstrs(f->next, upgradebb, SWITCH_STATUS_LINE, CRLF,
                UPGRADE_HEADER, CRLF, CONNECTION_HEADER, CRLF, CRLF, NULL);

    b = apr_bucket_flush_create(f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(upgradebb, b);

    rv = ap_pass_brigade(f->next, upgradebb);
    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "could not send interim 101 Upgrade response");
        return AP_FILTER_ERROR;
    }

    key = get_port_key(r->connection);

    if (csd && key) {
        int sockdes;
        apr_os_sock_get(&sockdes, csd);


        ret = SSLize_Socket(sockdes, key, r);
        if (!ret) {
            csd_data->is_secure = 1;
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "Upgradeable socket handle not found");
        return AP_FILTER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                 "Awaiting re-negotiation handshake");

    /* Now that we have initialized the ssl connection which added the ssl_io_filter,
       pass the brigade off to the connection based output filters so that the
       request can complete encrypted */
    return ap_pass_brigade(f->c->output_filters, bb);
}

static void ssl_hook_Insert_Filter(request_rec *r)
{
    NWSSLSrvConfigRec *sc = get_nwssl_cfg(r->server);

    if (isSecureUpgradeable (r)) {
        ap_add_output_filter("UPGRADE_FILTER", NULL, r, r->connection);
    }
}

static const command_rec nwssl_module_cmds[] =
{
    AP_INIT_TAKE23("SecureListen", set_secure_listener, NULL, RSRC_CONF,
      "specify an address and/or port with a key pair name.\n"
      "Optional third parameter of MUTUAL configures the port for mutual authentication."),
    AP_INIT_TAKE2("NWSSLUpgradeable", set_secure_upgradeable_listener, NULL, RSRC_CONF,
      "specify an address and/or port with a key pair name, that can be upgraded to an SSL connection.\n"
      "The address and/or port must have already be defined using a Listen directive."),
    AP_INIT_ITERATE("NWSSLTrustedCerts", set_trusted_certs, NULL, RSRC_CONF,
        "Adds trusted certificates that are used to create secure connections to proxied servers"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter ("UPGRADE_FILTER", ssl_io_filter_Upgrade, NULL, AP_FTYPE_PROTOCOL + 5);

    ap_hook_pre_config(nwssl_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(nwssl_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(nwssl_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(nwssl_hook_Fixup, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_http_scheme(nwssl_hook_http_scheme, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port(nwssl_hook_default_port, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_filter(ssl_hook_Insert_Filter, NULL, NULL, APR_HOOK_MIDDLE);

    APR_REGISTER_OPTIONAL_FN(ssl_is_https);
    APR_REGISTER_OPTIONAL_FN(ssl_var_lookup);

    APR_REGISTER_OPTIONAL_FN(ssl_proxy_enable);
    APR_REGISTER_OPTIONAL_FN(ssl_engine_disable);
}

AP_DECLARE_MODULE(nwssl) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    nwssl_config_server_create, /* server config */
    nwssl_config_server_merge,  /* merge server config */
    nwssl_module_cmds,          /* command apr_table_t */
    register_hooks
};

