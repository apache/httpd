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

/**
 * @file  vhost.c
 * @brief functions pertaining to virtual host addresses
 *        (configuration and run-time)
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_vhost.h"
#include "http_protocol.h"
#include "http_core.h"

#if APR_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

/*
 * After all the definitions there's an explanation of how it's all put
 * together.
 */

/* meta-list of name-vhosts.  Each server_rec can be in possibly multiple
 * lists of name-vhosts.
 */
typedef struct name_chain name_chain;
struct name_chain {
    name_chain *next;
    server_addr_rec *sar;       /* the record causing it to be in
                                 * this chain (needed for port comparisons) */
    server_rec *server;         /* the server to use on a match */
};

/* meta-list of ip addresses.  Each server_rec can be in possibly multiple
 * hash chains since it can have multiple ips.
 */
typedef struct ipaddr_chain ipaddr_chain;
struct ipaddr_chain {
    ipaddr_chain *next;
    server_addr_rec *sar;       /* the record causing it to be in
                                 * this chain (need for both ip addr and port
                                 * comparisons) */
    server_rec *server;         /* the server to use if this matches */
    name_chain *names;          /* if non-NULL then a list of name-vhosts
                                 * sharing this address */
    name_chain *initialnames;   /* no runtime use, temporary storage of first
                                 * NVH'es names */
};

/* This defines the size of the hash table used for hashing ip addresses
 * of virtual hosts.  It must be a power of two.
 */
#ifndef IPHASH_TABLE_SIZE
#define IPHASH_TABLE_SIZE 256
#endif

/* A (n) bucket hash table, each entry has a pointer to a server rec and
 * a pointer to the other entries in that bucket.  Each individual address,
 * even for virtualhosts with multiple addresses, has an entry in this hash
 * table.  There are extra buckets for _default_, and name-vhost entries.
 *
 * Note that after config time this is constant, so it is thread-safe.
 */
static ipaddr_chain *iphash_table[IPHASH_TABLE_SIZE];

/* dump out statistics about the hash function */
/* #define IPHASH_STATISTICS */

/* list of the _default_ servers */
static ipaddr_chain *default_list;

/* whether a config error was seen */
static int config_error = 0;

/* config check function */
static int vhost_check_config(apr_pool_t *p, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s);

/*
 * How it's used:
 *
 * The ip address determines which chain in iphash_table is interesting, then
 * a comparison is done down that chain to find the first ipaddr_chain whose
 * sar matches the address:port pair.
 *
 * If that ipaddr_chain has names == NULL then you're done, it's an ip-vhost.
 *
 * Otherwise it's a name-vhost list, and the default is the server in the
 * ipaddr_chain record.  We tuck away the ipaddr_chain record in the
 * conn_rec field vhost_lookup_data.  Later on after the headers we get a
 * second chance, and we use the name_chain to figure out what name-vhost
 * matches the headers.
 *
 * If there was no ip address match in the iphash_table then do a lookup
 * in the default_list.
 *
 * How it's put together ... well you should be able to figure that out
 * from how it's used.  Or something like that.
 */


/* called at the beginning of the config */
AP_DECLARE(void) ap_init_vhost_config(apr_pool_t *p)
{
    memset(iphash_table, 0, sizeof(iphash_table));
    default_list = NULL;
    ap_hook_check_config(vhost_check_config, NULL, NULL, APR_HOOK_MIDDLE);
}


/*
 * Parses a host of the form <address>[:port]
 * paddr is used to create a list in the order of input
 * **paddr is the ->next pointer of the last entry (or s->addrs)
 * *paddr is the variable used to keep track of **paddr between calls
 * port is the default port to assume
 */
static const char *get_addresses(apr_pool_t *p, const char *w_,
                                 server_addr_rec ***paddr,
                                 apr_port_t default_port)
{
    apr_sockaddr_t *my_addr;
    server_addr_rec *sar;
    char *w, *host, *scope_id;
    int wild_port;
    apr_size_t wlen;
    apr_port_t port;
    apr_status_t rv;

    if (*w_ == '\0')
        return NULL;

    wlen = strlen(w_);                   /* wlen must be > 0 at this point */
    w = apr_pstrmemdup(p, w_, wlen);
    /* apr_parse_addr_port() doesn't understand ":*" so handle that first. */
    wild_port = 0;
    if (w[wlen - 1] == '*') {
        if (wlen < 2) {
            wild_port = 1;
        }
        else if (w[wlen - 2] == ':') {
            w[wlen - 2] = '\0';
            wild_port = 1;
        }
    }
    rv = apr_parse_addr_port(&host, &scope_id, &port, w, p);
    /* If the string is "80", apr_parse_addr_port() will be happy and set
     * host to NULL and port to 80, so watch out for that.
     */
    if (rv != APR_SUCCESS) {
        return "The address or port is invalid";
    }
    if (!host) {
        return "Missing address for VirtualHost";
    }
    if (scope_id) {
        return "Scope ids are not supported";
    }
    if (!port && !wild_port) {
        port = default_port;
    }

    if (strcmp(host, "*") == 0 || strcasecmp(host, "_default_") == 0) {
        rv = apr_sockaddr_info_get(&my_addr, NULL, APR_UNSPEC, port, 0, p);
        if (rv) {
            return "Could not determine a wildcard address ('0.0.0.0') -- "
                "check resolver configuration.";
        }
    }
    else {
        rv = apr_sockaddr_info_get(&my_addr, host, APR_UNSPEC, port, 0, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, APLOGNO(00547)
                "Could not resolve host name %s -- ignoring!", host);
            return NULL;
        }
    }

    /* Remember all addresses for the host */

    do {
        sar = apr_pcalloc(p, sizeof(server_addr_rec));
        **paddr = sar;
        *paddr = &sar->next;
        sar->host_addr = my_addr;
        sar->host_port = port;
        sar->virthost = host;
        my_addr = my_addr->next;
    } while (my_addr);

    return NULL;
}


/* parse the <VirtualHost> addresses */
const char *ap_parse_vhost_addrs(apr_pool_t *p,
                                 const char *hostname,
                                 server_rec *s)
{
    server_addr_rec **addrs;
    const char *err;

    /* start the list of addreses */
    addrs = &s->addrs;
    while (hostname[0]) {
        err = get_addresses(p, ap_getword_conf(p, &hostname), &addrs, s->port);
        if (err) {
            *addrs = NULL;
            return err;
        }
    }
    /* terminate the list */
    *addrs = NULL;
    if (s->addrs) {
        if (s->addrs->host_port) {
            /* override the default port which is inherited from main_server */
            s->port = s->addrs->host_port;
        }
    }
    return NULL;
}


AP_DECLARE_NONSTD(const char *)ap_set_name_virtual_host(cmd_parms *cmd,
                                                        void *dummy,
                                                        const char *arg)
{
    static int warnonce = 0;
    if (++warnonce == 1) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE|APLOG_STARTUP, APR_SUCCESS, NULL, APLOGNO(00548)
                     "NameVirtualHost has no effect and will be removed in the "
                     "next release %s:%d",
                     cmd->directive->filename,
                     cmd->directive->line_num);
    }

    return NULL;
}


/* hash table statistics, keep this in here for the beta period so
 * we can find out if the hash function is ok
 */
#ifdef IPHASH_STATISTICS
static int iphash_compare(const void *a, const void *b)
{
    return (*(const int *) b - *(const int *) a);
}


static void dump_iphash_statistics(server_rec *main_s)
{
    unsigned count[IPHASH_TABLE_SIZE];
    int i;
    ipaddr_chain *src;
    unsigned total;
    char buf[HUGE_STRING_LEN];
    char *p;

    total = 0;
    for (i = 0; i < IPHASH_TABLE_SIZE; ++i) {
        count[i] = 0;
        for (src = iphash_table[i]; src; src = src->next) {
            ++count[i];
            if (i < IPHASH_TABLE_SIZE) {
                /* don't count the slop buckets in the total */
                ++total;
            }
        }
    }
    qsort(count, IPHASH_TABLE_SIZE, sizeof(count[0]), iphash_compare);
    p = buf + apr_snprintf(buf, sizeof(buf),
                           "iphash: total hashed = %u, avg chain = %u, "
                           "chain lengths (count x len):",
                           total, total / IPHASH_TABLE_SIZE);
    total = 1;
    for (i = 1; i < IPHASH_TABLE_SIZE; ++i) {
        if (count[i - 1] != count[i]) {
            p += apr_snprintf(p, sizeof(buf) - (p - buf), " %ux%u",
                              total, count[i - 1]);
            total = 1;
        }
        else {
            ++total;
        }
    }
    p += apr_snprintf(p, sizeof(buf) - (p - buf), " %ux%u",
                      total, count[IPHASH_TABLE_SIZE - 1]);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, main_s, buf);
}
#endif


/* This hashing function is designed to get good distribution in the cases
 * where the server is handling entire "networks" of servers.  i.e. a
 * whack of /24s.  This is probably the most common configuration for
 * ISPs with large virtual servers.
 *
 * NOTE: This function is symmetric (i.e. collapses all 4 octets
 * into one), so machine byte order (big/little endianness) does not matter.
 *
 * Hash function provided by David Hankins.
 */
static APR_INLINE unsigned hash_inaddr(unsigned key)
{
    key ^= (key >> 16);
    return ((key >> 8) ^ key) % IPHASH_TABLE_SIZE;
}

static APR_INLINE unsigned hash_addr(struct apr_sockaddr_t *sa)
{
    unsigned key;

    /* The key is the last four bytes of the IP address.
     * For IPv4, this is the entire address, as always.
     * For IPv6, this is usually part of the MAC address.
     */
    key = *(unsigned *)((char *)sa->ipaddr_ptr + sa->ipaddr_len - 4);
    return hash_inaddr(key);
}

static ipaddr_chain *new_ipaddr_chain(apr_pool_t *p,
                                      server_rec *s, server_addr_rec *sar)
{
    ipaddr_chain *new;

    new = apr_palloc(p, sizeof(*new));
    new->names = NULL;
    new->initialnames = NULL;
    new->server = s;
    new->sar = sar;
    new->next = NULL;
    return new;
}


static name_chain *new_name_chain(apr_pool_t *p,
                                  server_rec *s, server_addr_rec *sar)
{
    name_chain *new;

    new = apr_palloc(p, sizeof(*new));
    new->server = s;
    new->sar = sar;
    new->next = NULL;
    return new;
}


static APR_INLINE ipaddr_chain *find_ipaddr(apr_sockaddr_t *sa)
{
    unsigned bucket;
    ipaddr_chain *trav = NULL;
    ipaddr_chain *wild_match = NULL;

    /* scan the hash table for an exact match first */
    bucket = hash_addr(sa);
    for (trav = iphash_table[bucket]; trav; trav = trav->next) {
        server_addr_rec *sar = trav->sar;
        apr_sockaddr_t *cur = sar->host_addr;

        if (cur->port == sa->port) {
            if (apr_sockaddr_equal(cur, sa)) {
                return trav;
            }
        }
        if (wild_match == NULL && (cur->port == 0 || sa->port == 0)) {
            if (apr_sockaddr_equal(cur, sa)) {
                /* don't break, continue looking for an exact match */
                wild_match = trav;
            }
        }
    }
    return wild_match;
}

static ipaddr_chain *find_default_server(apr_port_t port)
{
    server_addr_rec *sar;
    ipaddr_chain *trav = NULL;
    ipaddr_chain *wild_match = NULL;

    for (trav = default_list; trav; trav = trav->next) {
        sar = trav->sar;
        if (sar->host_port == port) {
            /* match! */
            return trav;
        }
        if (wild_match == NULL && sar->host_port == 0) {
            /* don't break, continue looking for an exact match */
            wild_match = trav;
        }
    }
    return wild_match;
}

#if APR_HAVE_IPV6
#define IS_IN6_ANYADDR(ad) ((ad)->family == APR_INET6                   \
                            && IN6_IS_ADDR_UNSPECIFIED(&(ad)->sa.sin6.sin6_addr))
#else
#define IS_IN6_ANYADDR(ad) (0)
#endif

static void dump_a_vhost(apr_file_t *f, ipaddr_chain *ic)
{
    name_chain *nc;
    int len;
    char buf[MAX_STRING_LEN];
    apr_sockaddr_t *ha = ic->sar->host_addr;

    if ((ha->family == APR_INET && ha->sa.sin.sin_addr.s_addr == INADDR_ANY)
        || IS_IN6_ANYADDR(ha)) {
        len = apr_snprintf(buf, sizeof(buf), "*:%u",
                           ic->sar->host_port);
    }
    else {
        len = apr_snprintf(buf, sizeof(buf), "%pI", ha);
    }
    if (ic->sar->host_port == 0) {
        buf[len-1] = '*';
    }
    if (ic->names == NULL) {
        apr_file_printf(f, "%-22s %s (%s:%u)\n", buf,
                        ic->server->server_hostname,
                        ic->server->defn_name, ic->server->defn_line_number);
        return;
    }
    apr_file_printf(f, "%-22s is a NameVirtualHost\n"
                    "%8s default server %s (%s:%u)\n",
                    buf, "", ic->server->server_hostname,
                    ic->server->defn_name, ic->server->defn_line_number);
    for (nc = ic->names; nc; nc = nc->next) {
        if (nc->sar->host_port) {
            apr_file_printf(f, "%8s port %u ", "", nc->sar->host_port);
        }
        else {
            apr_file_printf(f, "%8s port * ", "");
        }
        apr_file_printf(f, "namevhost %s (%s:%u)\n",
                        nc->server->server_hostname,
                        nc->server->defn_name, nc->server->defn_line_number);
        if (nc->server->names) {
            apr_array_header_t *names = nc->server->names;
            char **name = (char **)names->elts;
            int i;
            for (i = 0; i < names->nelts; ++i) {
                if (name[i]) {
                    apr_file_printf(f, "%16s alias %s\n", "", name[i]);
                }
            }
        }
        if (nc->server->wild_names) {
            apr_array_header_t *names = nc->server->wild_names;
            char **name = (char **)names->elts;
            int i;
            for (i = 0; i < names->nelts; ++i) {
                if (name[i]) {
                    apr_file_printf(f, "%16s wild alias %s\n", "", name[i]);
                }
            }
        }
    }
}

static void dump_vhost_config(apr_file_t *f)
{
    ipaddr_chain *ic;
    int i;

    apr_file_printf(f, "VirtualHost configuration:\n");

    /* non-wildcard servers */
    for (i = 0; i < IPHASH_TABLE_SIZE; ++i) {
        for (ic = iphash_table[i]; ic; ic = ic->next) {
            dump_a_vhost(f, ic);
        }
    }

    /* wildcard servers */
    for (ic = default_list; ic; ic = ic->next) {
        dump_a_vhost(f, ic);
    }
}


/*
 * When a second or later virtual host maps to the same IP chain,
 * add the relevant server names to the chain.  Special care is taken
 * to avoid adding ic->names until we're sure there are multiple VH'es.
 */
static void add_name_vhost_config(apr_pool_t *p, server_rec *main_s,
                                 server_rec *s, server_addr_rec *sar,
                                 ipaddr_chain *ic)
{

   name_chain *nc = new_name_chain(p, s, sar);
   nc->next = ic->names;

   /* iterating backwards, so each one we see becomes the current default server */
   ic->server = s;

   if (ic->names == NULL) {
       if (ic->initialnames == NULL) {
           /* first pass, set these names aside in case we see another VH.
            * Until then, this looks like an IP-based VH to runtime.
            */
           ic->initialnames = nc;
       }
       else {
           /* second pass through this chain -- this really is an NVH, and we
            * have two sets of names to link in.
            */
           nc->next = ic->initialnames;
           ic->names = nc;
           ic->initialnames = NULL;
       }
   }
   else {
       /* 3rd or more -- just keep stacking the names */
       ic->names = nc;
   }
}

/* compile the tables and such we need to do the run-time vhost lookups */
AP_DECLARE(void) ap_fini_vhost_config(apr_pool_t *p, server_rec *main_s)
{
    server_addr_rec *sar;
    int has_default_vhost_addr;
    server_rec *s;
    int i;
    ipaddr_chain **iphash_table_tail[IPHASH_TABLE_SIZE];

    /* Main host first */
    s = main_s;

    if (!s->server_hostname) {
        s->server_hostname = ap_get_local_host(p);
    }

    /* initialize the tails */
    for (i = 0; i < IPHASH_TABLE_SIZE; ++i) {
        iphash_table_tail[i] = &iphash_table[i];
    }

    /* The next things to go into the hash table are the virtual hosts
     * themselves.  They're listed off of main_s->next in the reverse
     * order they occured in the config file, so we insert them at
     * the iphash_table_tail but don't advance the tail.
     */

    for (s = main_s->next; s; s = s->next) {
        server_addr_rec *sar_prev = NULL;
        has_default_vhost_addr = 0;
        for (sar = s->addrs; sar; sar = sar->next) {
            ipaddr_chain *ic;
            char inaddr_any[16] = {0}; /* big enough to handle IPv4 or IPv6 */
            /* XXX: this treats 0.0.0.0 as a "default" server which matches no-exact-match for IPv6 */
            if (!memcmp(sar->host_addr->ipaddr_ptr, inaddr_any, sar->host_addr->ipaddr_len)) {
                ic = find_default_server(sar->host_port);

                if (ic && sar->host_port == ic->sar->host_port) { /* we're a match for an existing "default server"  */
                    if (!sar_prev || memcmp(sar_prev->host_addr->ipaddr_ptr, inaddr_any, sar_prev->host_addr->ipaddr_len)
                                  || sar_prev->host_port != sar->host_port) { 
                        add_name_vhost_config(p, main_s, s, sar, ic);
                    }
                }
                else { 
                    /* No default server, or we found a default server but
                    ** exactly one of us is a wildcard port, which means we want
                    ** two ip-based vhosts not an NVH with two names
                    */
                    ic = new_ipaddr_chain(p, s, sar);
                    ic->next = default_list;
                    default_list = ic;
                    add_name_vhost_config(p, main_s, s, sar, ic);
                }
                has_default_vhost_addr = 1;
            }
            else {
                /* see if it matches something we've already got */
                ic = find_ipaddr(sar->host_addr);

                if (!ic || sar->host_port != ic->sar->host_port) {
                    /* No matching server, or we found a matching server but
                    ** exactly one of us is a wildcard port, which means we want
                    ** two ip-based vhosts not an NVH with two names
                    */
                    unsigned bucket = hash_addr(sar->host_addr);
                    ic = new_ipaddr_chain(p, s, sar);
                    ic->next = *iphash_table_tail[bucket];
                    *iphash_table_tail[bucket] = ic;
                }
                add_name_vhost_config(p, main_s, s, sar, ic);
            }
            sar_prev = sar;
        }

        /* Ok now we want to set up a server_hostname if the user was
         * silly enough to forget one.
         * XXX: This is silly we should just crash and burn.
         */
        if (!s->server_hostname) {
            if (has_default_vhost_addr) {
                s->server_hostname = main_s->server_hostname;
            }
            else if (!s->addrs) {
                /* what else can we do?  at this point this vhost has
                    no configured name, probably because they used
                    DNS in the VirtualHost statement.  It's disabled
                    anyhow by the host matching code.  -djg */
                s->server_hostname =
                    apr_pstrdup(p, "bogus_host_without_forward_dns");
            }
            else {
                apr_status_t rv;
                char *hostname;

                rv = apr_getnameinfo(&hostname, s->addrs->host_addr, 0);
                if (rv == APR_SUCCESS) {
                    s->server_hostname = apr_pstrdup(p, hostname);
                }
                else {
                    /* again, what can we do?  They didn't specify a
                       ServerName, and their DNS isn't working. -djg */
                    char *ipaddr_str;

                    apr_sockaddr_ip_get(&ipaddr_str, s->addrs->host_addr);
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, main_s, APLOGNO(00549)
                                 "Failed to resolve server name "
                                 "for %s (check DNS) -- or specify an explicit "
                                 "ServerName",
                                 ipaddr_str);
                    s->server_hostname =
                        apr_pstrdup(p, "bogus_host_without_reverse_dns");
                }
            }
        }
    }

#ifdef IPHASH_STATISTICS
    dump_iphash_statistics(main_s);
#endif
    if (ap_exists_config_define("DUMP_VHOSTS")) {
        apr_file_t *thefile = NULL;
        apr_file_open_stdout(&thefile, p);
        dump_vhost_config(thefile);
    }
}

static int vhost_check_config(apr_pool_t *p, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s)
{
    return config_error ? !OK : OK;
}

/*****************************************************************************
 * run-time vhost matching functions
 */

/* Lowercase and remove any trailing dot and/or :port from the hostname,
 * and check that it is sane.
 *
 * In most configurations the exact syntax of the hostname isn't
 * important so strict sanity checking isn't necessary. However, in
 * mass hosting setups (using mod_vhost_alias or mod_rewrite) where
 * the hostname is interpolated into the filename, we need to be sure
 * that the interpolation doesn't expose parts of the filesystem.
 * We don't do strict RFC 952 / RFC 1123 syntax checking in order
 * to support iDNS and people who erroneously use underscores.
 * Instead we just check for filesystem metacharacters: directory
 * separators / and \ and sequences of more than one dot.
 */
static void fix_hostname(request_rec *r)
{
    char *host, *scope_id;
    char *dst;
    apr_port_t port;
    apr_status_t rv;
    const char *c;

    /* According to RFC 2616, Host header field CAN be blank. */
    if (!*r->hostname) {
        return;
    }

    /* apr_parse_addr_port will interpret a bare integer as a port
     * which is incorrect in this context.  So treat it separately.
     */
    for (c = r->hostname; apr_isdigit(*c); ++c);
    if (!*c) {  /* pure integer */
        return;
    }

    rv = apr_parse_addr_port(&host, &scope_id, &port, r->hostname, r->pool);
    if (rv != APR_SUCCESS || scope_id) {
        goto bad;
    }

    if (port) {
        /* Don't throw the Host: header's port number away:
           save it in parsed_uri -- ap_get_server_port() needs it! */
        /* @@@ XXX there should be a better way to pass the port.
         *         Like r->hostname, there should be a r->portno
         */
        r->parsed_uri.port = port;
        r->parsed_uri.port_str = apr_itoa(r->pool, (int)port);
    }

    /* if the hostname is an IPv6 numeric address string, it was validated
     * already; otherwise, further validation is needed
     */
    if (r->hostname[0] != '[') {
        for (dst = host; *dst; dst++) {
            if (apr_islower(*dst)) {
                /* leave char unchanged */
            }
            else if (*dst == '.') {
                if (*(dst + 1) == '.') {
                    goto bad;
                }
            }
            else if (apr_isupper(*dst)) {
                *dst = apr_tolower(*dst);
            }
            else if (*dst == '/' || *dst == '\\') {
                goto bad;
            }
        }
        /* strip trailing gubbins */
        if (dst > host && dst[-1] == '.') {
            dst[-1] = '\0';
        }
    }
    r->hostname = host;
    return;

bad:
    r->status = HTTP_BAD_REQUEST;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00550)
                  "Client sent malformed Host header: %s",
                  r->hostname);
    return;
}


/* return 1 if host matches ServerName or ServerAliases */
static int matches_aliases(server_rec *s, const char *host)
{
    int i;
    apr_array_header_t *names;

    /* match ServerName */
    if (!strcasecmp(host, s->server_hostname)) {
        return 1;
    }

    /* search all the aliases from ServerAlias directive */
    names = s->names;
    if (names) {
        char **name = (char **) names->elts;
        for (i = 0; i < names->nelts; ++i) {
            if(!name[i]) continue;
            if (!strcasecmp(host, name[i]))
                return 1;
        }
    }
    names = s->wild_names;
    if (names) {
        char **name = (char **) names->elts;
        for (i = 0; i < names->nelts; ++i) {
            if(!name[i]) continue;
            if (!ap_strcasecmp_match(host, name[i]))
                return 1;
        }
    }
    return 0;
}


/* Suppose a request came in on the same socket as this r, and included
 * a header "Host: host:port", would it map to r->server?  It's more
 * than just that though.  When we do the normal matches for each request
 * we don't even bother considering Host: etc on non-namevirtualhosts,
 * we just call it a match.  But here we require the host:port to match
 * the ServerName and/or ServerAliases.
 */
AP_DECLARE(int) ap_matches_request_vhost(request_rec *r, const char *host,
                                         apr_port_t port)
{
    server_rec *s;
    server_addr_rec *sar;

    s = r->server;

    /* search all the <VirtualHost> values */
    /* XXX: If this is a NameVirtualHost then we may not be doing the Right Thing
     * consider:
     *
     *     NameVirtualHost 10.1.1.1
     *     <VirtualHost 10.1.1.1>
     *     ServerName v1
     *     </VirtualHost>
     *     <VirtualHost 10.1.1.1>
     *     ServerName v2
     *     </VirtualHost>
     *
     * Suppose r->server is v2, and we're asked to match "10.1.1.1".  We'll say
     * "yup it's v2", when really it isn't... if a request came in for 10.1.1.1
     * it would really go to v1.
     */
    for (sar = s->addrs; sar; sar = sar->next) {
        if ((sar->host_port == 0 || port == sar->host_port)
            && !strcasecmp(host, sar->virthost)) {
            return 1;
        }
    }

    /* the Port has to match now, because the rest don't have ports associated
     * with them. */
    if (port != s->port) {
        return 0;
    }

    return matches_aliases(s, host);
}


static void check_hostalias(request_rec *r)
{
    /*
     * Even if the request has a Host: header containing a port we ignore
     * that port.  We always use the physical port of the socket.  There
     * are a few reasons for this:
     *
     * - the default of 80 or 443 for SSL is easier to handle this way
     * - there is less of a possibility of a security problem
     * - it simplifies the data structure
     * - the client may have no idea that a proxy somewhere along the way
     *   translated the request to another ip:port
     * - except for the addresses from the VirtualHost line, none of the other
     *   names we'll match have ports associated with them
     */
    const char *host = r->hostname;
    apr_port_t port;
    server_rec *s;
    server_rec *virthost_s;
    server_rec *last_s;
    name_chain *src;

    virthost_s = NULL;
    last_s = NULL;

    port = r->connection->local_addr->port;

    /* Recall that the name_chain is a list of server_addr_recs, some of
     * whose ports may not match.  Also each server may appear more than
     * once in the chain -- specifically, it will appear once for each
     * address from its VirtualHost line which matched.  We only want to
     * do the full ServerName/ServerAlias comparisons once for each
     * server, fortunately we know that all the VirtualHost addresses for
     * a single server are adjacent to each other.
     */

    for (src = r->connection->vhost_lookup_data; src; src = src->next) {
        server_addr_rec *sar;

        /* We only consider addresses on the name_chain which have a matching
         * port
         */
        sar = src->sar;
        if (sar->host_port != 0 && port != sar->host_port) {
            continue;
        }

        s = src->server;

        /* If we still need to do ServerName and ServerAlias checks for this
         * server, do them now.
         */
        if (s != last_s) {
            /* does it match any ServerName or ServerAlias directive? */
            if (matches_aliases(s, host)) {
                goto found;
            }
        }
        last_s = s;

        /* Fallback: does it match the virthost from the sar? */
        if (!strcasecmp(host, sar->virthost)) {
            /* only the first match is used */
            if (virthost_s == NULL) {
                virthost_s = s;
            }
        }
    }

    /* If ServerName and ServerAlias check failed, we end up here.  If it
     * matches a VirtualHost, virthost_s is set. Use that as fallback
     */
    if (virthost_s) {
        s = virthost_s;
        goto found;
    }

    return;

found:
    /* s is the first matching server, we're done */
    r->server = s;
}


static void check_serverpath(request_rec *r)
{
    server_rec *s;
    server_rec *last_s;
    name_chain *src;
    apr_port_t port;

    port = r->connection->local_addr->port;

    /*
     * This is in conjunction with the ServerPath code in http_core, so we
     * get the right host attached to a non- Host-sending request.
     *
     * See the comment in check_hostalias about how each vhost can be
     * listed multiple times.
     */

    last_s = NULL;
    for (src = r->connection->vhost_lookup_data; src; src = src->next) {
        /* We only consider addresses on the name_chain which have a matching
         * port
         */
        if (src->sar->host_port != 0 && port != src->sar->host_port) {
            continue;
        }

        s = src->server;
        if (s == last_s) {
            continue;
        }
        last_s = s;

        if (s->path && !strncmp(r->uri, s->path, s->pathlen) &&
            (s->path[s->pathlen - 1] == '/' ||
             r->uri[s->pathlen] == '/' ||
             r->uri[s->pathlen] == '\0')) {
            r->server = s;
            return;
        }
    }
}


AP_DECLARE(void) ap_update_vhost_from_headers(request_rec *r)
{
    /* must set this for HTTP/1.1 support */
    if (r->hostname || (r->hostname = apr_table_get(r->headers_in, "Host"))) {
        fix_hostname(r);
        if (r->status != HTTP_OK)
            return;
    }
    /* check if we tucked away a name_chain */
    if (r->connection->vhost_lookup_data) {
        if (r->hostname)
            check_hostalias(r);
        else
            check_serverpath(r);
    }
}

/**
 * For every virtual host on this connection, call func_cb.
 */
AP_DECLARE(int) ap_vhost_iterate_given_conn(conn_rec *conn,
                                            ap_vhost_iterate_conn_cb func_cb,
                                            void* baton)
{
    server_rec *s;
    server_rec *last_s;
    name_chain *src;
    apr_port_t port;
    int rv = 0;

    if (conn->vhost_lookup_data) {
        last_s = NULL;
        port = conn->local_addr->port;

        for (src = conn->vhost_lookup_data; src; src = src->next) {
            server_addr_rec *sar;

            /* We only consider addresses on the name_chain which have a
             * matching port.
             */
            sar = src->sar;
            if (sar->host_port != 0 && port != sar->host_port) {
                continue;
            }

            s = src->server;

            if (s == last_s) {
                /* we've already done a callback for this vhost. */
                continue;
            }

            last_s = s;

            rv = func_cb(baton, conn, s);

            if (rv != 0) {
                break;
            }
        }
    }
    else {
        rv = func_cb(baton, conn, conn->base_server);
    }

    return rv;
}

/* Called for a new connection which has a known local_addr.  Note that the
 * new connection is assumed to have conn->server == main server.
 */
AP_DECLARE(void) ap_update_vhost_given_ip(conn_rec *conn)
{
    ipaddr_chain *trav;
    apr_port_t port;

    /* scan the hash table for an exact match first */
    trav = find_ipaddr(conn->local_addr);

    if (trav) {
        /* save the name_chain for later in case this is a name-vhost */
        conn->vhost_lookup_data = trav->names;
        conn->base_server = trav->server;
        return;
    }

    /* maybe there's a default server or wildcard name-based vhost
     * matching this port
     */
    port = conn->local_addr->port;

    trav = find_default_server(port);
    if (trav) {
        conn->vhost_lookup_data = trav->names;
        conn->base_server = trav->server;
        return;
    }

    /* otherwise we're stuck with just the main server
     * and no name-based vhosts
     */
    conn->vhost_lookup_data = NULL;
}
