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
 * Security options etc.
 * 
 * Module derived from code originally written by Rob McCool
 * 
 */

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

enum allowdeny_type {
    T_ENV,
    T_ALL,
    T_IP,
    T_HOST,
    T_FAIL
};

typedef struct {
    int limited;
    union {
	char *from;
	struct {
	    struct in_addr net;
	    struct in_addr mask;
	} ip;
    } x;
    enum allowdeny_type type;
} allowdeny;

/* things in the 'order' array */
#define DENY_THEN_ALLOW 0
#define ALLOW_THEN_DENY 1
#define MUTUAL_FAILURE 2

typedef struct {
    int order[METHODS];
    array_header *allows;
    array_header *denys;
} access_dir_conf;

module MODULE_VAR_EXPORT access_module;

static void *create_access_dir_config(pool *p, char *dummy)
{
    access_dir_conf *conf =
    (access_dir_conf *) ap_pcalloc(p, sizeof(access_dir_conf));
    int i;

    for (i = 0; i < METHODS; ++i)
	conf->order[i] = DENY_THEN_ALLOW;
    conf->allows = ap_make_array(p, 1, sizeof(allowdeny));
    conf->denys = ap_make_array(p, 1, sizeof(allowdeny));

    return (void *) conf;
}

static const char *order(cmd_parms *cmd, void *dv, char *arg)
{
    access_dir_conf *d = (access_dir_conf *) dv;
    int i, o;

    if (!strcasecmp(arg, "allow,deny"))
	o = ALLOW_THEN_DENY;
    else if (!strcasecmp(arg, "deny,allow"))
	o = DENY_THEN_ALLOW;
    else if (!strcasecmp(arg, "mutual-failure"))
	o = MUTUAL_FAILURE;
    else
	return "unknown order";

    for (i = 0; i < METHODS; ++i)
	if (cmd->limited & (1 << i))
	    d->order[i] = o;

    return NULL;
}

static int is_ip(const char *host)
{
    while ((*host == '.') || ap_isdigit(*host))
	host++;
    return (*host == '\0');
}

static const char *allow_cmd(cmd_parms *cmd, void *dv, char *from, char *where)
{
    access_dir_conf *d = (access_dir_conf *) dv;
    allowdeny *a;
    char *s;

    if (strcasecmp(from, "from"))
	return "allow and deny must be followed by 'from'";

    a = (allowdeny *) ap_push_array(cmd->info ? d->allows : d->denys);
    a->x.from = where;
    a->limited = cmd->limited;

    if (!strncasecmp(where, "env=", 4)) {
	a->type = T_ENV;
	a->x.from += 4;

    }
    else if (!strcasecmp(where, "all")) {
	a->type = T_ALL;

    }
    else if ((s = strchr(where, '/'))) {
	struct in_addr mask;

	a->type = T_IP;
	/* trample on where, we won't be using it any more */
	*s++ = '\0';

	if (!is_ip(where)
	    || (a->x.ip.net.s_addr = ap_inet_addr(where)) == INADDR_NONE) {
	    a->type = T_FAIL;
	    return "syntax error in network portion of network/netmask";
	}

	/* is_ip just tests if it matches [\d.]+ */
	if (!is_ip(s)) {
	    a->type = T_FAIL;
	    return "syntax error in mask portion of network/netmask";
	}
	/* is it in /a.b.c.d form? */
	if (strchr(s, '.')) {
	    mask.s_addr = ap_inet_addr(s);
	    if (mask.s_addr == INADDR_NONE) {
		a->type = T_FAIL;
		return "syntax error in mask portion of network/netmask";
	    }
	}
	else {
	    int i;

	    /* assume it's in /nnn form */
	    i = atoi(s);
	    if (i > 32 || i <= 0) {
		a->type = T_FAIL;
		return "invalid mask in network/netmask";
	    }
	    mask.s_addr = 0xFFFFFFFFUL << (32 - i);
	    mask.s_addr = htonl(mask.s_addr);
	}
	a->x.ip.mask = mask;
        a->x.ip.net.s_addr  = (a->x.ip.net.s_addr & mask.s_addr);   /* pjr - This fixes PR 4770 */
    }
    else if (ap_isdigit(*where) && is_ip(where)) {
	/* legacy syntax for ip addrs: a.b.c. ==> a.b.c.0/24 for example */
	int shift;
	char *t;
	int octet;

	a->type = T_IP;
	/* parse components */
	s = where;
	a->x.ip.net.s_addr = 0;
	a->x.ip.mask.s_addr = 0;
	shift = 24;
	while (*s) {
	    t = s;
	    if (!ap_isdigit(*t)) {
		a->type = T_FAIL;
		return "invalid ip address";
	    }
	    while (ap_isdigit(*t)) {
		++t;
	    }
	    if (*t == '.') {
		*t++ = 0;
	    }
	    else if (*t) {
		a->type = T_FAIL;
		return "invalid ip address";
	    }
	    if (shift < 0) {
		a->type = T_FAIL;
		return "invalid ip address, only 4 octets allowed";
	    }
	    octet = atoi(s);
	    if (octet < 0 || octet > 255) {
		a->type = T_FAIL;
		return "each octet must be between 0 and 255 inclusive";
	    }
	    a->x.ip.net.s_addr |= (unsigned int)octet << shift;
	    a->x.ip.mask.s_addr |= 0xFFUL << shift;
	    s = t;
	    shift -= 8;
	}
	a->x.ip.net.s_addr = ntohl(a->x.ip.net.s_addr);
	a->x.ip.mask.s_addr = ntohl(a->x.ip.mask.s_addr);
    }
    else {
	a->type = T_HOST;
    }

    return NULL;
}

static char its_an_allow;

static const command_rec access_cmds[] =
{
    {"order", order, NULL, OR_LIMIT, TAKE1,
     "'allow,deny', 'deny,allow', or 'mutual-failure'"},
    {"allow", allow_cmd, &its_an_allow, OR_LIMIT, ITERATE2,
     "'from' followed by hostnames or IP-address wildcards"},
    {"deny", allow_cmd, NULL, OR_LIMIT, ITERATE2,
     "'from' followed by hostnames or IP-address wildcards"},
    {NULL}
};

static int in_domain(const char *domain, const char *what)
{
    int dl = strlen(domain);
    int wl = strlen(what);

    if ((wl - dl) >= 0) {
	if (strcasecmp(domain, &what[wl - dl]) != 0)
	    return 0;

	/* Make sure we matched an *entire* subdomain --- if the user
	 * said 'allow from good.com', we don't want people from nogood.com
	 * to be able to get in.
	 */

	if (wl == dl)
	    return 1;		/* matched whole thing */
	else
	    return (domain[0] == '.' || what[wl - dl - 1] == '.');
    }
    else
	return 0;
}

static int find_allowdeny(request_rec *r, array_header *a, int method)
{
    allowdeny *ap = (allowdeny *) a->elts;
    int mmask = (1 << method);
    int i;
    int gothost = 0;
    const char *remotehost = NULL;

    for (i = 0; i < a->nelts; ++i) {
	if (!(mmask & ap[i].limited))
	    continue;

	switch (ap[i].type) {
	case T_ENV:
	    if (ap_table_get(r->subprocess_env, ap[i].x.from)) {
		return 1;
	    }
	    break;

	case T_ALL:
	    return 1;

	case T_IP:
	    if (ap[i].x.ip.net.s_addr != INADDR_NONE
		&& (r->connection->remote_addr.sin_addr.s_addr
		    & ap[i].x.ip.mask.s_addr) == ap[i].x.ip.net.s_addr) {
		return 1;
	    }
	    break;

	case T_HOST:
	    if (!gothost) {
		remotehost = ap_get_remote_host(r->connection, r->per_dir_config,
					    REMOTE_DOUBLE_REV);

		if ((remotehost == NULL) || is_ip(remotehost))
		    gothost = 1;
		else
		    gothost = 2;
	    }

	    if ((gothost == 2) && in_domain(ap[i].x.from, remotehost))
		return 1;
	    break;

	case T_FAIL:
	    /* do nothing? */
	    break;
	}
    }

    return 0;
}

static int check_dir_access(request_rec *r)
{
    int method = r->method_number;
    access_dir_conf *a =
    (access_dir_conf *)
    ap_get_module_config(r->per_dir_config, &access_module);
    int ret = OK;

    if (a->order[method] == ALLOW_THEN_DENY) {
	ret = FORBIDDEN;
	if (find_allowdeny(r, a->allows, method))
	    ret = OK;
	if (find_allowdeny(r, a->denys, method))
	    ret = FORBIDDEN;
    }
    else if (a->order[method] == DENY_THEN_ALLOW) {
	if (find_allowdeny(r, a->denys, method))
	    ret = FORBIDDEN;
	if (find_allowdeny(r, a->allows, method))
	    ret = OK;
    }
    else {
	if (find_allowdeny(r, a->allows, method)
	    && !find_allowdeny(r, a->denys, method))
	    ret = OK;
	else
	    ret = FORBIDDEN;
    }

    if (ret == FORBIDDEN
	&& (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r))) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
		  "client denied by server configuration: %s",
		  r->filename);
    }

    return ret;
}



module MODULE_VAR_EXPORT access_module =
{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    create_access_dir_config,	/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server config */
    access_cmds,
    NULL,			/* handlers */
    NULL,			/* filename translation */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    check_dir_access,		/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
