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
 */

/*
 * util_ldap.c: LDAP things
 * 
 * Original code from auth_ldap module for Apache v1.3:
 * Copyright 1998, 1999 Enbridge Pipelines Inc. 
 * Copyright 1999-2001 Dave Carrigan
 */

#include <apr_ldap.h>
#include <apr_strings.h>

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_ldap.h"
#include "util_ldap_cache.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef APU_HAS_LDAP
#error mod_ldap requires APR-util to have LDAP support built in
#endif

module AP_MODULE_DECLARE_DATA ldap_module;

int util_ldap_handler(request_rec *r);
void *util_ldap_create_config(apr_pool_t *p, server_rec *s);


/*
 * Some definitions to help between various versions of apache.
 */

#ifndef DOCTYPE_HTML_2_0
#define DOCTYPE_HTML_2_0  "<!DOCTYPE HTML PUBLIC \"-//IETF//" \
                          "DTD HTML 2.0//EN\">\n"
#endif

#ifndef DOCTYPE_HTML_3_2
#define DOCTYPE_HTML_3_2  "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 3.2 Final//EN\">\n"
#endif

#ifndef DOCTYPE_HTML_4_0S
#define DOCTYPE_HTML_4_0S "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 4.0//EN\"\n" \
                          "\"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
#endif

#ifndef DOCTYPE_HTML_4_0T
#define DOCTYPE_HTML_4_0T "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 4.0 Transitional//EN\"\n" \
                          "\"http://www.w3.org/TR/REC-html40/loose.dtd\">\n"
#endif

#ifndef DOCTYPE_HTML_4_0F
#define DOCTYPE_HTML_4_0F "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 4.0 Frameset//EN\"\n" \
                          "\"http://www.w3.org/TR/REC-html40/frameset.dtd\">\n"
#endif

/*
 * Status Handler
 * --------------
 *
 * This handler generates a status page about the current performance of
 * the LDAP cache. It is enabled as follows:
 *
 * <Location /ldap-status>
 *   SetHandler ldap-status
 * </Location>
 *
 */
int util_ldap_handler(request_rec *r)
{

    r->allowed |= (1 << M_GET);
    if (r->method_number != M_GET)
        return DECLINED;

    if (strcmp(r->handler, "ldap-status")) {
        return DECLINED;
    }

    r->content_type = "text/html";
    if (r->header_only)
        return OK;

    ap_rputs(DOCTYPE_HTML_3_2
             "<html><head><title>LDAP Cache Information</title></head>\n", r);
    ap_rputs("<body bgcolor='#ffffff'><h1 align=center>LDAP Cache Information</h1>\n", r);

    ap_rputs("<p>\n"
             "<table border='0'>\n"
             "<tr bgcolor='#000000'>\n"
             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Cache Name</b></font></td>"
             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Entries</b></font></td>"
             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Avg. Chain Len.</b></font></td>"
             "<td colspan='2'><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Hits</b></font></td>"
             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Ins/Rem</b></font></td>"
             "<td colspan='2'><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Purges</b></font></td>"
             "<td><font size='-1' face='Arial,Helvetica' color='#ffffff'><b>Avg Purge Time</b></font></td>"
             "</tr>\n", r
            );

    ap_rputs(util_ald_cache_display(r->pool), r);

    ap_rputs("</table>\n</p>\n", r);

    return OK;
}

/* ------------------------------------------------------------------ */


/*
 * Closes an LDAP connection by unlocking it. The next time
 * util_ldap_connection_find() is called this connection will be
 * available for reuse.
 */
LDAP_DECLARE(void) util_ldap_connection_close(util_ldap_connection_t *ldc)
{

    /*
     * QUESTION:
     *
     * Is it safe leaving bound connections floating around between the
     * different modules? Keeping the user bound is a performance boost,
     * but it is also a potential security problem - maybe.
     *
     * For now we unbind the user when we finish with a connection, but
     * we don't have to...
     */

    /* mark our connection as available for reuse */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(ldc->lock);
#endif
}


/*
 * Destroys an LDAP connection by unbinding. This function is registered
 * with the pool cleanup function - causing the LDAP connections to be
 * shut down cleanly on graceful restart.
 */
LDAP_DECLARE_NONSTD(apr_status_t) util_ldap_connection_destroy(void *param)
{
    util_ldap_connection_t *ldc = param;

    /* unbinding from the LDAP server */
    if (ldc->ldap) {
        ldap_unbind_s(ldc->ldap);
        ldc->bound = 0;
        ldc->ldap = NULL;
    }

    /* release the lock we were using.  The lock should have
       already been released in the close connection call.  
       But just in case it wasn't, we first try to get the lock
       before unlocking it to avoid unlocking an unheld lock. 
       Unlocking an unheld lock causes problems on NetWare.  The
       other option would be to assume that close connection did
       its job. */
#if APR_HAS_THREADS
    apr_thread_mutex_trylock(ldc->lock);
    apr_thread_mutex_unlock(ldc->lock);
#endif

    return APR_SUCCESS;
}


/*
 * Connect to the LDAP server and binds. Does not connect if already
 * connected (i.e. ldc->ldap is non-NULL.) Does not bind if already bound.
 *
 * Returns LDAP_SUCCESS on success; and an error code on failure
 */
LDAP_DECLARE(int) util_ldap_connection_open(util_ldap_connection_t *ldc)
{
    int result = 0;
    int failures = 0;


start_over:
    if (failures++ > 10) {
	/* too many failures - leave */
        return result;
    }

    if (!ldc->ldap) {
        ldc->bound = 0;

	/* opening connection to LDAP server */
        if ((ldc->ldap = ldap_init(ldc->host, ldc->port)) == NULL) {
	    /* couldn't connect */
            ldc->reason = "ldap_init() failed";
            return -1;
        }

	/* add the cleanup to the pool */
        apr_pool_cleanup_register(ldc->pool, ldc,
                                  util_ldap_connection_destroy,
                                  apr_pool_cleanup_null);

#if LDAP_VENDOR_VERSION >= 20000
    /* set protocol version 3 on this connection */
        {
            int version = LDAP_VERSION3;

            if ((result = ldap_set_option(ldc->ldap, LDAP_OPT_PROTOCOL_VERSION,
                                         &version)) != LDAP_SUCCESS) {
                /* setting LDAP version failed - ignore error */
            }
        }
#endif

        /* Set the alias dereferencing option */
#if LDAP_VERSION_MAX == 2
        ldc->ldap->ld_deref = ldc->deref;
#else
        result = ldap_set_option(ldc->ldap, LDAP_OPT_DEREF, &(ldc->deref));
        if (result != LDAP_SUCCESS) {
	    /* setting LDAP dereference option failed */
	    /* we ignore this error */
        }
#endif /* LDAP_VERSION_MAX */

#ifdef APU_HAS_LDAP_NETSCAPE_SSL
        if (ldc->netscapessl) {
            if (!ldc->certdb) {
		/* secure LDAP requested, but no CA cert defined */
                ldc->reason = "secure LDAP requested, but no CA cert defined";
                return -1;
            } else {
                result = ldapssl_install_routines(ldc->ldap);
                if (result != LDAP_SUCCESS) {
		    /* SSL initialisation failed */
                    ldc->reason = "ldapssl_install_routines() failed";
                    return result;
                }
                result = ldap_set_option(ldc->ldap, LDAP_OPT_SSL, LDAP_OPT_ON);
                if (result != LDAP_SUCCESS) {
		    /* SSL option failed */
                    ldc->reason = "ldap_set_option() failed trying to set LDAP_OPT_SSL";
                    return result;
                }
            }
        }
#endif /* APU_HAS_LDAP_NETSCAPE_SSL */

#ifdef APU_HAS_LDAP_STARTTLS
        if (ldc->starttls) {
            /* LDAP protocol version 3 is required for TLS */

            /* 
             * In util_ldap_connection_find, we compare ldc->withtls to
             * sec->starttls to see if we have a cache match. On the off
             * chance that apache's config processing rotines set starttls to
             * some other true value besides 1, we set it to 1 here to ensure
             * that the comparison succeeds.
             */
            ldc->starttls = 1;

            result = ldap_start_tls_s(ldc->ldap, NULL, NULL);
            if (result != LDAP_SUCCESS) {
		/* start TLS failed */
		ldc->withtls = 0;
                ldc->reason = "ldap_start_tls_s() failed";
	        return result;
            }
            ldc->withtls = 1;
        } else {
            ldc->withtls = 0;
        }
#endif /* APU_HAS_LDAP_STARTTLS */
    }

    /* 
     * At this point the LDAP connection is guaranteed alive. If bound says
     * that we're bound already, we can just return.
     */
    if (ldc->bound) {
        ldc->reason = "LDAP connection open successful (already bound)";
        return LDAP_SUCCESS;
    }

    /* 
     * Now bind with the username/password provided by the
     * configuration. It will be an anonymous bind if no u/p was
     * provided. 
     */
    if ((result = ldap_simple_bind_s(ldc->ldap, ldc->binddn, ldc->bindpw))
        == LDAP_SERVER_DOWN) {
	/* couldn't connect - try again */
        ldc->reason = "ldap_simple_bind_s() failed with server down";
        goto start_over;
    }

    if (result != LDAP_SUCCESS) {
	/* LDAP fatal error occured */
        ldc->reason = "ldap_simple_bind_s() failed";
        return result;
    }

    /* note how we are bound */
    ldc->bound = 1;

    ldc->reason = "LDAP connection open successful";
    return LDAP_SUCCESS;
}


/*
 * Find an existing ldap connection struct that matches the
 * provided ldap connection parameters.
 *
 * If not found in the cache, a new ldc structure will be allocated from st->pool
 * and returned to the caller. If found in the cache, a pointer to the existing
 * ldc structure will be returned.
 */
LDAP_DECLARE(util_ldap_connection_t *)util_ldap_connection_find(request_rec *r, const char *host, int port,
                                              const char *binddn, const char *bindpw, deref_options deref,
                                              int netscapessl, int starttls)
{
    struct util_ldap_connection_t *l, *p;	/* To traverse the linked list */

    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(r->server->module_config,
        &ldap_module);


#if APR_HAS_THREADS
    /* mutex lock this function */
    if (!st->mutex) {
        apr_thread_mutex_create(&st->mutex, APR_THREAD_MUTEX_DEFAULT, st->pool);
    }
    apr_thread_mutex_lock(st->mutex);
#endif

    /* Search for an exact connection match in the list that is not
     * being used.
     */
    for (l=st->connections,p=NULL; l; l=l->next) {
#if APR_HAS_THREADS
        if ( (APR_SUCCESS == apr_thread_mutex_trylock(l->lock)) &&
#else
        if (
#endif
            l->port == port
	    && strcmp(l->host, host) == 0
	    && ( (!l->binddn && !binddn) || (l->binddn && binddn && !strcmp(l->binddn, binddn)) )
	    && ( (!l->bindpw && !bindpw) || (l->bindpw && bindpw && !strcmp(l->bindpw, bindpw)) )
            && l->deref == deref
#ifdef APU_HAS_LDAP_NETSCAPE_SSL
            && l->netscapessl == netscapessl
#endif
#ifdef APU_HAS_LDAP_STARTTLS
	    && l->withtls == starttls
#endif
            )
            break;
        p = l;
    }

    /* If nothing found, search again, but we don't care about the
     * binddn and bindpw this time.
     */
    if (!l) {
        for (l=st->connections,p=NULL; l; l=l->next) {
#if APR_HAS_THREADS
            if ( (APR_SUCCESS == apr_thread_mutex_trylock(l->lock)) &&
#else
            if (
#endif
                l->port == port
	        && strcmp(l->host, host) == 0
                && l->deref == deref
#ifdef APU_HAS_LDAP_NETSCAPE_SSL
                && l->netscapessl == netscapessl
#endif
#ifdef APU_HAS_LDAP_STARTTLS
                && l->withtls == starttls
#endif
                ) {
                /* the bind credentials have changed */
                l->bound = 0;
                l->binddn = apr_pstrdup(st->pool, binddn);
                l->bindpw = apr_pstrdup(st->pool, bindpw);
                break;
            }
            p = l;
        }
    }

/* artificially disable cache */
//l = NULL;

    /* If no connection what found after the second search, we
     * must create one.
     */
    if (!l) {

        /* 
         * Add the new connection entry to the linked list. Note that we
         * don't actually establish an LDAP connection yet; that happens
         * the first time authentication is requested.
         */
        /* create the details to the pool in st */
        l = apr_pcalloc(st->pool, sizeof(util_ldap_connection_t));
#if APR_HAS_THREADS
        apr_thread_mutex_create(&l->lock, APR_THREAD_MUTEX_DEFAULT, st->pool);
        apr_thread_mutex_lock(l->lock);
#endif
        l->pool = st->pool;
        l->bound = 0;
        l->host = apr_pstrdup(st->pool, host);
        l->port = port;
        l->deref = deref;
        l->binddn = apr_pstrdup(st->pool, binddn);
        l->bindpw = apr_pstrdup(st->pool, bindpw);
        l->netscapessl = netscapessl;
        l->starttls = starttls;
        l->withtls = 0;

        if (p) {
            p->next = l;
        }
        else {
            st->connections = l;
        }
    }

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(st->mutex);
#endif
    return l;
}

/* ------------------------------------------------------------------ */

/*
 * Compares two DNs to see if they're equal. The only way to do this correctly is to 
 * search for the dn and then do ldap_get_dn() on the result. This should match the 
 * initial dn, since it would have been also retrieved with ldap_get_dn(). This is
 * expensive, so if the configuration value compare_dn_on_server is
 * false, just does an ordinary strcmp.
 *
 * The lock for the ldap cache should already be acquired.
 */
LDAP_DECLARE(int) util_ldap_cache_comparedn(request_rec *r, util_ldap_connection_t *ldc, 
                            const char *url, const char *dn, const char *reqdn, 
                            int compare_dn_on_server)
{
    int result = 0;
    util_url_node_t *curl; 
    util_url_node_t curnode;
    util_dn_compare_node_t *node;
    util_dn_compare_node_t newnode;
    int failures = 0;
    LDAPMessage *res, *entry;
    char *searchdn;

    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(r->server->module_config,
        &ldap_module);

    /* read lock this function */
    LDAP_CACHE_LOCK_CREATE(st->pool);

    /* get cache entry (or create one) */
    LDAP_CACHE_WRLOCK();

    curnode.url = url;
    curl = util_ald_cache_fetch(util_ldap_cache, &curnode);
    if (curl == NULL) {
        curl = util_ald_create_caches(st, url);
    }
    LDAP_CACHE_UNLOCK();

    /* a simple compare? */
    if (!compare_dn_on_server) {
        /* unlock this read lock */
        if (strcmp(dn, reqdn)) {
            ldc->reason = "DN Comparison FALSE (direct strcmp())";
            return LDAP_COMPARE_FALSE;
        }
        else {
            ldc->reason = "DN Comparison TRUE (direct strcmp())";
            return LDAP_COMPARE_TRUE;
        }
    }

    if (curl) {
        /* no - it's a server side compare */
        LDAP_CACHE_RDLOCK();
    
        /* is it in the compare cache? */
        newnode.reqdn = (char *)reqdn;
        node = util_ald_cache_fetch(curl->dn_compare_cache, &newnode);
        if (node != NULL) {
            /* If it's in the cache, it's good */
            /* unlock this read lock */
            LDAP_CACHE_UNLOCK();
            ldc->reason = "DN Comparison TRUE (cached)";
            return LDAP_COMPARE_TRUE;
        }
    
        /* unlock this read lock */
        LDAP_CACHE_UNLOCK();
    }

start_over:
    if (failures++ > 10) {
	/* too many failures */
        return result;
    }

    /* make a server connection */
    if (LDAP_SUCCESS != (result = util_ldap_connection_open(ldc))) {
	/* connect to server failed */
        return result;
    }

    /* search for reqdn */
    if ((result = ldap_search_ext_s(ldc->ldap, const_cast(reqdn), LDAP_SCOPE_BASE, 
				    "(objectclass=*)", NULL, 1, 
				    NULL, NULL, NULL, -1, &res)) == LDAP_SERVER_DOWN) {
        util_ldap_connection_close(ldc);
        ldc->reason = "DN Comparison ldap_search_ext_s() failed with server down";
        goto start_over;
    }
    if (result != LDAP_SUCCESS) {
        /* search for reqdn failed - no match */
        ldc->reason = "DN Comparison ldap_search_ext_s() failed";
        return result;
    }

    entry = ldap_first_entry(ldc->ldap, res);
    searchdn = ldap_get_dn(ldc->ldap, entry);

    ldap_msgfree(res);
    if (strcmp(dn, searchdn) != 0) {
        /* compare unsuccessful */
        ldc->reason = "DN Comparison FALSE (checked on server)";
        result = LDAP_COMPARE_FALSE;
    }
    else {
        if (curl) {
            /* compare successful - add to the compare cache */
            LDAP_CACHE_RDLOCK();
            newnode.reqdn = (char *)reqdn;
            newnode.dn = (char *)dn;
            util_ald_cache_insert(curl->dn_compare_cache, &newnode);
            LDAP_CACHE_UNLOCK();
        }
        ldc->reason = "DN Comparison TRUE (checked on server)";
        result = LDAP_COMPARE_TRUE;
    }
    ldap_memfree(searchdn);
    return result;

}

/*
 * Does an generic ldap_compare operation. It accepts a cache that it will use
 * to lookup the compare in the cache. We cache two kinds of compares 
 * (require group compares) and (require user compares). Each compare has a different
 * cache node: require group includes the DN; require user does not because the
 * require user cache is owned by the 
 *
 */
LDAP_DECLARE(int) util_ldap_cache_compare(request_rec *r, util_ldap_connection_t *ldc,
                          const char *url, const char *dn,
                          const char *attrib, const char *value)
{
    int result = 0;
    util_url_node_t *curl; 
    util_url_node_t curnode;
    util_compare_node_t *compare_nodep;
    util_compare_node_t the_compare_node;
    apr_time_t curtime;
    int failures = 0;

    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(r->server->module_config,
        &ldap_module);

    /* read lock this function */
    LDAP_CACHE_LOCK_CREATE(st->pool);

    /* get cache entry (or create one) */
    LDAP_CACHE_WRLOCK();
    curnode.url = url;
    curl = util_ald_cache_fetch(util_ldap_cache, &curnode);
    if (curl == NULL) {
        curl = util_ald_create_caches(st, url);
    }
    LDAP_CACHE_UNLOCK();

    if (curl) {
        /* make a comparison to the cache */
        LDAP_CACHE_RDLOCK();
        curtime = apr_time_now();
    
        the_compare_node.dn = (char *)dn;
        the_compare_node.attrib = (char *)attrib;
        the_compare_node.value = (char *)value;
        the_compare_node.result = 0;
    
        compare_nodep = util_ald_cache_fetch(curl->compare_cache, &the_compare_node);
    
        if (compare_nodep != NULL) {
            /* found it... */
            if (curtime - compare_nodep->lastcompare > st->compare_cache_ttl) {
                /* ...but it is too old */
                util_ald_cache_remove(curl->compare_cache, compare_nodep);
            }
            else {
                /* ...and it is good */
                /* unlock this read lock */
                LDAP_CACHE_UNLOCK();
                if (LDAP_COMPARE_TRUE == compare_nodep->result) {
                    ldc->reason = "Comparison true (cached)";
                    return compare_nodep->result;
                }
                else if (LDAP_COMPARE_FALSE == compare_nodep->result) {
                    ldc->reason = "Comparison false (cached)";
                    return compare_nodep->result;
                }
                else if (LDAP_NO_SUCH_ATTRIBUTE == compare_nodep->result) {
                    ldc->reason = "Comparison no such attribute (cached)";
                    return compare_nodep->result;
                }
                else {
                    ldc->reason = "Comparison undefined (cached)";
                    return compare_nodep->result;
                }
            }
        }
        /* unlock this read lock */
        LDAP_CACHE_UNLOCK();
    }

start_over:
    if (failures++ > 10) {
        /* too many failures */
        return result;
    }
    if (LDAP_SUCCESS != (result = util_ldap_connection_open(ldc))) {
        /* connect failed */
        return result;
    }

    if ((result = ldap_compare_s(ldc->ldap, const_cast(dn), 
			         const_cast(attrib), const_cast(value)))
        == LDAP_SERVER_DOWN) { 
        /* connection failed - try again */
        util_ldap_connection_close(ldc);
        ldc->reason = "ldap_compare_s() failed with server down";
        goto start_over;
    }

    ldc->reason = "Comparison complete";
    if ((LDAP_COMPARE_TRUE == result) || 
        (LDAP_COMPARE_FALSE == result) ||
        (LDAP_NO_SUCH_ATTRIBUTE == result)) {
        if (curl) {
            /* compare completed; caching result */
            LDAP_CACHE_WRLOCK();
            the_compare_node.lastcompare = curtime;
            the_compare_node.result = result;
            util_ald_cache_insert(curl->compare_cache, &the_compare_node);
            LDAP_CACHE_UNLOCK();
        }
        if (LDAP_COMPARE_TRUE == result) {
            ldc->reason = "Comparison true (adding to cache)";
            return LDAP_COMPARE_TRUE;
        }
        else if (LDAP_COMPARE_FALSE == result) {
            ldc->reason = "Comparison false (adding to cache)";
            return LDAP_COMPARE_FALSE;
        }
        else {
            ldc->reason = "Comparison no such attribute (adding to cache)";
            return LDAP_NO_SUCH_ATTRIBUTE;
        }
    }
    return result;
}

LDAP_DECLARE(int) util_ldap_cache_checkuserid(request_rec *r, util_ldap_connection_t *ldc,
                              const char *url, const char *basedn, int scope, char **attrs,
                              const char *filter, const char *bindpw, const char **binddn,
                              const char ***retvals)
{
    const char **vals = NULL;
    int result = 0;
    LDAPMessage *res, *entry;
    char *dn;
    int count;
    int failures = 0;
    util_url_node_t *curl;		/* Cached URL node */
    util_url_node_t curnode;
    util_search_node_t *search_nodep;	/* Cached search node */
    util_search_node_t the_search_node;
    apr_time_t curtime;

    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(r->server->module_config,
        &ldap_module);

    /* read lock this function */
    LDAP_CACHE_LOCK_CREATE(st->pool);

    /* Get the cache node for this url */
    LDAP_CACHE_WRLOCK();
    curnode.url = url;
    curl = (util_url_node_t *)util_ald_cache_fetch(util_ldap_cache, &curnode);
    if (curl == NULL) {
        curl = util_ald_create_caches(st, url);
    }
    LDAP_CACHE_UNLOCK();

    if (curl) {
        LDAP_CACHE_RDLOCK();
        the_search_node.username = filter;
        search_nodep = util_ald_cache_fetch(curl->search_cache, &the_search_node);
        if (search_nodep != NULL && search_nodep->bindpw) {
    
            /* found entry in search cache... */
            curtime = apr_time_now();
    
            /*
             * Remove this item from the cache if its expired, or if the 
             * sent password doesn't match the storepassword.
             */
            if ((curtime - search_nodep->lastbind) > st->search_cache_ttl) {
                /* ...but entry is too old */
                util_ald_cache_remove(curl->search_cache, search_nodep);
            }
            else if (strcmp(search_nodep->bindpw, bindpw) != 0) {
    	    /* ...but cached password doesn't match sent password */
                util_ald_cache_remove(curl->search_cache, search_nodep);
            }
            else {
                /* ...and entry is valid */
                *binddn = search_nodep->dn;
                *retvals = search_nodep->vals;
                LDAP_CACHE_UNLOCK();
                ldc->reason = "Authentication successful (cached)";
                return LDAP_SUCCESS;
            }
        }
        /* unlock this read lock */
        LDAP_CACHE_UNLOCK();
    }

    /*	
     * At this point, there is no valid cached search, so lets do the search.
     */

    /*
     * If any LDAP operation fails due to LDAP_SERVER_DOWN, control returns here.
     */
start_over:
    if (failures++ > 10) {
        return result;
    }
    if (LDAP_SUCCESS != (result = util_ldap_connection_open(ldc))) {
        return result;
    }

    /* try do the search */
    if ((result = ldap_search_ext_s(ldc->ldap,
				    basedn, scope, 
				    filter, attrs, 0, 
				    NULL, NULL, NULL, -1, &res)) == LDAP_SERVER_DOWN) {
        ldc->reason = "ldap_search_ext_s() for user failed with server down";
        goto start_over;
    }

    /* if there is an error (including LDAP_NO_SUCH_OBJECT) return now */
    if (result != LDAP_SUCCESS) {
        ldc->reason = "ldap_search_ext_s() for user failed";
        return result;
    }

    /* 
     * We should have found exactly one entry; to find a different
     * number is an error.
     */
    count = ldap_count_entries(ldc->ldap, res);
    if (count != 1) {
        if (count == 0 )
            ldc->reason = "User not found";
        else
            ldc->reason = "User is not unique (search found two or more matches)";
        ldap_msgfree(res);
        return LDAP_NO_SUCH_OBJECT;
    }

    entry = ldap_first_entry(ldc->ldap, res);

    /* Grab the dn, copy it into the pool, and free it again */
    dn = ldap_get_dn(ldc->ldap, entry);
    *binddn = apr_pstrdup(st->pool, dn);
    ldap_memfree(dn);

    /* 
     * A bind to the server with an empty password always succeeds, so
     * we check to ensure that the password is not empty. This implies
     * that users who actually do have empty passwords will never be
     * able to authenticate with this module. I don't see this as a big
     * problem.
     */
    if (strlen(bindpw) <= 0) {
        ldap_msgfree(res);
        ldc->reason = "Empty password not allowed";
        return LDAP_INVALID_CREDENTIALS;
    }

    /* 
     * Attempt to bind with the retrieved dn and the password. If the bind
     * fails, it means that the password is wrong (the dn obviously
     * exists, since we just retrieved it)
     */
    if ((result = 
         ldap_simple_bind_s(ldc->ldap, *binddn, bindpw)) == 
         LDAP_SERVER_DOWN) {
        ldc->reason = "ldap_simple_bind_s() to check user credentials failed with server down";
        ldap_msgfree(res);
        goto start_over;
    }

    /* failure? if so - return */
    if (result != LDAP_SUCCESS) {
        ldc->reason = "ldap_simple_bind_s() to check user credentials failed";
        ldap_msgfree(res);
        return result;
    }

    /*
     * Get values for the provided attributes.
     */
    if (attrs) {
        int k = 0;
        int i = 0;
        while (attrs[k++]);
        vals = apr_pcalloc(r->pool, sizeof(char *) * (k+1));
        while (attrs[i]) {
            char **values;
            int j = 0;
            char *str = NULL;
            /* get values */
            values = ldap_get_values(ldc->ldap, entry, attrs[i]);
            while (values && values[j]) {
                str = str ? apr_pstrcat(r->pool, str, "; ", values[j], NULL) : apr_pstrdup(r->pool, values[j]);
                j++;
            }
            ldap_value_free(values);
            vals[i] = str;
            i++;
        }
        *retvals = vals;
    }

    /* 		
     * Add the new username to the search cache.
     */
    LDAP_CACHE_WRLOCK();
    the_search_node.username = filter;
    the_search_node.dn = *binddn;
    the_search_node.bindpw = bindpw;
    the_search_node.lastbind = apr_time_now();
    the_search_node.vals = vals;
    if (curl) {
        util_ald_cache_insert(curl->search_cache, &the_search_node);
    }
    ldap_msgfree(res);
    LDAP_CACHE_UNLOCK();

    ldc->reason = "Authentication successful";
    return LDAP_SUCCESS;
}



/* ---------------------------------------- */
/* config directives */


static const char *util_ldap_set_cache_bytes(cmd_parms *cmd, void *dummy, const char *bytes)
{
    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config, 
						  &ldap_module);

    st->cache_bytes = atol(bytes);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server, 
                      "[%d] ldap cache: Setting shared memory cache size to %d bytes.", 
                      getpid(), st->cache_bytes);

    return NULL;
}

static const char *util_ldap_set_cache_ttl(cmd_parms *cmd, void *dummy, const char *ttl)
{
    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config, 
						  &ldap_module);

    st->search_cache_ttl = atol(ttl) * 1000000;

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server, 
                      "[%d] ldap cache: Setting cache TTL to %ld microseconds.", 
                      getpid(), st->search_cache_ttl);

    return NULL;
}

static const char *util_ldap_set_cache_entries(cmd_parms *cmd, void *dummy, const char *size)
{
    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config, 
						  &ldap_module);


    st->search_cache_size = atol(size);
    if (st->search_cache_size < 0) {
        st->search_cache_size = 0;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server, 
                      "[%d] ldap cache: Setting search cache size to %ld entries.", 
                      getpid(), st->search_cache_size);

    return NULL;
}

static const char *util_ldap_set_opcache_ttl(cmd_parms *cmd, void *dummy, const char *ttl)
{
    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config, 
						  &ldap_module);

    st->compare_cache_ttl = atol(ttl) * 1000000;

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server, 
                      "[%d] ldap cache: Setting operation cache TTL to %ld microseconds.", 
                      getpid(), st->compare_cache_ttl);

    return NULL;
}

static const char *util_ldap_set_opcache_entries(cmd_parms *cmd, void *dummy, const char *size)
{
    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config, 
						  &ldap_module);

    st->compare_cache_size = atol(size);
    if (st->compare_cache_size < 0) {
        st->compare_cache_size = 0;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server, 
                      "[%d] ldap cache: Setting operation cache size to %ld entries.", 
                      getpid(), st->compare_cache_size);

    return NULL;
}

#ifdef APU_HAS_LDAP_NETSCAPE_SSL
static const char *util_ldap_set_certdbpath(cmd_parms *cmd, void *dummy, const char *path)
{
    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(cmd->server->module_config, 
						  &ldap_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server, 
                      "[%d] ldap cache: Setting LDAP SSL client certificate dbpath to %s.", 
                      getpid(), path);

    st->have_certdb = 1;
    if (ldapssl_client_init(path, NULL) != 0) {
        return "Could not initialize SSL client";
    }
    else {
        return NULL;
    }
}
#endif

void *util_ldap_create_config(apr_pool_t *p, server_rec *s)
{
    util_ldap_state_t *st = 
        (util_ldap_state_t *)apr_pcalloc(p, sizeof(util_ldap_state_t));

    st->pool = p;

    st->cache_bytes = 100000;
    st->search_cache_ttl = 600000000;
    st->search_cache_size = 1024;
    st->compare_cache_ttl = 600000000;
    st->compare_cache_size = 1024;

    st->connections = NULL;
#ifdef APU_HAS_LDAP_NETSCAPE_SSL
    st->have_certdb = 0;
#endif

    return st;
}

static void util_ldap_init_module(apr_pool_t *pool, server_rec *s)
{
    util_ldap_state_t *st = 
        (util_ldap_state_t *)ap_get_module_config(s->module_config, 
						  &ldap_module);

    apr_status_t result = util_ldap_cache_init(pool, st->cache_bytes);
    char buf[MAX_STRING_LEN];

    apr_strerror(result, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, result, s, 
                      "[%d] ldap cache init: %s", 
                      getpid(), buf);
}


command_rec util_ldap_cmds[] = {
    AP_INIT_TAKE1("LDAPSharedCacheSize", util_ldap_set_cache_bytes, NULL, RSRC_CONF,
                  "Sets the size of the shared memory cache in bytes. "
                  "Zero means disable the shared memory cache. Defaults to 100KB."),

    AP_INIT_TAKE1("LDAPCacheEntries", util_ldap_set_cache_entries, NULL, RSRC_CONF,
                  "Sets the maximum number of entries that are possible in the LDAP "
                  "search cache. "
                  "Zero means no limit; -1 disables the cache. Defaults to 1024 entries."),

    AP_INIT_TAKE1("LDAPCacheTTL", util_ldap_set_cache_ttl, NULL, RSRC_CONF,
                  "Sets the maximum time (in seconds) that an item can be cached in the LDAP "
                  "search cache. Zero means no limit. Defaults to 600 seconds (10 minutes)."),

    AP_INIT_TAKE1("LDAPOpCacheEntries", util_ldap_set_opcache_entries, NULL, RSRC_CONF,
                  "Sets the maximum number of entries that are possible in the LDAP "
                  "compare cache. "
                  "Zero means no limit; -1 disables the cache. Defaults to 1024 entries."),

    AP_INIT_TAKE1("LDAPOpCacheTTL", util_ldap_set_opcache_ttl, NULL, RSRC_CONF,
                  "Sets the maximum time (in seconds) that an item is cached in the LDAP "
                  "operation cache. Zero means no limit. Defaults to 600 seconds (10 minutes)."),

#ifdef APU_HAS_LDAP_NETSCAPE_SSL
    AP_INIT_TAKE1("LDAPCertDBPath", util_ldap_set_certdbpath, NULL, RSRC_CONF,
                  "Specifies the file containing Certificate Authority certificates "
                  "for validating secure LDAP server certificates. This file must be the "
                  "cert7.db database used by Netscape Communicator"),
#endif

    {NULL}
};

static void util_ldap_register_hooks(apr_pool_t *p)
{
    ap_hook_child_init(util_ldap_init_module, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(util_ldap_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module ldap_module = {
   STANDARD20_MODULE_STUFF,
   NULL,				/* dir config creater */
   NULL,				/* dir merger --- default is to override */
   util_ldap_create_config,		/* server config */
   NULL,				/* merge server config */
   util_ldap_cmds,			/* command table */
   util_ldap_register_hooks,		/* set up request processing hooks */
};
