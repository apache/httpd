/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

#include "apr.h"
#include "apr_strings.h"
#include "apr_lock.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_main.h"
#include "mpm.h"
#include "pod.h"
#include "mpm_common.h"
#include "ap_mpm.h"
#include "ap_listen.h"
#include "mpm_default.h"

AP_DECLARE(apr_status_t) ap_mpm_pod_open(apr_pool_t *p, ap_pod_t **pod)
{
    apr_status_t rv;

    *pod = apr_palloc(p, sizeof(**pod));
    rv = apr_file_pipe_create(&((*pod)->pod_in), &((*pod)->pod_out), p);
    if (rv != APR_SUCCESS) {
        return rv;
    }
/*
    apr_file_pipe_timeout_set((*pod)->pod_in, 0);
*/
    (*pod)->p = p;
    
    apr_sockaddr_info_get(&(*pod)->sa, ap_listeners->bind_addr->hostname,
                          APR_UNSPEC, ap_listeners->bind_addr->port, 0, p);

    return APR_SUCCESS;
}

AP_DECLARE(int) ap_mpm_pod_check(ap_pod_t *pod)
{
    char c;
    apr_size_t len = 1;
    apr_status_t rv;

    rv = apr_file_read(pod->pod_in, &c, &len);

    if ((rv == APR_SUCCESS) && (len ==1)) {
        if (c == RESTART_CHAR) {
            return AP_RESTART;
        }
        if (c == GRACEFUL_CHAR) {
            return AP_GRACEFUL;
        }
    }
    else if (rv != APR_SUCCESS) {
        return rv;
    }
    return AP_NORESTART;
}

AP_DECLARE(apr_status_t) ap_mpm_pod_close(ap_pod_t *pod)
{
    apr_status_t rv;

    rv = apr_file_close(pod->pod_out);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_file_close(pod->pod_in);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    return rv;
}

static apr_status_t pod_signal_internal(ap_pod_t *pod, int graceful)
{
    apr_status_t rv;
    char char_of_death = graceful ? GRACEFUL_CHAR : RESTART_CHAR;
    apr_size_t one = 1;

    do {
        rv = apr_file_write(pod->pod_out, &char_of_death, &one);
    } while (APR_STATUS_IS_EINTR(rv));
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "write pipe_of_death");
    }
    return rv;
}

/* This function connects to the server, then immediately closes the connection.
 * This permits the MPM to skip the poll when there is only one listening
 * socket, because it provides a alternate way to unblock an accept() when
 * the pod is used.
 */

static apr_status_t dummy_connection(ap_pod_t *pod)
{
    apr_status_t rv;
    apr_socket_t *sock;
    apr_pool_t *p;
    
    /* create a temporary pool for the socket.  pconf stays around too long */
    rv = apr_pool_create(&p, pod->p);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    rv = apr_socket_create(&sock, pod->sa->family, SOCK_STREAM, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "get socket to connect to listener");
        return rv;
    }
    /* on some platforms (e.g., FreeBSD), the kernel won't accept many
     * queued connections before it starts blocking local connects...
     * we need to keep from blocking too long and instead return an error,
     * because the MPM won't want to hold up a graceful restart for a
     * long time
     */
    rv = apr_setsocketopt(sock, APR_SO_TIMEOUT, 3 * APR_USEC_PER_SEC);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "set timeout on socket to connect to listener");
        return rv;
    }
    
    rv = apr_connect(sock, pod->sa);    
    if (rv != APR_SUCCESS) {
        int log_level = APLOG_WARNING;

        if (APR_STATUS_IS_TIMEUP(rv)) {
            /* probably some server processes bailed out already and there 
             * is nobody around to call accept and clear out the kernel 
             * connection queue; usually this is not worth logging
             */
            log_level = APLOG_DEBUG;
        }
	
        ap_log_error(APLOG_MARK, log_level, rv, ap_server_conf,
                     "connect to listener");
    }

    apr_socket_close(sock);
    apr_pool_destroy(p);

    return rv;
}

AP_DECLARE(apr_status_t) ap_mpm_pod_signal(ap_pod_t *pod, int graceful)
{
    apr_status_t rv;

    rv = pod_signal_internal(pod, graceful);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    return dummy_connection(pod);
}

AP_DECLARE(void) ap_mpm_pod_killpg(ap_pod_t *pod, int num, int graceful)
{
    int i;
    apr_status_t rv = APR_SUCCESS;

    for (i = 0; i < num && rv == APR_SUCCESS; i++) {
        rv = pod_signal_internal(pod, graceful);
    }
    if (rv == APR_SUCCESS) {
        for (i = 0; i < num && rv == APR_SUCCESS; i++) {
             rv = dummy_connection(pod);
        }
    }
}

