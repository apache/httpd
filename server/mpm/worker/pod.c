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

#include "pod.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

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
    
    /* close these before exec. */
    apr_file_unset_inherit((*pod)->pod_in);
    apr_file_unset_inherit((*pod)->pod_out);

    return APR_SUCCESS;
}

AP_DECLARE(int) ap_mpm_pod_check(ap_pod_t *pod)
{
    char c;
    apr_os_file_t fd;
    int rc;

    /* we need to surface EINTR so we'll have to grab the
     * native file descriptor and do the OS read() ourselves
     */
    apr_os_file_get(&fd, pod->pod_in);
    rc = read(fd, &c, 1);
    if (rc == 1) {
        switch(c) {
        case RESTART_CHAR:
            return AP_RESTART;
        case GRACEFUL_CHAR:
            return AP_GRACEFUL;
        }
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

    rv = apr_file_write(pod->pod_out, &char_of_death, &one);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "write pipe_of_death");
    }
    return rv;
}

AP_DECLARE(apr_status_t) ap_mpm_pod_signal(ap_pod_t *pod, int graceful)
{
    return pod_signal_internal(pod, graceful);
}

AP_DECLARE(void) ap_mpm_pod_killpg(ap_pod_t *pod, int num, int graceful)
{
    int i;
    apr_status_t rv = APR_SUCCESS;

    for (i = 0; i < num && rv == APR_SUCCESS; i++) {
        rv = pod_signal_internal(pod, graceful);
    }
}

