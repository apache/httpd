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

#ifndef FDQUEUE_H
#define FDQUEUE_H
#include "httpd.h"
#include <stdlib.h>
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <apr_errno.h>

#define FD_QUEUE_SUCCESS 0
#define FD_QUEUE_FAILURE -1 /* Needs to be an invalid file descriptor because
                               of queue_pop semantics */
#define FD_QUEUE_EINTR APR_EINTR
#define FD_QUEUE_OVERFLOW -2

struct fd_queue_elem_t {
    apr_socket_t      *sd;
    apr_pool_t        *p;
};
typedef struct fd_queue_elem_t fd_queue_elem_t;

struct fd_queue_t {
    int                tail;
    fd_queue_elem_t   *data;
    int                bounds;
    int                blanks;
    pthread_mutex_t    one_big_mutex;
    pthread_cond_t     not_empty;
    int                cancel_state;
};
typedef struct fd_queue_t fd_queue_t;

int ap_queue_init(fd_queue_t *queue, int queue_capacity, apr_pool_t *a);
int ap_queue_push(fd_queue_t *queue, apr_socket_t *sd, apr_pool_t *p);
apr_status_t ap_queue_pop(fd_queue_t *queue, apr_socket_t **sd, apr_pool_t **p);
apr_status_t ap_queue_interrupt_all(fd_queue_t *queue);

#endif /* FDQUEUE_H */
