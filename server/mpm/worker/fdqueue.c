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

#include "fdqueue.h"

/**
 * Detects when the fd_queue_t is full. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
static int ap_queue_full(fd_queue_t *queue)
{
    return (queue->blanks <= 0);
}

/**
 * Detects when the fd_queue_t is empty. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
static int ap_queue_empty(fd_queue_t *queue)
{
    return (queue->blanks >= queue->bounds - 1);
}

/**
 * Callback routine that is called to destroy this
 * fd_queue_t when it's pool is destroyed.
 */
static apr_status_t ap_queue_destroy(void *data) 
{
    fd_queue_t *queue = data;

    /* Ignore errors here, we can't do anything about them anyway.
     * XXX: We should at least try to signal an error here, it is
     * indicative of a programmer error. -aaron */
    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->one_big_mutex);

    return FD_QUEUE_SUCCESS;
}

/**
 * Initialize the fd_queue_t.
 */
int ap_queue_init(fd_queue_t *queue, int queue_capacity, apr_pool_t *a) 
{
    int i;
    int bounds;

    if (pthread_mutex_init(&queue->one_big_mutex, NULL) != 0)
        return FD_QUEUE_FAILURE;
    if (pthread_cond_init(&queue->not_empty, NULL) != 0)
        return FD_QUEUE_FAILURE;

    bounds = queue_capacity + 1;
    queue->tail = 0;
    queue->data = apr_palloc(a, bounds * sizeof(fd_queue_elem_t));
    queue->bounds = bounds;
    queue->blanks = queue_capacity;

    /* Set all the sockets in the queue to NULL */
    for (i = 0; i < bounds; ++i)
        queue->data[i].sd = NULL;

    apr_pool_cleanup_register(a, queue, ap_queue_destroy, apr_pool_cleanup_null);

    return FD_QUEUE_SUCCESS;
}

/**
 * Push a new socket onto the queue. Blocks if the queue is full. Once
 * the push operation has completed, it signals other threads waiting
 * in apr_queue_pop() that they may continue consuming sockets.
 */
int ap_queue_push(fd_queue_t *queue, apr_socket_t *sd, apr_pool_t *p) 
{
    if (pthread_mutex_lock(&queue->one_big_mutex) != 0) {
        return FD_QUEUE_FAILURE;
    }

    /* If the caller didn't allocate enough slots and tries to push
     * too many, too bad. */
    if (ap_queue_full(queue)) {
        if (pthread_mutex_unlock(&queue->one_big_mutex) != 0) {
            return FD_QUEUE_FAILURE;
        }
        return FD_QUEUE_OVERFLOW;
    }

    queue->data[queue->tail].sd = sd;
    queue->data[queue->tail].p = p;
    queue->tail++;
    queue->blanks--;

    pthread_cond_signal(&queue->not_empty);

    if (pthread_mutex_unlock(&queue->one_big_mutex) != 0) {
        return FD_QUEUE_FAILURE;
    }

    return FD_QUEUE_SUCCESS;
}

/**
 * Retrieves the next available socket from the queue. If there are no
 * sockets available, it will block until one becomes available.
 * Once retrieved, the socket is placed into the address specified by
 * 'sd'.
 */
apr_status_t ap_queue_pop(fd_queue_t *queue, apr_socket_t **sd, apr_pool_t **p) 
{
    fd_queue_elem_t *elem;

    if (pthread_mutex_lock(&queue->one_big_mutex) != 0) {
        return FD_QUEUE_FAILURE;
    }

    /* Keep waiting until we wake up and find that the queue is not empty. */
    if (ap_queue_empty(queue)) {
        pthread_cond_wait(&queue->not_empty, &queue->one_big_mutex);
        /* If we wake up and it's still empty, then we were interrupted */
        if (ap_queue_empty(queue)) {
            if (pthread_mutex_unlock(&queue->one_big_mutex) != 0) {
                return FD_QUEUE_FAILURE;
            }
            return FD_QUEUE_EINTR;
        }
    } 
    
    queue->tail--;
    elem = &queue->data[queue->tail];
    *sd = elem->sd;
    *p = elem->p;
    elem->sd = NULL;
    elem->p = NULL;
    queue->blanks++;

    if (pthread_mutex_unlock(&queue->one_big_mutex) != 0) {
        return FD_QUEUE_FAILURE;
    }

    return APR_SUCCESS;
}

apr_status_t ap_queue_interrupt_all(fd_queue_t *queue)
{
    if (pthread_mutex_lock(&queue->one_big_mutex) != 0) {
        return FD_QUEUE_FAILURE;
    }
    pthread_cond_broadcast(&queue->not_empty);
    if (pthread_mutex_unlock(&queue->one_big_mutex) != 0) {
        return FD_QUEUE_FAILURE;
    }
    return FD_QUEUE_SUCCESS;
}

