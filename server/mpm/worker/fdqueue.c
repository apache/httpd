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
#include "apr_pools.h"

/* Assumption: queue itself is allocated by the user */
/* Assumption: increment and decrement are atomic on int */

int ap_queue_size(FDQueue *queue) {
    return ((queue->tail - queue->head + queue->bounds) % queue->bounds);
}

int ap_queue_full(FDQueue *queue) {
    return(queue->blanks <= 0);
}

int ap_block_on_queue(FDQueue *queue) {
#if 0
    if (pthread_mutex_lock(&queue->one_big_mutex) != 0) {
        return FD_QUEUE_FAILURE;
    }
#endif
    if (ap_queue_full(queue)) {
        pthread_cond_wait(&queue->not_full, &queue->one_big_mutex);
    }
#if 0
    if (pthread_mutex_unlock(&queue->one_big_mutex) != 0) {
        return FD_QUEUE_FAILURE;
    }
#endif
    return FD_QUEUE_SUCCESS;
}

static int increase_blanks(FDQueue *queue) {
    queue->blanks++;
    return FD_QUEUE_SUCCESS;
}

static apr_status_t ap_queue_destroy(void *data) {
    FDQueue *queue = data;
    /* Ignore errors here, we can't do anything about them anyway */
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    pthread_mutex_destroy(&queue->one_big_mutex);
    return FD_QUEUE_SUCCESS;
}

int ap_queue_init(FDQueue *queue, int queue_capacity, apr_pool_t *a) {
    int i;
    int bounds = queue_capacity + 1;
    pthread_mutex_init(&queue->one_big_mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
    queue->head = queue->tail = 0;
    queue->data = apr_palloc(a, bounds * sizeof(FDQueueElement));
    queue->bounds = bounds;
    queue->blanks = queue_capacity;
    apr_pool_cleanup_register(a, queue, ap_queue_destroy, apr_pool_cleanup_null);
    for (i=0; i < bounds; ++i)
        queue->data[i].sd = NULL;
    return FD_QUEUE_SUCCESS;
}

int ap_queue_push(FDQueue *queue, apr_socket_t *sd, apr_pool_t *p) {
    queue->data[queue->tail].sd = sd;
    queue->data[queue->tail].p  = p;
    queue->tail = (queue->tail + 1) % queue->bounds;
    queue->blanks--;
    pthread_cond_signal(&queue->not_empty);
#if 0
    if (queue->head == (queue->tail + 1) % queue->bounds) {
#endif
    if (ap_queue_full(queue)) {
        pthread_cond_wait(&queue->not_full, &queue->one_big_mutex);
    }
    return FD_QUEUE_SUCCESS;
}

apr_status_t ap_queue_pop(FDQueue *queue, apr_socket_t **sd, apr_pool_t **p, int block_if_empty) {
    increase_blanks(queue);
    /* We have just removed one from the queue.  By definition, it is
     * no longer full.  We can ALWAYS signal the listener thread at
     * this point.  However, the original code didn't do it this way,
     * so I am leaving the original code in, just commented out.  BTW,
     * originally, the increase_blanks wasn't in this function either.
     *
     if (queue->blanks > 0) {
     */
    pthread_cond_signal(&queue->not_full);

    /*    }    */
    if (queue->head == queue->tail) {
        if (block_if_empty) {
            pthread_cond_wait(&queue->not_empty, &queue->one_big_mutex);
fprintf(stderr, "Found a non-empty queue  :-)\n");
        }
    } 
    
    *sd = queue->data[queue->head].sd;
    *p  = queue->data[queue->head].p;
    queue->data[queue->head].sd = NULL;
    if (*sd != NULL) {
        queue->head = (queue->head + 1) % queue->bounds;
    }
    return APR_SUCCESS;
}

void ap_queue_signal_all_wakeup(FDQueue *queue)
{
fprintf(stderr, "trying to broadcast to all workers\n");
    pthread_cond_broadcast(&queue->not_empty);
}
