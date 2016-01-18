/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stddef.h>

#include <httpd.h>
#include <http_core.h>

#include "h2_task_queue.h"


static void tq_grow(h2_task_queue *q, int nlen);
static void tq_swap(h2_task_queue *q, int i, int j);
static int tq_bubble_up(h2_task_queue *q, int i, int top, 
                        h2_tq_cmp *cmp, void *ctx);
static int tq_bubble_down(h2_task_queue *q, int i, int bottom, 
                          h2_tq_cmp *cmp, void *ctx);

h2_task_queue *h2_tq_create(apr_pool_t *pool, int capacity)
{
    h2_task_queue *q = apr_pcalloc(pool, sizeof(h2_task_queue));
    if (q) {
        q->pool = pool;
        tq_grow(q, capacity);
        q->nelts = 0;
    }
    return q;
}

int h2_tq_empty(h2_task_queue *q)
{
    return q->nelts == 0;
}

void h2_tq_add(h2_task_queue *q, int sid, h2_tq_cmp *cmp, void *ctx)
{
    int i;
    
    if (q->nelts >= q->nalloc) {
        tq_grow(q, q->nalloc * 2);
    }
    
    i = (q->head + q->nelts) % q->nalloc;
    q->elts[i] = sid;
    ++q->nelts;
    
    /* bubble it to the front of the queue */
    tq_bubble_up(q, i, q->head, cmp, ctx);
}

int h2_tq_remove(h2_task_queue *q, int sid)
{
    int i;
    for (i = 0; i < q->nelts; ++i) {
        if (sid == q->elts[(q->head + i) % q->nalloc]) {
            break;
        }
    }
    
    if (i < q->nelts) {
        ++i;
        for (; i < q->nelts; ++i) {
            q->elts[(q->head+i-1)%q->nalloc] = q->elts[(q->head+i)%q->nalloc];
        }
        --q->nelts;
        return 1;
    }
    return 0;
}

void h2_tq_sort(h2_task_queue *q, h2_tq_cmp *cmp, void *ctx)
{
    /* Assume that changes in ordering are minimal. This needs,
     * best case, q->nelts - 1 comparisions to check that nothing
     * changed.
     */
    if (q->nelts > 0) {
        int i, ni, prev, last;
        
        /* Start at the end of the queue and create a tail of sorted
         * entries. Make that tail one element longer in each iteration.
         */
        last = i = (q->head + q->nelts - 1) % q->nalloc;
        while (i != q->head) {
            prev = (q->nalloc + i - 1) % q->nalloc;
            
            ni = tq_bubble_up(q, i, prev, cmp, ctx);
            if (ni == prev) {
                /* i bubbled one up, bubble the new i down, which
                 * keeps all tasks below i sorted. */
                tq_bubble_down(q, i, last, cmp, ctx);
            }
            i = prev;
        };
    }
}


int h2_tq_shift(h2_task_queue *q)
{
    int sid;
    
    if (q->nelts <= 0) {
        return 0;
    }
    
    sid = q->elts[q->head];
    q->head = (q->head + 1) % q->nalloc;
    q->nelts--;
    
    return sid;
}

static void tq_grow(h2_task_queue *q, int nlen)
{
    AP_DEBUG_ASSERT(q->nalloc <= nlen);
    if (nlen > q->nalloc) {
        int *nq = apr_pcalloc(q->pool, sizeof(int) * nlen);
        if (q->nelts > 0) {
            int l = ((q->head + q->nelts) % q->nalloc) - q->head;
            
            memmove(nq, q->elts + q->head, sizeof(int) * l);
            if (l < q->nelts) {
                /* elts wrapped, append elts in [0, remain] to nq */
                int remain = q->nelts - l;
                memmove(nq + l, q->elts, sizeof(int) * remain);
            }
        }
        q->elts = nq;
        q->nalloc = nlen;
        q->head = 0;
    }
}

static void tq_swap(h2_task_queue *q, int i, int j)
{
    int x = q->elts[i];
    q->elts[i] = q->elts[j];
    q->elts[j] = x;
}

static int tq_bubble_up(h2_task_queue *q, int i, int top, 
                        h2_tq_cmp *cmp, void *ctx) 
{
    int prev;
    while (((prev = (q->nalloc + i - 1) % q->nalloc), i != top) 
           && (*cmp)(q->elts[i], q->elts[prev], ctx) < 0) {
        tq_swap(q, prev, i);
        i = prev;
    }
    return i;
}

static int tq_bubble_down(h2_task_queue *q, int i, int bottom, 
                          h2_tq_cmp *cmp, void *ctx)
{
    int next;
    while (((next = (q->nalloc + i + 1) % q->nalloc), i != bottom) 
           && (*cmp)(q->elts[i], q->elts[next], ctx) > 0) {
        tq_swap(q, next, i);
        i = next;
    }
    return i;
}
