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

#include "h2_task.h"
#include "h2_task_queue.h"


static void grow(h2_task_queue *q, int nlen);
static h2_task *qrm(h2_task_queue *q, int index);
static void tqsort(h2_task_queue *q, int left, int right,  
                   h2_tq_cmp *cmp, void *ctx);

h2_task_queue *h2_tq_create(apr_pool_t *pool, int capacity)
{
    h2_task_queue *q = apr_pcalloc(pool, sizeof(h2_task_queue));
    if (q) {
        q->pool = pool;
        grow(q, capacity);
        q->nelts = 0;
    }
    return q;
}

void h2_tq_destroy(h2_task_queue *q)
{
}

int h2_tq_empty(h2_task_queue *q)
{
    return q->nelts == 0;
}

void h2_tq_add(h2_task_queue *q, struct h2_task *task,
               h2_tq_cmp *cmp, void *ctx)
{
    int i;
    
    if (q->nelts >= q->nalloc) {
        grow(q, q->nalloc * 2);
    }
    
    /* Assume tasks most commonly arrive in ascending order */
    for (i = q->nelts; i > 0; --i) {
        if (cmp(q->elts[i-1], task, ctx) <= 0) {
            if (i < q->nelts) {
                memmove(q->elts+i+1, q->elts+i, q->nelts - i);
            }
            q->elts[i] = task;
            q->nelts++;
            return;
        }
    }
    /* insert at front */
    if (q->nelts) {
        memmove(q->elts+1, q->elts, q->nelts);
    }
    q->elts[q->nelts++] = task;
}

void h2_tq_sort(h2_task_queue *q, h2_tq_cmp *cmp, void *ctx)
{
    tqsort(q, 0, q->nelts - 1, cmp, ctx);
}


apr_status_t h2_tq_remove(h2_task_queue *q, struct h2_task *task)
{
    int i;
    
    for (i = 0; i < q->nelts; ++i) {
        if (task == q->elts[i]) {
            qrm(q, i);
            return APR_SUCCESS;
        }
    }
    return APR_NOTFOUND;
}

h2_task *h2_tq_shift(h2_task_queue *q)
{
    return qrm(q, 0);
}

static void grow(h2_task_queue *q, int nlen)
{
    AP_DEBUG_ASSERT(q->nalloc <= nlen);
    if (nlen > q->nalloc) {
        h2_task **nq = apr_pcalloc(q->pool, sizeof(h2_task *) * nlen);
        if (q->nelts > 0) {
            memmove(nq, q->elts, sizeof(h2_task *) * q->nelts);
        }
        q->elts = nq;
        q->nalloc = nlen;
    }
}

static h2_task *qrm(h2_task_queue *q, int index)
{
    if (index >= q->nelts) {
        return NULL;
    }
    else if (index == q->nelts - 1) {
        q->nelts--;
        return q->elts[index];
    }
    else {
        h2_task *t = q->elts[index];
        q->nelts--;
        memmove(q->elts+index, q->elts+index+1, 
                sizeof(q->elts[0]) * (q->nelts - index));
        return t;
    }
}

static void tqswap(h2_task_queue *q, int i, int j)
{
    h2_task *t = q->elts[i];
    q->elts[i] = q->elts[j];
    q->elts[j] = t;
}

static void tqsort(h2_task_queue *q, int left, int right,  
                   h2_tq_cmp *cmp, void *ctx) 
{
    int i, last;

    if (left >= right)
        return;
    tqswap(q, left, (left + right)/2);
    last = left;
    for (i = left+1; i <= right; i++) {
        if ((*cmp)(q->elts[i], q->elts[left], ctx) < 0) {
            tqswap(q, ++last, i);
        }
    }
    tqswap(q, left, last);
    tqsort(q, left, last-1, cmp, ctx);
    tqsort(q, last+1, right, cmp, ctx);
}




