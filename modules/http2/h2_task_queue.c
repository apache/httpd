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


h2_task_queue *h2_tq_create(long id, apr_pool_t *pool)
{
    h2_task_queue *q = apr_pcalloc(pool, sizeof(h2_task_queue));
    if (q) {
        q->id = id;
        APR_RING_ELEM_INIT(q, link);
        APR_RING_INIT(&q->tasks, h2_task, link);
    }
    return q;
}

void h2_tq_destroy(h2_task_queue *q)
{
    while (!H2_TASK_LIST_EMPTY(&q->tasks)) {
        h2_task *task = H2_TASK_LIST_FIRST(&q->tasks);
        H2_TASK_REMOVE(task);
    }
}

static int in_list(h2_task_queue *q, h2_task *task)
{
    h2_task *e;
    for (e = H2_TASK_LIST_FIRST(&q->tasks); 
         e != H2_TASK_LIST_SENTINEL(&q->tasks);
         e = H2_TASK_NEXT(e)) {
        if (e == task) {
            return 1;
        }
    }
    return 0;
}

int h2_tq_empty(h2_task_queue *q)
{
    return H2_TASK_LIST_EMPTY(&q->tasks);
}

void h2_tq_append(h2_task_queue *q, struct h2_task *task)
{
    H2_TASK_LIST_INSERT_TAIL(&q->tasks, task);
}

apr_status_t h2_tq_remove(h2_task_queue *q, struct h2_task *task)
{
    if (in_list(q, task)) {
        H2_TASK_REMOVE(task);
        return APR_SUCCESS;
    }
    return APR_NOTFOUND;
}

h2_task *h2_tq_pop_first(h2_task_queue *q)
{
    if (!H2_TASK_LIST_EMPTY(&q->tasks)) {
        h2_task *task = H2_TASK_LIST_FIRST(&q->tasks);
        H2_TASK_REMOVE(task);
        return task;
    }
    return NULL;
}



