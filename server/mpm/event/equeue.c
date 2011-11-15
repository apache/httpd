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

#include "equeue.h"

#include <apr_atomic.h>
#include <sched.h>

struct ap_equeue_t {
    apr_uint32_t nelem;
    apr_size_t elem_size;
    uint8_t *bytes;
    volatile apr_uint32_t writeCount;
    volatile apr_uint32_t readCount;
};


static APR_INLINE apr_uint32_t count_to_index(ap_equeue_t *eq, apr_uint32_t count)
{
    return (count & (eq->nelem - 1));
}

static APR_INLINE void* index_to_bytes(ap_equeue_t *eq, apr_uint32_t idx)
{
    apr_size_t offset = idx * eq->elem_size;
    return (void*)&eq->bytes[offset];
}

static APR_INLINE apr_uint32_t nearest_power(apr_uint32_t num)
{
    apr_uint32_t n = 1;
    while (n < num) {
        n <<= 1;
    }

    return n;
}

#if 0
static void dump_queue(ap_equeue_t *eq)
{
    apr_uint32_t i;

    fprintf(stderr, "dumping %p\n", eq);
    fprintf(stderr, "  nelem:   %u\n", eq->nelem);
    fprintf(stderr, "  esize:   %"APR_SIZE_T_FMT"\n", eq->elem_size);
    fprintf(stderr, "  wcnt:    %u\n", eq->writeCount);
    fprintf(stderr, "  rcnt:    %u\n", eq->writeCount);
    fprintf(stderr, "  bytes:   %p\n", eq->bytes);
    for (i = 0; i < eq->nelem; i++) {
        fprintf(stderr, "    [%u] = %p\n", i, index_to_bytes(eq, i));
    }

    fprintf(stderr, "\n");
    fflush(stderr);
}
#endif

apr_status_t
ap_equeue_create(apr_pool_t *p, apr_uint32_t nelem, apr_size_t elem_size, ap_equeue_t **eqout)
{
    ap_equeue_t *eq;

    *eqout = NULL;

    eq = apr_palloc(p, sizeof(ap_equeue_t));
    eq->bytes = apr_palloc(p, (1 + nelem) * elem_size);
    eq->nelem = nearest_power(nelem);
    eq->elem_size = elem_size;
    eq->writeCount = 0;
    eq->readCount = 0;
    *eqout = eq;

    return APR_SUCCESS;
}

void *
ap_equeue_reader_next(ap_equeue_t *eq)
{
    if (apr_atomic_read32(&eq->writeCount) == eq->readCount) {
        return NULL;
    }
    else {
        apr_uint32_t idx = count_to_index(eq, apr_atomic_inc32(&eq->readCount));
        return index_to_bytes(eq, idx);
    }
}

void *
ap_equeue_writer_value(ap_equeue_t *eq)
{
    apr_uint32_t idx;

    while (1) {
        apr_uint32_t readCount = apr_atomic_read32(&eq->readCount);

        if (count_to_index(eq, eq->writeCount + 1) != count_to_index(eq, readCount)) {
            break;
        }
        /* TODO: research if sched_yield is even worth doing  */
        sched_yield();
    }

    idx = count_to_index(eq, eq->writeCount);
    return index_to_bytes(eq, idx);
}


void ap_equeue_writer_onward(ap_equeue_t *eq)
{
    apr_atomic_inc32(&eq->writeCount);
}
