#include "apr_general.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif

#if APR_HAVE_STRING_H
#include <string.h>
#endif

#include "cache_pqueue.h"
#define left(i) (2*(i))
#define right(i) ((2*i)+1)
#define parent(i) (i/2)
/*
 *  Priority queue structure
 */
struct cache_pqueue_t
{
    apr_ssize_t size;
    apr_ssize_t avail;
    apr_ssize_t step;
    cache_pqueue_get_priority* pri;
    cache_pqueue_getpos* get;
    cache_pqueue_setpos* set;
    void **d;
};

cache_pqueue_t *cache_pq_init(apr_ssize_t n,
                              cache_pqueue_get_priority* pri,
                              cache_pqueue_getpos get,
                              cache_pqueue_setpos set)
{
    cache_pqueue_t *q;

    if (!(q = malloc(sizeof(cache_pqueue_t)))) {
        return NULL;
    }

    if (!(q->d = malloc(sizeof(void*) * n))) {
        free(q);
        return NULL;
    }
    q->avail = q->step = n;
    q->pri = pri;
    q->size = 1;
    q->get = get;
    q->set = set;
    return q;
}
/*
 * cleanup
 */
void cache_pq_free(cache_pqueue_t *q)
{
    free(q->d);
    free(q);
}
/*
 * pqsize: size of the queue.
 */
apr_ssize_t cache_pq_size(cache_pqueue_t *q)
{
    return q->size;
}

static void cache_pq_bubble_up(cache_pqueue_t*q, apr_ssize_t i)
{
    apr_ssize_t parent_node;
    parent_node = parent(i);

    while (i > 1 && q->pri(q->d[parent_node]) < q->pri(q->d[i])) {
        void *tmp;
        tmp = q->d[i];

        q->d[i] = q->d[parent_node];
        q->d[parent_node] = tmp;
        q->set(q->d[i], i);
        q->set(q->d[parent_node], parent_node);
        i = parent_node;
        parent_node = parent(i);
    }
}

static apr_ssize_t minchild(cache_pqueue_t *q, apr_ssize_t i)
{
    apr_ssize_t y, minc;
    minc = left(i);
    if (minc >= q->size)
        return -1;

    for (y = minc + 1; y <= right(i) && y < q->size; y++) {
        if (q->pri(q->d[y]) > q->pri(q->d[minc]))
            minc = y;
    }
    return minc;
}

static void cache_pq_percolate_down(cache_pqueue_t*q, apr_ssize_t i)
{
    apr_ssize_t cx = minchild(q, i);
    while ((cx != -1) && (q->pri(q->d[cx]) > q->pri(q->d[i])))
    {
        void *tmp;

        tmp = q->d[i];
        q->d[i] = q->d[cx];
        q->d[cx] = tmp;
        q->set(q->d[i], i);
        q->set(q->d[cx], cx);
        i = cx;
        cx = minchild(q, i);
    }
}

apr_status_t cache_pq_insert(cache_pqueue_t *q, void* d)
{
    void *tmp;
    apr_ssize_t i;
    apr_ssize_t parent_node;
    apr_ssize_t newsize;

    if (!q) return APR_EGENERAL;

    /* allocate more memory if necessary */
    if (q->size >= q->avail) {
        newsize = q->size + q->step;
        if (!(tmp = realloc(q->d, sizeof(void*) * newsize))) {
            return APR_EGENERAL;
        };
        q->d = tmp;
        q->avail = newsize;
    }

    /* insert item */
    i = q->size++;
    parent_node = parent(i);
    /*
     * this is an optimization of the bubble-up as it doesn't
     * have to swap the member around
     */
    while ((i > 1) && q->pri(q->d[parent_node]) < q->pri(d)) {
        q->d[i] = q->d[parent_node];
        q->set(q->d[i], i);
        i = parent_node;
        parent_node = parent(i);
    }
    q->d[i] = d;
    q->set(q->d[i], i);
    return APR_SUCCESS;
}

/*
 * move a existing entry to a new priority
 */
void cache_pq_change_priority(cache_pqueue_t*q,
                              long old_priority,
                              long new_priority,
                              void *d)
{
    apr_ssize_t posn;

    posn = q->get(d);
    if (new_priority > old_priority)
        cache_pq_bubble_up(q, posn);
    else
        cache_pq_percolate_down(q, posn);
}

apr_status_t cache_pq_remove(cache_pqueue_t *q, void* d)
{
    apr_ssize_t posn;
    void *popped = NULL;
    long pri_popped;
    long pri_removed;

    popped = cache_pq_pop(q);
    posn  = q->get(d);

    if (!popped)
        return APR_EGENERAL;

    if (d == popped) {
        return APR_SUCCESS;
    }
    pri_popped = q->pri(popped);
    pri_removed = q->pri(d);

    q->d[posn] = popped;
    q->set(popped,posn);
    if (pri_popped > pri_removed)
        cache_pq_bubble_up(q, posn);
    else
        cache_pq_percolate_down(q, posn);

    return APR_SUCCESS;
}

void *cache_pq_pop(cache_pqueue_t *q)
{
    void *tmp;
    void *d;
    int i = 1;
    int j;

    if (!q || q->size == 1)
        return NULL;

    d = q->d[1];
    tmp = q->d[--q->size];
    while (i <= q->size / 2) {
        j = 2 * i;
        if (j < q->size && q->pri(q->d[j]) < q->pri(q->d[j + 1])) {
            j++;
        }
        if (q->pri(q->d[j]) <= q->pri(tmp)) {
            break;
        }
        q->d[i] = q->d[j];
        q->set(q->d[i], i);
        i = j;
    }
    q->d[i] = tmp;
    q->set(q->d[i], i);
    return d;
}

void *cache_pq_peek(cache_pqueue_t *q)
{
    void *d;
    if (!q || q->size == 1)
        return NULL;
    d = q->d[1];
    return d;
}

static void cache_pq_set_null( void*d, apr_ssize_t val)
{
    /* do nothing */
}
/*
 * this is a debug function.. so it's EASY not fast
 */
void cache_pq_dump(cache_pqueue_t *q,
                   FILE*out,
                   cache_pqueue_print_entry print)
{
    int i;

    fprintf(stdout,"posn\tleft\tright\tparent\tminchild\t...\n");
    for (i = 1; i < q->size ;i++) {
        fprintf(stdout,
                "%d\t%d\t%d\t%d\t%d\t",
                i,
                left(i), right(i), parent(i),
                minchild(q, i));
        print(out, q->d[i]);
    }
}
/*
 * this is a debug function.. so it's EASY not fast
 */
void cache_pq_print(cache_pqueue_t *q,
                    FILE*out,
                    cache_pqueue_print_entry print)
{
    cache_pqueue_t *dup;
    dup = cache_pq_init(q->size, q->pri, q->get, cache_pq_set_null);
    dup->size = q->size;
    dup->avail = q->avail;
    dup->step = q->step;

    memcpy(dup->d, q->d, q->size*sizeof(void*));

    while (cache_pq_size(dup) > 1) {
        void *e = NULL;
        e = cache_pq_pop(dup);
        if (e)
            print(out, e);
        else
            break;
    }
    cache_pq_free(dup);
}
