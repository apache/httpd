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

/*
 * Modified to use APR and APR pools.
 *  TODO: Is malloc() better? Will long running skiplists grow too much?
 *  Keep the skiplist_alloc() and skiplist_free() until we know
 *  Yeah, if using pools it means some bogus cycles for checks
 *  (and an useless function call for skiplist_free) which we
 *  can removed if/when needed.
 */

#include "ap_skiplist.h"

#ifndef MIN
#define MIN(a,b) ((a<b)?(a):(b))
#endif

static int get_b_rand(void)
{
    static int ph = 32;         /* More bits than we will ever use */
    static apr_uint32_t randseq;
    if (ph > 31) {              /* Num bits in return of rand() */
        ph = 0;
        randseq = (apr_uint32_t) rand();
    }
    ph++;
    return ((randseq & (1 << (ph - 1))) >> (ph - 1));
}

void *ap_skiplist_alloc(ap_skiplist *sl, size_t size)
{
    if (sl->pool) {
        return apr_pcalloc(sl->pool, size);
    }
    else {
        return ap_calloc(1, size);
    }
}

void ap_skiplist_free(ap_skiplist *sl, void *mem)
{
    if (!sl->pool) {
        free(mem);
    }
}

static apr_status_t skiplisti_init(ap_skiplist **s, apr_pool_t *p)
{
    ap_skiplist *sl;
    if (p) {
        sl = apr_pcalloc(p, sizeof(ap_skiplist));
    }
    else {
        sl = ap_calloc(1, sizeof(ap_skiplist));
    }
#if 0
    sl->compare = (ap_skiplist_compare) NULL;
    sl->comparek = (ap_skiplist_compare) NULL;
    sl->height = 0;
    sl->preheight = 0;
    sl->size = 0;
    sl->top = NULL;
    sl->bottom = NULL;
    sl->index = NULL;
#endif
    sl->pool = p;
    *s = sl;
    return APR_SUCCESS;
}

static int indexing_comp(void *a, void *b)
{
    void *ac = (void *) (((ap_skiplist *) a)->compare);
    void *bc = (void *) (((ap_skiplist *) b)->compare);
    AP_DEBUG_ASSERT(a);
    AP_DEBUG_ASSERT(b);
    return ((ac < bc) ? -1 : ((ac > bc) ? 1 : 0));
}

static int indexing_compk(void *ac, void *b)
{
    void *bc = (void *) (((ap_skiplist *) b)->compare);
    AP_DEBUG_ASSERT(b);
    return ((ac < bc) ? -1 : ((ac > bc) ? 1 : 0));
}

apr_status_t ap_skiplist_init(ap_skiplist **s, apr_pool_t *p)
{
    ap_skiplist *sl;
    skiplisti_init(s, p);
    sl = *s;
    skiplisti_init(&(sl->index), p);
    ap_skiplist_set_compare(sl->index, indexing_comp, indexing_compk);
    return APR_SUCCESS;
}

void ap_skiplist_set_compare(ap_skiplist *sl,
                          ap_skiplist_compare comp,
                          ap_skiplist_compare compk)
{
    if (sl->compare && sl->comparek) {
        ap_skiplist_add_index(sl, comp, compk);
    }
    else {
        sl->compare = comp;
        sl->comparek = compk;
    }
}

void ap_skiplist_add_index(ap_skiplist *sl,
                        ap_skiplist_compare comp,
                        ap_skiplist_compare compk)
{
    ap_skiplistnode *m;
    ap_skiplist *ni;
    int icount = 0;
    ap_skiplist_find(sl->index, (void *)comp, &m);
    if (m) {
        return;                 /* Index already there! */
    }
    skiplisti_init(&ni, sl->pool);
    ap_skiplist_set_compare(ni, comp, compk);
    /* Build the new index... This can be expensive! */
    m = ap_skiplist_insert(sl->index, ni);
    while (m->prev) {
        m = m->prev;
        icount++;
    }
    for (m = ap_skiplist_getlist(sl); m; ap_skiplist_next(sl, &m)) {
        int j = icount - 1;
        ap_skiplistnode *nsln;
        nsln = ap_skiplist_insert(ni, m->data);
        /* skip from main index down list */
        while (j > 0) {
            m = m->nextindex;
            j--;
        }
        /* insert this node in the indexlist after m */
        nsln->nextindex = m->nextindex;
        if (m->nextindex) {
            m->nextindex->previndex = nsln;
        }
        nsln->previndex = m;
        m->nextindex = nsln;
    }
}

ap_skiplistnode *ap_skiplist_getlist(ap_skiplist *sl)
{
    if (!sl->bottom) {
        return NULL;
    }
    return sl->bottom->next;
}

void *ap_skiplist_find(ap_skiplist *sl, void *data, ap_skiplistnode **iter)
{
    void *ret;
    ap_skiplistnode *aiter;
    if (!sl->compare) {
        return 0;
    }
    if (iter) {
        ret = ap_skiplist_find_compare(sl, data, iter, sl->compare);
    }
    else {
        ret = ap_skiplist_find_compare(sl, data, &aiter, sl->compare);
    }
    return ret;
}

static int skiplisti_find_compare(ap_skiplist *sl, void *data,
                           ap_skiplistnode **ret,
                           ap_skiplist_compare comp)
{
    ap_skiplistnode *m = NULL;
    int count = 0;
    m = sl->top;
    while (m) {
        int compared;
        compared = (m->next) ? comp(data, m->next->data) : -1;
        if (compared == 0) {
            m = m->next;
            while (m->down) {
                m = m->down;
            }
            *ret = m;
            return count;
        }
        if ((m->next == NULL) || (compared < 0)) {
            m = m->down;
            count++;
        }
        else {
            m = m->next;
            count++;
        }
    }
    *ret = NULL;
    return count;
}

void *ap_skiplist_find_compare(ap_skiplist *sli, void *data,
                               ap_skiplistnode **iter,
                               ap_skiplist_compare comp)
{
    ap_skiplistnode *m = NULL;
    ap_skiplist *sl;
    if (comp == sli->compare || !sli->index) {
        sl = sli;
    }
    else {
        ap_skiplist_find(sli->index, (void *)comp, &m);
        AP_DEBUG_ASSERT(m);
        sl = (ap_skiplist *) m->data;
    }
    skiplisti_find_compare(sl, data, iter, sl->comparek);
    return (*iter) ? ((*iter)->data) : (*iter);
}


void *ap_skiplist_next(ap_skiplist *sl, ap_skiplistnode **iter)
{
    if (!*iter) {
        return NULL;
    }
    *iter = (*iter)->next;
    return (*iter) ? ((*iter)->data) : NULL;
}

void *ap_skiplist_previous(ap_skiplist *sl, ap_skiplistnode **iter)
{
    if (!*iter) {
        return NULL;
    }
    *iter = (*iter)->prev;
    return (*iter) ? ((*iter)->data) : NULL;
}

ap_skiplistnode *ap_skiplist_insert(ap_skiplist *sl, void *data)
{
    if (!sl->compare) {
        return 0;
    }
    return ap_skiplist_insert_compare(sl, data, sl->compare);
}

ap_skiplistnode *ap_skiplist_insert_compare(ap_skiplist *sl, void *data,
                                      ap_skiplist_compare comp)
{
    ap_skiplistnode *m, *p, *tmp, *ret, **stack;
    int nh = 1, ch, stacki;
    if (!sl->top) {
        sl->height = 1;
        sl->topend = sl->bottomend = sl->top = sl->bottom =
            (ap_skiplistnode *)ap_skiplist_alloc(sl, sizeof(ap_skiplistnode));
        AP_DEBUG_ASSERT(sl->top);
#if 0
        sl->top->next = (ap_skiplistnode *)NULL;
        sl->top->data = (ap_skiplistnode *)NULL;
        sl->top->prev = (ap_skiplistnode *)NULL;
        sl->top->up = (ap_skiplistnode *)NULL;
        sl->top->down = (ap_skiplistnode *)NULL;
        sl->top->nextindex = (ap_skiplistnode *)NULL;
        sl->top->previndex = (ap_skiplistnode *)NULL;
#endif
        sl->top->sl = sl;
    }
    if (sl->preheight) {
        while (nh < sl->preheight && get_b_rand()) {
            nh++;
        }
    }
    else {
        while (nh <= sl->height && get_b_rand()) {
            nh++;
        }
    }
    /* Now we have the new height at which we wish to insert our new node */
    /*
     * Let us make sure that our tree is a least that tall (grow if
     * necessary)
     */
    for (; sl->height < nh; sl->height++) {
        sl->top->up =
            (ap_skiplistnode *)ap_skiplist_alloc(sl, sizeof(ap_skiplistnode));
        AP_DEBUG_ASSERT(sl->top->up);
        sl->top->up->down = sl->top;
        sl->top = sl->topend = sl->top->up;
#if 0
        sl->top->prev = sl->top->next = sl->top->nextindex =
            sl->top->previndex = sl->top->up = NULL;
        sl->top->data = NULL;
#endif
        sl->top->sl = sl;
    }
    ch = sl->height;
    /* Find the node (or node after which we would insert) */
    /* Keep a stack to pop back through for insertion */
    /* malloc() is OK since we free the temp stack */
    m = sl->top;
    stack = (ap_skiplistnode **)ap_malloc(sizeof(ap_skiplistnode *) * (nh));
    stacki = 0;
    while (m) {
        int compared = -1;
        if (m->next) {
            compared = comp(data, m->next->data);
        }
        if (compared == 0) {
            free(stack);    /* OK. was ap_malloc'ed */
            return 0;
        }
        if ((m->next == NULL) || (compared < 0)) {
            if (ch <= nh) {
                /* push on stack */
                stack[stacki++] = m;
            }
            m = m->down;
            ch--;
        }
        else {
            m = m->next;
        }
    }
    /* Pop the stack and insert nodes */
    p = NULL;
    for (; stacki > 0; stacki--) {
        m = stack[stacki - 1];
        tmp = (ap_skiplistnode *)ap_skiplist_alloc(sl, sizeof(ap_skiplistnode));
        tmp->next = m->next;
        if (m->next) {
            m->next->prev = tmp;
        }
        tmp->prev = m;
        tmp->up = NULL;
        tmp->nextindex = tmp->previndex = NULL;
        tmp->down = p;
        if (p) {
            p->up = tmp;
        }
        tmp->data = data;
        tmp->sl = sl;
        m->next = tmp;
        /* This sets ret to the bottom-most node we are inserting */
        if (!p) {
            ret = tmp;
            sl->size++; /* this seems to go here got each element to be counted */
        }
        p = tmp;
    }
    free(stack); /* OK. was malloc'ed */
    if (sl->index != NULL) {
        /*
         * this is a external insertion, we must insert into each index as
         * well
         */
        ap_skiplistnode *p, *ni, *li;
        li = ret;
        for (p = ap_skiplist_getlist(sl->index); p; ap_skiplist_next(sl->index, &p)) {
            ni = ap_skiplist_insert((ap_skiplist *) p->data, ret->data);
            AP_DEBUG_ASSERT(ni);
            li->nextindex = ni;
            ni->previndex = li;
            li = ni;
        }
    }
    else {
        /* sl->size++; */
    }
    return ret;
}

int ap_skiplist_remove(ap_skiplist *sl, void *data, ap_skiplist_freefunc myfree)
{
    if (!sl->compare) {
        return 0;
    }
    return ap_skiplist_remove_compare(sl, data, myfree, sl->comparek);
}

#if 0
void skiplist_print_struct(ap_skiplist * sl, char *prefix)
{
    ap_skiplistnode *p, *q;
    fprintf(stderr, "Skiplist Structure (height: %d)\n", sl->height);
    p = sl->bottom;
    while (p) {
        q = p;
        fprintf(stderr, prefix);
        while (q) {
            fprintf(stderr, "%p ", q->data);
            q = q->up;
        }
        fprintf(stderr, "\n");
        p = p->next;
    }
}
#endif

static int skiplisti_remove(ap_skiplist *sl, ap_skiplistnode *m, ap_skiplist_freefunc myfree)
{
    ap_skiplistnode *p;
    if (!m) {
        return 0;
    }
    if (m->nextindex) {
        skiplisti_remove(m->nextindex->sl, m->nextindex, NULL);
    }
    while (m->up) {
        m = m->up;
    }
    while (m) {
        p = m;
        p->prev->next = p->next;/* take me out of the list */
        if (p->next) {
            p->next->prev = p->prev;    /* take me out of the list */
        }
        m = m->down;
        /* This only frees the actual data in the bottom one */
        if (!m && myfree && p->data) {
            myfree(p->data);
        }
        ap_skiplist_free(sl, p);
    }
    sl->size--;
    while (sl->top && sl->top->next == NULL) {
        /* While the row is empty and we are not on the bottom row */
        p = sl->top;
        sl->top = sl->top->down;/* Move top down one */
        if (sl->top) {
            sl->top->up = NULL; /* Make it think its the top */
        }
        ap_skiplist_free(sl, p);
        sl->height--;
    }
    if (!sl->top) {
        sl->bottom = NULL;
    }
    AP_DEBUG_ASSERT(sl->height >= 0);
    return sl->height;  /* return 1; ?? */
}

int ap_skiplist_remove_compare(ap_skiplist *sli,
                            void *data,
                            ap_skiplist_freefunc myfree, ap_skiplist_compare comp)
{
    ap_skiplistnode *m;
    ap_skiplist *sl;
    if (comp == sli->comparek || !sli->index) {
        sl = sli;
    }
    else {
        ap_skiplist_find(sli->index, (void *)comp, &m);
        AP_DEBUG_ASSERT(m);
        sl = (ap_skiplist *) m->data;
    }
    skiplisti_find_compare(sl, data, &m, comp);
    if (!m) {
        return 0;
    }
    while (m->previndex) {
        m = m->previndex;
    }
    return skiplisti_remove(sl, m, myfree);
}

void ap_skiplist_remove_all(ap_skiplist *sl, ap_skiplist_freefunc myfree)
{
    /*
     * This must remove even the place holder nodes (bottom though top)
     * because we specify in the API that one can free the Skiplist after
     * making this call without memory leaks
     */
    ap_skiplistnode *m, *p, *u;
    m = sl->bottom;
    while (m) {
        p = m->next;
        if (myfree && p->data)
            myfree(p->data);
        while (m) {
            u = m->up;
            ap_skiplist_free(sl, p);
            m = u;
        }
        m = p;
    }
    sl->top = sl->bottom = NULL;
    sl->height = 0;
    sl->size = 0;
}

void *ap_skiplist_pop(ap_skiplist *a, ap_skiplist_freefunc myfree)
{
    ap_skiplistnode *sln;
    void *data = NULL;
    sln = ap_skiplist_getlist(a);
    if (sln) {
        data = sln->data;
        skiplisti_remove(a, sln, myfree);
    }
    return data;
}

void *ap_skiplist_peek(ap_skiplist *a)
{
    ap_skiplistnode *sln;
    sln = ap_skiplist_getlist(a);
    if (sln) {
        return sln->data;
    }
    return NULL;
}

static void skiplisti_destroy(void *vsl)
{
    ap_skiplist_destroy((ap_skiplist *) vsl, NULL);
    ap_skiplist_free((ap_skiplist *) vsl, vsl);
}

void ap_skiplist_destroy(ap_skiplist *sl, ap_skiplist_freefunc myfree)
{
    while (ap_skiplist_pop(sl->index, skiplisti_destroy) != NULL)
        ;
    ap_skiplist_remove_all(sl, myfree);
}

ap_skiplist *ap_skiplist_merge(ap_skiplist *sl1, ap_skiplist *sl2)
{
    /* Check integrity! */
    ap_skiplist temp;
    struct ap_skiplistnode *b2;
    if (sl1->bottomend == NULL || sl1->bottomend->prev == NULL) {
        ap_skiplist_remove_all(sl1, NULL);
        temp = *sl1;
        *sl1 = *sl2;
        *sl2 = temp;
        /* swap them so that sl2 can be freed normally upon return. */
        return sl1;
    }
    if(sl2->bottom == NULL || sl2->bottom->next == NULL) {
        ap_skiplist_remove_all(sl2, NULL);
        return sl1;
    }
    /* This is what makes it brute force... Just insert :/ */
    b2 = ap_skiplist_getlist(sl2);
    while (b2) {
        ap_skiplist_insert(sl1, b2->data);
        ap_skiplist_next(sl2, &b2);
    }
    ap_skiplist_remove_all(sl2, NULL);
    return sl1;
}
