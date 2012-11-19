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

#include "skiplist.h"

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

void *skiplist_alloc(Skiplist *sl, size_t size)
{
    if (sl->pool) {
        return apr_palloc(sl->pool, size);
    }
    else {
        return ap_malloc(size);
    }
}

void skiplist_free(Skiplist *sl, void *mem)
{
    if (!sl->pool) {
        free(mem);
    }
}

static apr_status_t skiplisti_init(Skiplist **s, apr_pool_t *p)
{
    Skiplist *sl;
    if (p) {
        sl = apr_palloc(p, sizeof(Skiplist));
    }
    else {
        sl = ap_malloc(sizeof(Skiplist));
    }
    sl->compare = (SkiplistComparator) NULL;
    sl->comparek = (SkiplistComparator) NULL;
    sl->height = 0;
    sl->preheight = 0;
    sl->size = 0;
    sl->top = NULL;
    sl->bottom = NULL;
    sl->index = NULL;
    sl->pool = p;
    *s = sl;
    return APR_SUCCESS;
}

static int indexing_comp(void *a, void *b)
{
    void *ac = (void *) (((Skiplist *) a)->compare);
    void *bc = (void *) (((Skiplist *) b)->compare);
    AP_DEBUG_ASSERT(a);
    AP_DEBUG_ASSERT(b);
    return ((ac < bc) ? -1 : ((ac > bc) ? 1 : 0));
}

static int indexing_compk(void *ac, void *b)
{
    void *bc = (void *) (((Skiplist *) b)->compare);
    AP_DEBUG_ASSERT(b);
    return ((ac < bc) ? -1 : ((ac > bc) ? 1 : 0));
}

apr_status_t skiplist_init(Skiplist **s, apr_pool_t *p)
{
    Skiplist *sl;
    skiplisti_init(s, p);
    sl = *s;
    skiplisti_init(&(sl->index), p);
    skiplist_set_compare(sl->index, indexing_comp, indexing_compk);
    return APR_SUCCESS;
}

void skiplist_set_compare(Skiplist *sl,
                          SkiplistComparator comp,
                          SkiplistComparator compk)
{
    if (sl->compare && sl->comparek) {
        skiplist_add_index(sl, comp, compk);
    }
    else {
        sl->compare = comp;
        sl->comparek = compk;
    }
}

void skiplist_add_index(Skiplist *sl,
                        SkiplistComparator comp,
                        SkiplistComparator compk)
{
    skiplistnode *m;
    Skiplist *ni;
    int icount = 0;
    skiplist_find(sl->index, (void *)comp, &m);
    if (m) {
        return;                 /* Index already there! */
    }
    skiplisti_init(&ni, sl->pool);
    skiplist_set_compare(ni, comp, compk);
    /* Build the new index... This can be expensive! */
    m = skiplist_insert(sl->index, ni);
    while (m->prev) {
        m = m->prev;
        icount++;
    }
    for (m = skiplist_getlist(sl); m; skiplist_next(sl, &m)) {
        int j = icount - 1;
        skiplistnode *nsln;
        nsln = skiplist_insert(ni, m->data);
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

skiplistnode *skiplist_getlist(Skiplist *sl)
{
    if (!sl->bottom) {
        return NULL;
    }
    return sl->bottom->next;
}

void *skiplist_find(Skiplist *sl, void *data, skiplistnode **iter)
{
    void *ret;
    skiplistnode *aiter;
    if (!sl->compare) {
        return 0;
    }
    if (iter) {
        ret = skiplist_find_compare(sl, data, iter, sl->compare);
    }
    else {
        ret = skiplist_find_compare(sl, data, &aiter, sl->compare);
    }
    return ret;
}

static int skiplisti_find_compare(Skiplist *sl, void *data,
                           skiplistnode **ret,
                           SkiplistComparator comp)
{
    skiplistnode *m = NULL;
    int count = 0;
    m = sl->top;
    while (m) {
        int compared;
        if (m->next) {
            compared = comp(data, m->next->data);
        }
        if (compared == 0) {
            m = m->next;
            while (m->down) {
                m = m->down;
            }
            *ret = m;
            return count;
        }
        if ((m->next == NULL) || (compared < 0)) {
            m = m->down, count++;
        }
        else {
            m = m->next, count++;
        }
    }
    *ret = NULL;
    return count;
}

void *skiplist_find_compare(Skiplist *sli, void *data,
                            skiplistnode **iter,
                            SkiplistComparator comp)
{
    skiplistnode *m = NULL;
    Skiplist *sl;
    if (comp == sli->compare || !sli->index) {
        sl = sli;
    }
    else {
        skiplist_find(sli->index, (void *)comp, &m);
        AP_DEBUG_ASSERT(m);
        sl = (Skiplist *) m->data;
    }
    skiplisti_find_compare(sl, data, iter, sl->comparek);
    return (*iter) ? ((*iter)->data) : (*iter);
}


void *skiplist_next(Skiplist *sl, skiplistnode **iter)
{
    if (!*iter) {
        return NULL;
    }
    *iter = (*iter)->next;
    return (*iter) ? ((*iter)->data) : NULL;
}

void *skiplist_previous(Skiplist *sl, skiplistnode **iter)
{
    if (!*iter) {
        return NULL;
    }
    *iter = (*iter)->prev;
    return (*iter) ? ((*iter)->data) : NULL;
}

skiplistnode *skiplist_insert(Skiplist *sl, void *data)
{
    if (!sl->compare) {
        return 0;
    }
    return skiplist_insert_compare(sl, data, sl->compare);
}

skiplistnode *skiplist_insert_compare(Skiplist *sl, void *data,
                                      SkiplistComparator comp)
{
    skiplistnode *m, *p, *tmp, *ret, **stack;
    int nh = 1, ch, stacki;
    if (!sl->top) {
        sl->height = 1;
        sl->topend = sl->bottomend = sl->top = sl->bottom =
            (skiplistnode *)skiplist_alloc(sl, sizeof(skiplistnode));
        AP_DEBUG_ASSERT(sl->top);
        sl->top->next = (skiplistnode *)NULL;
        sl->top->data = (skiplistnode *)NULL;
        sl->top->prev = (skiplistnode *)NULL;
        sl->top->up = (skiplistnode *)NULL;
        sl->top->down = (skiplistnode *)NULL;
        sl->top->nextindex = (skiplistnode *)NULL;
        sl->top->previndex = (skiplistnode *)NULL;
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
            (skiplistnode *)skiplist_alloc(sl, sizeof(skiplistnode));
        AP_DEBUG_ASSERT(sl->top->up);
        sl->top->up->down = sl->top;
        sl->top = sl->topend = sl->top->up;
        sl->top->prev = sl->top->next = sl->top->nextindex =
            sl->top->previndex = sl->top->up = NULL;
        sl->top->data = NULL;
        sl->top->sl = sl;
    }
    ch = sl->height;
    /* Find the node (or node after which we would insert) */
    /* Keep a stack to pop back through for insertion */
    /* malloc() is OK since we free the temp stack */
    m = sl->top;
    stack = (skiplistnode **)ap_malloc(sizeof(skiplistnode *) * (nh));
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
        tmp = (skiplistnode *)skiplist_alloc(sl, sizeof(skiplistnode));
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
        skiplistnode *p, *ni, *li;
        li = ret;
        for (p = skiplist_getlist(sl->index); p; skiplist_next(sl->index, &p)) {
            ni = skiplist_insert((Skiplist *) p->data, ret->data);
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

#if 0
/*
 * There are reports of skiplist_append() being buggy.
 * Use at own risk
 */
skiplistnode *skiplist_append(Skiplist *sl, void *data)
{
    int nh = 1, ch, compared;
    skiplistnode *lastnode, *nodeago;
    if (sl->bottomend != sl->bottom) {
        compared = sl->compare(data, sl->bottomend->prev->data);
        /* If it doesn't belong at the end, then fail */
        if (compared <= 0)
            return NULL;
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
    lastnode = sl->bottomend;
    nodeago = NULL;

    if (!lastnode) {
        return skiplist_insert(sl, data);
    }

    for (; sl->height < nh; sl->height++) {
        sl->top->up = (skiplistnode *)skiplist_alloc(sl, sizeof(skiplistnode));
        AP_DEBUG_ASSERT(sl->top);
        sl->top->up->down = sl->top;
        sl->top = sl->top->up;
        sl->top->prev = sl->top->next = sl->top->nextindex =
            sl->top->previndex = NULL;
        sl->top->data = NULL;
        sl->top->sl = sl;
    }
    ch = sl->height;
    while (nh) {
        skiplistnode *anode;
        anode = (skiplistnode *)skiplist_alloc(sl, sizeof(skiplistnode));
        anode->next = lastnode;
        anode->prev = lastnode->prev;
        anode->up = NULL;
        anode->down = nodeago;
        if (lastnode->prev) {
            if (lastnode == sl->bottom)
                sl->bottom = anode;
            else if (lastnode == sl->top)
                sl->top = anode;
        }
        nodeago = anode;
        lastnode = lastnode->up;
        nh--;
    }
    sl->size++;
    return sl->bottomend;
}

/*
 * There are reports of skiplist_concat() being buggy.
 * Use at own risk
 */
Skiplist *skiplist_concat(Skiplist *sl1, Skiplist *sl2)
{
    /* Check integrity! */
    int compared, eheight;
    Skiplist temp;
    skiplistnode *lbottom, *lbottomend, *b1, *e1, *b2, *e2;
    if (sl1->bottomend == NULL || sl1->bottomend->prev == NULL) {
        skiplist_remove_all(sl1, NULL);
        temp = *sl1;
        *sl1 = *sl2;
        *sl2 = temp;
        /* swap them so that sl2 can be freed normally upon return. */
        return sl1;
    }
    if (sl2->bottom == NULL || sl2->bottom->next == NULL) {
        skiplist_remove_all(sl2, NULL);
        return sl1;
    }
    compared = sl1->compare(sl1->bottomend->prev->data, sl2->bottom->data);
    /* If it doesn't belong at the end, then fail */
    if (compared <= 0) {
        return NULL;
    }

    /* OK now append sl2 onto sl1 */
    lbottom = lbottomend = NULL;
    eheight = MIN(sl1->height, sl2->height);
    b1 = sl1->bottom;
    e1 = sl1->bottomend;
    b2 = sl2->bottom;
    e2 = sl2->bottomend;
    while (eheight) {
        e1->prev->next = b2;
        b2->prev = e1->prev->next;
        e2->prev->next = e1;
        e1->prev = e2->prev;
        e2->prev = NULL;
        b2 = e2;
        b1->down = lbottom;
        e1->down = lbottomend;
        if (lbottom) {
            lbottom->up = b1;
        }
        if (lbottomend) {
            lbottomend->up = e1;
        }

        lbottom = b1;
        lbottomend = e1;
    }
    /* Take the top of the longer one (if it is sl2) and make it sl1's */
    if (sl2->height > sl1->height) {
        b1->up = b2->up;
        e1->up = e2->up;
        b1->up->down = b1;
        e1->up->down = e1;
        sl1->height = sl2->height;
        sl1->top = sl2->top;
        sl1->topend = sl2->topend;
    }

    /* move the top pointer to here if it isn't there already */
    sl2->top = sl2->topend = b2;
    sl2->top->up = NULL;        /* If it isn't already */
    sl1->size += sl2->size;
    skiplist_remove_all(sl2, NULL);
    return sl1;
}
#endif

int skiplist_remove(Skiplist *sl, void *data, FreeFunc myfree)
{
    if (!sl->compare) {
        return 0;
    }
    return skiplist_remove_compare(sl, data, myfree, sl->comparek);
}

#if 0
void skiplist_print_struct(Skiplist * sl, char *prefix)
{
    skiplistnode *p, *q;
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

static int skiplisti_remove(Skiplist *sl, skiplistnode *m, FreeFunc myfree)
{
    skiplistnode *p;
    if (!m) {
        return 0;
    }
    if (m->nextindex) {
        skiplisti_remove(m->nextindex->sl, m->nextindex, NULL);
    }
    else {
        sl->size--;
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
        skiplist_free(sl, p);
    }
    while (sl->top && sl->top->next == NULL) {
        /* While the row is empty and we are not on the bottom row */
        p = sl->top;
        sl->top = sl->top->down;/* Move top down one */
        if (sl->top) {
            sl->top->up = NULL; /* Make it think its the top */
        }
        skiplist_free(sl, p);
        sl->height--;
    }
    if (!sl->top) {
        sl->bottom = NULL;
    }
    AP_DEBUG_ASSERT(sl->height >= 0);
    return sl->height;
}

int skiplist_remove_compare(Skiplist *sli,
                            void *data,
                            FreeFunc myfree, SkiplistComparator comp)
{
    skiplistnode *m;
    Skiplist *sl;
    if (comp == sli->comparek || !sli->index) {
        sl = sli;
    }
    else {
        skiplist_find(sli->index, (void *)comp, &m);
        AP_DEBUG_ASSERT(m);
        sl = (Skiplist *) m->data;
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

void skiplist_remove_all(Skiplist *sl, FreeFunc myfree)
{
    /*
     * This must remove even the place holder nodes (bottom though top)
     * because we specify in the API that one can free the Skiplist after
     * making this call without memory leaks
     */
    skiplistnode *m, *p, *u;
    m = sl->bottom;
    while (m) {
        p = m->next;
        if (myfree && p->data)
            myfree(p->data);
        while (m) {
            u = m->up;
            skiplist_free(sl, p);
            m = u;
        }
        m = p;
    }
    sl->top = sl->bottom = NULL;
    sl->height = 0;
    sl->size = 0;
}

void *skiplist_pop(Skiplist *a, FreeFunc myfree)
{
    skiplistnode *sln;
    void *data = NULL;
    sln = skiplist_getlist(a);
    if (sln) {
        data = sln->data;
        skiplisti_remove(a, sln, myfree);
    }
    return data;
}

void *skiplist_peek(Skiplist *a)
{
    skiplistnode *sln;
    void *data = NULL;
    sln = skiplist_getlist(a);
    return data;
}

Skiplist *skiplist_merge(Skiplist *sl1, Skiplist *sl2)
{
    /* Check integrity! */
    Skiplist temp;
    struct skiplistnode *b2;
    if (sl1->bottomend == NULL || sl1->bottomend->prev == NULL) {
        skiplist_remove_all(sl1, NULL);
        temp = *sl1;
        *sl1 = *sl2;
        *sl2 = temp;
        /* swap them so that sl2 can be freed normally upon return. */
        return sl1;
    }
    if(sl2->bottom == NULL || sl2->bottom->next == NULL) {
        skiplist_remove_all(sl2, NULL);
        return sl1;
    }
    /* This is what makes it brute force... Just insert :/ */
    b2 = skiplist_getlist(sl2);
    while (b2) {
        skiplist_insert(sl1, b2->data);
        skiplist_next(sl2, &b2);
    }
    skiplist_remove_all(sl2, NULL);
    return sl1;
}

