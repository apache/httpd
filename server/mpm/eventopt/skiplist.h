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

#ifndef _SKIPLIST_P_H
#define _SKIPLIST_P_H

#include "apr.h"
#include "apr_portable.h"
#include "ap_config.h"
#include "httpd.h"

/* This is the function type that must be implemented per object type
   that is used in a skiplist for comparisons to maintain order */
typedef int (*SkiplistComparator) (void *, void *);
typedef void (*FreeFunc) (void *);

typedef struct skiplistnode skiplistnode;
typedef struct Skiplist Skiplist;

struct Skiplist {
    SkiplistComparator compare;
    SkiplistComparator comparek;
    int height;
    int preheight;
    int size;
    skiplistnode *top;
    skiplistnode *bottom;
    /* These two are needed for appending */
    skiplistnode *topend;
    skiplistnode *bottomend;
    Skiplist *index;
    apr_pool_t *pool;
};

struct skiplistnode {
    void *data;
    skiplistnode *next;
    skiplistnode *prev;
    skiplistnode *down;
    skiplistnode *up;
    skiplistnode *previndex;
    skiplistnode *nextindex;
    Skiplist *sl;
};

void *skiplist_alloc(Skiplist *sl, size_t size);

void skiplist_free(Skiplist *sl, void *mem);

apr_status_t skiplist_init(Skiplist **sl, apr_pool_t *p);

void skiplist_set_compare(Skiplist *sl, SkiplistComparator,
                          SkiplistComparator);

void skiplist_add_index(Skiplist *sl, SkiplistComparator,
                        SkiplistComparator);

skiplistnode *skiplist_getlist(Skiplist *sl);

void *skiplist_find_compare(Skiplist *sl,
                            void *data,
                            skiplistnode **iter,
                            SkiplistComparator func);

void *skiplist_find(Skiplist *sl, void *data, skiplistnode **iter);

void *skiplist_next(Skiplist *sl, skiplistnode **iter);

void *skiplist_previous(Skiplist *sl, skiplistnode **iter);


skiplistnode *skiplist_insert_compare(Skiplist *sl,
                                       void *data, SkiplistComparator comp);

skiplistnode *skiplist_insert(Skiplist* sl, void *data);

int skiplist_remove_compare(Skiplist *sl, void *data,
                            FreeFunc myfree, SkiplistComparator comp);

int skiplist_remove(Skiplist *sl, void *data, FreeFunc myfree);

#if 0
int skiplisti_remove(Skiplist *sl, skiplistnode *m, FreeFunc myfree);
#endif

void skiplist_remove_all(Skiplist *sl, FreeFunc myfree);

#if 0
int skiplisti_find_compare(Skiplist *sl,
                           void *data,
                           skiplistnode **ret,
                           SkiplistComparator comp);

#endif

void *skiplist_pop(Skiplist *a, FreeFunc myfree);

void *skiplist_peek(Skiplist *a);

/* Below 2 are buggy */
#if 0
Skiplist *skiplist_concat(Skiplist *sl1, Skiplist *sl2);
skiplistnode *skiplist_append(Skiplist *sl, void *data);
#endif

Skiplist *skiplist_merge(Skiplist *sl1, Skiplist *sl2);

#endif
