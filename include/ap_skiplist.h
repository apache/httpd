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

#ifndef _AP_SKIPLIST_P_H
#define _AP_SKIPLIST_P_H

#include "apr.h"
#include "apr_portable.h"
#include "ap_config.h"
#include "httpd.h"

/* This is the function type that must be implemented per object type
   that is used in a skiplist for comparisons to maintain order */
typedef int (*ap_skiplist_compare) (void *, void *);
typedef void (*ap_skiplist_freefunc) (void *);

typedef struct ap_skiplistnode ap_skiplistnode;
typedef struct ap_skiplist ap_skiplist;

struct ap_skiplist {
    ap_skiplist_compare compare;
    ap_skiplist_compare comparek;
    int height;
    int preheight;
    int size;
    ap_skiplistnode *top;
    ap_skiplistnode *bottom;
    /* These two are needed for appending */
    ap_skiplistnode *topend;
    ap_skiplistnode *bottomend;
    ap_skiplist *index;
    apr_pool_t *pool;
};

struct ap_skiplistnode {
    void *data;
    ap_skiplistnode *next;
    ap_skiplistnode *prev;
    ap_skiplistnode *down;
    ap_skiplistnode *up;
    ap_skiplistnode *previndex;
    ap_skiplistnode *nextindex;
    ap_skiplist *sl;
};

AP_DECLARE(void *) ap_skiplist_alloc(ap_skiplist *sl, size_t size);

AP_DECLARE(void) ap_skiplist_free(ap_skiplist *sl, void *mem);

AP_DECLARE(apr_status_t) ap_skiplist_init(ap_skiplist **sl, apr_pool_t *p);

AP_DECLARE(void) ap_skiplist_set_compare(ap_skiplist *sl, ap_skiplist_compare,
                             ap_skiplist_compare);

AP_DECLARE(void) ap_skiplist_add_index(ap_skiplist *sl, ap_skiplist_compare,
                        ap_skiplist_compare);

AP_DECLARE(ap_skiplistnode *) ap_skiplist_getlist(ap_skiplist *sl);

AP_DECLARE(void *) ap_skiplist_find_compare(ap_skiplist *sl,
                               void *data,
                               ap_skiplistnode **iter,
                               ap_skiplist_compare func);

AP_DECLARE(void *) ap_skiplist_find(ap_skiplist *sl, void *data, ap_skiplistnode **iter);

AP_DECLARE(void *) ap_skiplist_next(ap_skiplist *sl, ap_skiplistnode **iter);

AP_DECLARE(void *) ap_skiplist_previous(ap_skiplist *sl, ap_skiplistnode **iter);


AP_DECLARE(ap_skiplistnode *) ap_skiplist_insert_compare(ap_skiplist *sl,
                                          void *data, ap_skiplist_compare comp);

AP_DECLARE(ap_skiplistnode *) ap_skiplist_insert(ap_skiplist* sl, void *data);

AP_DECLARE(int) ap_skiplist_remove_compare(ap_skiplist *sl, void *data,
                               ap_skiplist_freefunc myfree, ap_skiplist_compare comp);

AP_DECLARE(int) ap_skiplist_remove(ap_skiplist *sl, void *data, ap_skiplist_freefunc myfree);

AP_DECLARE(void) ap_skiplist_remove_all(ap_skiplist *sl, ap_skiplist_freefunc myfree);

AP_DECLARE(void) ap_skiplist_destroy(ap_skiplist *sl, ap_skiplist_freefunc myfree);

AP_DECLARE(void *) ap_skiplist_pop(ap_skiplist *a, ap_skiplist_freefunc myfree);

AP_DECLARE(void *) ap_skiplist_peek(ap_skiplist *a);

AP_DECLARE(ap_skiplist *) ap_skiplist_merge(ap_skiplist *sl1, ap_skiplist *sl2);

#endif
