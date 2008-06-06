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

#include "apr_general.h"

#include "mod_cache.h"
#include "cache_hash.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STRING_H
#include <string.h>
#endif


/*
 * The internal form of a hash table.
 *
 * The table is an array indexed by the hash of the key; collisions
 * are resolved by hanging a linked list of hash entries off each
 * element of the array. Although this is a really simple design it
 * isn't too bad given that pools have a low allocation overhead.
 */

typedef struct cache_hash_entry_t cache_hash_entry_t;

struct cache_hash_entry_t {
    cache_hash_entry_t   *next;
    unsigned int         hash;
    const void           *key;
    apr_ssize_t          klen;
    const void           *val;
};

/*
 * Data structure for iterating through a hash table.
 *
 * We keep a pointer to the next hash entry here to allow the current
 * hash entry to be freed or otherwise mangled between calls to
 * cache_hash_next().
 */
struct cache_hash_index_t {
    cache_hash_t         *ht;
    cache_hash_entry_t   *this, *next;
    int                  index;
};

/*
 * The size of the array is always a power of two. We use the maximum
 * index rather than the size so that we can use bitwise-AND for
 * modular arithmetic.
 * The count of hash entries may be greater depending on the chosen
 * collision rate.
 */
struct cache_hash_t {
    cache_hash_entry_t   **array;
    cache_hash_index_t     iterator;  /* For cache_hash_first(NULL, ...) */
    int                  count, max;
};

/*
 * Hash creation functions.
 */
static cache_hash_entry_t **alloc_array(cache_hash_t *ht, int max)
{
   return calloc(1, sizeof(*ht->array) * (max + 1));
}

cache_hash_t* cache_hash_make(apr_size_t size)
{
    cache_hash_t *ht;
    ht = malloc(sizeof(cache_hash_t));
    if (!ht) {
        return NULL;
    }
    ht->count = 0;
    ht->max = size;
    ht->array = alloc_array(ht, ht->max);
    if (!ht->array) {
        free(ht);
        return NULL;
    }
    return ht;
}

void cache_hash_free(cache_hash_t *ht)
{
    if (ht) {
        if (ht->array) {
            free (ht->array);
        }
        free (ht);
    }
}
/*
 * Hash iteration functions.
 */

cache_hash_index_t* cache_hash_next(cache_hash_index_t *hi)
{
    hi->this = hi->next;
    while (!hi->this) {
        if (hi->index > hi->ht->max)
            return NULL;
        hi->this = hi->ht->array[hi->index++];
    }
    hi->next = hi->this->next;
    return hi;
}

cache_hash_index_t* cache_hash_first(cache_hash_t *ht)
{
    cache_hash_index_t *hi;

    hi = &ht->iterator;
    hi->ht = ht;
    hi->index = 0;
    hi->this = NULL;
    hi->next = NULL;
    return cache_hash_next(hi);
}

void cache_hash_this(cache_hash_index_t *hi,
                                  const void **key,
                                  apr_ssize_t *klen,
                                  void **val)
{
    if (key)  *key  = hi->this->key;
    if (klen) *klen = hi->this->klen;
    if (val)  *val  = (void *)hi->this->val;
}


/*
 * This is where we keep the details of the hash function and control
 * the maximum collision rate.
 *
 * If val is non-NULL it creates and initializes a new hash entry if
 * there isn't already one there; it returns an updatable pointer so
 * that hash entries can be removed.
 */

static cache_hash_entry_t **find_entry(cache_hash_t *ht,
                                       const void *key,
                                       apr_ssize_t klen,
                                       const void *val)
{
    cache_hash_entry_t **hep, *he;
    const unsigned char *p;
    unsigned int hash;
    apr_ssize_t i;

    /*
     * This is the popular `times 33' hash algorithm which is used by
     * perl and also appears in Berkeley DB. This is one of the best
     * known hash functions for strings because it is both computed
     * very fast and distributes very well.
     *
     * The originator may be Dan Bernstein but the code in Berkeley DB
     * cites Chris Torek as the source. The best citation I have found
     * is "Chris Torek, Hash function for text in C, Usenet message
     * <27038@mimsy.umd.edu> in comp.lang.c , October, 1990." in Rich
     * Salz's USENIX 1992 paper about INN which can be found at
     * <http://citeseer.nj.nec.com/salz92internetnews.html>.
     *
     * The magic of number 33, i.e. why it works better than many other
     * constants, prime or not, has never been adequately explained by
     * anyone. So I try an explanation: if one experimentally tests all
     * multipliers between 1 and 256 (as I did while writing a low-level
     * data structure library some time ago) one detects that even
     * numbers are not useable at all. The remaining 128 odd numbers
     * (except for the number 1) work more or less all equally well.
     * They all distribute in an acceptable way and this way fill a hash
     * table with an average percent of approx. 86%.
     *
     * If one compares the chi^2 values of the variants (see
     * Bob Jenkins ``Hashing Frequently Asked Questions'' at
     * http://burtleburtle.net/bob/hash/hashfaq.html for a description
     * of chi^2), the number 33 not even has the best value. But the
     * number 33 and a few other equally good numbers like 17, 31, 63,
     * 127 and 129 have nevertheless a great advantage to the remaining
     * numbers in the large set of possible multipliers: their multiply
     * operation can be replaced by a faster operation based on just one
     * shift plus either a single addition or subtraction operation. And
     * because a hash function has to both distribute good _and_ has to
     * be very fast to compute, those few numbers should be preferred.
     *
     *                  -- Ralf S. Engelschall <rse@engelschall.com>
     */
    hash = 0;
    if (klen == CACHE_HASH_KEY_STRING) {
        for (p = key; *p; p++) {
            hash = hash * 33 + *p;
        }
        klen = p - (const unsigned char *)key;
    }
    else {
        for (p = key, i = klen; i; i--, p++) {
            hash = hash * 33 + *p;
        }
    }

    /* scan linked list */
    for (hep = &ht->array[hash % ht->max], he = *hep;
         he;
         hep = &he->next, he = *hep) {
        if (he->hash == hash &&
            he->klen == klen &&
            memcmp(he->key, key, klen) == 0)
            break;
    }
    if (he || !val)
        return hep;
    /* add a new entry for non-NULL values */
    he = malloc(sizeof(*he));
    if (!he) {
        return NULL;
    }
    he->next = NULL;
    he->hash = hash;
    he->key  = key;
    he->klen = klen;
    he->val  = val;
    *hep = he;
    ht->count++;
    return hep;
}

void* cache_hash_get(cache_hash_t *ht,
                                   const void *key,
                                   apr_ssize_t klen)
{
    cache_hash_entry_t *he;
    he = *find_entry(ht, key, klen, NULL);
    if (he)
        return (void *)he->val;
    else
        return NULL;
}

void* cache_hash_set(cache_hash_t *ht,
                                     const void *key,
                                     apr_ssize_t klen,
                                     const void *val)
{
    cache_hash_entry_t **hep, *tmp;
    const void *tval;
    hep = find_entry(ht, key, klen, val);
    /* If hep == NULL, then the malloc() in find_entry failed */
    if (hep && *hep) {
        if (!val) {
            /* delete entry */
            tval = (*hep)->val;
            tmp = *hep;
            *hep = (*hep)->next;
            free(tmp);
            --ht->count;
        }
        else {
            /* replace entry */
            tval = (*hep)->val;
            (*hep)->val = val;
        }
        /* Return the object just removed from the cache to let the
         * caller clean it up. Cast the constness away upon return.
         */
        return (void *) tval;
    }
    /* else key not present and val==NULL */
    return NULL;
}

int cache_hash_count(cache_hash_t *ht)
{
    return ht->count;
}
