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

/* Memory handler for a shared memory divided in slot.
 * This one uses shared memory.
 */
#define CORE_PRIVATE

#include "apr.h"
#include "apr_strings.h"
#include "apr_pools.h"
#include "apr_shm.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include "slotmem.h"
#include "sharedmem_util.h"

/* The description of the slots to reuse the slotmem */
struct sharedslotdesc {
    apr_size_t item_size;
    int item_num;
};

struct ap_slotmem {
    char *name;
    apr_shm_t *shm;
    void *base;
    apr_size_t size;
    int num;
    struct ap_slotmem *next;
};

/* global pool and list of slotmem we are handling */
static struct ap_slotmem *globallistmem = NULL;
static apr_pool_t *globalpool = NULL;

apr_status_t cleanup_slotmem(void *param)
{
    ap_slotmem_t **mem = param;
    apr_status_t rv;

    if (*mem) {
        ap_slotmem_t *next = *mem;
        while (next) {
            rv = apr_shm_destroy(next->shm);
            next = next->next;
        }
    }
    return APR_SUCCESS;
}

static apr_status_t ap_slotmem_do(ap_slotmem_t *mem, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool)
{
    int i;
    void *ptr;

    if (!mem)
        return APR_ENOSHMAVAIL;

    ptr = mem->base;
    for (i = 0; i < mem->num; i++) {
        ptr = ptr + mem->size;
        func((void *)ptr, data, pool);
    }
    return 0;
}
static apr_status_t ap_slotmem_create(ap_slotmem_t **new, const char *name, apr_size_t item_size, int item_num, apr_pool_t *pool)
{
    void *slotmem = NULL;
    void *ptr;
    struct sharedslotdesc desc;
    ap_slotmem_t *res;
    ap_slotmem_t *next = globallistmem;
    char *fname;
    char *dir, *sep;
    char *dname;
    apr_status_t rv;

    fname = ap_server_root_relative(pool, name);
    dir = apr_pstrdup(pool, name);
    sep = strrchr(dir, '/');
    if (sep != NULL) {
        *sep++ = '\0'; 
        dname = ap_server_root_relative(pool, dir);
        apr_dir_make(dname, APR_UREAD|APR_UWRITE|APR_UEXECUTE, pool);
    }

    /* first try to attach to existing slotmem */
    if (next) {
        for (;;) {
            if (strcmp(next->name, fname) == 0) {
                /* we already have it */
                *new = next;
                return APR_SUCCESS;
            }
            if (!next->next)
                break;
            next = next->next;
        }
    }

    /* first try to attach to existing shared memory */
    res = (ap_slotmem_t *) apr_pcalloc(globalpool, sizeof(ap_slotmem_t));
    rv = apr_shm_attach(&res->shm, fname, globalpool);
    if (rv == APR_SUCCESS) {
        /* check size */
        if (apr_shm_size_get(res->shm) != item_size * item_num + sizeof(struct sharedslotdesc)) {
            apr_shm_detach(res->shm);
            res->shm = NULL;
            return APR_EINVAL;
        }
        ptr = apr_shm_baseaddr_get(res->shm);
        memcpy(&desc, ptr, sizeof(desc));
        if ( desc.item_size != item_size || desc.item_num != item_num) {
            apr_shm_detach(res->shm);
            res->shm = NULL;
            return APR_EINVAL;
        }
        ptr = ptr +  sizeof(desc);
    } else  {
        rv = apr_shm_create(&res->shm, item_size * item_num + sizeof(struct sharedslotdesc), fname, globalpool);
        if (rv != APR_SUCCESS)
            return rv;
        ptr = apr_shm_baseaddr_get(res->shm);
        desc.item_size = item_size;
        desc.item_num = item_num;
        memcpy(ptr, &desc, sizeof(desc));
        ptr = ptr +  sizeof(desc);
        memset(ptr, 0, item_size * item_num);
        
    }

    /* For the chained slotmem stuff */
    res->name = apr_pstrdup(globalpool, fname);
    res->base = ptr;
    res->size = item_size;
    res->num = item_num;
    res->next = NULL;
    if (globallistmem==NULL)
        globallistmem = res;
    else
        next->next = res;

    *new = res;
    return APR_SUCCESS;
}
static apr_status_t ap_slotmem_attach(ap_slotmem_t **new, const char *name, apr_size_t *item_size, int *item_num, apr_pool_t *pool)
{
    void *slotmem = NULL;
    void *ptr;
    ap_slotmem_t *res;
    ap_slotmem_t *next = globallistmem;
    struct sharedslotdesc desc;
    char *fname;
    apr_status_t rv;

    fname = ap_server_root_relative(pool, name);

    /* first try to attach to existing slotmem */
    if (next) {
        for (;;) {
            if (strcmp(next->name, fname) == 0) {
                /* we already have it */
                *new = next;
                *item_size = next->size;
                *item_num = next->num;
                return APR_SUCCESS;
            }
            if (!next->next)
                break;
            next = next->next;
        }
    }

    /* first try to attach to existing shared memory */
    res = (ap_slotmem_t *) apr_pcalloc(globalpool, sizeof(ap_slotmem_t));
    rv = apr_shm_attach(&res->shm, fname, globalpool);
    if (rv != APR_SUCCESS)
        return rv;

    /* Read the description of the slotmem */
    ptr = apr_shm_baseaddr_get(res->shm);
    memcpy(&desc, ptr, sizeof(desc));
    ptr = ptr + sizeof(desc);

    /* For the chained slotmem stuff */
    res->name = apr_pstrdup(globalpool, fname);
    res->base = ptr;
    res->size = desc.item_size;
    res->num = desc.item_num;
    res->next = NULL;
    if (globallistmem==NULL)
        globallistmem = res;
    else
        next->next = res;

    *new = res;
    *item_size = desc.item_size;
    *item_num = desc.item_num;
    return APR_SUCCESS;
}
static apr_status_t ap_slotmem_mem(ap_slotmem_t *score, int id, void**mem)
{

    void *ptr;

    if (!score)
        return APR_ENOSHMAVAIL;
    if (id<0 || id>score->num)
        return APR_ENOSHMAVAIL;

    ptr = score->base + score->size * id;
    if (!ptr)
        return APR_ENOSHMAVAIL;
    ptr = score->base + score->size * id;
    *mem = ptr;
    return APR_SUCCESS;
}

static const slotmem_storage_method storage = {
    &ap_slotmem_do,
    &ap_slotmem_create,
    &ap_slotmem_attach,
    &ap_slotmem_mem
};

/* make the storage usuable from outside */
const slotmem_storage_method *sharedmem_getstorage()
{
    return(&storage);
}
/* initialise the global pool */
void sharedmem_initglobalpool(apr_pool_t *p)
{
    globalpool = p;
}
/* Add the pool_clean routine */
void sharedmem_initialize_cleanup(apr_pool_t *p)
{
    apr_pool_cleanup_register(p, &globallistmem, cleanup_slotmem, apr_pool_cleanup_null);
}
