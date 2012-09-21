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

/* Memory handler for a plain memory divided in slot.
 * This one uses plain memory.
 */

#include  "ap_slotmem.h"

#define AP_SLOTMEM_IS_PREGRAB(t) (t->type & AP_SLOTMEM_TYPE_PREGRAB)

struct ap_slotmem_instance_t {
    char                 *name;       /* per segment name */
    void                 *base;       /* data set start */
    apr_size_t           size;        /* size of each memory slot */
    unsigned int         num;         /* number of mem slots */
    apr_pool_t           *gpool;      /* per segment global pool */
    char                 *inuse;      /* in-use flag table*/
    ap_slotmem_type_t    type;        /* type-specific flags */
    struct ap_slotmem_instance_t  *next;       /* location of next allocated segment */
};


/* global pool and list of slotmem we are handling */
static struct ap_slotmem_instance_t *globallistmem = NULL;
static apr_pool_t *gpool = NULL;

static apr_status_t slotmem_do(ap_slotmem_instance_t *mem, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool)
{
    unsigned int i;
    char *ptr;
    char *inuse;
    apr_status_t retval = APR_SUCCESS;


    if (!mem)
        return APR_ENOSHMAVAIL;

    ptr = (char *)mem->base;
    inuse = mem->inuse;
    for (i = 0; i < mem->num; i++, inuse++) {
        if (!AP_SLOTMEM_IS_PREGRAB(mem) ||
           (AP_SLOTMEM_IS_PREGRAB(mem) && *inuse)) {
            retval = func((void *) ptr, data, pool);
            if (retval != APR_SUCCESS)
                break;
        }
        ptr += mem->size;
    }
    return retval;
}

static apr_status_t slotmem_create(ap_slotmem_instance_t **new, const char *name, apr_size_t item_size, unsigned int item_num, ap_slotmem_type_t type, apr_pool_t *pool)
{
    ap_slotmem_instance_t *res;
    ap_slotmem_instance_t *next = globallistmem;
    apr_size_t basesize = (item_size * item_num);

    const char *fname;

    if (name) {
        if (name[0] == ':')
            fname = name;
        else
            fname = ap_runtime_dir_relative(pool, name);

        /* first try to attach to existing slotmem */
        if (next) {
            for (;;) {
                if (strcmp(next->name, fname) == 0) {
                    /* we already have it */
                    *new = next;
                    return APR_SUCCESS;
                }
                if (!next->next) {
                     break;
                }
                next = next->next;
            }
        }
    }
    else
        fname = "anonymous";

    /* create the memory using the gpool */
    res = (ap_slotmem_instance_t *) apr_pcalloc(gpool, sizeof(ap_slotmem_instance_t));
    res->base = apr_pcalloc(gpool, basesize + (item_num * sizeof(char)));
    if (!res->base)
        return APR_ENOSHMAVAIL;

    /* For the chained slotmem stuff */
    res->name = apr_pstrdup(gpool, fname);
    res->size = item_size;
    res->num = item_num;
    res->next = NULL;
    res->type = type;
    res->inuse = (char *)res->base + basesize;
    if (globallistmem == NULL)
        globallistmem = res;
    else
        next->next = res;

    *new = res;
    return APR_SUCCESS;
}

static apr_status_t slotmem_attach(ap_slotmem_instance_t **new, const char *name, apr_size_t *item_size, unsigned int *item_num, apr_pool_t *pool)
{
    ap_slotmem_instance_t *next = globallistmem;
    const char *fname;

    if (name) {
        if (name[0] == ':')
            fname = name;
        else
            fname = ap_runtime_dir_relative(pool, name);
    }
    else
        return APR_ENOSHMAVAIL;

    /* first try to attach to existing slotmem */
    while (next) {
        if (strcmp(next->name, fname) == 0) {
            /* we already have it */
            *new = next;
            *item_size = next->size;
            *item_num = next->num;
            return APR_SUCCESS;
        }
        next = next->next;
    }

    return APR_ENOSHMAVAIL;
}

static apr_status_t slotmem_dptr(ap_slotmem_instance_t *score, unsigned int id, void **mem)
{

    char *ptr;

    if (!score)
        return APR_ENOSHMAVAIL;
    if (id >= score->num)
        return APR_EINVAL;

    ptr = (char *)score->base + score->size * id;
    if (!ptr)
        return APR_ENOSHMAVAIL;
    *mem = ptr;
    return APR_SUCCESS;
}

static apr_status_t slotmem_get(ap_slotmem_instance_t *slot, unsigned int id, unsigned char *dest, apr_size_t dest_len)
{
    void *ptr;
    char *inuse;
    apr_status_t ret;

    if (!slot) {
        return APR_ENOSHMAVAIL;
    }

    inuse = slot->inuse + id;
    if (id >= slot->num) {
        return APR_EINVAL;
    }
    if (AP_SLOTMEM_IS_PREGRAB(slot) && !*inuse) {
        return APR_NOTFOUND;
    }
    ret = slotmem_dptr(slot, id, &ptr);
    if (ret != APR_SUCCESS) {
        return ret;
    }
    *inuse=1;
    memcpy(dest, ptr, dest_len); /* bounds check? */
    return APR_SUCCESS;
}

static apr_status_t slotmem_put(ap_slotmem_instance_t *slot, unsigned int id, unsigned char *src, apr_size_t src_len)
{
    void *ptr;
    char *inuse;
    apr_status_t ret;

    if (!slot) {
        return APR_ENOSHMAVAIL;
    }

    inuse = slot->inuse + id;
    if (id >= slot->num) {
        return APR_EINVAL;
    }
    if (AP_SLOTMEM_IS_PREGRAB(slot) && !*inuse) {
        return APR_NOTFOUND;
    }
    ret = slotmem_dptr(slot, id, &ptr);
    if (ret != APR_SUCCESS) {
        return ret;
    }
    *inuse=1;
    memcpy(ptr, src, src_len); /* bounds check? */
    return APR_SUCCESS;
}

static unsigned int slotmem_num_slots(ap_slotmem_instance_t *slot)
{
    return slot->num;
}

static unsigned int slotmem_num_free_slots(ap_slotmem_instance_t *slot)
{
    unsigned int i, counter=0;
    char *inuse = slot->inuse;
    for (i = 0; i < slot->num; i++, inuse++) {
        if (!*inuse)
            counter++;
    }
    return counter;
}

static apr_size_t slotmem_slot_size(ap_slotmem_instance_t *slot)
{
    return slot->size;
}

/*
 * XXXX: if !AP_SLOTMEM_IS_PREGRAB, then still worry about
 *       inuse for grab and return?
 */
static apr_status_t slotmem_grab(ap_slotmem_instance_t *slot, unsigned int *id)
{
    unsigned int i;
    char *inuse;

    if (!slot) {
        return APR_ENOSHMAVAIL;
    }

    inuse = slot->inuse;

    for (i = 0; i < slot->num; i++, inuse++) {
        if (!*inuse) {
            break;
        }
    }
    if (i >= slot->num) {
        return APR_EINVAL;
    }
    *inuse = 1;
    *id = i;
    return APR_SUCCESS;
}

static apr_status_t slotmem_fgrab(ap_slotmem_instance_t *slot, unsigned int id)
{
    char *inuse;
    
    if (!slot) {
        return APR_ENOSHMAVAIL;
    }
    
    if (id >= slot->num) {
        return APR_EINVAL;
    }
    inuse = slot->inuse + id;
    *inuse = 1;
    return APR_SUCCESS;
}

static apr_status_t slotmem_release(ap_slotmem_instance_t *slot, unsigned int id)
{
    char *inuse;

    if (!slot) {
        return APR_ENOSHMAVAIL;
    }

    inuse = slot->inuse;

    if (id >= slot->num) {
        return APR_EINVAL;
    }
    if (!inuse[id] ) {
        return APR_NOTFOUND;
    }
    inuse[id] = 0;
    return APR_SUCCESS;
}

static const ap_slotmem_provider_t storage = {
    "plainmem",
    &slotmem_do,
    &slotmem_create,
    &slotmem_attach,
    &slotmem_dptr,
    &slotmem_get,
    &slotmem_put,
    &slotmem_num_slots,
    &slotmem_num_free_slots,
    &slotmem_slot_size,
    &slotmem_grab,
    &slotmem_release,
    &slotmem_fgrab
};

static int pre_config(apr_pool_t *p, apr_pool_t *plog,
                      apr_pool_t *ptemp)
{
    gpool = p;
    return OK;
}

static void ap_slotmem_plain_register_hook(apr_pool_t *p)
{
    /* XXX: static const char * const prePos[] = { "mod_slotmem.c", NULL }; */
    ap_register_provider(p, AP_SLOTMEM_PROVIDER_GROUP, "plain",
                         AP_SLOTMEM_PROVIDER_VERSION, &storage);
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(slotmem_plain) = {
    STANDARD20_MODULE_STUFF,
    NULL,                        /* create per-directory config structure */
    NULL,                        /* merge per-directory config structures */
    NULL,                        /* create per-server config structure */
    NULL,                        /* merge per-server config structures */
    NULL,                        /* command apr_table_t */
    ap_slotmem_plain_register_hook    /* register hooks */
};

