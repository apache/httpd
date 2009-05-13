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

#ifndef SLOTMEM_H
#define SLOTMEM_H

/* Memory handler for a shared memory divided in slot.
 */
/**
 * @file  slotmem.h
 * @brief Memory Slot Extension Storage Module for Apache
 *
 * @defgroup MEM mem
 * @ingroup  APACHE_MODS
 * @{
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "ap_provider.h"

#include "apr.h"
#include "apr_strings.h"
#include "apr_pools.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "apr_file_io.h"

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#if APR_HAVE_UNISTD_H
#include <unistd.h>         /* for getpid() */
#endif

#define AP_SLOTMEM_STORAGE "slotmem"

typedef enum {
    SLOTMEM_PERSIST      /* create a persistent slotmem */
} apslotmem_type;

typedef struct ap_slotmem_t ap_slotmem_t;

/**
 * callback function used for slotmem.
 * @param mem is the memory associated with a worker.
 * @param data is what is passed to slotmem.
 * @param pool is pool used
 * @return APR_SUCCESS if all went well
 */
typedef apr_status_t ap_slotmem_callback_fn_t(void* mem, void *data, apr_pool_t *pool);

struct ap_slotmem_storage_method {
    /*
     * Name of the provider method
     */
    const char *name;
    /**
     * call the callback on all worker slots
     * @param s ap_slotmem_t to use.
     * @param funct callback function to call for each element.
     * @param data parameter for the callback function.
     * @param pool is pool used
     * @return APR_SUCCESS if all went well
     */
    apr_status_t (* slotmem_do)(ap_slotmem_t *s, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool);
    /**
     * create a new slotmem with each item size is item_size.
     * This would create shared memory, basically.
     * @param name is a key used for debugging and in mod_status output or allow another process to share this space.
     * @param item_size size of each item
     * @param item_num number of item to create.
     * @param type type of slotmem.
     * @param pool is pool used
     * @return APR_SUCCESS if all went well
     */
    apr_status_t (* slotmem_create)(ap_slotmem_t **new, const char *name, apr_size_t item_size, unsigned int item_num, apslotmem_type type, apr_pool_t *pool);
    /**
     * attach to an existing slotmem.
     * This would attach to  shared memory, basically.
     * @param name is a key used for debugging and in mod_status output or allow another process to share this space.
     * @param item_size size of each item
     * @param item_num max number of item.
     * @param pool is pool to memory allocate.
     * @return APR_SUCCESS if all went well
     */
    apr_status_t (* slotmem_attach)(ap_slotmem_t **new, const char *name, apr_size_t *item_size, unsigned int *item_num, apr_pool_t *pool);
    /**
     * retrieve the memory associated with this worker slot.
     * @param s ap_slotmem_t to use.
     * @param item_id item to return for 0 to item_num
     * @param dest address to store the data
     * @param dest_len length of dataset to retrieve
     * @return APR_SUCCESS if all went well
     */
    apr_status_t (* slotmem_get)(ap_slotmem_t *s, unsigned int item_id, unsigned char *dest, apr_size_t dest_len);
    /**
     * store the memory associated with this worker slot.
     * @param s ap_slotmem_t to use.
     * @param item_id item to return for 0 to item_num
     * @param src address of the data to store in the slot
     * @param src_len length of dataset to store in the slot
     * @return APR_SUCCESS if all went well
     */
    apr_status_t (* slotmem_put)(ap_slotmem_t *slot, unsigned int item_id, unsigned char *src, apr_size_t src_len);
    /**
     * return number of slots allocated for this entry.
     * @param s ap_slotmem_t to use.
     * @return number of slots
     */
    unsigned int (* slotmem_num_slots)(ap_slotmem_t *s);
    /**
     * return slot size allocated for this entry.
     * @param s ap_slotmem_t to use.
     * @return size of slot
     */
    apr_size_t (* slotmem_slot_size)(ap_slotmem_t *s);
};

typedef struct ap_slotmem_storage_method ap_slotmem_storage_method;

/*
 * mod_slotmem externals exposed to the outside world.
 *  Thus the provider nature of mod_slotmem is somewhat insulated
 *  from the end user but can still be used directed if need
 *  be. The rationale is to make it easier for additional
 *  memory providers to be provided and having a single
 *  simple interface for all
 */
/**
 * obtain the array of provider methods desired
 * @param pool is the pool to use
 * @return pointer to array of provider names available
 */
AP_DECLARE(apr_array_header_t *) ap_slotmem_methods(apr_pool_t *pool);
/**
 * obtain the provider method desired
 * @param provider is name of the provider to use
 * @return pointer to provider or NULL
 */
AP_DECLARE(ap_slotmem_storage_method *) ap_slotmem_method(const char *provider);
/**
 * call the callback on all worker slots
 * @param sm ap_slotmem_storage_method provider obtained
 * @param s ap_slotmem_t to use.
 * @param funct callback function to call for each element.
 * @param data parameter for the callback function.
 * @param pool is pool used
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_do(ap_slotmem_storage_method *sm, ap_slotmem_t *s, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool);

/**
 * create a new slotmem with each item size is item_size.
 * This would create shared memory, basically.
 * @param sm ap_slotmem_storage_method provider obtained
 * @param name is a key used for debugging and in mod_status output or allow another process to share this space.
 * @param item_size size of each item
 * @param item_num number of item to create.
 * @param type (persistent/allocatable/etc)
 * @param pool is pool used
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_create(ap_slotmem_storage_method *sm, ap_slotmem_t **new, const char *name, apr_size_t item_size, unsigned int item_num, apslotmem_type type, apr_pool_t *pool);

/**
 * attach to an existing slotmem.
 * This would attach to  shared memory, basically.
 * @param sm ap_slotmem_storage_method provider obtained
 * @param name is a key used for debugging and in mod_status output or allow another process to share this space.
 * @param item_size size of each item
 * @param item_num max number of item.
 * @param pool is pool to memory allocate.
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_attach(ap_slotmem_storage_method *sm, ap_slotmem_t **new, const char *name, apr_size_t *item_size, unsigned int *item_num, apr_pool_t *pool);
/**
 * retrieve the memory associated with this worker slot.
 * @param sm ap_slotmem_storage_method provider obtained
 * @param s ap_slotmem_t to use.
 * @param item_id item to return for 0 to item_num
 * @param dest address to store the data
 * @param dest_len length of dataset to retrieve
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_get(ap_slotmem_storage_method *sm, ap_slotmem_t *s, unsigned int item_id, unsigned char *dest, apr_size_t dest_len);
/**
 * store the memory associated with this worker slot.
 * @param sm ap_slotmem_storage_method provider obtained
 * @param s ap_slotmem_t to use.
 * @param item_id item to return for 0 to item_num
 * @param src address of the data to store in the slot
 * @param src_len length of dataset to store in the slot
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_put(ap_slotmem_storage_method *sm, ap_slotmem_t *s, unsigned int item_id, unsigned char *src, apr_size_t src_len);
/**
 * return number of slots allocated for this entry.
 * @param sm ap_slotmem_storage_method provider obtained
 * @param s ap_slotmem_t to use.
 * @return number of slots
 */
AP_DECLARE(unsigned int) ap_slotmem_num_slots(ap_slotmem_storage_method *sm, ap_slotmem_t *s);
/**
 * return slot size allocated for this entry.
 * @param sm ap_slotmem_storage_method provider obtained
 * @param s ap_slotmem_t to use.
 * @return size of slot
 */
AP_DECLARE(apr_size_t) ap_slotmem_slot_size(ap_slotmem_storage_method *sm, ap_slotmem_t *s);

#endif /*SLOTMEM_H*/
