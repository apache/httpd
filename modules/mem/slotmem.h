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


#define SLOTMEM_STORAGE "slotmem"

typedef struct ap_slotmem ap_slotmem_t; 

/**
 * callback function used for slotmem.
 * @param mem is the memory associated with a worker.
 * @param data is what is passed to slotmem.
 * @param pool is pool used to create scoreboard
 * @return APR_SUCCESS if all went well
 */
typedef apr_status_t ap_slotmem_callback_fn_t(void* mem, void *data, apr_pool_t *pool);

struct slotmem_storage_method {
/**
 * call the callback on all worker slots
 * @param s ap_slotmem_t to use.
 * @param funct callback function to call for each element.
 * @param data parameter for the callback function.
 * @param pool is pool used to create scoreboard
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) (* slotmem)(ap_slotmem_t *s, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool);

/**
 * create a new slotmem with each item size is item_size.
 * This would create shared memory, basically.
 * @param pointer to store the address of the scoreboard.
 * @param name is a key used for debugging and in mod_status output or allow another process to share this space.
 * @param item_size size of each idem
 * @param item_num number of idem to create.
 * @param pool is pool used to create scoreboard
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) (* ap_slotmem_create)(ap_slotmem_t **new, const char *name, apr_size_t item_size, int item_num, apr_pool_t *pool);

/**
 * attach to an existing slotmem.
 * This would attach to  shared memory, basically.
 * @param pointer to store the address of the scoreboard.
 * @param name is a key used for debugging and in mod_status output or allow another process to share this space.
 * @param item_size size of each idem
 * @param item_num max number of idem.
 * @param pool is pool to memory allocate.
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) (* ap_slotmem_attach)(ap_slotmem_t **new, const char *name, apr_size_t *item_size, int *item_num, apr_pool_t *pool);
/**
 * get the memory associated with this worker slot.
 * @param s ap_slotmem_t to use.
 * @param item_id item to return for 0 to item_num
 * @param mem address to store the pointer to the slot
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) (* ap_slotmem_mem)(ap_slotmem_t *s, int item_id, void**mem); 
};

typedef struct slotmem_storage_method slotmem_storage_method;
