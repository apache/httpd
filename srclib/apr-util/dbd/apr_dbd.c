/* Copyright 2000-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>

#include "apu.h"
#include "apr_pools.h"
#include "apr_dbd.h"
#include "apr_hash.h"
#include "apr_thread_mutex.h"
#include "apr_dso.h"
#include "apr_strings.h"

static apr_hash_t *drivers = NULL;


/* Once the autofoo supports building it for dynamic load, we can use
 * #define APR_DSO_BUILD APR_HAS_DSO
 */

#if APR_DSO_BUILD
#if APR_HAS_THREADS
static apr_thread_mutex_t* mutex = NULL;
#endif
#else
#define DRIVER_LOAD(name,driver,pool) \
    {   \
        extern apr_dbd_driver_t driver; \
        apr_hash_set(drivers,name,APR_HASH_KEY_STRING,&driver); \
        if (driver.init) {     \
            driver.init(pool); \
        }  \
    }
#endif

APU_DECLARE(apr_status_t) apr_dbd_init(apr_pool_t *pool)
{
    apr_status_t ret;
    drivers = apr_hash_make(pool);

#if APR_DSO_BUILD

#if APR_HAS_THREADS
    ret = apr_thread_mutex_create(&mutex, APR_THREAD_MUTEX_DEFAULT, pool);
    apr_pool_cleanup_register(pool, mutex, (void*)apr_thread_mutex_destroy,
                              apr_pool_cleanup_null);
#endif

#else
    ret = APR_SUCCESS;

#if APU_HAVE_MYSQL
    DRIVER_LOAD("mysql", apr_dbd_mysql_driver, pool);
#endif
#if APU_HAVE_PGSQL
    DRIVER_LOAD("pgsql", apr_dbd_pgsql_driver, pool);
#endif
#if APU_HAVE_SQLITE3
    DRIVER_LOAD("sqlite3", apr_dbd_sqlite3_driver, pool);
#endif
#if APU_HAVE_SQLITE2
    DRIVER_LOAD("sqlite2", apr_dbd_sqlite2_driver, pool);
#endif
#if APU_HAVE_SOME_OTHER_BACKEND
    DRIVER_LOAD("firebird", apr_dbd_other_driver, pool);
#endif
#endif
    return ret;
}
APU_DECLARE(apr_status_t) apr_dbd_get_driver(apr_pool_t *pool, const char *name,
                                             apr_dbd_driver_t **driver)
{
#if APR_DSO_BUILD
    char path[80];
    apr_dso_handle_t *dlhandle = NULL;
#endif
    apr_status_t rv;

   *driver = apr_hash_get(drivers, name, APR_HASH_KEY_STRING);
    if (*driver) {
        return APR_SUCCESS;
    }

#if APR_DSO_BUILD

#if APR_HAS_THREADS
    rv = apr_thread_mutex_lock(mutex);
    if (rv != APR_SUCCESS) {
        goto unlock;
    }
    *driver = apr_hash_get(drivers, name, APR_HASH_KEY_STRING);
    if (*driver) {
        goto unlock;
    }
#endif

    sprintf(path, "apr_dbd_%s.so", name);
    rv = apr_dso_load(&dlhandle, path, pool);
    if (rv != APR_SUCCESS) { /* APR_EDSOOPEN */
        goto unlock;
    }
    sprintf(path, "apr_dbd_%s_driver", name);
    rv = apr_dso_sym((void*)driver, dlhandle, path);
    if (rv != APR_SUCCESS) { /* APR_ESYMNOTFOUND */
        apr_dso_unload(dlhandle);
        goto unlock;
    }
    if ((*driver)->init) {
        (*driver)->init(pool);
    }
    apr_hash_set(drivers, name, APR_HASH_KEY_STRING, *driver);

unlock:
#if APR_HAS_THREADS
    apr_thread_mutex_unlock(mutex);
#endif

#else	/* APR_DSO_BUILD - so if it wasn't already loaded, it's NOTIMPL */
    rv = APR_ENOTIMPL;
#endif

    return rv;
}
APU_DECLARE(apr_status_t) apr_dbd_open(apr_dbd_driver_t *driver,
                                       apr_pool_t *pool, const char *params,
                                       apr_dbd_t **handle)
{

    *handle = driver->open(pool, params);
    if (*handle == NULL) {
        return APR_EGENERAL;
    }
    if (apr_dbd_check_conn(driver, pool, *handle) != APR_SUCCESS) {
        apr_dbd_close(driver, *handle);
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}
APU_DECLARE(int) apr_dbd_transaction_start(apr_dbd_driver_t *driver,
                                           apr_pool_t *pool, apr_dbd_t *handle,
                                           apr_dbd_transaction_t **trans)
{
    int ret = driver->start_transaction(pool, handle, trans);
    if (*trans) {
        apr_pool_cleanup_register(pool, *trans, (void*)driver->end_transaction,
                                  apr_pool_cleanup_null);
    }
    return ret;
}
APU_DECLARE(int) apr_dbd_transaction_end(apr_dbd_driver_t *driver,
                                         apr_pool_t *pool,
                                         apr_dbd_transaction_t *trans)
{
    apr_pool_cleanup_kill(pool, trans, (void*)driver->end_transaction);
    return driver->end_transaction(trans);
}
