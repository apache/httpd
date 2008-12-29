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

#include  "slotmem.h"
#include "sharedmem_util.h"

/* 
 * Create the shared mem mutex and
 * make sure the shared memory is cleaned
 */
static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    const char *temp_dir;
    char *template;
    apr_status_t rv;
    void *data;
    apr_file_t *fmutex;
    const char *userdata_key = "sharedmem_post_config";

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                               apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    rv = apr_temp_dir_get(&temp_dir, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "sharedmem: search for temporary directory failed");
        return rv;
    }
    apr_filepath_merge(&template, temp_dir, "sharedmem.lck.XXXXXX",
                       APR_FILEPATH_NATIVE, p);
    rv = apr_file_mktemp(&fmutex, template, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "sharedmem: creation of mutex file in directory %s failed",
                     temp_dir);
        return rv;
    }

    rv = apr_file_name_get(&mutex_fname, fmutex);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "sharedmem: unable to get mutex fname");
        return rv;
    }

    rv = apr_global_mutex_create(&sharedmem_mutex,
                                 mutex_fname, APR_LOCK_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "sharedmem: creation of mutex failed");
        return rv;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
    rv = ap_unixd_set_global_mutex_perms(sharedmem_mutex);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "sharedmem: failed to set mutex permissions");
        return rv;
    }
#endif

    sharedmem_initialize_cleanup(p);
    return OK;
}

static int pre_config(apr_pool_t *p, apr_pool_t *plog,
		          apr_pool_t *ptemp)
{
    apr_pool_t *global_pool;
    apr_status_t rv;

    rv = apr_pool_create(&global_pool, NULL);
    if (rv != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
	    "Fatal error: unable to create global pool for shared slotmem");
	return rv;
    }
    sharedmem_initglobalpool(global_pool);
    return OK;
}

static void child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv;

    rv = apr_global_mutex_child_init(&sharedmem_mutex,
                                     mutex_fname, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Failed to initialise global mutex %s in child process %"
                     APR_PID_T_FMT ".",
                     mutex_fname, getpid());
    }
}

static void ap_sharedmem_register_hook(apr_pool_t *p)
{
    const slotmem_storage_method *storage = sharedmem_getstorage();
    ap_register_provider(p, SLOTMEM_STORAGE, "shared", "0", storage);
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA sharedmem_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    NULL,			/* command apr_table_t */
    ap_sharedmem_register_hook	/* register hooks */
};
