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

#include  "ap_slotmem.h"

#include "httpd.h"
#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#if APR_HAVE_UNISTD_H
#include <unistd.h>         /* for getpid() */
#endif

#if HAVE_SYS_SEM_H
#include <sys/shm.h>
#if !defined(SHM_R)
#define SHM_R 0400
#endif
#if !defined(SHM_W)
#define SHM_W 0200
#endif
#endif

struct ap_slotmem_t {
    char                 *name;       /* per segment name */
    void                 *shm;        /* ptr to memory segment (apr_shm_t *) */
    void                 *base;       /* data set start */
    apr_size_t           size;        /* size of each memory slot */
    unsigned int         num;         /* number of mem slots */
    apr_pool_t           *gpool;      /* per segment global pool */
    apr_global_mutex_t   *smutex;     /* mutex */
    struct ap_slotmem_t  *next;       /* location of next allocated segment */
    char                 *inuse;      /* is-use flag table*/
};


/* The description of the slots to reuse the slotmem */
struct sharedslotdesc {
    apr_size_t item_size;
    unsigned int item_num;
};

/*
 * Memory layout:
 *     sharedslotdesc | slots | isuse array
 */

/* global pool and list of slotmem we are handling */
static struct ap_slotmem_t *globallistmem = NULL;
static apr_pool_t *gpool = NULL;
static apr_global_mutex_t *smutex = NULL;
static const char *mutex_fname = NULL;

#define SLOTMEM_LOCK(s) do {      \
    if (s)                        \
        apr_global_mutex_lock(s); \
} while (0)

#define SLOTMEM_UNLOCK(s) do {      \
    if (s)                          \
        apr_global_mutex_unlock(s); \
} while (0)

/* apr:shmem/unix/shm.c */
static apr_status_t unixd_set_shm_perms(const char *fname)
{
#ifdef AP_NEED_SET_MUTEX_PERMS
#if APR_USE_SHMEM_SHMGET || APR_USE_SHMEM_SHMGET_ANON
    struct shmid_ds shmbuf;
    key_t shmkey;
    int shmid;

    shmkey = ftok(fname, 1);
    if (shmkey == (key_t)-1) {
        return errno;
    }
    if ((shmid = shmget(shmkey, 0, SHM_R | SHM_W)) == -1) {
        return errno;
    }
#if MODULE_MAGIC_NUMBER_MAJOR > 20081212
    shmbuf.shm_perm.uid  = ap_unixd_config.user_id;
    shmbuf.shm_perm.gid  = ap_unixd_config.group_id;
#else
    shmbuf.shm_perm.uid  = unixd_config.user_id;
    shmbuf.shm_perm.gid  = unixd_config.group_id;
#endif
    shmbuf.shm_perm.mode = 0600;
    if (shmctl(shmid, IPC_SET, &shmbuf) == -1) {
        return errno;
    }
    return APR_SUCCESS;
#else
    return APR_ENOTIMPL;
#endif
#else
    return APR_ENOTIMPL;
#endif
}

/*
 * Persiste the slotmem in a file
 * slotmem name and file name.
 * anonymous : $server_root/logs/anonymous.slotmem
 * :module.c : $server_root/logs/module.c.slotmem
 * abs_name  : $abs_name.slotmem
 *
 */
static const char *store_filename(apr_pool_t *pool, const char *slotmemname)
{
    const char *storename;
    const char *fname;
    if (strcmp(slotmemname, "anonymous") == 0)
        fname = ap_server_root_relative(pool, "logs/anonymous");
    else if (slotmemname[0] == ':') {
        const char *tmpname;
        tmpname = apr_pstrcat(pool, "logs/", &slotmemname[1], NULL);
        fname = ap_server_root_relative(pool, tmpname);
    }
    else {
        fname = slotmemname;
    }
    storename = apr_pstrcat(pool, fname, ".slotmem", NULL);
    return storename;
}

static void store_slotmem(ap_slotmem_t *slotmem)
{
    apr_file_t *fp;
    apr_status_t rv;
    apr_size_t nbytes;
    const char *storename;

    storename = store_filename(slotmem->gpool, slotmem->name);

    rv = apr_file_open(&fp, storename, APR_CREATE | APR_READ | APR_WRITE, APR_OS_DEFAULT, slotmem->gpool);
    if (APR_STATUS_IS_EEXIST(rv)) {
        apr_file_remove(storename, slotmem->gpool);
        rv = apr_file_open(&fp, storename, APR_CREATE | APR_READ | APR_WRITE, APR_OS_DEFAULT, slotmem->gpool);
    }
    if (rv != APR_SUCCESS) {
        return;
    }
    nbytes = (slotmem->size * slotmem->num) + (slotmem->num * sizeof(char));
    apr_file_write(fp, slotmem->base, &nbytes);
    apr_file_close(fp);
}

static void restore_slotmem(void *ptr, const char *name, apr_size_t size, apr_pool_t *pool)
{
    const char *storename;
    apr_file_t *fp;
    apr_size_t nbytes = size;
    apr_status_t rv;

    storename = store_filename(pool, name);
    rv = apr_file_open(&fp, storename, APR_READ | APR_WRITE, APR_OS_DEFAULT, pool);
    if (rv == APR_SUCCESS) {
        apr_finfo_t fi;
        if (apr_file_info_get(&fi, APR_FINFO_SIZE, fp) == APR_SUCCESS) {
            if (fi.size == nbytes) {
                apr_file_read(fp, ptr, &nbytes);
            }
            else {
                apr_file_close(fp);
                apr_file_remove(storename, pool);
                return;
            }
        }
        apr_file_close(fp);
    }
}

static apr_status_t cleanup_slotmem(void *param)
{
    ap_slotmem_t **mem = param;
    apr_status_t rv;
    apr_pool_t *pool = NULL;

    if (*mem) {
        ap_slotmem_t *next = *mem;
        pool = next->gpool;
        while (next) {
            store_slotmem(next);
            rv = apr_shm_destroy((apr_shm_t *)next->shm);
            next = next->next;
        }
        apr_pool_destroy(pool);
    }
    return APR_SUCCESS;
}

static apr_status_t slotmem_do(ap_slotmem_t *mem, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool)
{
    unsigned int i;
    void *ptr;
    char *inuse;

    if (!mem) {
        return APR_ENOSHMAVAIL;
    }

    ptr = mem->base;
    inuse = ptr + (mem->size * mem->num);
    SLOTMEM_LOCK(mem->smutex);
    for (i = 0; i < mem->num; i++, inuse++) {
        if (*inuse) {
            func((void *) ptr, data, pool);
        }
        ptr += mem->size;
    }
    SLOTMEM_UNLOCK(mem->smutex);
    return APR_SUCCESS;
}

static apr_status_t slotmem_create(ap_slotmem_t **new, const char *name, apr_size_t item_size, unsigned int item_num, apslotmem_type type, apr_pool_t *pool)
{
/*    void *slotmem = NULL; */
    void *ptr;
    struct sharedslotdesc desc;
    ap_slotmem_t *res;
    ap_slotmem_t *next = globallistmem;
    const char *fname;
    apr_shm_t *shm;
    apr_size_t basesize = (item_size * item_num);
    apr_size_t size = sizeof(struct sharedslotdesc) + (item_num * sizeof(char)) + basesize;
    apr_status_t rv;

    if (gpool == NULL)
        return APR_ENOSHMAVAIL;
    if (name) {
        if (name[0] == ':') {
            fname = name;
        }
        else {
            fname = ap_server_root_relative(pool, name);
        }

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
    else {
        fname = "anonymous";
    }

    /* first try to attach to existing shared memory */
    if (name && name[0] != ':') {
        rv = apr_shm_attach(&shm, fname, gpool);
    }
    else {
        rv = APR_EINVAL;
    }
    if (rv == APR_SUCCESS) {
        /* check size */
        if (apr_shm_size_get(shm) != size) {
            apr_shm_detach(shm);
            return APR_EINVAL;
        }
        ptr = apr_shm_baseaddr_get(shm);
        memcpy(&desc, ptr, sizeof(desc));
        if (desc.item_size != item_size || desc.item_num != item_num) {
            apr_shm_detach(shm);
            return APR_EINVAL;
        }
        ptr = ptr + sizeof(desc);
    }
    else {
        apr_size_t dsize = size - sizeof(struct sharedslotdesc);
        SLOTMEM_LOCK(smutex);
        if (name && name[0] != ':') {
            apr_shm_remove(fname, gpool);
            rv = apr_shm_create(&shm, size, fname, gpool);
        }
        else {
            rv = apr_shm_create(&shm, size, NULL, gpool);
        }
        SLOTMEM_UNLOCK(smutex);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        if (name && name[0] != ':') {
            /* Set permissions to shared memory
             * so it can be attached by child process
             * having different user credentials
             *
             * See apr:shmem/unix/shm.c
             */
            unixd_set_shm_perms(fname);
        }
        ptr = apr_shm_baseaddr_get(shm);
        desc.item_size = item_size;
        desc.item_num = item_num;
        memcpy(ptr, &desc, sizeof(desc));
        ptr = ptr + sizeof(desc);
        memset(ptr, 0, dsize);
        if (type == SLOTMEM_PERSIST)
            restore_slotmem(ptr, fname, dsize, pool);
    }

    /* For the chained slotmem stuff */
    res = (ap_slotmem_t *) apr_pcalloc(gpool, sizeof(ap_slotmem_t));
    res->name = apr_pstrdup(gpool, fname);
    res->shm = shm;
    res->base = ptr;
    res->size = item_size;
    res->num = item_num;
    res->gpool = gpool;
    res->smutex = smutex;
    res->next = NULL;
    res->inuse = ptr + basesize;
    if (globallistmem == NULL) {
        globallistmem = res;
    }
    else {
        next->next = res;
    }

    *new = res;
    return APR_SUCCESS;
}

static apr_status_t slotmem_attach(ap_slotmem_t **new, const char *name, apr_size_t *item_size, unsigned int *item_num, apr_pool_t *pool)
{
/*    void *slotmem = NULL; */
    void *ptr;
    ap_slotmem_t *res;
    ap_slotmem_t *next = globallistmem;
    struct sharedslotdesc desc;
    const char *fname;
    apr_shm_t *shm;
    apr_status_t rv;

    if (gpool == NULL) {
        return APR_ENOSHMAVAIL;
    }
    if (name) {
        if (name[0] == ':') {
            fname = name;
        }
        else {
            fname = ap_server_root_relative(pool, name);
        }
    }
    else {
        return APR_ENOSHMAVAIL;
    }

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
    rv = apr_shm_attach(&shm, fname, gpool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    /* Read the description of the slotmem */
    ptr = apr_shm_baseaddr_get(shm);
    memcpy(&desc, ptr, sizeof(desc));
    ptr = ptr + sizeof(desc);

    /* For the chained slotmem stuff */
    res = (ap_slotmem_t *) apr_pcalloc(gpool, sizeof(ap_slotmem_t));
    res->name = apr_pstrdup(gpool, fname);
    res->shm = shm;
    res->base = ptr;
    res->size = desc.item_size;
    res->num = desc.item_num;
    res->gpool = gpool;
    res->smutex = smutex;
    res->inuse = ptr + (desc.item_size * desc.item_num);
    res->next = NULL;
    if (globallistmem == NULL) {
        globallistmem = res;
    }
    else {
        next->next = res;
    }

    *new = res;
    *item_size = desc.item_size;
    *item_num = desc.item_num;
    return APR_SUCCESS;
}

static apr_status_t slotmem_mem(ap_slotmem_t *slot, unsigned int id, void **mem)
{

    void *ptr;

    if (!slot) {
        return APR_ENOSHMAVAIL;
    }
    if (id < 0 || id > slot->num) {
        return APR_ENOSHMAVAIL;
    }

    ptr = slot->base + slot->size * id;
    if (!ptr) {
        return APR_ENOSHMAVAIL;
    }
    *mem = ptr;
    return APR_SUCCESS;
}

static apr_status_t slotmem_get(ap_slotmem_t *slot, unsigned int id, unsigned char *dest, apr_size_t dest_len)
{

    void *ptr;
    apr_status_t ret;

    ret = slotmem_mem(slot, id, &ptr);
    if (ret != APR_SUCCESS) {
        return ret;
    }
    memcpy(dest, ptr, dest_len); /* bounds check? */
    return APR_SUCCESS;
}

static apr_status_t slotmem_put(ap_slotmem_t *slot, unsigned int id, unsigned char *src, apr_size_t src_len)
{

    void *ptr;
    char *inuse;
    apr_status_t ret;

    ret = slotmem_mem(slot, id, &ptr);
    if (ret != APR_SUCCESS) {
        return ret;
    }
    memcpy(ptr, src, src_len); /* bounds check? */
    /* We know the id fit it */
    inuse = (slot->base + (slot->size * slot->num));
    inuse[id] = 1;
    return APR_SUCCESS;
}

static unsigned int slotmem_num_slots(ap_slotmem_t *slot)
{
    return slot->num;
}

static apr_size_t slotmem_slot_size(ap_slotmem_t *slot)
{
    return slot->size;
}

static const ap_slotmem_storage_method storage = {
    "sharedmem",
    &slotmem_do,
    &slotmem_create,
    &slotmem_attach,
    &slotmem_mem,
    &slotmem_get,
    &slotmem_put,
    &slotmem_num_slots,
    &slotmem_slot_size
};

/* make the storage usuable from outside */
static const ap_slotmem_storage_method *sharedmem_getstorage(void)
{
    return (&storage);
}

/* initialise the global pool */
static void sharedmem_initgpool(apr_pool_t *p)
{
    gpool = p;
}

/* Add the pool_clean routine */
static void sharedmem_initialize_cleanup(apr_pool_t *p)
{
    apr_pool_cleanup_register(p, &globallistmem, cleanup_slotmem, apr_pool_cleanup_null);
}

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

    rv = apr_file_close(fmutex);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "sharedmem: could not close mutex file");
        return rv;
    }

    rv = apr_global_mutex_create(&smutex,
                                 mutex_fname, APR_LOCK_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "sharedmem: creation of mutex failed");
        return rv;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
    rv = ap_unixd_set_global_mutex_perms(smutex);
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
    sharedmem_initgpool(global_pool);
    return OK;
}

static void child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv;

    rv = apr_global_mutex_child_init(&smutex,
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
    const ap_slotmem_storage_method *storage = sharedmem_getstorage();
    ap_register_provider(p, AP_SLOTMEM_STORAGE, "shared", "0", storage);
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA sharedmem_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    ap_sharedmem_register_hook  /* register hooks */
};

