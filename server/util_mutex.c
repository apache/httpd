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

/*
 * util_mutex.c: Useful functions for determining allowable
 *               mutexes and mutex settings
 */


#include "apr.h"
#include "apr_hash.h"
#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_config.h"
#include "http_log.h"
#include "util_mutex.h"
#if AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h> /* getpid() */
#endif

AP_DECLARE(apr_status_t) ap_parse_mutex(const char *arg, apr_pool_t *pool,
                                        apr_lockmech_e *mutexmech,
                                        const char **mutexfile)
{
    /* Split arg into meth and file */
    char *meth = apr_pstrdup(pool, arg);
    char *file = strchr(meth, ':');
    if (file) {
        *(file++) = '\0';
        if (!*file) {
            file = NULL;
        }
    }

    /* APR determines temporary filename unless overridden below,
     * we presume file indicates an mutexfile is a file path
     * unless the method sets mutexfile=file and NULLs file
     */
    *mutexfile = NULL;

    if (!strcasecmp(meth, "none") || !strcasecmp(meth, "no")) {
        return APR_ENOLOCK;
    }

    /* NOTE: previously, 'yes' implied 'sem' */
    if (!strcasecmp(meth, "default") || !strcasecmp(meth, "yes")) {
        *mutexmech = APR_LOCK_DEFAULT;
    }
#if APR_HAS_FCNTL_SERIALIZE
    else if (!strcasecmp(meth, "fcntl") || !strcasecmp(meth, "file")) {
        *mutexmech = APR_LOCK_FCNTL;
    }
#endif
#if APR_HAS_FLOCK_SERIALIZE
    else if (!strcasecmp(meth, "flock") || !strcasecmp(meth, "file")) {
        *mutexmech = APR_LOCK_FLOCK;
    }
#endif
#if APR_HAS_POSIXSEM_SERIALIZE
    else if (!strcasecmp(meth, "posixsem") || !strcasecmp(meth, "sem")) {
        *mutexmech = APR_LOCK_POSIXSEM;
        /* Posix/SysV semaphores aren't file based, use the literal name
         * if provided and fall back on APR's default if not.  Today, APR
         * will ignore it, but once supported it has an absurdly short limit.
         */
        if (file) {
            *mutexfile = apr_pstrdup(pool, file);

            file = NULL;
        }
    }
#endif
#if APR_HAS_SYSVSEM_SERIALIZE
    else if (!strcasecmp(meth, "sysvsem") || !strcasecmp(meth, "sem")) {
        *mutexmech = APR_LOCK_SYSVSEM;
    }
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    else if (!strcasecmp(meth, "pthread")) {
        *mutexmech = APR_LOCK_PROC_PTHREAD;
    }
#endif
    else {
        return APR_ENOTIMPL;
    }

    /* Unless the method above assumed responsibility for setting up
     * mutexfile and NULLing out file, presume it is a file we
     * are looking to use
     */
    if (file) {
        *mutexfile = ap_server_root_relative(pool, file);
        if (!*mutexfile) {
            return APR_BADARG;
        }
    }

    return APR_SUCCESS;
}

typedef struct {
    apr_int32_t options;
    int set;
    int none;
    int omit_pid;
    apr_lockmech_e mech;
    const char *dir;
} mutex_cfg_t;

/* hash is created the first time a module calls ap_mutex_register(),
 * rather than attempting to be the REALLY_REALLY_FIRST pre-config
 * hook; it is cleaned up when the associated pool goes away; assume
 * pconf is the pool passed to ap_mutex_register()
 */
static apr_hash_t *mxcfg_by_type;

static apr_status_t cleanup_mx_hash(void *dummy)
{
    mxcfg_by_type = NULL;
    return APR_SUCCESS;
}

AP_DECLARE_NONSTD(void) ap_mutex_init(apr_pool_t *p)
{
    mutex_cfg_t *def;

    if (mxcfg_by_type) {
        return;
    }

    mxcfg_by_type = apr_hash_make(p);
    apr_pool_cleanup_register(p, NULL, cleanup_mx_hash, apr_pool_cleanup_null);

    /* initialize default mutex configuration */
    def = apr_pcalloc(p, sizeof *def);
    def->mech = APR_LOCK_DEFAULT;
#ifdef DEFAULT_REL_RUNTIMEDIR
    def->dir = DEFAULT_REL_RUNTIMEDIR;
#else
    def->dir = "logs";
#endif
    apr_hash_set(mxcfg_by_type, "default", APR_HASH_KEY_STRING, def);
}

AP_DECLARE_NONSTD(const char *)ap_set_mutex(cmd_parms *cmd, void *dummy,
                                            const char *arg)
{
    apr_pool_t *p = cmd->pool;
    const char **elt;
    const char *mechdir;
    int no_mutex = 0, omit_pid = 0;
    apr_array_header_t *type_list;
    apr_lockmech_e mech;
    apr_status_t rv;
    const char *mutexdir;
    mutex_cfg_t *mxcfg;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    mechdir = ap_getword_conf(cmd->pool, &arg);
    if (*mechdir == '\0') {
        return "Mutex requires at least a mechanism argument (" 
               AP_ALL_AVAILABLE_MUTEXES_STRING ")";
    }

    rv = ap_parse_mutex(mechdir, p, &mech, &mutexdir);
    if (rv == APR_ENOTIMPL) {
        return apr_pstrcat(p, "Invalid Mutex argument ", mechdir,
                           " (" AP_ALL_AVAILABLE_MUTEXES_STRING ")", NULL);
    }
    else if (rv == APR_BADARG
             || (mutexdir && !ap_is_directory(p, mutexdir))) {
        return apr_pstrcat(p, "Invalid Mutex directory in argument ",
                           mechdir, NULL);
    }
    else if (rv == APR_ENOLOCK) { /* "none" */
        no_mutex = 1;
    }

    /* "OmitPID" can appear at the end of the list, so build a list of
     * mutex type names while looking for "OmitPID" (anywhere) or the end
     */
    type_list = apr_array_make(cmd->pool, 4, sizeof(const char *));
    while (*arg) {
        const char *s = ap_getword_conf(cmd->pool, &arg);

        if (!strcasecmp(s, "omitpid")) {
            omit_pid = 1;
        }
        else {
            const char **new_type = (const char **)apr_array_push(type_list);
            *new_type = s;
        }
    }

    if (apr_is_empty_array(type_list)) { /* no mutex type?  assume "default" */
        const char **new_type = (const char **)apr_array_push(type_list);
        *new_type = "default";
    }

    while ((elt = (const char **)apr_array_pop(type_list)) != NULL) {
        const char *type = *elt;
        mxcfg = apr_hash_get(mxcfg_by_type, type, APR_HASH_KEY_STRING);
        if (!mxcfg) {
            return apr_psprintf(p, "Mutex type %s is not valid", type);
        }

        mxcfg->none = 0; /* in case that was the default */
        mxcfg->omit_pid = omit_pid;

        mxcfg->set = 1;
        if (no_mutex) {
            if (!(mxcfg->options & AP_MUTEX_ALLOW_NONE)) {
                return apr_psprintf(p,
                                    "None is not allowed for mutex type %s",
                                    type);
            }
            mxcfg->none = 1;
        }
        else {
            mxcfg->mech = mech;
            if (mutexdir) { /* retain mutex default if not configured */
                mxcfg->dir = mutexdir;
            }
        }
    }

    return NULL;
}

AP_DECLARE(apr_status_t) ap_mutex_register(apr_pool_t *pconf,
                                           const char *type,
                                           const char *default_dir,
                                           apr_lockmech_e default_mech,
                                           apr_int32_t options)
{
    mutex_cfg_t *mxcfg = apr_pcalloc(pconf, sizeof *mxcfg);

    if ((options & ~(AP_MUTEX_ALLOW_NONE | AP_MUTEX_DEFAULT_NONE))) {
        return APR_EINVAL;
    }

    ap_mutex_init(pconf); /* in case this mod's pre-config ran before core's */

    mxcfg->options = options;
    if (options & AP_MUTEX_DEFAULT_NONE) {
        mxcfg->none = 1;
    }
    mxcfg->dir = default_dir; /* usually NULL */
    mxcfg->mech = default_mech; /* usually APR_LOCK_DEFAULT */
    apr_hash_set(mxcfg_by_type, type, APR_HASH_KEY_STRING, mxcfg);

    return APR_SUCCESS;
}

static int mutex_needs_file(apr_lockmech_e mech)
{
    if (mech != APR_LOCK_FLOCK
        && mech != APR_LOCK_FCNTL
#if APR_USE_FLOCK_SERIALIZE || APR_USE_FCNTL_SERIALIZE
        && mech != APR_LOCK_DEFAULT
#endif
        ) {
        return 0;
    }
    return 1;
}

static const char *get_mutex_filename(apr_pool_t *p, mutex_cfg_t *mxcfg,
                                      const char *type,
                                      const char *instance_id)
{
    const char *pid_suffix = "";

    if (!mutex_needs_file(mxcfg->mech)) {
        return NULL;
    }

#if HAVE_UNISTD_H
    if (!mxcfg->omit_pid) {
        pid_suffix = apr_psprintf(p, ".%" APR_PID_T_FMT, getpid());
    }
#endif

    return ap_server_root_relative(p,
                                   apr_pstrcat(p,
                                               mxcfg->dir,
                                               "/",
                                               type,
                                               instance_id ? "-" : "",
                                               instance_id ? instance_id : "",
                                               pid_suffix,
                                               NULL));
}

static mutex_cfg_t *mxcfg_lookup(apr_pool_t *p, const char *type)
{
    mutex_cfg_t *defcfg, *mxcfg, *newcfg;

    defcfg = apr_hash_get(mxcfg_by_type, "default", APR_HASH_KEY_STRING);

    /* MUST exist in table, or wasn't registered */
    mxcfg = apr_hash_get(mxcfg_by_type, type, APR_HASH_KEY_STRING);
    if (!mxcfg) {
        return NULL;
    }

    /* order of precedence:
     * 1. Mutex directive for this mutex
     * 2. Mutex directive for "default"
     * 3. Defaults for this mutex from ap_mutex_register()
     * 4. Global defaults
     */

    if (mxcfg->set) {
        newcfg = mxcfg;
    }
    else if (defcfg->set) {
        newcfg = defcfg;
    }
    else if (mxcfg->none || mxcfg->mech != APR_LOCK_DEFAULT) {
        newcfg = mxcfg;
    }
    else {
        newcfg = defcfg;
    }

    if (!newcfg->none && mutex_needs_file(newcfg->mech) && !newcfg->dir) {
        /* a file-based mutex mechanism was configured, but
         * without a mutex file directory; go back through
         * the chain to find the directory, store in new
         * mutex cfg structure
         */
        newcfg = apr_pmemdup(p, newcfg, sizeof *newcfg);

        /* !true if dir not already set: mxcfg->set && defcfg->dir */
        if (defcfg->set && defcfg->dir) {
            newcfg->dir = defcfg->dir;
        }
        else if (mxcfg->dir) {
            newcfg->dir = mxcfg->dir;
        }
        else {
            newcfg->dir = defcfg->dir;
        }
    }

    return newcfg;
}

static void log_bad_create_options(server_rec *s, const char *type)
{
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                 "Invalid options were specified when creating the %s mutex",
                 type);
}

static void log_unknown_type(server_rec *s, const char *type)
{
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                 "Can't create mutex of unknown type %s", type);
}

static void log_create_failure(apr_status_t rv, server_rec *s, const char *type,
                               const char *fname)
{
    ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                 "Couldn't create the %s mutex %s%s%s", type,
                 fname ? "(file " : "",
                 fname ? fname : "",
                 fname ? ")" : "");
}

static void log_perms_failure(apr_status_t rv, server_rec *s, const char *type)
{
    ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                 "Couldn't set permissions on the %s mutex; "
                 "check User and Group directives",
                 type);
}

AP_DECLARE(apr_status_t) ap_global_mutex_create(apr_global_mutex_t **mutex,
                                                const char *type,
                                                const char *instance_id,
                                                server_rec *s, apr_pool_t *p,
                                                apr_int32_t options)
{
    apr_status_t rv;
    const char *fname;
    mutex_cfg_t *mxcfg = mxcfg_lookup(p, type);

    if (options) {
        log_bad_create_options(s, type);
        return APR_EINVAL;
    }

    if (!mxcfg) {
        log_unknown_type(s, type);
        return APR_EINVAL;
    }

    if (mxcfg->none) {
        *mutex = NULL;
        return APR_SUCCESS;
    }

    fname = get_mutex_filename(p, mxcfg, type, instance_id);

    rv = apr_global_mutex_create(mutex, fname, mxcfg->mech, p);
    if (rv != APR_SUCCESS) {
        log_create_failure(rv, s, type, fname);
        return rv;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
    rv = ap_unixd_set_global_mutex_perms(*mutex);
    if (rv != APR_SUCCESS) {
        log_perms_failure(rv, s, type);
        return rv;
    }
#endif

    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_proc_mutex_create(apr_proc_mutex_t **mutex,
                                              const char *type,
                                              const char *instance_id,
                                              server_rec *s, apr_pool_t *p,
                                              apr_int32_t options)
{
    apr_status_t rv;
    const char *fname;
    mutex_cfg_t *mxcfg = mxcfg_lookup(p, type);

    if (options) {
        log_bad_create_options(s, type);
        return APR_EINVAL;
    }

    if (!mxcfg) {
        log_unknown_type(s, type);
        return APR_EINVAL;
    }

    if (mxcfg->none) {
        *mutex = NULL;
        return APR_SUCCESS;
    }

    fname = get_mutex_filename(p, mxcfg, type, instance_id);

    rv = apr_proc_mutex_create(mutex, fname, mxcfg->mech, p);
    if (rv != APR_SUCCESS) {
        log_create_failure(rv, s, type, fname);
        return rv;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
    rv = ap_unixd_set_proc_mutex_perms(*mutex);
    if (rv != APR_SUCCESS) {
        log_perms_failure(rv, s, type);
        return rv;
    }
#endif

    return APR_SUCCESS;
}
