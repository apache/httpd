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
 * mod_isapi.c - Internet Server Application (ISA) module for Apache
 * by Alexei Kosut <akosut@apache.org>, significant overhauls and
 * redesign by William Rowe <wrowe@covalent.net>, and hints from many
 * other developer/users who have hit on specific flaws.
 *
 * This module implements the ISAPI Handler architecture, allowing
 * Apache to load Internet Server Applications (ISAPI extensions),
 * similar to the support in IIS, Zope, O'Reilly's WebSite and others.
 *
 * It is a complete implementation of the ISAPI 2.0 specification,
 * except for "Microsoft extensions" to the API which provide
 * asynchronous I/O.  It is further extended to include additional
 * "Microsoft extentions" through IIS 5.0, with some deficiencies
 * where one-to-one mappings don't exist.
 *
 * Refer to /manual/mod/mod_isapi.html for additional details on
 * configuration and use, but check this source for specific support
 * of the API,
 */

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "util_script.h"
#include "mod_core.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_buckets.h"
#include "apr_thread_mutex.h"
#include "apr_thread_rwlock.h"
#include "apr_hash.h"
#include "mod_isapi.h"

/* Retry frequency for a failed-to-load isapi .dll */
#define ISAPI_RETRY apr_time_from_sec(30)

/**********************************************************
 *
 *  ISAPI Module Configuration
 *
 **********************************************************/

module AP_MODULE_DECLARE_DATA isapi_module;

#define ISAPI_UNDEF -1

/* Our isapi per-dir config structure */
typedef struct isapi_dir_conf {
    int read_ahead_buflen;
    int log_unsupported;
    int log_to_errlog;
    int log_to_query;
    int fake_async;
} isapi_dir_conf;

typedef struct isapi_loaded isapi_loaded;

apr_status_t isapi_lookup(apr_pool_t *p, server_rec *s, request_rec *r,
                          const char *fpath, isapi_loaded** isa);

static void *create_isapi_dir_config(apr_pool_t *p, char *dummy)
{
    isapi_dir_conf *dir = apr_palloc(p, sizeof(isapi_dir_conf));

    dir->read_ahead_buflen = ISAPI_UNDEF;
    dir->log_unsupported   = ISAPI_UNDEF;
    dir->log_to_errlog     = ISAPI_UNDEF;
    dir->log_to_query      = ISAPI_UNDEF;
    dir->fake_async        = ISAPI_UNDEF;

    return dir;
}

static void *merge_isapi_dir_configs(apr_pool_t *p, void *base_, void *add_)
{
    isapi_dir_conf *base = (isapi_dir_conf *) base_;
    isapi_dir_conf *add = (isapi_dir_conf *) add_;
    isapi_dir_conf *dir = apr_palloc(p, sizeof(isapi_dir_conf));

    dir->read_ahead_buflen = (add->read_ahead_buflen == ISAPI_UNDEF)
                                ? base->read_ahead_buflen
                                 : add->read_ahead_buflen;
    dir->log_unsupported   = (add->log_unsupported == ISAPI_UNDEF)
                                ? base->log_unsupported
                                 : add->log_unsupported;
    dir->log_to_errlog     = (add->log_to_errlog == ISAPI_UNDEF)
                                ? base->log_to_errlog
                                 : add->log_to_errlog;
    dir->log_to_query      = (add->log_to_query == ISAPI_UNDEF)
                                ? base->log_to_query
                                 : add->log_to_query;
    dir->fake_async        = (add->fake_async == ISAPI_UNDEF)
                                ? base->fake_async
                                 : add->fake_async;

    return dir;
}

static const char *isapi_cmd_cachefile(cmd_parms *cmd, void *dummy,
                                       const char *filename)
{
    isapi_loaded *isa;
    apr_finfo_t tmp;
    apr_status_t rv;
    char *fspec;

    /* ### Just an observation ... it would be terribly cool to be
     * able to use this per-dir, relative to the directory block being
     * defined.  The hash result remains global, but shorthand of
     * <Directory "c:/webapps/isapi">
     *     ISAPICacheFile myapp.dll anotherapp.dll thirdapp.dll
     * </Directory>
     * would be very convienent.
     */
    fspec = ap_server_root_relative(cmd->pool, filename);
    if (!fspec) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, APR_EBADPATH, cmd->server, APLOGNO(02103)
                     "invalid module path, skipping %s", filename);
        return NULL;
    }
    if ((rv = apr_stat(&tmp, fspec, APR_FINFO_TYPE,
                      cmd->temp_pool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, cmd->server, APLOGNO(02104)
                     "unable to stat, skipping %s", fspec);
        return NULL;
    }
    if (tmp.filetype != APR_REG) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server, APLOGNO(02105)
                     "not a regular file, skipping %s", fspec);
        return NULL;
    }

    /* Load the extention as cached (with null request_rec) */
    rv = isapi_lookup(cmd->pool, cmd->server, NULL, fspec, &isa);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, cmd->server, APLOGNO(02106)
                     "unable to cache, skipping %s", fspec);
        return NULL;
    }

    return NULL;
}

static const command_rec isapi_cmds[] = {
    AP_INIT_TAKE1("ISAPIReadAheadBuffer", ap_set_int_slot,
        (void *)APR_OFFSETOF(isapi_dir_conf, read_ahead_buflen),
        OR_FILEINFO, "Maximum client request body to initially pass to the"
                     " ISAPI handler (default: 49152)"),
    AP_INIT_FLAG("ISAPILogNotSupported", ap_set_flag_slot,
        (void *)APR_OFFSETOF(isapi_dir_conf, log_unsupported),
        OR_FILEINFO, "Log requests not supported by the ISAPI server"
                     " on or off (default: off)"),
    AP_INIT_FLAG("ISAPIAppendLogToErrors", ap_set_flag_slot,
        (void *)APR_OFFSETOF(isapi_dir_conf, log_to_errlog),
        OR_FILEINFO, "Send all Append Log requests to the error log"
                     " on or off (default: off)"),
    AP_INIT_FLAG("ISAPIAppendLogToQuery", ap_set_flag_slot,
        (void *)APR_OFFSETOF(isapi_dir_conf, log_to_query),
        OR_FILEINFO, "Append Log requests are concatinated to the query args"
                     " on or off (default: on)"),
    AP_INIT_FLAG("ISAPIFakeAsync", ap_set_flag_slot,
        (void *)APR_OFFSETOF(isapi_dir_conf, fake_async),
        OR_FILEINFO, "Fake Asynchronous support for isapi callbacks"
                     " on or off [Experimental] (default: off)"),
    AP_INIT_ITERATE("ISAPICacheFile", isapi_cmd_cachefile, NULL,
        RSRC_CONF, "Cache the specified ISAPI extension in-process"),
    {NULL}
};

/**********************************************************
 *
 *  ISAPI Module Cache handling section
 *
 **********************************************************/

/* Our isapi global config values */
static struct isapi_global_conf {
    apr_pool_t         *pool;
    apr_thread_mutex_t *lock;
    apr_hash_t         *hash;
} loaded;

/* Our loaded isapi module description structure */
struct isapi_loaded {
    const char          *filename;
    apr_thread_rwlock_t *in_progress;
    apr_status_t         last_load_rv;
    apr_time_t           last_load_time;
    apr_dso_handle_t    *handle;
    HSE_VERSION_INFO    *isapi_version;
    apr_uint32_t         report_version;
    apr_uint32_t         timeout;
    PFN_GETEXTENSIONVERSION GetExtensionVersion;
    PFN_HTTPEXTENSIONPROC   HttpExtensionProc;
    PFN_TERMINATEEXTENSION  TerminateExtension;
};

static apr_status_t isapi_unload(isapi_loaded *isa, int force)
{
    /* All done with the DLL... get rid of it...
     *
     * If optionally cached, and we weren't asked to force the unload,
     * pass HSE_TERM_ADVISORY_UNLOAD, and if it returns 1, unload,
     * otherwise, leave it alone (it didn't choose to cooperate.)
     */
    if (!isa->handle) {
        return APR_SUCCESS;
    }
    if (isa->TerminateExtension) {
        if (force) {
            (*isa->TerminateExtension)(HSE_TERM_MUST_UNLOAD);
        }
        else if (!(*isa->TerminateExtension)(HSE_TERM_ADVISORY_UNLOAD)) {
            return APR_EGENERAL;
        }
    }
    apr_dso_unload(isa->handle);
    isa->handle = NULL;
    return APR_SUCCESS;
}

static apr_status_t cleanup_isapi(void *isa_)
{
    isapi_loaded* isa = (isapi_loaded*) isa_;

    /* We must force the module to unload, we are about
     * to lose the isapi structure's allocation entirely.
     */
    return isapi_unload(isa, 1);
}

static apr_status_t isapi_load(apr_pool_t *p, server_rec *s, isapi_loaded *isa)
{
    apr_status_t rv;

    isa->isapi_version = apr_pcalloc(p, sizeof(HSE_VERSION_INFO));

    /* TODO: These aught to become overrideable, so that we
     * assure a given isapi can be fooled into behaving well.
     *
     * The tricky bit, they aren't really a per-dir sort of
     * config, they will always be constant across every
     * reference to the .dll no matter what context (vhost,
     * location, etc) they apply to.
     */
    isa->report_version = 0x500; /* Revision 5.0 */
    isa->timeout = 300 * 1000000; /* microsecs, not used */

    rv = apr_dso_load(&isa->handle, isa->filename, p);
    if (rv)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(02107)
                     "failed to load %s", isa->filename);
        isa->handle = NULL;
        return rv;
    }

    rv = apr_dso_sym((void**)&isa->GetExtensionVersion, isa->handle,
                     "GetExtensionVersion");
    if (rv)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(02108)
                     "missing GetExtensionVersion() in %s",
                     isa->filename);
        apr_dso_unload(isa->handle);
        isa->handle = NULL;
        return rv;
    }

    rv = apr_dso_sym((void**)&isa->HttpExtensionProc, isa->handle,
                     "HttpExtensionProc");
    if (rv)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(02109)
                     "missing HttpExtensionProc() in %s",
                     isa->filename);
        apr_dso_unload(isa->handle);
        isa->handle = NULL;
        return rv;
    }

    /* TerminateExtension() is an optional interface */
    rv = apr_dso_sym((void**)&isa->TerminateExtension, isa->handle,
                     "TerminateExtension");
    apr_set_os_error(0);

    /* Run GetExtensionVersion() */
    if (!(isa->GetExtensionVersion)(isa->isapi_version)) {
        apr_status_t rv = apr_get_os_error();
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(02110)
                     "failed call to GetExtensionVersion() in %s",
                     isa->filename);
        apr_dso_unload(isa->handle);
        isa->handle = NULL;
        return rv;
    }

    apr_pool_cleanup_register(p, isa, cleanup_isapi,
                              apr_pool_cleanup_null);

    return APR_SUCCESS;
}

apr_status_t isapi_lookup(apr_pool_t *p, server_rec *s, request_rec *r,
                          const char *fpath, isapi_loaded** isa)
{
    apr_status_t rv;
    const char *key;

    if ((rv = apr_thread_mutex_lock(loaded.lock)) != APR_SUCCESS) {
        return rv;
    }

    *isa = apr_hash_get(loaded.hash, fpath, APR_HASH_KEY_STRING);

    if (*isa) {

        /* If we find this lock exists, use a set-aside copy of gainlock
         * to avoid race conditions on NULLing the in_progress variable
         * when the load has completed.  Release the global isapi hash
         * lock so other requests can proceed, then rdlock for completion
         * of loading our desired dll or wrlock if we would like to retry
         * loading the dll (because last_load_rv failed and retry is up.)
         */
        apr_thread_rwlock_t *gainlock = (*isa)->in_progress;

        /* gainlock is NULLed after the module loads successfully.
         * This free-threaded module can be used without any locking.
         */
        if (!gainlock) {
            rv = (*isa)->last_load_rv;
            apr_thread_mutex_unlock(loaded.lock);
            return rv;
        }


        if ((*isa)->last_load_rv == APR_SUCCESS) {
            apr_thread_mutex_unlock(loaded.lock);
            if ((rv = apr_thread_rwlock_rdlock(gainlock))
                    != APR_SUCCESS) {
                return rv;
            }
            rv = (*isa)->last_load_rv;
            apr_thread_rwlock_unlock(gainlock);
            return rv;
        }

        if (apr_time_now() > (*isa)->last_load_time + ISAPI_RETRY) {

            /* Remember last_load_time before releasing the global
             * hash lock to avoid colliding with another thread
             * that hit this exception at the same time as our
             * retry attempt, since we unlock the global mutex
             * before attempting a write lock for this module.
             */
            apr_time_t check_time = (*isa)->last_load_time;
            apr_thread_mutex_unlock(loaded.lock);

            if ((rv = apr_thread_rwlock_wrlock(gainlock))
                    != APR_SUCCESS) {
                return rv;
            }

            /* If last_load_time is unchanged, we still own this
             * retry, otherwise presume another thread provided
             * our retry (for good or ill).  Relock the global
             * hash for updating last_load_ vars, so their update
             * is always atomic to the global lock.
             */
            if (check_time == (*isa)->last_load_time) {

                rv = isapi_load(loaded.pool, s, *isa);

                apr_thread_mutex_lock(loaded.lock);
                (*isa)->last_load_rv = rv;
                (*isa)->last_load_time = apr_time_now();
                apr_thread_mutex_unlock(loaded.lock);
            }
            else {
                rv = (*isa)->last_load_rv;
            }
            apr_thread_rwlock_unlock(gainlock);

            return rv;
        }

        /* We haven't hit timeup on retry, let's grab the last_rv
         * within the hash mutex before unlocking.
         */
        rv = (*isa)->last_load_rv;
        apr_thread_mutex_unlock(loaded.lock);

        return rv;
    }

    /* If the module was not found, it's time to create a hash key entry
     * before releasing the hash lock to avoid multiple threads from
     * loading the same module.
     */
    key = apr_pstrdup(loaded.pool, fpath);
    *isa = apr_pcalloc(loaded.pool, sizeof(isapi_loaded));
    (*isa)->filename = key;
    if (r) {
        /* A mutex that exists only long enough to attempt to
         * load this isapi dll, the release this module to all
         * other takers that came along during the one-time
         * load process.  Short lifetime for this lock would
         * be great, however, using r->pool is nasty if those
         * blocked on the lock haven't all unlocked before we
         * attempt to destroy.  A nastier race condition than
         * I want to deal with at this moment...
         */
        apr_thread_rwlock_create(&(*isa)->in_progress, loaded.pool);
        apr_thread_rwlock_wrlock((*isa)->in_progress);
    }

    apr_hash_set(loaded.hash, key, APR_HASH_KEY_STRING, *isa);

    /* Now attempt to load the isapi on our own time,
     * allow other isapi processing to resume.
     */
    apr_thread_mutex_unlock(loaded.lock);

    rv = isapi_load(loaded.pool, s, *isa);
    (*isa)->last_load_time = apr_time_now();
    (*isa)->last_load_rv = rv;

    if (r && (rv == APR_SUCCESS)) {
        /* Let others who are blocked on this particular
         * module resume their requests, for better or worse.
         */
        apr_thread_rwlock_t *unlock = (*isa)->in_progress;
        (*isa)->in_progress = NULL;
        apr_thread_rwlock_unlock(unlock);
    }
    else if (!r && (rv != APR_SUCCESS)) {
        /* We must leave a rwlock around for requests to retry
         * loading this dll after timeup... since we were in
         * the setup code we had avoided creating this lock.
         */
        apr_thread_rwlock_create(&(*isa)->in_progress, loaded.pool);
    }

    return (*isa)->last_load_rv;
}

/**********************************************************
 *
 *  ISAPI Module request callbacks section
 *
 **********************************************************/

/* Our "Connection ID" structure */
struct isapi_cid {
    EXTENSION_CONTROL_BLOCK *ecb;
    isapi_dir_conf           dconf;
    isapi_loaded            *isa;
    request_rec             *r;
    int                      headers_set;
    int                      response_sent;
    PFN_HSE_IO_COMPLETION    completion;
    void                    *completion_arg;
    apr_thread_mutex_t      *completed;
};

static int APR_THREAD_FUNC regfnGetServerVariable(isapi_cid    *cid,
                                                  char         *variable_name,
                                                  void         *buf_ptr,
                                                  apr_uint32_t *buf_size)
{
    request_rec *r = cid->r;
    const char *result;
    char *buf_data = (char*)buf_ptr;
    apr_uint32_t len;

    if (!strcmp(variable_name, "ALL_HTTP"))
    {
        /* crlf delimited, colon split, comma separated and
         * null terminated list of HTTP_ vars
         */
        const apr_array_header_t *arr = apr_table_elts(r->subprocess_env);
        const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
        int i;

        for (len = 0, i = 0; i < arr->nelts; i++) {
            if (!strncmp(elts[i].key, "HTTP_", 5)) {
                len += strlen(elts[i].key) + strlen(elts[i].val) + 3;
            }
        }

        if (*buf_size < len + 1) {
            *buf_size = len + 1;
            apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INSUFFICIENT_BUFFER));
            return 0;
        }

        for (i = 0; i < arr->nelts; i++) {
            if (!strncmp(elts[i].key, "HTTP_", 5)) {
                strcpy(buf_data, elts[i].key);
                buf_data += strlen(elts[i].key);
                *(buf_data++) = ':';
                strcpy(buf_data, elts[i].val);
                buf_data += strlen(elts[i].val);
                *(buf_data++) = '\r';
                *(buf_data++) = '\n';
            }
        }

        *(buf_data++) = '\0';
        *buf_size = len + 1;
        return 1;
    }

    if (!strcmp(variable_name, "ALL_RAW"))
    {
        /* crlf delimited, colon split, comma separated and
         * null terminated list of the raw request header
         */
        const apr_array_header_t *arr = apr_table_elts(r->headers_in);
        const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
        int i;

        for (len = 0, i = 0; i < arr->nelts; i++) {
            len += strlen(elts[i].key) + strlen(elts[i].val) + 4;
        }

        if (*buf_size < len + 1) {
            *buf_size = len + 1;
            apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INSUFFICIENT_BUFFER));
            return 0;
        }

        for (i = 0; i < arr->nelts; i++) {
            strcpy(buf_data, elts[i].key);
            buf_data += strlen(elts[i].key);
            *(buf_data++) = ':';
            *(buf_data++) = ' ';
            strcpy(buf_data, elts[i].val);
            buf_data += strlen(elts[i].val);
            *(buf_data++) = '\r';
            *(buf_data++) = '\n';
        }
        *(buf_data++) = '\0';
        *buf_size = len + 1;
        return 1;
    }

    /* Not a special case */
    result = apr_table_get(r->subprocess_env, variable_name);

    if (result) {
        len = strlen(result);
        if (*buf_size < len + 1) {
            *buf_size = len + 1;
            apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INSUFFICIENT_BUFFER));
            return 0;
        }
        strcpy(buf_data, result);
        *buf_size = len + 1;
        return 1;
    }

    /* Not Found */
    apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_INDEX));
    return 0;
}

static int APR_THREAD_FUNC regfnReadClient(isapi_cid    *cid,
                                           void         *buf_data,
                                           apr_uint32_t *buf_size)
{
    request_rec *r = cid->r;
    apr_uint32_t read = 0;
    int res = 0;

    if (r->remaining < *buf_size) {
        *buf_size = (apr_size_t)r->remaining;
    }

    while (read < *buf_size &&
           ((res = ap_get_client_block(r, (char*)buf_data + read,
                                       *buf_size - read)) > 0)) {
        read += res;
    }

    *buf_size = read;
    if (res < 0) {
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_READ_FAULT));
    }
    return (res >= 0);
}

/* Common code invoked for both HSE_REQ_SEND_RESPONSE_HEADER and
 * the newer HSE_REQ_SEND_RESPONSE_HEADER_EX ServerSupportFunction(s)
 * as well as other functions that write responses and presume that
 * the support functions above are optional.
 *
 * Other callers trying to split headers and body bytes should pass
 * head/headlen alone (leaving stat/statlen NULL/0), so that they
 * get a proper count of bytes consumed.  The argument passed to stat
 * isn't counted as the head bytes are.
 */
static apr_ssize_t send_response_header(isapi_cid *cid,
                                        const char *stat,
                                        const char *head,
                                        apr_size_t statlen,
                                        apr_size_t headlen)
{
    int head_present = 1;
    int termarg;
    int res;
    int old_status;
    const char *termch;
    apr_size_t ate = 0;

    if (!head || headlen == 0 || !*head) {
        head = stat;
        stat = NULL;
        headlen = statlen;
        statlen = 0;
        head_present = 0; /* Don't eat the header */
    }

    if (!stat || statlen == 0 || !*stat) {
        if (head && headlen && *head && ((stat = memchr(head, '\r', headlen))
                                      || (stat = memchr(head, '\n', headlen))
                                      || (stat = memchr(head, '\0', headlen))
                                      || (stat = head + headlen))) {
            statlen = stat - head;
            if (memchr(head, ':', statlen)) {
                stat = "Status: 200 OK";
                statlen = strlen(stat);
            }
            else {
                const char *flip = head;
                head = stat;
                stat = flip;
                headlen -= statlen;
                ate += statlen;
                if (*head == '\r' && headlen)
                    ++head, --headlen, ++ate;
                if (*head == '\n' && headlen)
                    ++head, --headlen, ++ate;
            }
        }
    }

    if (stat && (statlen > 0) && *stat) {
        char *newstat;
        if (!apr_isdigit(*stat)) {
            const char *stattok = stat;
            int toklen = statlen;
            while (toklen && *stattok && !apr_isspace(*stattok)) {
                ++stattok; --toklen;
            }
            while (toklen && apr_isspace(*stattok)) {
                ++stattok; --toklen;
            }
            /* Now decide if we follow the xxx message
             * or the http/x.x xxx message format
             */
            if (toklen && apr_isdigit(*stattok)) {
                statlen = toklen;
                stat = stattok;
            }
        }
        newstat = apr_palloc(cid->r->pool, statlen + 9);
        strcpy(newstat, "Status: ");
        apr_cpystrn(newstat + 8, stat, statlen + 1);
        stat = newstat;
        statlen += 8;
    }

    if (!head || headlen == 0 || !*head) {
        head = "\r\n";
        headlen = 2;
    }
    else
    {
        if (head[headlen - 1] && head[headlen]) {
            /* Whoops... not NULL terminated */
            head = apr_pstrndup(cid->r->pool, head, headlen);
        }
    }

    /* Seems IIS does not enforce the requirement for \r\n termination
     * on HSE_REQ_SEND_RESPONSE_HEADER, but we won't panic...
     * ap_scan_script_header_err_strs handles this aspect for us.
     *
     * Parse them out, or die trying
     */
    old_status = cid->r->status;

    if (stat) {
        res = ap_scan_script_header_err_strs_ex(cid->r, NULL,
                APLOG_MODULE_INDEX, &termch, &termarg, stat, head, NULL);
    }
    else {
        res = ap_scan_script_header_err_strs_ex(cid->r, NULL,
                APLOG_MODULE_INDEX, &termch, &termarg, head, NULL);
    }

    /* Set our status. */
    if (res) {
        /* This is an immediate error result from the parser
         */
        cid->r->status = res;
        cid->r->status_line = ap_get_status_line(cid->r->status);
        cid->ecb->dwHttpStatusCode = cid->r->status;
    }
    else if (cid->r->status) {
        /* We have a status in r->status, so let's just use it.
         * This is likely to be the Status: parsed above, and
         * may also be a delayed error result from the parser.
         * If it was filled in, status_line should also have
         * been filled in.
         */
        cid->ecb->dwHttpStatusCode = cid->r->status;
    }
    else if (cid->ecb->dwHttpStatusCode
              && cid->ecb->dwHttpStatusCode != HTTP_OK) {
        /* Now we fall back on dwHttpStatusCode if it appears
         * ap_scan_script_header fell back on the default code.
         * Any other results set dwHttpStatusCode to the decoded
         * status value.
         */
        cid->r->status = cid->ecb->dwHttpStatusCode;
        cid->r->status_line = ap_get_status_line(cid->r->status);
    }
    else if (old_status) {
        /* Well... either there is no dwHttpStatusCode or it's HTTP_OK.
         * In any case, we don't have a good status to return yet...
         * Perhaps the one we came in with will be better. Let's use it,
         * if we were given one (note this is a pendantic case, it would
         * normally be covered above unless the scan script code unset
         * the r->status). Should there be a check here as to whether
         * we are setting a valid response code?
         */
        cid->r->status = old_status;
        cid->r->status_line = ap_get_status_line(cid->r->status);
        cid->ecb->dwHttpStatusCode = cid->r->status;
    }
    else {
        /* None of dwHttpStatusCode, the parser's r->status nor the
         * old value of r->status were helpful, and nothing was decoded
         * from Status: string passed to us.  Let's just say HTTP_OK
         * and get the data out, this was the isapi dev's oversight.
         */
        cid->r->status = HTTP_OK;
        cid->r->status_line = ap_get_status_line(cid->r->status);
        cid->ecb->dwHttpStatusCode = cid->r->status;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, cid->r, APLOGNO(02111)
                "Could not determine HTTP response code; using %d",
                cid->r->status);
    }

    if (cid->r->status == HTTP_INTERNAL_SERVER_ERROR) {
        return -1;
    }

    /* If only Status was passed, we consumed nothing
     */
    if (!head_present)
        return 0;

    cid->headers_set = 1;

    /* If all went well, tell the caller we consumed the headers complete
     */
    if (!termch)
        return(ate + headlen);

    /* Any data left must be sent directly by the caller, all we
     * give back is the size of the headers we consumed (which only
     * happens if the parser got to the head arg, which varies based
     * on whether we passed stat+head to scan, or only head.
     */
    if (termch && (termarg == (stat ? 1 : 0))
               && head_present && head + headlen > termch) {
        return ate + termch - head;
    }
    return ate;
}

static int APR_THREAD_FUNC regfnWriteClient(isapi_cid    *cid,
                                            void         *buf_ptr,
                                            apr_uint32_t *size_arg,
                                            apr_uint32_t  flags)
{
    request_rec *r = cid->r;
    conn_rec *c = r->connection;
    apr_uint32_t buf_size = *size_arg;
    char *buf_data = (char*)buf_ptr;
    apr_bucket_brigade *bb;
    apr_bucket *b;
    apr_status_t rv = APR_SUCCESS;

    if (!cid->headers_set) {
        /* It appears that the foxisapi module and other clients
         * presume that WriteClient("headers\n\nbody") will work.
         * Parse them out, or die trying.
         */
        apr_ssize_t ate;
        ate = send_response_header(cid, NULL, buf_data, 0, buf_size);
        if (ate < 0) {
            apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
            return 0;
        }

        buf_data += ate;
        buf_size -= ate;
    }

    if (buf_size) {
        bb = apr_brigade_create(r->pool, c->bucket_alloc);
        b = apr_bucket_transient_create(buf_data, buf_size, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        b = apr_bucket_flush_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        rv = ap_pass_brigade(r->output_filters, bb);
        cid->response_sent = 1;
        if (rv != APR_SUCCESS)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                          "WriteClient ap_pass_brigade failed: %s",
                          r->filename);
    }

    if ((flags & HSE_IO_ASYNC) && cid->completion) {
        if (rv == APR_SUCCESS) {
            cid->completion(cid->ecb, cid->completion_arg,
                            *size_arg, ERROR_SUCCESS);
        }
        else {
            cid->completion(cid->ecb, cid->completion_arg,
                            *size_arg, ERROR_WRITE_FAULT);
        }
    }
    return (rv == APR_SUCCESS);
}

static int APR_THREAD_FUNC regfnServerSupportFunction(isapi_cid    *cid,
                                                      apr_uint32_t  HSE_code,
                                                      void         *buf_ptr,
                                                      apr_uint32_t *buf_size,
                                                      apr_uint32_t *data_type)
{
    request_rec *r = cid->r;
    conn_rec *c = r->connection;
    char *buf_data = (char*)buf_ptr;
    request_rec *subreq;
    apr_status_t rv;

    switch (HSE_code) {
    case HSE_REQ_SEND_URL_REDIRECT_RESP:
        /* Set the status to be returned when the HttpExtensionProc()
         * is done.
         * WARNING: Microsoft now advertises HSE_REQ_SEND_URL_REDIRECT_RESP
         *          and HSE_REQ_SEND_URL as equivalent per the Jan 2000 SDK.
         *          They most definitely are not, even in their own samples.
         */
        apr_table_set (r->headers_out, "Location", buf_data);
        cid->r->status = cid->ecb->dwHttpStatusCode = HTTP_MOVED_TEMPORARILY;
        cid->r->status_line = ap_get_status_line(cid->r->status);
        cid->headers_set = 1;
        return 1;

    case HSE_REQ_SEND_URL:
        /* Soak up remaining input */
        if (r->remaining > 0) {
            char argsbuffer[HUGE_STRING_LEN];
            while (ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN));
        }

        /* Reset the method to GET */
        r->method = "GET";
        r->method_number = M_GET;

        /* Don't let anyone think there's still data */
        apr_table_unset(r->headers_in, "Content-Length");

        /* AV fault per PR3598 - redirected path is lost! */
        buf_data = apr_pstrdup(r->pool, (char*)buf_data);
        ap_internal_redirect(buf_data, r);
        return 1;

    case HSE_REQ_SEND_RESPONSE_HEADER:
    {
        /* Parse them out, or die trying */
        apr_size_t statlen = 0, headlen = 0;
        apr_ssize_t ate;
        if (buf_data)
            statlen = strlen((char*) buf_data);
        if (data_type)
            headlen = strlen((char*) data_type);
        ate = send_response_header(cid, (char*) buf_data,
                                   (char*) data_type,
                                   statlen, headlen);
        if (ate < 0) {
            apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
            return 0;
        }
        else if ((apr_size_t)ate < headlen) {
            apr_bucket_brigade *bb;
            apr_bucket *b;
            bb = apr_brigade_create(cid->r->pool, c->bucket_alloc);
            b = apr_bucket_transient_create((char*) data_type + ate,
                                           headlen - ate, c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, b);
            b = apr_bucket_flush_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, b);
            rv = ap_pass_brigade(cid->r->output_filters, bb);
            cid->response_sent = 1;
            if (rv != APR_SUCCESS)
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                              "ServerSupport function "
                              "HSE_REQ_SEND_RESPONSE_HEADER "
                              "ap_pass_brigade failed: %s", r->filename);
            return (rv == APR_SUCCESS);
        }
        /* Deliberately hold off sending 'just the headers' to begin to
         * accumulate the body and speed up the overall response, or at
         * least wait for the end the session.
         */
        return 1;
    }

    case HSE_REQ_DONE_WITH_SESSION:
        /* Signal to resume the thread completing this request,
         * leave it to the pool cleanup to dispose of our mutex.
         */
        if (cid->completed) {
            (void)apr_thread_mutex_unlock(cid->completed);
            return 1;
        }
        else if (cid->dconf.log_unsupported) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "ServerSupportFunction "
                          "HSE_REQ_DONE_WITH_SESSION is not supported: %s",
                          r->filename);
        }
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
        return 0;

    case HSE_REQ_MAP_URL_TO_PATH:
    {
        /* Map a URL to a filename */
        char *file = (char *)buf_data;
        apr_uint32_t len;
        subreq = ap_sub_req_lookup_uri(
                     apr_pstrndup(cid->r->pool, file, *buf_size), r, NULL);

        if (!subreq->filename) {
            ap_destroy_sub_req(subreq);
            return 0;
        }

        len = (apr_uint32_t)strlen(r->filename);

        if ((subreq->finfo.filetype == APR_DIR)
              && (!subreq->path_info)
              && (file[len - 1] != '/'))
            file = apr_pstrcat(cid->r->pool, subreq->filename, "/", NULL);
        else
            file = apr_pstrcat(cid->r->pool, subreq->filename,
                                              subreq->path_info, NULL);

        ap_destroy_sub_req(subreq);

#ifdef WIN32
        /* We need to make this a real Windows path name */
        apr_filepath_merge(&file, "", file, APR_FILEPATH_NATIVE, r->pool);
#endif

        *buf_size = apr_cpystrn(buf_data, file, *buf_size) - buf_data;

        return 1;
    }

    case HSE_REQ_GET_SSPI_INFO:
        if (cid->dconf.log_unsupported)
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                           "ServerSupportFunction HSE_REQ_GET_SSPI_INFO "
                           "is not supported: %s", r->filename);
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
        return 0;

    case HSE_APPEND_LOG_PARAMETER:
        /* Log buf_data, of buf_size bytes, in the URI Query (cs-uri-query) field
         */
        apr_table_set(r->notes, "isapi-parameter", (char*) buf_data);
        if (cid->dconf.log_to_query) {
            if (r->args)
                r->args = apr_pstrcat(r->pool, r->args, (char*) buf_data, NULL);
            else
                r->args = apr_pstrdup(r->pool, (char*) buf_data);
        }
        if (cid->dconf.log_to_errlog)
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "%s: %s", cid->r->filename,
                          (char*) buf_data);
        return 1;

    case HSE_REQ_IO_COMPLETION:
        /* Emulates a completion port...  Record callback address and
         * user defined arg, we will call this after any async request
         * (e.g. transmitfile) as if the request executed async.
         * Per MS docs... HSE_REQ_IO_COMPLETION replaces any prior call
         * to HSE_REQ_IO_COMPLETION, and buf_data may be set to NULL.
         */
        if (cid->dconf.fake_async) {
            cid->completion = (PFN_HSE_IO_COMPLETION) buf_data;
            cid->completion_arg = (void *) data_type;
            return 1;
        }
        if (cid->dconf.log_unsupported)
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "ServerSupportFunction HSE_REQ_IO_COMPLETION "
                      "is not supported: %s", r->filename);
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
        return 0;

    case HSE_REQ_TRANSMIT_FILE:
    {
        /* we do nothing with (tf->dwFlags & HSE_DISCONNECT_AFTER_SEND)
         */
        HSE_TF_INFO *tf = (HSE_TF_INFO*)buf_data;
        apr_uint32_t sent = 0;
        apr_ssize_t ate = 0;
        apr_bucket_brigade *bb;
        apr_bucket *b;
        apr_file_t *fd;
        apr_off_t fsize;

        if (!cid->dconf.fake_async && (tf->dwFlags & HSE_IO_ASYNC)) {
            if (cid->dconf.log_unsupported)
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                         "ServerSupportFunction HSE_REQ_TRANSMIT_FILE "
                         "as HSE_IO_ASYNC is not supported: %s", r->filename);
            apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
            return 0;
        }

        /* Presume the handle was opened with the CORRECT semantics
         * for TransmitFile
         */
        if ((rv = apr_os_file_put(&fd, &tf->hFile,
                                  APR_READ | APR_XTHREAD, r->pool))
                != APR_SUCCESS) {
            return 0;
        }
        if (tf->BytesToWrite) {
            fsize = tf->BytesToWrite;
        }
        else {
            apr_finfo_t fi;
            if (apr_file_info_get(&fi, APR_FINFO_SIZE, fd) != APR_SUCCESS) {
                apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
                return 0;
            }
            fsize = fi.size - tf->Offset;
        }

        /* apr_dupfile_oshandle (&fd, tf->hFile, r->pool); */
        bb = apr_brigade_create(r->pool, c->bucket_alloc);

        /* According to MS: if calling HSE_REQ_TRANSMIT_FILE with the
         * HSE_IO_SEND_HEADERS flag, then you can't otherwise call any
         * HSE_SEND_RESPONSE_HEADERS* fn, but if you don't use the flag,
         * you must have done so.  They document that the pHead headers
         * option is valid only for HSE_IO_SEND_HEADERS - we are a bit
         * more flexible and assume with the flag, pHead are the
         * response headers, and without, pHead simply contains text
         * (handled after this case).
         */
        if ((tf->dwFlags & HSE_IO_SEND_HEADERS) && tf->pszStatusCode) {
            ate = send_response_header(cid, tf->pszStatusCode,
                                            (char*)tf->pHead,
                                            strlen(tf->pszStatusCode),
                                            tf->HeadLength);
        }
        else if (!cid->headers_set && tf->pHead && tf->HeadLength
                                   && *(char*)tf->pHead) {
            ate = send_response_header(cid, NULL, (char*)tf->pHead,
                                            0, tf->HeadLength);
            if (ate < 0)
            {
                apr_brigade_destroy(bb);
                apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
                return 0;
            }
        }

        if (tf->pHead && (apr_size_t)ate < tf->HeadLength) {
            b = apr_bucket_transient_create((char*)tf->pHead + ate,
                                            tf->HeadLength - ate,
                                            c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, b);
            sent = tf->HeadLength;
        }

        sent += (apr_uint32_t)fsize;
        apr_brigade_insert_file(bb, fd, tf->Offset, fsize, r->pool);

        if (tf->pTail && tf->TailLength) {
            sent += tf->TailLength;
            b = apr_bucket_transient_create((char*)tf->pTail,
                                            tf->TailLength, c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, b);
        }

        b = apr_bucket_flush_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        rv = ap_pass_brigade(r->output_filters, bb);
        cid->response_sent = 1;
        if (rv != APR_SUCCESS)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                          "ServerSupport function "
                          "HSE_REQ_TRANSMIT_FILE "
                          "ap_pass_brigade failed: %s", r->filename);

        /* Use tf->pfnHseIO + tf->pContext, or if NULL, then use cid->fnIOComplete
         * pass pContect to the HseIO callback.
         */
        if (tf->dwFlags & HSE_IO_ASYNC) {
            if (tf->pfnHseIO) {
                if (rv == APR_SUCCESS) {
                    tf->pfnHseIO(cid->ecb, tf->pContext,
                                 ERROR_SUCCESS, sent);
                }
                else {
                    tf->pfnHseIO(cid->ecb, tf->pContext,
                                 ERROR_WRITE_FAULT, sent);
                }
            }
            else if (cid->completion) {
                if (rv == APR_SUCCESS) {
                    cid->completion(cid->ecb, cid->completion_arg,
                                    sent, ERROR_SUCCESS);
                }
                else {
                    cid->completion(cid->ecb, cid->completion_arg,
                                    sent, ERROR_WRITE_FAULT);
                }
            }
        }
        return (rv == APR_SUCCESS);
    }

    case HSE_REQ_REFRESH_ISAPI_ACL:
        if (cid->dconf.log_unsupported)
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "ServerSupportFunction "
                          "HSE_REQ_REFRESH_ISAPI_ACL "
                          "is not supported: %s", r->filename);
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
        return 0;

    case HSE_REQ_IS_KEEP_CONN:
        *((int *)buf_data) = (r->connection->keepalive == AP_CONN_KEEPALIVE);
        return 1;

    case HSE_REQ_ASYNC_READ_CLIENT:
    {
        apr_uint32_t read = 0;
        int res = 0;
        if (!cid->dconf.fake_async) {
            if (cid->dconf.log_unsupported)
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                            "asynchronous I/O not supported: %s",
                            r->filename);
            apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
            return 0;
        }

        if (r->remaining < *buf_size) {
            *buf_size = (apr_size_t)r->remaining;
        }

        while (read < *buf_size &&
            ((res = ap_get_client_block(r, (char*)buf_data + read,
                                        *buf_size - read)) > 0)) {
            read += res;
        }

        if ((*data_type & HSE_IO_ASYNC) && cid->completion) {
            /* XXX: Many authors issue their next HSE_REQ_ASYNC_READ_CLIENT
             * within the completion logic.  An example is MS's own PSDK
             * sample web/iis/extensions/io/ASyncRead.  This potentially
             * leads to stack exhaustion.  To refactor, the notification
             * logic needs to move to isapi_handler() - differentiating
             * the cid->completed event with a new flag to indicate
             * an async-notice versus the async request completed.
             */
            if (res >= 0) {
                cid->completion(cid->ecb, cid->completion_arg,
                                read, ERROR_SUCCESS);
            }
            else {
                cid->completion(cid->ecb, cid->completion_arg,
                                read, ERROR_READ_FAULT);
            }
        }
        return (res >= 0);
    }

    case HSE_REQ_GET_IMPERSONATION_TOKEN:  /* Added in ISAPI 4.0 */
        if (cid->dconf.log_unsupported)
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "ServerSupportFunction "
                          "HSE_REQ_GET_IMPERSONATION_TOKEN "
                          "is not supported: %s", r->filename);
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
        return 0;

    case HSE_REQ_MAP_URL_TO_PATH_EX:
    {
        /* Map a URL to a filename */
        HSE_URL_MAPEX_INFO *info = (HSE_URL_MAPEX_INFO*)data_type;
        char* test_uri = apr_pstrndup(r->pool, (char *)buf_data, *buf_size);

        subreq = ap_sub_req_lookup_uri(test_uri, r, NULL);
        info->cchMatchingURL = strlen(test_uri);
        info->cchMatchingPath = apr_cpystrn(info->lpszPath, subreq->filename,
                                      sizeof(info->lpszPath)) - info->lpszPath;

        /* Mapping started with assuming both strings matched.
         * Now roll on the path_info as a mismatch and handle
         * terminating slashes for directory matches.
         */
        if (subreq->path_info && *subreq->path_info) {
            apr_cpystrn(info->lpszPath + info->cchMatchingPath,
                        subreq->path_info,
                        sizeof(info->lpszPath) - info->cchMatchingPath);
            info->cchMatchingURL -= strlen(subreq->path_info);
            if (subreq->finfo.filetype == APR_DIR
                 && info->cchMatchingPath < sizeof(info->lpszPath) - 1) {
                /* roll forward over path_info's first slash */
                ++info->cchMatchingPath;
                ++info->cchMatchingURL;
            }
        }
        else if (subreq->finfo.filetype == APR_DIR
                 && info->cchMatchingPath < sizeof(info->lpszPath) - 1) {
            /* Add a trailing slash for directory */
            info->lpszPath[info->cchMatchingPath++] = '/';
            info->lpszPath[info->cchMatchingPath] = '\0';
        }

        /* If the matched isn't a file, roll match back to the prior slash */
        if (subreq->finfo.filetype == APR_NOFILE) {
            while (info->cchMatchingPath && info->cchMatchingURL) {
                if (info->lpszPath[info->cchMatchingPath - 1] == '/')
                    break;
                --info->cchMatchingPath;
                --info->cchMatchingURL;
            }
        }

        /* Paths returned with back slashes */
        for (test_uri = info->lpszPath; *test_uri; ++test_uri)
            if (*test_uri == '/')
                *test_uri = '\\';

        /* is a combination of:
         * HSE_URL_FLAGS_READ         0x001 Allow read
         * HSE_URL_FLAGS_WRITE        0x002 Allow write
         * HSE_URL_FLAGS_EXECUTE      0x004 Allow execute
         * HSE_URL_FLAGS_SSL          0x008 Require SSL
         * HSE_URL_FLAGS_DONT_CACHE   0x010 Don't cache (VRoot only)
         * HSE_URL_FLAGS_NEGO_CERT    0x020 Allow client SSL cert
         * HSE_URL_FLAGS_REQUIRE_CERT 0x040 Require client SSL cert
         * HSE_URL_FLAGS_MAP_CERT     0x080 Map client SSL cert to account
         * HSE_URL_FLAGS_SSL128       0x100 Require 128-bit SSL cert
         * HSE_URL_FLAGS_SCRIPT       0x200 Allow script execution
         *
         * XxX: As everywhere, EXEC flags could use some work...
         *      and this could go further with more flags, as desired.
         */
        info->dwFlags = (subreq->finfo.protection & APR_UREAD    ? 0x001 : 0)
                      | (subreq->finfo.protection & APR_UWRITE   ? 0x002 : 0)
                      | (subreq->finfo.protection & APR_UEXECUTE ? 0x204 : 0);
        return 1;
    }

    case HSE_REQ_ABORTIVE_CLOSE:
        if (cid->dconf.log_unsupported)
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "ServerSupportFunction HSE_REQ_ABORTIVE_CLOSE"
                          " is not supported: %s", r->filename);
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
        return 0;

    case HSE_REQ_GET_CERT_INFO_EX:  /* Added in ISAPI 4.0 */
        if (cid->dconf.log_unsupported)
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "ServerSupportFunction "
                          "HSE_REQ_GET_CERT_INFO_EX "
                          "is not supported: %s", r->filename);
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
        return 0;

    case HSE_REQ_SEND_RESPONSE_HEADER_EX:  /* Added in ISAPI 4.0 */
    {
        HSE_SEND_HEADER_EX_INFO *shi = (HSE_SEND_HEADER_EX_INFO*)buf_data;

        /*  Ignore shi->fKeepConn - we don't want the advise
         */
        apr_ssize_t ate = send_response_header(cid, shi->pszStatus,
                                               shi->pszHeader,
                                               shi->cchStatus,
                                               shi->cchHeader);
        if (ate < 0) {
            apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
            return 0;
        }
        else if ((apr_size_t)ate < shi->cchHeader) {
            apr_bucket_brigade *bb;
            apr_bucket *b;
            bb = apr_brigade_create(cid->r->pool, c->bucket_alloc);
            b = apr_bucket_transient_create(shi->pszHeader + ate,
                                            shi->cchHeader - ate,
                                            c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, b);
            b = apr_bucket_flush_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, b);
            rv = ap_pass_brigade(cid->r->output_filters, bb);
            cid->response_sent = 1;
            if (rv != APR_SUCCESS)
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                              "ServerSupport function "
                              "HSE_REQ_SEND_RESPONSE_HEADER_EX "
                              "ap_pass_brigade failed: %s", r->filename);
            return (rv == APR_SUCCESS);
        }
        /* Deliberately hold off sending 'just the headers' to begin to
         * accumulate the body and speed up the overall response, or at
         * least wait for the end the session.
         */
        return 1;
    }

    case HSE_REQ_CLOSE_CONNECTION:  /* Added after ISAPI 4.0 */
        if (cid->dconf.log_unsupported)
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "ServerSupportFunction "
                          "HSE_REQ_CLOSE_CONNECTION "
                          "is not supported: %s", r->filename);
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
        return 0;

    case HSE_REQ_IS_CONNECTED:  /* Added after ISAPI 4.0 */
        /* Returns True if client is connected c.f. MSKB Q188346
         * assuming the identical return mechanism as HSE_REQ_IS_KEEP_CONN
         */
        *((int *)buf_data) = (r->connection->aborted == 0);
        return 1;

    case HSE_REQ_EXTENSION_TRIGGER:  /* Added after ISAPI 4.0 */
        /*  Undocumented - defined by the Microsoft Jan '00 Platform SDK
         */
        if (cid->dconf.log_unsupported)
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "ServerSupportFunction "
                          "HSE_REQ_EXTENSION_TRIGGER "
                          "is not supported: %s", r->filename);
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
        return 0;

    default:
        if (cid->dconf.log_unsupported)
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "ServerSupportFunction (%d) not supported: "
                          "%s", HSE_code, r->filename);
        apr_set_os_error(APR_FROM_OS_ERROR(ERROR_INVALID_PARAMETER));
        return 0;
    }
}

/**********************************************************
 *
 *  ISAPI Module request invocation section
 *
 **********************************************************/

static apr_status_t isapi_handler (request_rec *r)
{
    isapi_dir_conf *dconf;
    apr_table_t *e;
    apr_status_t rv;
    isapi_loaded *isa;
    isapi_cid *cid;
    const char *val;
    apr_uint32_t read;
    int res;

    if(strcmp(r->handler, "isapi-isa")
        && strcmp(r->handler, "isapi-handler")) {
        /* Hang on to the isapi-isa for compatibility with older docs
         * (wtf did '-isa' mean in the first place?) but introduce
         * a newer and clearer "isapi-handler" name.
         */
        return DECLINED;
    }
    dconf = ap_get_module_config(r->per_dir_config, &isapi_module);
    e = r->subprocess_env;

    /* Use similar restrictions as CGIs
     *
     * If this fails, it's pointless to load the isapi dll.
     */
    if (!(ap_allow_options(r) & OPT_EXECCGI)) {
        return HTTP_FORBIDDEN;
    }
    if (r->finfo.filetype == APR_NOFILE) {
        return HTTP_NOT_FOUND;
    }
    if (r->finfo.filetype != APR_REG) {
        return HTTP_FORBIDDEN;
    }
    if ((r->used_path_info == AP_REQ_REJECT_PATH_INFO) &&
        r->path_info && *r->path_info) {
        /* default to accept */
        return HTTP_NOT_FOUND;
    }

    if (isapi_lookup(r->pool, r->server, r, r->filename, &isa)
           != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* Set up variables */
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);
    apr_table_setn(e, "UNMAPPED_REMOTE_USER", "REMOTE_USER");
    if ((val = apr_table_get(e, "HTTPS")) && (strcmp(val, "on") == 0))
        apr_table_setn(e, "SERVER_PORT_SECURE", "1");
    else
        apr_table_setn(e, "SERVER_PORT_SECURE", "0");
    apr_table_setn(e, "URL", r->uri);

    /* Set up connection structure and ecb,
     * NULL or zero out most fields.
     */
    cid = apr_pcalloc(r->pool, sizeof(isapi_cid));

    /* Fixup defaults for dconf */
    cid->dconf.read_ahead_buflen = (dconf->read_ahead_buflen == ISAPI_UNDEF)
                                     ? 49152 : dconf->read_ahead_buflen;
    cid->dconf.log_unsupported   = (dconf->log_unsupported == ISAPI_UNDEF)
                                     ? 0 : dconf->log_unsupported;
    cid->dconf.log_to_errlog     = (dconf->log_to_errlog == ISAPI_UNDEF)
                                     ? 0 : dconf->log_to_errlog;
    cid->dconf.log_to_query      = (dconf->log_to_query == ISAPI_UNDEF)
                                     ? 1 : dconf->log_to_query;
    cid->dconf.fake_async        = (dconf->fake_async == ISAPI_UNDEF)
                                     ? 0 : dconf->fake_async;

    cid->ecb = apr_pcalloc(r->pool, sizeof(EXTENSION_CONTROL_BLOCK));
    cid->ecb->ConnID = cid;
    cid->isa = isa;
    cid->r = r;
    r->status = 0;

    cid->ecb->cbSize = sizeof(EXTENSION_CONTROL_BLOCK);
    cid->ecb->dwVersion = isa->report_version;
    cid->ecb->dwHttpStatusCode = 0;
    strcpy(cid->ecb->lpszLogData, "");
    /* TODO: are copies really needed here?
     */
    cid->ecb->lpszMethod = (char*) r->method;
    cid->ecb->lpszQueryString = (char*) apr_table_get(e, "QUERY_STRING");
    cid->ecb->lpszPathInfo = (char*) apr_table_get(e, "PATH_INFO");
    cid->ecb->lpszPathTranslated = (char*) apr_table_get(e, "PATH_TRANSLATED");
    cid->ecb->lpszContentType = (char*) apr_table_get(e, "CONTENT_TYPE");

    /* Set up the callbacks */
    cid->ecb->GetServerVariable = regfnGetServerVariable;
    cid->ecb->WriteClient = regfnWriteClient;
    cid->ecb->ReadClient = regfnReadClient;
    cid->ecb->ServerSupportFunction = regfnServerSupportFunction;

    /* Set up client input */
    res = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
    if (res) {
        return res;
    }

    if (ap_should_client_block(r)) {
        /* Time to start reading the appropriate amount of data,
         * and allow the administrator to tweak the number
         */
        if (r->remaining) {
            cid->ecb->cbTotalBytes = (apr_size_t)r->remaining;
            if (cid->ecb->cbTotalBytes > (apr_uint32_t)cid->dconf.read_ahead_buflen)
                cid->ecb->cbAvailable = cid->dconf.read_ahead_buflen;
            else
                cid->ecb->cbAvailable = cid->ecb->cbTotalBytes;
        }
        else
        {
            cid->ecb->cbTotalBytes = 0xffffffff;
            cid->ecb->cbAvailable = cid->dconf.read_ahead_buflen;
        }

        cid->ecb->lpbData = apr_pcalloc(r->pool, cid->ecb->cbAvailable + 1);

        read = 0;
        while (read < cid->ecb->cbAvailable &&
               ((res = ap_get_client_block(r, (char*)cid->ecb->lpbData + read,
                                        cid->ecb->cbAvailable - read)) > 0)) {
            read += res;
        }

        if (res < 0) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Although it's not to spec, IIS seems to null-terminate
         * its lpdData string. So we will too.
         */
        if (res == 0)
            cid->ecb->cbAvailable = cid->ecb->cbTotalBytes = read;
        else
            cid->ecb->cbAvailable = read;
        cid->ecb->lpbData[read] = '\0';
    }
    else {
        cid->ecb->cbTotalBytes = 0;
        cid->ecb->cbAvailable = 0;
        cid->ecb->lpbData = NULL;
    }

    /* To emulate async behavior...
     *
     * We create a cid->completed mutex and lock on it so that the
     * app can believe is it running async.
     *
     * This request completes upon a notification through
     * ServerSupportFunction(HSE_REQ_DONE_WITH_SESSION), which
     * unlocks this mutex.  If the HttpExtensionProc() returns
     * HSE_STATUS_PENDING, we will attempt to gain this lock again
     * which may *only* happen once HSE_REQ_DONE_WITH_SESSION has
     * unlocked the mutex.
     */
    if (cid->dconf.fake_async) {
        rv = apr_thread_mutex_create(&cid->completed,
                                     APR_THREAD_MUTEX_UNNESTED,
                                     r->pool);
        if (cid->completed && (rv == APR_SUCCESS)) {
            rv = apr_thread_mutex_lock(cid->completed);
        }

        if (!cid->completed || (rv != APR_SUCCESS)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02112)
                          "Failed to create completion mutex");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* All right... try and run the sucker */
    rv = (*isa->HttpExtensionProc)(cid->ecb);

    /* Check for a log message - and log it */
    if (cid->ecb->lpszLogData && *cid->ecb->lpszLogData)
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02113)
                      "%s: %s", r->filename, cid->ecb->lpszLogData);

    switch(rv) {
        case 0:  /* Strange, but MS isapi accepts this as success */
        case HSE_STATUS_SUCCESS:
        case HSE_STATUS_SUCCESS_AND_KEEP_CONN:
            /* Ignore the keepalive stuff; Apache handles it just fine without
             * the ISAPI Handler's "advice".
             * Per Microsoft: "In IIS versions 4.0 and later, the return
             * values HSE_STATUS_SUCCESS and HSE_STATUS_SUCCESS_AND_KEEP_CONN
             * are functionally identical: Keep-Alive connections are
             * maintained, if supported by the client."
             * ... so we were pat all this time
             */
            break;

        case HSE_STATUS_PENDING:
            /* emulating async behavior...
             */
            if (cid->completed) {
                /* The completion port was locked prior to invoking
                 * HttpExtensionProc().  Once we can regain the lock,
                 * when ServerSupportFunction(HSE_REQ_DONE_WITH_SESSION)
                 * is called by the extension to release the lock,
                 * we may finally destroy the request.
                 */
                (void)apr_thread_mutex_lock(cid->completed);
                break;
            }
            else if (cid->dconf.log_unsupported) {
                 ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02114)
                               "asynch I/O result HSE_STATUS_PENDING "
                               "from HttpExtensionProc() is not supported: %s",
                               r->filename);
                 r->status = HTTP_INTERNAL_SERVER_ERROR;
            }
            break;

        case HSE_STATUS_ERROR:
            /* end response if we have yet to do so.
             */
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, apr_get_os_error(), r, APLOGNO(02115)
                          "HSE_STATUS_ERROR result from "
                          "HttpExtensionProc(): %s", r->filename);
            r->status = HTTP_INTERNAL_SERVER_ERROR;
            break;

        default:
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, apr_get_os_error(), r, APLOGNO(02116)
                          "unrecognized result code %d "
                          "from HttpExtensionProc(): %s ",
                          rv, r->filename);
            r->status = HTTP_INTERNAL_SERVER_ERROR;
            break;
    }

    /* Flush the response now, including headers-only responses */
    if (cid->headers_set || cid->response_sent) {
        conn_rec *c = r->connection;
        apr_bucket_brigade *bb;
        apr_bucket *b;
        apr_status_t rv;

        bb = apr_brigade_create(r->pool, c->bucket_alloc);
        b = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        rv = ap_pass_brigade(r->output_filters, bb);
        cid->response_sent = 1;

        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(02117)
                          "ap_pass_brigade failed to "
                          "complete the response: %s ", r->filename);
        }

        return OK; /* NOT r->status, even if it has changed. */
    }

    /* As the client returned no error, and if we did not error out
     * ourselves, trust dwHttpStatusCode to say something relevant.
     */
    if (!ap_is_HTTP_SERVER_ERROR(r->status) && cid->ecb->dwHttpStatusCode) {
        r->status = cid->ecb->dwHttpStatusCode;
    }

    /* For all missing-response situations simply return the status,
     * and let the core respond to the client.
     */
    return r->status;
}

/**********************************************************
 *
 *  ISAPI Module Setup Hooks
 *
 **********************************************************/

static int isapi_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    apr_status_t rv;

    apr_pool_create_ex(&loaded.pool, pconf, NULL, NULL);
    if (!loaded.pool) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, NULL, APLOGNO(02118)
                     "could not create the isapi cache pool");
        return APR_EGENERAL;
    }

    loaded.hash = apr_hash_make(loaded.pool);
    if (!loaded.hash) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(02119)
                     "Failed to create module cache");
        return APR_EGENERAL;
    }

    rv = apr_thread_mutex_create(&loaded.lock, APR_THREAD_MUTEX_DEFAULT,
                                 loaded.pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                     "Failed to create module cache lock");
        return rv;
    }
    return OK;
}

static void isapi_hooks(apr_pool_t *cont)
{
    ap_hook_pre_config(isapi_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(isapi_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(isapi) = {
   STANDARD20_MODULE_STUFF,
   create_isapi_dir_config,     /* create per-dir config */
   merge_isapi_dir_configs,     /* merge per-dir config */
   NULL,                        /* server config */
   NULL,                        /* merge server config */
   isapi_cmds,                  /* command apr_table_t */
   isapi_hooks                  /* register hooks */
};
