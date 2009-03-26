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
 *  mod_example_ipc -- Apache sample module 
 * 
 * This module illustrates the use in an Apache 2.x module of the Interprocess
 * Communications routines that come with APR. It is example code, and not meant 
 * to be used in a production server. 
 *
 * To play with this sample module first compile it into a DSO file and install
 * it into Apache's modules directory by running:
 *
 *    $ /path/to/apache2/bin/apxs -c -i mod_example_ipc.c
 *
 * Then activate it in Apache's httpd.conf file for instance for the URL
 * /example_ipc in as follows:
 *
 *    #   httpd.conf
 *    LoadModule example_ipc_module modules/mod_example_ipc.so
 *    <Location /example_ipc>
 *    SetHandler example_ipc
 *    </Location>
 *
 * Then restart Apache via
 *
 *    $ /path/to/apache2/bin/apachectl restart
 *
 * The module allocates a counter in shared memory, which is incremented by the
 * request handler under a mutex. After installation, activate the handler by
 * hitting the URL configured above with ab at various concurrency levels to see
 * how mutex contention affects server performance. 
 */ 

#include "apr.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"

#if !defined(WIN32) && !defined(NETWARE)
#include "unixd.h"
#define MOD_EXIPC_SET_MUTEX_PERMS /* XXX Apache should define something */
#endif

#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#define HTML_HEADER "<html>\n<head>\n<title>Mod_example_IPC Status Page " \
                    "</title>\n</head>\n<body>\n<h1>Mod_example_IPC Status</h1>\n"
#define HTML_FOOTER "</body>\n</html>\n"

/* Number of microseconds to camp out on the mutex */
#define CAMPOUT 10
/* Maximum number of times we camp out before giving up */
#define MAXCAMP 10
/* Number of microseconds the handler sits on the lock once acquired. */
#define SLEEPYTIME 1000

apr_shm_t *exipc_shm; /* Pointer to shared memory block */
char *shmfilename; /* Shared memory file name, used on some systems */
apr_global_mutex_t *exipc_mutex; /* Lock around shared memory segment access */
char *mutexfilename; /* Lock file name, used on some systems */

/* Data structure for shared memory block */
typedef struct exipc_data {
    apr_uint64_t counter; 
    /* More fields if necessary */
} exipc_data;

/* 
 * Clean up the shared memory block. This function is registered as 
 * cleanup function for the configuration pool, which gets called
 * on restarts. It assures that the new children will not talk to a stale 
 * shared memory segment. 
 */
static apr_status_t shm_cleanup_wrapper(void *unused) {
    if (exipc_shm)
        return apr_shm_destroy(exipc_shm);
    return OK;
}


/* 
 * This routine is called in the parent, so we'll set up the shared
 * memory segment and mutex here. 
 */

static int exipc_post_config(apr_pool_t *pconf, apr_pool_t *plog, 
                             apr_pool_t *ptemp, server_rec *s)
{
    void *data; /* These two help ensure that we only init once. */
    const char *userdata_key;
    apr_status_t rs;
    exipc_data *base;
    const char *tempdir; 


    /* 
     * The following checks if this routine has been called before. 
     * This is necessary because the parent process gets initialized
     * a couple of times as the server starts up, and we don't want 
     * to create any more mutexes and shared memory segments than
     * we're actually going to use. 
     * 
     * The key needs to be unique for the entire web server, so put
     * the module name in it.
     */ 
    userdata_key = "example_ipc_init_module";
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        /* 
         * If no data was found for our key, this must be the first
         * time the module is initialized. Put some data under that
         * key and return.
         */
        apr_pool_userdata_set((const void *) 1, userdata_key, 
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    } /* Kilroy was here */

    /* 
     * Both the shared memory and mutex allocation routines take a
     * file name. Depending on system-specific implementation of these
     * routines, that file may or may not actually be created. We'd
     * like to store those files in the operating system's designated
     * temporary directory, which APR can point us to.
     */
    rs = apr_temp_dir_get(&tempdir, pconf);
    if (APR_SUCCESS != rs) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rs, s, 
                     "Failed to find temporary directory");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Create the shared memory segment */

    /* 
     * Create a unique filename using our pid. This information is 
     * stashed in the global variable so the children inherit it.
     */
    shmfilename = apr_psprintf(pconf, "%s/httpd_shm.%ld", tempdir, 
                               (long int)getpid());

    /* Now create that segment */
    rs = apr_shm_create(&exipc_shm, sizeof(exipc_data), 
                        (const char *) shmfilename, pconf);
    if (APR_SUCCESS != rs) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rs, s, 
                     "Failed to create shared memory segment on file %s", 
                     shmfilename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Created it, now let's zero it out */
    base = (exipc_data *)apr_shm_baseaddr_get(exipc_shm);
    base->counter = 0;

    /* Create global mutex */

    /* 
     * Create another unique filename to lock upon. Note that
     * depending on OS and locking mechanism of choice, the file
     * may or may not be actually created. 
     */
    mutexfilename = apr_psprintf(pconf, "%s/httpd_mutex.%ld", tempdir,
                                 (long int) getpid());
  
    rs = apr_global_mutex_create(&exipc_mutex, (const char *) mutexfilename, 
                                 APR_LOCK_DEFAULT, pconf);
    if (APR_SUCCESS != rs) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rs, s, 
                     "Failed to create mutex on file %s", 
                     mutexfilename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 
     * After the mutex is created, its permissions need to be adjusted
     * on unix platforms so that the child processe can acquire
     * it. This call takes care of that. The preprocessor define was
     * set up early in this source file since Apache doesn't provide
     * it.
     */
#ifdef MOD_EXIPC_SET_MUTEX_PERMS
    rs = ap_unixd_set_global_mutex_perms(exipc_mutex);
    if (APR_SUCCESS != rs) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rs, s, 
                     "Parent could not set permissions on Example IPC "
                     "mutex: check User and Group directives");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif /* MOD_EXIPC_SET_MUTEX_PERMS */

    /* 
     * Destroy the shm segment when the configuration pool gets destroyed. This
     * happens on server restarts. The parent will then (above) allocate a new
     * shm segment that the new children will bind to. 
     */
    apr_pool_cleanup_register(pconf, NULL, shm_cleanup_wrapper, 
                              apr_pool_cleanup_null);    
    return OK;
}

/* 
 * This routine gets called when a child inits. We use it to attach
 * to the shared memory segment, and reinitialize the mutex.
 */

static void exipc_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rs;
         
    /* 
     * Re-open the mutex for the child. Note we're reusing
     * the mutex pointer global here. 
     */
    rs = apr_global_mutex_child_init(&exipc_mutex, 
                                     (const char *) mutexfilename, 
                                     p);
    if (APR_SUCCESS != rs) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rs, s, 
                     "Failed to reopen mutex on file %s", 
                     shmfilename);
        /* There's really nothing else we can do here, since This
         * routine doesn't return a status. If this ever goes wrong,
         * it will turn Apache into a fork bomb. Let's hope it never
         * will.
         */
        exit(1); /* Ugly, but what else? */
    } 
}

/* The sample content handler */
static int exipc_handler(request_rec *r)
{
    int gotlock = 0;
    int camped;
    apr_time_t startcamp;
    apr_int64_t timecamped;
    apr_status_t rs; 
    exipc_data *base;
    
    if (strcmp(r->handler, "example_ipc")) {
        return DECLINED;
    }
    
    /* 
     * The main function of the handler, aside from sending the 
     * status page to the client, is to increment the counter in 
     * the shared memory segment. This action needs to be mutexed 
     * out using the global mutex. 
     */
     
    /* 
     * First, acquire the lock. This code is a lot more involved than
     * it usually needs to be, because the process based trylock
     * routine is not implemented on unix platforms. I left it in to
     * show how it would work if trylock worked, and for situations
     * and platforms where trylock works.
     */
    for (camped = 0, timecamped = 0; camped < MAXCAMP; camped++) {
        rs = apr_global_mutex_trylock(exipc_mutex); 
        if (APR_STATUS_IS_EBUSY(rs)) {
            apr_sleep(CAMPOUT);
        } else if (APR_SUCCESS == rs) {
            gotlock = 1; 
            break; /* Get out of the loop */
        } else if (APR_STATUS_IS_ENOTIMPL(rs)) {
            /* If it's not implemented, just hang in the mutex. */
            startcamp = apr_time_now();
            rs = apr_global_mutex_lock(exipc_mutex);
            timecamped = (apr_int64_t) (apr_time_now() - startcamp);
            if (APR_SUCCESS == rs) {
                gotlock = 1;
                break; /* Out of the loop */
            } else {
                /* Some error, log and bail */
                ap_log_error(APLOG_MARK, APLOG_ERR, rs, r->server, 
                             "Child %ld failed to acquire lock", 
                             (long int)getpid());
                break; /* Out of the loop without having the lock */
            }                
        } else {
            /* Some other error, log and bail */
            ap_log_error(APLOG_MARK, APLOG_ERR, rs, r->server, 
                         "Child %ld failed to try and acquire lock", 
                         (long int)getpid());
            break; /* Out of the loop without having the lock */
            
        }
        /* 
         * The only way to get to this point is if the trylock worked
         * and returned BUSY. So, bump the time and try again
         */
        timecamped += CAMPOUT;
        ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_NOTICE, 
                     0, r->server, "Child %ld camping out on mutex for %" APR_INT64_T_FMT
                     " microseconds",
                     (long int) getpid(), timecamped);
    } /* Lock acquisition loop */
    
    /* Sleep for a millisecond to make it a little harder for
     * httpd children to acquire the lock. 
     */
    apr_sleep(SLEEPYTIME);
    
    r->content_type = "text/html";      

    if (!r->header_only) {
        ap_rputs(HTML_HEADER, r);
        if (gotlock) {
            /* Increment the counter */
            base = (exipc_data *)apr_shm_baseaddr_get(exipc_shm);
            base->counter++;
            /* Send a page with our pid and the new value of the counter. */
            ap_rprintf(r, "<p>Lock acquired after %ld microseoncds.</p>\n", 
                       (long int) timecamped); 
            ap_rputs("<table border=\"1\">\n", r);
            ap_rprintf(r, "<tr><td>Child pid:</td><td>%d</td></tr>\n", 
                       (int) getpid());
            ap_rprintf(r, "<tr><td>Counter:</td><td>%u</td></tr>\n", 
                       (unsigned int)base->counter);
            ap_rputs("</table>\n", r);
        } else {
            /* 
             * Send a page saying that we couldn't get the lock. Don't say
             * what the counter is, because without the lock the value could
             * race. 
             */
            ap_rprintf(r, "<p>Child %d failed to acquire lock "
                       "after camping out for %d microseconds.</p>\n", 
                       (int) getpid(), (int) timecamped);
        }
        ap_rputs(HTML_FOOTER, r); 
    } /* r->header_only */
    
    /* Release the lock */
    if (gotlock)
        rs = apr_global_mutex_unlock(exipc_mutex); 
    /* Swallowing the result because what are we going to do with it at 
     * this stage? 
     */

    return OK;
}

static void exipc_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(exipc_post_config, NULL, NULL, APR_HOOK_MIDDLE); 
    ap_hook_child_init(exipc_child_init, NULL, NULL, APR_HOOK_MIDDLE); 
    ap_hook_handler(exipc_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA example_ipc_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    exipc_register_hooks   /* register hooks                      */
};

