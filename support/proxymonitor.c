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
 * proxymonitor.c: simple program for monitor proxy back-end server.
 *
 */

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"
#include "apr_getopt.h"
#include "apr_ring.h"
#include "apr_date.h"

#include "mod_proxy.h"
#include "ajp.h"

#include "slotmem.h"
#include "sharedmem_util.h"
#include "mod_proxy_health_checker.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif

static int interrupted; /* flag: true if SIGINT or SIGTERM occurred */

static apr_time_t now;  /* start time of this processing run */

extern int AP_DECLARE_DATA ap_default_loglevel;

static apr_file_t *errfile;   /* stderr file handle */
static apr_file_t *outfile;   /* stdout file handle */

/* short program name as called */
static const char *shortname = "proxymonitor";

static const health_worker_method *worker_storage;

char *basedir = NULL;

/* XXX: hack to use a part of the mod_sharedmem and mod_proxy_health_checker */
static apr_status_t init_healthck(apr_pool_t *pool, int *num)
{
    apr_size_t size;
    apr_status_t rv;
    const slotmem_storage_method *checkstorage;
    ap_slotmem_t *myscore;
    
    sharedmem_initglobalpool(pool);
    checkstorage = sharedmem_getstorage();
    rv = checkstorage->ap_slotmem_attach(&myscore, "proxy/checker", &size, num, pool);

    health_checker_init_slotmem_storage(checkstorage);
    health_checker_init_slotmem(myscore);
    worker_storage = health_checker_get_storage();

    return rv;
}

/*
 * httpd routine to be able to link with the modules.
 */
char * ap_server_root_relative(apr_pool_t *p, const char *name)
{
    char *fname;

    /* XXX: apr_filepath_merge better ? */
    if (basedir && name[0] != '/') {
        fname = apr_pstrcat(p, basedir, "/", name, NULL);
    } else {
        fname = apr_pstrdup(p, name);
    }
    return fname;
}

/*
 * called on SIGINT or SIGTERM
 */
static void setterm(int unused)
{
    interrupted = 1;
}

/*
 * called in out of memory condition
 */
static int oom(int unused)
{
    static int called = 0;

    /* be careful to call exit() only once */
    if (!called) {
        called = 1;
        exit(1);
    }
    return APR_ENOMEM;
}

/*
 * usage info
 */
#define NL APR_EOL_STR
static void usage(void)
{
    apr_file_printf(errfile,
    "%s -- program for monitoring proxies of httpd."                         NL
    "Usage: %s [-n] [-pPATH] [-dINTERVAL] [-rN]"                             NL
                                                                             NL
    "Options:"                                                               NL
    "  -d   Repeat checking every INTERVAL seconds."                         NL
                                                                             NL
    "  -r   Repeat checking N times."                                        NL
                                                                             NL
    "  -p   Specify PATH where the httpd is running."                        NL,

    shortname,
    shortname,
    shortname
    );

    exit(1);
}
#undef NL

/* Quick hack to allow logging */
AP_DECLARE(void) ap_log_error(const char *file, int line, int level,
                              apr_status_t status, const server_rec *s,
                              const char *fmt, ...)
{
    va_list args;
    char scratch[MAX_STRING_LEN];

    va_start(args, fmt);
    apr_vsnprintf(scratch, MAX_STRING_LEN, fmt, args);
    apr_file_printf(errfile,"%s\n", scratch);
    va_end(args);
}

/*
 * Reads the configuration from shared memory
 */
int process_sharedmem(apr_pool_t *pool, int num)
{
    apr_status_t rv;
    int n;
    struct proxy_worker_conf *worker;
    char *balancer_name;
    int status;

    for (n = 0; n < num; n++) {

        rv = worker_storage->get_entryconf(n, &worker, &balancer_name, pool);
        if (worker->used == 0 || worker->used  == 2)
            continue;
        worker_storage->get_health(n, &status);
         apr_file_printf(outfile, "balancer %s worker %s: host %s port %d status: %d ", 
                worker->balancer_name,  worker->name,
                worker->hostname,  worker->port, status);
        rv = worker_storage->check_entryhealth(n, pool);
        if (rv != APR_SUCCESS) {
            apr_file_printf(outfile, "now: FAILED\n");
            worker_storage->set_health(n, HEALTH_NO);
        } else {
            apr_file_printf(outfile, "now: OK\n");
            worker_storage->set_health(n, HEALTH_OK);
        }
    }
}

/*
 * main
 */
int main(int argc, const char * const argv[])
{
    apr_time_t current, delay;
    apr_status_t status;
    apr_pool_t *pool, *instance, *instance_socket;
    apr_getopt_t *o;
    int repeat = -1;
    char opt;
    const char *arg;
    char datestring[APR_RFC822_DATE_LEN];
    int num;

    /* only log errors */
    // ap_default_loglevel = APLOG_ERR;

    delay = 5 * APR_USEC_PER_SEC;

    if (apr_app_initialize(&argc, &argv, NULL) != APR_SUCCESS) {
        return 1;
    }
    atexit(apr_terminate);

    if (argc) {
        shortname = apr_filepath_name_get(argv[0]);
    }

    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        return 1;
    }
    apr_pool_abort_set(oom, pool);
    apr_file_open_stderr(&errfile, pool);
    apr_file_open_stdout(&outfile, pool);
    apr_signal(SIGINT, setterm);
    apr_signal(SIGTERM, setterm);

    apr_getopt_init(&o, pool, argc, argv);

    while (1) {
        status = apr_getopt(o, "p:d:r:", &opt, &arg);
        if (status == APR_EOF) {
            break;
        }
        else if (status != APR_SUCCESS) {
            usage();
        }
        else {
            switch (opt) {
            case 'd':
                delay = apr_atoi64(arg);
                delay *= APR_USEC_PER_SEC;
                break;


            case 'r':
                repeat = apr_atoi64(arg);
                break;

            case 'p':
                if (basedir) {
                    usage();
                }
                basedir = apr_pstrdup(pool, arg);
                break;
            default:
                usage();
            } /* switch */
        } /* else */
    } /* while */
    if (basedir == NULL)
        usage();

    instance_socket = NULL;

    while (repeat && ! interrupted) {

        if (instance_socket == NULL) {
            apr_pool_create(&instance_socket, pool);
            init_healthck(instance_socket, &num);
        }

        apr_pool_create(&instance, instance_socket);
        apr_sleep(delay);
        now = apr_time_now();
        process_sharedmem(instance_socket, num);
        current = apr_time_now();
        apr_rfc822_date(datestring, current);
        apr_file_printf(outfile,"at %s in %d\n", datestring, current-now);

        if (repeat>0)
            repeat--;
        apr_pool_destroy(instance);
        /* If something goes really wrong we should clean all */
        if (0) {
            apr_pool_destroy(instance_socket);
            instance_socket = NULL;
        }
    }
    if (interrupted) {
        apr_file_printf(errfile, "Monitoring aborted due to user "
                                 "request." APR_EOL_STR);
        return 1;
    }

    return 0;
}
