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

#include "apr.h"
#include "apr_strings.h"
#include "apr_getopt.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "apr_md5.h"
#include "apr_time.h"
#include "apr_version.h"
#include "apu_version.h"

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_vhost.h"
#include "apr_uri.h"
#include "util_ebcdic.h"
#include "ap_mpm.h"
#include "mpm_common.h"
#include "ap_expr.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* WARNING: Win32 binds http_main.c dynamically to the server. Please place
 *          extern functions and global data in another appropriate module.
 *
 * Most significant main() global data can be found in http_config.c
 */

/* XXX call after module loading based on some cmd-line option/define
 */

static void show_mpm_settings(void)
{
    int mpm_query_info;
    apr_status_t retval;

    printf("Server MPM:     %s\n", ap_show_mpm());

    retval = ap_mpm_query(AP_MPMQ_IS_THREADED, &mpm_query_info);

    if (retval == APR_SUCCESS) {
        printf("  threaded:     ");

        if (mpm_query_info == AP_MPMQ_DYNAMIC) {
            printf("yes (variable thread count)\n");
        }
        else if (mpm_query_info == AP_MPMQ_STATIC) {
            printf("yes (fixed thread count)\n");
        }
        else {
            printf("no\n");
        }
    }

    retval = ap_mpm_query(AP_MPMQ_IS_FORKED, &mpm_query_info);

    if (retval == APR_SUCCESS) {
        printf("    forked:     ");

        if (mpm_query_info == AP_MPMQ_DYNAMIC) {
            printf("yes (variable process count)\n");
        }
        else if (mpm_query_info == AP_MPMQ_STATIC) {
            printf("yes (fixed process count)\n");
        }
        else {
            printf("no\n");
        }
    }
}

static void show_compile_settings(void)
{
    printf("Server version: %s\n", ap_get_server_description());
    printf("Server built:   %s\n", ap_get_server_built());
    printf("Server's Module Magic Number: %u:%u\n",
           MODULE_MAGIC_NUMBER_MAJOR, MODULE_MAGIC_NUMBER_MINOR);
    printf("Server loaded:  APR %s, APR-UTIL %s\n",
           apr_version_string(), apu_version_string());
    printf("Compiled using: APR %s, APR-UTIL %s\n",
           APR_VERSION_STRING, APU_VERSION_STRING);
    /* sizeof(foo) is long on some platforms so we might as well
     * make it long everywhere to keep the printf format
     * consistent
     */
    printf("Architecture:   %ld-bit\n", 8 * (long)sizeof(void *));

    printf("Server compiled with....\n");
#ifdef BIG_SECURITY_HOLE
    printf(" -D BIG_SECURITY_HOLE\n");
#endif

#ifdef SECURITY_HOLE_PASS_AUTHORIZATION
    printf(" -D SECURITY_HOLE_PASS_AUTHORIZATION\n");
#endif

#ifdef OS
    printf(" -D OS=\"" OS "\"\n");
#endif

#ifdef APACHE_MPM_DIR
    printf(" -D APACHE_MPM_DIR=\"" APACHE_MPM_DIR "\"\n");
#endif

#ifdef HAVE_SHMGET
    printf(" -D HAVE_SHMGET\n");
#endif

#if APR_FILE_BASED_SHM
    printf(" -D APR_FILE_BASED_SHM\n");
#endif

#if APR_HAS_SENDFILE
    printf(" -D APR_HAS_SENDFILE\n");
#endif

#if APR_HAS_MMAP
    printf(" -D APR_HAS_MMAP\n");
#endif

#ifdef NO_WRITEV
    printf(" -D NO_WRITEV\n");
#endif

#ifdef NO_LINGCLOSE
    printf(" -D NO_LINGCLOSE\n");
#endif

#if APR_HAVE_IPV6
    printf(" -D APR_HAVE_IPV6 (IPv4-mapped addresses ");
#ifdef AP_ENABLE_V4_MAPPED
    printf("enabled)\n");
#else
    printf("disabled)\n");
#endif
#endif

#if APR_USE_FLOCK_SERIALIZE
    printf(" -D APR_USE_FLOCK_SERIALIZE\n");
#endif

#if APR_USE_SYSVSEM_SERIALIZE
    printf(" -D APR_USE_SYSVSEM_SERIALIZE\n");
#endif

#if APR_USE_POSIXSEM_SERIALIZE
    printf(" -D APR_USE_POSIXSEM_SERIALIZE\n");
#endif

#if APR_USE_FCNTL_SERIALIZE
    printf(" -D APR_USE_FCNTL_SERIALIZE\n");
#endif

#if APR_USE_PROC_PTHREAD_SERIALIZE
    printf(" -D APR_USE_PROC_PTHREAD_SERIALIZE\n");
#endif

#if APR_USE_PTHREAD_SERIALIZE
    printf(" -D APR_USE_PTHREAD_SERIALIZE\n");
#endif

#if APR_PROCESS_LOCK_IS_GLOBAL
    printf(" -D APR_PROCESS_LOCK_IS_GLOBAL\n");
#endif

#ifdef SINGLE_LISTEN_UNSERIALIZED_ACCEPT
    printf(" -D SINGLE_LISTEN_UNSERIALIZED_ACCEPT\n");
#endif

#if APR_HAS_OTHER_CHILD
    printf(" -D APR_HAS_OTHER_CHILD\n");
#endif

#ifdef AP_HAVE_RELIABLE_PIPED_LOGS
    printf(" -D AP_HAVE_RELIABLE_PIPED_LOGS\n");
#endif

#ifdef BUFFERED_LOGS
    printf(" -D BUFFERED_LOGS\n");
#ifdef PIPE_BUF
    printf(" -D PIPE_BUF=%ld\n",(long)PIPE_BUF);
#endif
#endif

    printf(" -D DYNAMIC_MODULE_LIMIT=%ld\n",(long)DYNAMIC_MODULE_LIMIT);

#if APR_CHARSET_EBCDIC
    printf(" -D APR_CHARSET_EBCDIC\n");
#endif

#ifdef NEED_HASHBANG_EMUL
    printf(" -D NEED_HASHBANG_EMUL\n");
#endif

#ifdef SHARED_CORE
    printf(" -D SHARED_CORE\n");
#endif

/* This list displays the compiled in default paths: */
#ifdef HTTPD_ROOT
    printf(" -D HTTPD_ROOT=\"" HTTPD_ROOT "\"\n");
#endif

#ifdef SUEXEC_BIN
    printf(" -D SUEXEC_BIN=\"" SUEXEC_BIN "\"\n");
#endif

#if defined(SHARED_CORE) && defined(SHARED_CORE_DIR)
    printf(" -D SHARED_CORE_DIR=\"" SHARED_CORE_DIR "\"\n");
#endif

#ifdef DEFAULT_PIDLOG
    printf(" -D DEFAULT_PIDLOG=\"" DEFAULT_PIDLOG "\"\n");
#endif

#ifdef DEFAULT_SCOREBOARD
    printf(" -D DEFAULT_SCOREBOARD=\"" DEFAULT_SCOREBOARD "\"\n");
#endif

#ifdef DEFAULT_LOCKFILE
    printf(" -D DEFAULT_LOCKFILE=\"" DEFAULT_LOCKFILE "\"\n");
#endif

#ifdef DEFAULT_ERRORLOG
    printf(" -D DEFAULT_ERRORLOG=\"" DEFAULT_ERRORLOG "\"\n");
#endif

#ifdef AP_TYPES_CONFIG_FILE
    printf(" -D AP_TYPES_CONFIG_FILE=\"" AP_TYPES_CONFIG_FILE "\"\n");
#endif

#ifdef SERVER_CONFIG_FILE
    printf(" -D SERVER_CONFIG_FILE=\"" SERVER_CONFIG_FILE "\"\n");
#endif
}

#define TASK_SWITCH_SLEEP 10000

static void destroy_and_exit_process(process_rec *process,
                                     int process_exit_value)
{
    /*
     * Sleep for TASK_SWITCH_SLEEP micro seconds to cause a task switch on
     * OS layer and thus give possibly started piped loggers a chance to
     * process their input. Otherwise it is possible that they get killed
     * by us before they can do so. In this case maybe valueable log messages
     * might get lost.
     */
    apr_sleep(TASK_SWITCH_SLEEP);
    apr_pool_destroy(process->pool); /* and destroy all descendent pools */
    apr_terminate();
    exit(process_exit_value);
}

#define OOM_MESSAGE "[crit] Memory allocation failed, " \
    "aborting process." APR_EOL_STR

/* APR callback invoked if allocation fails. */
static int abort_on_oom(int retcode)
{
    write(STDERR_FILENO, OOM_MESSAGE, strlen(OOM_MESSAGE));
    abort();
    return retcode; /* unreachable, hopefully. */
}

static process_rec *init_process(int *argc, const char * const * *argv)
{
    process_rec *process;
    apr_pool_t *cntx;
    apr_status_t stat;
    const char *failed = "apr_app_initialize()";

    stat = apr_app_initialize(argc, argv, NULL);
    if (stat == APR_SUCCESS) {
        failed = "apr_pool_create()";
        stat = apr_pool_create(&cntx, NULL);
    }

    if (stat != APR_SUCCESS) {
        /* For all intents and purposes, this is impossibly unlikely,
         * but APR doesn't exist yet, we can't use it for reporting
         * these earliest two failures;
         *
         * XXX: Note the apr_ctime() and apr_time_now() calls.  These
         * work, today, against an uninitialized APR, but in the future
         * (if they relied on global pools or mutexes, for example) then
         * the datestamp logic will need to be replaced.
         */
        char ctimebuff[APR_CTIME_LEN];
        apr_ctime(ctimebuff, apr_time_now());
        fprintf(stderr, "[%s] [crit] (%d) %s: %s failed "
                        "to initial context, exiting\n", 
                        ctimebuff, stat, (*argv)[0], failed);
        apr_terminate();
        exit(1);
    }

    apr_pool_abort_set(abort_on_oom, cntx);
    apr_pool_tag(cntx, "process");
    ap_open_stderr_log(cntx);

    /* Now we have initialized apr and our logger, no more
     * exceptional error reporting required for the lifetime
     * of this server process.
     */

    process = apr_palloc(cntx, sizeof(process_rec));
    process->pool = cntx;

    apr_pool_create(&process->pconf, process->pool);
    apr_pool_tag(process->pconf, "pconf");
    process->argc = *argc;
    process->argv = *argv;
    process->short_name = apr_filepath_name_get((*argv)[0]);
    return process;
}

static void usage(process_rec *process)
{
    const char *bin = process->argv[0];
    char pad[MAX_STRING_LEN];
    unsigned i;

    for (i = 0; i < strlen(bin); i++) {
        pad[i] = ' ';
    }

    pad[i] = '\0';

#ifdef SHARED_CORE
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL ,
                 "Usage: %s [-R directory] [-D name] [-d directory] [-f file]",
                 bin);
#else
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "Usage: %s [-D name] [-d directory] [-f file]", bin);
#endif

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "       %s [-C \"directive\"] [-c \"directive\"]", pad);

#ifdef WIN32
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "       %s [-w] [-k start|restart|stop|shutdown]", pad);
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "       %s [-k install|config|uninstall] [-n service_name]",
                 pad);
#endif
/* XXX not all MPMs support signalling the server in general or graceful-stop
 * in particular
 */
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "       %s [-k start|restart|graceful|graceful-stop|stop]",
                 pad);
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "       %s [-v] [-V] [-h] [-l] [-L] [-t] [-S]", pad);
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "Options:");

#ifdef SHARED_CORE
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -R directory       : specify an alternate location for "
                 "shared object files");
#endif

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -D name            : define a name for use in "
                 "<IfDefine name> directives");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -d directory       : specify an alternate initial "
                 "ServerRoot");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -f file            : specify an alternate ServerConfigFile");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -C \"directive\"     : process directive before reading "
                 "config files");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -c \"directive\"     : process directive after reading "
                 "config files");

#ifdef NETWARE
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -n name            : set screen name");
#endif
#ifdef WIN32
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -n name            : set service name and use its "
                 "ServerConfigFile");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -k start           : tell Apache to start");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -k restart         : tell running Apache to do a graceful "
                 "restart");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -k stop|shutdown   : tell running Apache to shutdown");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -k install         : install an Apache service");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -k config          : change startup Options of an Apache "
                 "service");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -k uninstall       : uninstall an Apache service");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -w                 : hold open the console window on error");
#endif

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -e level           : show startup errors of level "
                 "(see LogLevel)");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -E file            : log startup errors to file");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -v                 : show version number");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -V                 : show compile settings");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -h                 : list available command line options "
                 "(this page)");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -l                 : list compiled in modules");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -L                 : list available configuration "
                 "directives");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -t -D DUMP_VHOSTS  : show parsed settings (currently only "
                 "vhost settings)");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -S                 : a synonym for -t -D DUMP_VHOSTS");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -t -D DUMP_MODULES : show all loaded modules ");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -M                 : a synonym for -t -D DUMP_MODULES");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -t                 : run syntax check for config files");

    destroy_and_exit_process(process, 1);
}

int main(int argc, const char * const argv[])
{
    char c;
    int configtestonly = 0;
    const char *confname = SERVER_CONFIG_FILE;
    const char *def_server_root = HTTPD_ROOT;
    const char *temp_error_log = NULL;
    const char *error;
    process_rec *process;
    apr_pool_t *pconf;
    apr_pool_t *plog; /* Pool of log streams, reset _after_ each read of conf */
    apr_pool_t *ptemp; /* Pool for temporary config stuff, reset often */
    apr_pool_t *pcommands; /* Pool for -D, -C and -c switches */
    apr_getopt_t *opt;
    apr_status_t rv;
    module **mod;
    const char *optarg;
    APR_OPTIONAL_FN_TYPE(ap_signal_server) *signal_server;

    AP_MONCONTROL(0); /* turn off profiling of startup */

    process = init_process(&argc, &argv);
    ap_pglobal = process->pool;
    pconf = process->pconf;
    ap_server_argv0 = process->short_name;

    /* Set up the OOM callback in the global pool, so all pools should
     * by default inherit it. */
    apr_pool_abort_set(abort_on_oom, apr_pool_parent_get(process->pool));

#if APR_CHARSET_EBCDIC
    if (ap_init_ebcdic(ap_pglobal) != APR_SUCCESS) {
        destroy_and_exit_process(process, 1);
    }
#endif
    if (ap_expr_init(ap_pglobal) != APR_SUCCESS) {
        destroy_and_exit_process(process, 1);
    }

    apr_pool_create(&pcommands, ap_pglobal);
    apr_pool_tag(pcommands, "pcommands");
    ap_server_pre_read_config  = apr_array_make(pcommands, 1, sizeof(char *));
    ap_server_post_read_config = apr_array_make(pcommands, 1, sizeof(char *));
    ap_server_config_defines   = apr_array_make(pcommands, 1, sizeof(char *));

    error = ap_setup_prelinked_modules(process);
    if (error) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_EMERG, 0, NULL, "%s: %s",
                     ap_server_argv0, error);
        destroy_and_exit_process(process, 1);
    }

    ap_run_rewrite_args(process);

    /* Maintain AP_SERVER_BASEARGS list in http_main.h to allow the MPM
     * to safely pass on our args from its rewrite_args() handler.
     */
    apr_getopt_init(&opt, pcommands, process->argc, process->argv);

    while ((rv = apr_getopt(opt, AP_SERVER_BASEARGS, &c, &optarg))
            == APR_SUCCESS) {
        char **new;

        switch (c) {
        case 'c':
            new = (char **)apr_array_push(ap_server_post_read_config);
            *new = apr_pstrdup(pcommands, optarg);
            break;

        case 'C':
            new = (char **)apr_array_push(ap_server_pre_read_config);
            *new = apr_pstrdup(pcommands, optarg);
            break;

        case 'd':
            def_server_root = optarg;
            break;

        case 'D':
            new = (char **)apr_array_push(ap_server_config_defines);
            *new = apr_pstrdup(pcommands, optarg);
            /* Setting -D DUMP_VHOSTS is equivalent to setting -S */
            if (strcmp(optarg, "DUMP_VHOSTS") == 0)
                configtestonly = 1;
            /* Setting -D DUMP_MODULES is equivalent to setting -M */
            if (strcmp(optarg, "DUMP_MODULES") == 0)
                configtestonly = 1;
            break;

        case 'e':
            if (strcasecmp(optarg, "emerg") == 0) {
                ap_default_loglevel = APLOG_EMERG;
            }
            else if (strcasecmp(optarg, "alert") == 0) {
                ap_default_loglevel = APLOG_ALERT;
            }
            else if (strcasecmp(optarg, "crit") == 0) {
                ap_default_loglevel = APLOG_CRIT;
            }
            else if (strncasecmp(optarg, "err", 3) == 0) {
                ap_default_loglevel = APLOG_ERR;
            }
            else if (strncasecmp(optarg, "warn", 4) == 0) {
                ap_default_loglevel = APLOG_WARNING;
            }
            else if (strcasecmp(optarg, "notice") == 0) {
                ap_default_loglevel = APLOG_NOTICE;
            }
            else if (strcasecmp(optarg, "info") == 0) {
                ap_default_loglevel = APLOG_INFO;
            }
            else if (strcasecmp(optarg, "debug") == 0) {
                ap_default_loglevel = APLOG_DEBUG;
            }
            else {
                usage(process);
            }
            break;

        case 'E':
            temp_error_log = apr_pstrdup(process->pool, optarg);
            break;

        case 'X':
            new = (char **)apr_array_push(ap_server_config_defines);
            *new = "DEBUG";
            break;

        case 'f':
            confname = optarg;
            break;

        case 'v':
            printf("Server version: %s\n", ap_get_server_description());
            printf("Server built:   %s\n", ap_get_server_built());
            destroy_and_exit_process(process, 0);

        case 'V':
            show_compile_settings();
            destroy_and_exit_process(process, 0);

        case 'l':
            ap_show_modules();
            destroy_and_exit_process(process, 0);

        case 'L':
            ap_show_directives();
            destroy_and_exit_process(process, 0);

        case 't':
            configtestonly = 1;
            break;

        case 'S':
            configtestonly = 1;
            new = (char **)apr_array_push(ap_server_config_defines);
            *new = "DUMP_VHOSTS";
            break;

        case 'M':
            configtestonly = 1;
            new = (char **)apr_array_push(ap_server_config_defines);
            *new = "DUMP_MODULES";
            break;

        case 'h':
        case '?':
            usage(process);
        }
    }

    /* bad cmdline option?  then we die */
    if (rv != APR_EOF || opt->ind < opt->argc) {
        usage(process);
    }

    apr_pool_create(&plog, ap_pglobal);
    apr_pool_tag(plog, "plog");
    apr_pool_create(&ptemp, pconf);
    apr_pool_tag(ptemp, "ptemp");

    /* Note that we preflight the config file once
     * before reading it _again_ in the main loop.
     * This allows things, log files configuration
     * for example, to settle down.
     */

    ap_server_root = def_server_root;
    if (temp_error_log) {
        ap_replace_stderr_log(process->pool, temp_error_log);
    }
    ap_server_conf = ap_read_config(process, ptemp, confname, &ap_conftree);
    if (!ap_server_conf) {
        destroy_and_exit_process(process, 1);
    }

    if (ap_run_pre_config(pconf, plog, ptemp) != OK) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR, 0,
                     NULL, "Pre-configuration failed");
        destroy_and_exit_process(process, 1);
    }

    rv = ap_process_config_tree(ap_server_conf, ap_conftree,
                                process->pconf, ptemp);
    if (rv == OK) {
        ap_fixup_virtual_hosts(pconf, ap_server_conf);
        ap_fini_vhost_config(pconf, ap_server_conf);
        apr_hook_sort_all();

        if (ap_run_check_config(pconf, plog, ptemp, ap_server_conf) != OK) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR, 0,
                         NULL, "Configuration check failed");
            destroy_and_exit_process(process, 1);
        }

        if (configtestonly) {
            ap_run_test_config(pconf, ap_server_conf);
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, "Syntax OK");
            destroy_and_exit_process(process, 0);
        }
    }

    signal_server = APR_RETRIEVE_OPTIONAL_FN(ap_signal_server);
    if (signal_server) {
        int exit_status;

        if (signal_server(&exit_status, pconf) != 0) {
            destroy_and_exit_process(process, exit_status);
        }
    }

    /* If our config failed, deal with that here. */
    if (rv != OK) {
        destroy_and_exit_process(process, 1);
    }

    apr_pool_clear(plog);

    if ( ap_run_open_logs(pconf, plog, ptemp, ap_server_conf) != OK) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR,
                     0, NULL, "Unable to open logs");
        destroy_and_exit_process(process, 1);
    }

    if ( ap_run_post_config(pconf, plog, ptemp, ap_server_conf) != OK) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR, 0,
                     NULL, "Configuration Failed");
        destroy_and_exit_process(process, 1);
    }

    apr_pool_destroy(ptemp);

    for (;;) {
        apr_hook_deregister_all();
        apr_pool_clear(pconf);
        ap_clear_auth_internal();

        for (mod = ap_prelinked_modules; *mod != NULL; mod++) {
            ap_register_hooks(*mod, pconf);
        }

        /* This is a hack until we finish the code so that it only reads
         * the config file once and just operates on the tree already in
         * memory.  rbb
         */
        ap_conftree = NULL;
        apr_pool_create(&ptemp, pconf);
        apr_pool_tag(ptemp, "ptemp");
        ap_server_root = def_server_root;
        ap_server_conf = ap_read_config(process, ptemp, confname, &ap_conftree);
        if (!ap_server_conf) {
            destroy_and_exit_process(process, 1);
        }

        if (ap_run_pre_config(pconf, plog, ptemp) != OK) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR,
                         0, NULL, "Pre-configuration failed");
            destroy_and_exit_process(process, 1);
        }

        if (ap_process_config_tree(ap_server_conf, ap_conftree, process->pconf,
                                   ptemp) != OK) {
            destroy_and_exit_process(process, 1);
        }
        ap_fixup_virtual_hosts(pconf, ap_server_conf);
        ap_fini_vhost_config(pconf, ap_server_conf);
        apr_hook_sort_all();

        if (ap_run_check_config(pconf, plog, ptemp, ap_server_conf) != OK) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR, 0,
                         NULL, "Configuration check failed");
            destroy_and_exit_process(process, 1);
        }

        apr_pool_clear(plog);
        if (ap_run_open_logs(pconf, plog, ptemp, ap_server_conf) != OK) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR,
                         0, NULL, "Unable to open logs");
            destroy_and_exit_process(process, 1);
        }

        if (ap_run_post_config(pconf, plog, ptemp, ap_server_conf) != OK) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR,
                         0, NULL, "Configuration Failed");
            destroy_and_exit_process(process, 1);
        }

        apr_pool_destroy(ptemp);
        apr_pool_lock(pconf, 1);

        ap_run_optional_fn_retrieve();

        if (ap_mpm_run(pconf, plog, ap_server_conf))
            break;

        apr_pool_lock(pconf, 0);
    }

    apr_pool_lock(pconf, 0);
    destroy_and_exit_process(process, 0);

    return 0; /* Termination 'ok' */
}

#ifdef AP_USING_AUTOCONF
/* This ugly little hack pulls any function referenced in exports.c into
 * the web server.  exports.c is generated during the build, and it
 * has all of the APR functions specified by the apr/apr.exports and
 * apr-util/aprutil.exports files.
 */
const void *ap_suck_in_APR(void);
const void *ap_suck_in_APR(void)
{
    extern const void *ap_ugly_hack;

    return ap_ugly_hack;
}
#endif
