/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer.  
 * 
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in 
 *    the documentation and/or other materials provided with the 
 *    distribution. 
 * 
 * 3. All advertising materials mentioning features or use of this 
 *    software must display the following acknowledgment: 
 *    "This product includes software developed by the Apache Group 
 *    for use in the Apache HTTP server project (http://www.apache.org/)." 
 * 
 * 4. The names "Apache Server" and "Apache Group" must not be used to 
 *    endorse or promote products derived from this software without 
 *    prior written permission. For written permission, please contact 
 *    apache@apache.org. 
 * 
 * 5. Products derived from this software may not be called "Apache" 
 *    nor may "Apache" appear in their names without prior written 
 *    permission of the Apache Group. 
 * 
 * 6. Redistributions of any form whatsoever must retain the following 
 *    acknowledgment: 
 *    "This product includes software developed by the Apache Group 
 *    for use in the Apache HTTP server project (http://www.apache.org/)." 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY 
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR 
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
 * OF THE POSSIBILITY OF SUCH DAMAGE. 
 * ==================================================================== 
 * 
 * This software consists of voluntary contributions made by many 
 * individuals on behalf of the Apache Group and was originally based 
 * on public domain software written at the National Center for 
 * Supercomputing Applications, University of Illinois, Urbana-Champaign. 
 * For more information on the Apache Group and the Apache HTTP server 
 * project, please see <http://www.apache.org/>. 
 * 
 */ 

#define CORE_PRIVATE
#include "httpd.h" 
#include "http_main.h" 
#include "http_config.h"
#include "util_uri.h" 
#include "ap_mpm.h"

char *ap_server_argv0;

API_VAR_EXPORT const char *ap_server_root;

array_header *ap_server_pre_read_config;
array_header *ap_server_post_read_config;
array_header *ap_server_config_defines;

static void show_compile_settings(void)
{
    printf("Server version: %s\n", ap_get_server_version());
    printf("Server built:   %s\n", ap_get_server_built());
    printf("Server's Module Magic Number: %u:%u\n",
	   MODULE_MAGIC_NUMBER_MAJOR, MODULE_MAGIC_NUMBER_MINOR);
    printf("Server compiled with....\n");
#ifdef BIG_SECURITY_HOLE
    printf(" -D BIG_SECURITY_HOLE\n");
#endif
#ifdef SECURITY_HOLE_PASS_AUTHORIZATION
    printf(" -D SECURITY_HOLE_PASS_AUTHORIZATION\n");
#endif
#ifdef HAVE_MMAP
    printf(" -D HAVE_MMAP\n");
#endif
#ifdef HAVE_SHMGET
    printf(" -D HAVE_SHMGET\n");
#endif
#ifdef USE_MMAP_SCOREBOARD
    printf(" -D USE_MMAP_SCOREBOARD\n");
#endif
#ifdef USE_SHMGET_SCOREBOARD
    printf(" -D USE_SHMGET_SCOREBOARD\n");
#endif
#ifdef USE_OS2_SCOREBOARD
    printf(" -D USE_OS2_SCOREBOARD\n");
#endif
#ifdef USE_POSIX_SCOREBOARD
    printf(" -D USE_POSIX_SCOREBOARD\n");
#endif
#ifdef USE_MMAP_FILES
    printf(" -D USE_MMAP_FILES\n");
#ifdef MMAP_SEGMENT_SIZE
	printf(" -D MMAP_SEGMENT_SIZE=%ld\n",(long)MMAP_SEGMENT_SIZE);
#endif
#endif /*USE_MMAP_FILES*/
#ifdef NO_WRITEV
    printf(" -D NO_WRITEV\n");
#endif
#ifdef NO_LINGCLOSE
    printf(" -D NO_LINGCLOSE\n");
#endif
#ifdef USE_FCNTL_SERIALIZED_ACCEPT
    printf(" -D USE_FCNTL_SERIALIZED_ACCEPT\n");
#endif
#ifdef USE_FLOCK_SERIALIZED_ACCEPT
    printf(" -D USE_FLOCK_SERIALIZED_ACCEPT\n");
#endif
#ifdef USE_USLOCK_SERIALIZED_ACCEPT
    printf(" -D USE_USLOCK_SERIALIZED_ACCEPT\n");
#endif
#ifdef USE_SYSVSEM_SERIALIZED_ACCEPT
    printf(" -D USE_SYSVSEM_SERIALIZED_ACCEPT\n");
#endif
#ifdef USE_PTHREAD_SERIALIZED_ACCEPT
    printf(" -D USE_PTHREAD_SERIALIZED_ACCEPT\n");
#endif
#ifdef SINGLE_LISTEN_UNSERIALIZED_ACCEPT
    printf(" -D SINGLE_LISTEN_UNSERIALIZED_ACCEPT\n");
#endif
#ifdef HAS_OTHER_CHILD
    printf(" -D HAS_OTHER_CHILD\n");
#endif
#ifdef NO_RELIABLE_PIPED_LOGS
    printf(" -D NO_RELIABLE_PIPED_LOGS\n");
#endif
#ifdef BUFFERED_LOGS
    printf(" -D BUFFERED_LOGS\n");
#ifdef PIPE_BUF
	printf(" -D PIPE_BUF=%ld\n",(long)PIPE_BUF);
#endif
#endif
#ifdef MULTITHREAD
    printf(" -D MULTITHREAD\n");
#endif
#ifdef CHARSET_EBCDIC
    printf(" -D CHARSET_EBCDIC\n");
#endif
#ifdef NEED_HASHBANG_EMUL
    printf(" -D NEED_HASHBANG_EMUL\n");
#endif
#ifdef SHARED_CORE
    printf(" -D SHARED_CORE\n");
#endif

/* This list displays the compiled-in default paths: */
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
#ifdef DEFAULT_XFERLOG
    printf(" -D DEFAULT_XFERLOG=\"" DEFAULT_XFERLOG "\"\n");
#endif
#ifdef DEFAULT_ERRORLOG
    printf(" -D DEFAULT_ERRORLOG=\"" DEFAULT_ERRORLOG "\"\n");
#endif
#ifdef TYPES_CONFIG_FILE
    printf(" -D TYPES_CONFIG_FILE=\"" TYPES_CONFIG_FILE "\"\n");
#endif
#ifdef SERVER_CONFIG_FILE
    printf(" -D SERVER_CONFIG_FILE=\"" SERVER_CONFIG_FILE "\"\n");
#endif
#ifdef ACCESS_CONFIG_FILE
    printf(" -D ACCESS_CONFIG_FILE=\"" ACCESS_CONFIG_FILE "\"\n");
#endif
#ifdef RESOURCE_CONFIG_FILE
    printf(" -D RESOURCE_CONFIG_FILE=\"" RESOURCE_CONFIG_FILE "\"\n");
#endif
}

static void usage(char *bin)
{
    char pad[MAX_STRING_LEN];
    unsigned i;

    for (i = 0; i < strlen(bin); i++)
	pad[i] = ' ';
    pad[i] = '\0';
#ifdef SHARED_CORE
    fprintf(stderr, "Usage: %s [-R directory] [-D name] [-d directory] [-f file]\n", bin);
#else
    fprintf(stderr, "Usage: %s [-D name] [-d directory] [-f file]\n", bin);
#endif
    fprintf(stderr, "       %s [-C \"directive\"] [-c \"directive\"]\n", pad);
    fprintf(stderr, "       %s [-v] [-V] [-h] [-l] [-L] [-S] [-t] [-T]\n", pad);
    fprintf(stderr, "Options:\n");
#ifdef SHARED_CORE
    fprintf(stderr, "  -R directory     : specify an alternate location for shared object files\n");
#endif
    fprintf(stderr, "  -D name          : define a name for use in <IfDefine name> directives\n");
    fprintf(stderr, "  -d directory     : specify an alternate initial ServerRoot\n");
    fprintf(stderr, "  -f file          : specify an alternate ServerConfigFile\n");
    fprintf(stderr, "  -C \"directive\"   : process directive before reading config files\n");
    fprintf(stderr, "  -c \"directive\"   : process directive after  reading config files\n");
    fprintf(stderr, "  -v               : show version number\n");
    fprintf(stderr, "  -V               : show compile settings\n");
    fprintf(stderr, "  -h               : list available command line options (this page)\n");
    fprintf(stderr, "  -l               : list compiled-in modules\n");
    fprintf(stderr, "  -L               : list available configuration directives\n");
    /* TODOC: -S has been replaced by '-t -D DUMP_VHOSTS' */
    /* fprintf(stderr, "  -S               : show parsed settings (currently only vhost settings)\n"); */
    fprintf(stderr, "  -t               : run syntax check for config files (with docroot check)\n");
    fprintf(stderr, "  -T               : run syntax check for config files (without docroot check)\n");
    /* TODOC: -X goes away, expect MPMs to use -D options */
    exit(1);
}

pool *g_pHookPool;
#ifdef WIN32
__declspec(dllexport)
     int apache_main(int argc, char *argv[])
#else
int main(int argc, char **argv)
#endif
{
    int c;
    int configtestonly = 0;
    char *s;
    const char *confname = SERVER_CONFIG_FILE;
    const char *def_server_root = HTTPD_ROOT;
    server_rec *server_conf;
    pool *pglobal;           	/* Global pool */
    pool *pconf;		/* Pool for config stuff */
    pool *plog;			/* Pool for error-logging files */
    pool *ptemp;		/* Pool for temporart config stuff */
    pool *pcommands;		/* Pool for -C and -c switches */
    extern char *optarg;

    /* TODO: PATHSEPARATOR should be one of the os defines */
#define PATHSEPARATOR '/'
    if ((s = strrchr(argv[0], PATHSEPARATOR)) != NULL) {
	ap_server_argv0 = ++s;
    }
    else {
	ap_server_argv0 = argv[0];
    }

    ap_util_init();
    ap_util_uri_init();

    pglobal = ap_init_alloc();
    g_pHookPool=pglobal;

    pcommands = ap_make_sub_pool(pglobal);
    ap_server_pre_read_config  = ap_make_array(pcommands, 1, sizeof(char *));
    ap_server_post_read_config = ap_make_array(pcommands, 1, sizeof(char *));
    ap_server_config_defines   = ap_make_array(pcommands, 1, sizeof(char *));

    ap_setup_prelinked_modules();

    while ((c = getopt(argc, argv, "D:C:c:Xd:f:vVlLR:th")) != -1) {
        char **new;
        switch (c) {
 	case 'c':
	    new = (char **)ap_push_array(ap_server_post_read_config);
	    *new = ap_pstrdup(pcommands, optarg);
	    break;
	case 'C':
	    new = (char **)ap_push_array(ap_server_pre_read_config);
	    *new = ap_pstrdup(pcommands, optarg);
	    break;
	case 'd':
	    def_server_root = optarg;
	    break;
	case 'f':
	    confname = optarg;
	    break;
	case 'v':
	    printf("Server version: %s\n", ap_get_server_version());
	    printf("Server built:   %s\n", ap_get_server_built());
	    exit(0);
	case 'V':
	    show_compile_settings();
	    exit(0);
	case 'l':
	    ap_show_modules();
	    exit(0);
	case 'L':
	    ap_show_directives();
	    exit(0);
	case 't':
	    configtestonly = 1;
	    break;
	case 'h':
	    usage(argv[0]);
	case '?':
	    usage(argv[0]);
	}
    }

    pconf = ap_make_sub_pool(pglobal);
    plog = ap_make_sub_pool(pglobal);
    ptemp = ap_make_sub_pool(pconf);

    /* for legacy reasons, we read the configuration twice before
	we actually serve any requests */

    ap_server_root = def_server_root;
    ap_run_pre_config(pconf, plog, ptemp);
    server_conf = ap_read_config(pconf, ptemp, confname);

    if (configtestonly) {
	fprintf(stderr, "Syntax OK\n");
	exit(0);
    }

    ap_clear_pool(plog);
    ap_run_open_logs(pconf, plog, ptemp, server_conf);
    ap_post_config_hook(pconf, plog, ptemp, server_conf);
    ap_clear_pool(ptemp);

    for (;;) {
	ap_clear_pool(pconf);
	ptemp = ap_make_sub_pool(pconf);
	ap_server_root = def_server_root;
	ap_run_pre_config(pconf, plog, ptemp);
	server_conf = ap_read_config(pconf, ptemp, confname);
	ap_clear_pool(plog);
	ap_run_open_logs(pconf, plog, ptemp, server_conf);
	ap_post_config_hook(pconf, plog, ptemp, server_conf);
	ap_destroy_pool(ptemp);

	if (ap_mpm_run(pconf, plog, server_conf)) break;
    }

    ap_clear_pool(pconf);
    ap_clear_pool(plog);
    ap_destroy_pool(pglobal);
    exit(0);
}

/* force Expat to be linked into the server executable */
#if defined(USE_EXPAT) && !defined(SHARED_CORE_BOOTSTRAP)
#include "xmlparse.h"
const XML_LChar *suck_in_expat(void);
const XML_LChar *suck_in_expat(void)
{
    return XML_ErrorString(XML_ERROR_NONE);
}
#endif /* USE_EXPAT */

#ifndef SHARED_CORE_BOOTSTRAP
/*
 * Force ap_validate_password() into the image so that modules like
 * mod_auth can use it even if they're dynamically loaded.
 */
void suck_in_ap_validate_password(void);
void suck_in_ap_validate_password(void)
{
    ap_validate_password("a", "b");
}
#endif

