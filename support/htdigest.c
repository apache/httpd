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

/******************************************************************************
 ******************************************************************************
 * NOTE! This program is not safe as a setuid executable!  Do not make it
 * setuid!
 ******************************************************************************
 *****************************************************************************/
/*
 * htdigest.c: simple program for manipulating digest passwd file for Apache
 *
 * by Alexei Kosut, based on htpasswd.c, by Rob McCool
 */

#include "apr.h"
#include "apr_file_io.h"
#include "apr_md5.h"
#include "apr_lib.h"            /* for apr_getpass() */
#include "apr_general.h"
#include "apr_signal.h"
#include "apr_strings.h"        /* for apr_pstrdup() */

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef WIN32
#include <conio.h>
#endif


#if APR_CHARSET_EBCDIC
#define LF '\n'
#define CR '\r'
#else
#define LF 10
#define CR 13
#endif /* APR_CHARSET_EBCDIC */

#define MAX_STRING_LEN 256

apr_file_t *tfp = NULL;
apr_file_t *errfile;
apr_pool_t *cntxt;
#if APR_CHARSET_EBCDIC
apr_xlate_t *to_ascii;
#endif

static void cleanup_tempfile_and_exit(int rc)
{
    if (tfp) {
        apr_file_close(tfp);
    }
    exit(rc);
}

static void getword(char *word, char *line, char stop)
{
    int x = 0, y;

    for (x = 0; ((line[x]) && (line[x] != stop)); x++)
        word[x] = line[x];

    word[x] = '\0';
    if (line[x])
        ++x;
    y = 0;

    while ((line[y++] = line[x++]));
}

static int get_line(char *s, int n, apr_file_t *f)
{
    register int i = 0;
    char ch;
    apr_status_t rv = APR_EINVAL;

    while (i < (n - 1) &&
           ((rv = apr_file_getc(&ch, f)) == APR_SUCCESS) && (ch != '\n')) {
        s[i++] = ch;
    }
    if (ch == '\n')
        s[i++] = ch;
    s[i] = '\0';

    if (rv != APR_SUCCESS)
        return 1;

    return 0;
}

static void putline(apr_file_t *f, char *l)
{
    int x;

    for (x = 0; l[x]; x++)
        apr_file_putc(l[x], f);
}


static void add_password(const char *user, const char *realm, apr_file_t *f)
{
    char *pw;
    apr_md5_ctx_t context;
    unsigned char digest[16];
    char string[MAX_STRING_LEN];
    char pwin[MAX_STRING_LEN];
    char pwv[MAX_STRING_LEN];
    unsigned int i;
    apr_size_t len = sizeof(pwin);

    if (apr_password_get("New password: ", pwin, &len) != APR_SUCCESS) {
        apr_file_printf(errfile, "password too long");
        cleanup_tempfile_and_exit(5);
    }
    len = sizeof(pwin);
    apr_password_get("Re-type new password: ", pwv, &len);
    if (strcmp(pwin, pwv) != 0) {
        apr_file_printf(errfile, "They don't match, sorry.\n");
        cleanup_tempfile_and_exit(1);
    }
    pw = pwin;
    apr_file_printf(f, "%s:%s:", user, realm);

    /* Do MD5 stuff */
    sprintf(string, "%s:%s:%s", user, realm, pw);

    apr_md5_init(&context);
#if APR_CHARSET_EBCDIC
    apr_md5_set_xlate(&context, to_ascii);
#endif
    apr_md5_update(&context, (unsigned char *) string, strlen(string));
    apr_md5_final(digest, &context);

    for (i = 0; i < 16; i++)
        apr_file_printf(f, "%02x", digest[i]);

    apr_file_printf(f, "\n");
}

static void usage(void)
{
    apr_file_printf(errfile, "Usage: htdigest [-c] passwordfile realm username\n");
    apr_file_printf(errfile, "The -c flag creates a new file.\n");
    exit(1);
}

static void interrupted(void)
{
    apr_file_printf(errfile, "Interrupted.\n");
    cleanup_tempfile_and_exit(1);
}

static void terminate(void)
{
    apr_terminate();
#ifdef NETWARE
    pressanykey();
#endif
}

int main(int argc, const char * const argv[])
{
    apr_file_t *f;
    apr_status_t rv;
    char tn[] = "htdigest.tmp.XXXXXX";
    char *dirname;
    char user[MAX_STRING_LEN];
    char realm[MAX_STRING_LEN];
    char line[MAX_STRING_LEN];
    char l[MAX_STRING_LEN];
    char w[MAX_STRING_LEN];
    char x[MAX_STRING_LEN];
    int found;

    apr_app_initialize(&argc, &argv, NULL);
    atexit(terminate);
    apr_pool_create(&cntxt, NULL);
    apr_file_open_stderr(&errfile, cntxt);

#if APR_CHARSET_EBCDIC
    rv = apr_xlate_open(&to_ascii, "ISO-8859-1", APR_DEFAULT_CHARSET, cntxt);
    if (rv) {
        apr_file_printf(errfile, "apr_xlate_open(): %s (%d)\n",
                apr_strerror(rv, line, sizeof(line)), rv);
        exit(1);
    }
#endif

    apr_signal(SIGINT, (void (*)(int)) interrupted);
    if (argc == 5) {
        if (strcmp(argv[1], "-c"))
            usage();
        rv = apr_file_open(&f, argv[2], APR_WRITE | APR_CREATE,
                           APR_OS_DEFAULT, cntxt);
        if (rv != APR_SUCCESS) {
            char errmsg[120];

            apr_file_printf(errfile, "Could not open passwd file %s for writing: %s\n",
                    argv[2],
                    apr_strerror(rv, errmsg, sizeof errmsg));
            exit(1);
        }
	apr_cpystrn(user, argv[4], sizeof(user));
	apr_cpystrn(realm, argv[3], sizeof(realm));
        apr_file_printf(errfile, "Adding password for %s in realm %s.\n",
                    user, realm);
        add_password(user, realm, f);
        apr_file_close(f);
        exit(0);
    }
    else if (argc != 4)
        usage();

    if (apr_temp_dir_get((const char**)&dirname, cntxt) != APR_SUCCESS) {
        apr_file_printf(errfile, "%s: could not determine temp dir\n",
                        argv[0]);
        exit(1);
    }
    dirname = apr_psprintf(cntxt, "%s/%s", dirname, tn);

    if (apr_file_mktemp(&tfp, dirname, 0, cntxt) != APR_SUCCESS) {
        apr_file_printf(errfile, "Could not open temp file %s.\n", dirname);
        exit(1);
    }

    if (apr_file_open(&f, argv[1], APR_READ, APR_OS_DEFAULT, cntxt) != APR_SUCCESS) {
        apr_file_printf(errfile,
                "Could not open passwd file %s for reading.\n", argv[1]);
        apr_file_printf(errfile, "Use -c option to create new one.\n");
        cleanup_tempfile_and_exit(1);
    }
    apr_cpystrn(user, argv[3], sizeof(user));
    apr_cpystrn(realm, argv[2], sizeof(realm));

    found = 0;
    while (!(get_line(line, MAX_STRING_LEN, f))) {
        if (found || (line[0] == '#') || (!line[0])) {
            putline(tfp, line);
            continue;
        }
        strcpy(l, line);
        getword(w, l, ':');
        getword(x, l, ':');
        if (strcmp(user, w) || strcmp(realm, x)) {
            putline(tfp, line);
            continue;
        }
        else {
            apr_file_printf(errfile, "Changing password for user %s in realm %s\n",
                    user, realm);
            add_password(user, realm, tfp);
            found = 1;
        }
    }
    if (!found) {
        apr_file_printf(errfile, "Adding user %s in realm %s\n", user, realm);
        add_password(user, realm, tfp);
    }
    apr_file_close(f);

    /* The temporary file has all the data, just copy it to the new location.
     */
    if (apr_file_copy(dirname, argv[1], APR_FILE_SOURCE_PERMS, cntxt) !=
                APR_SUCCESS) {
        apr_file_printf(errfile, "%s: unable to update file %s\n",
                        argv[0], argv[1]);
    }
    apr_file_close(tfp);

    return 0;
}
