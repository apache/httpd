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
 * htpasswd.c: simple program for manipulating password file for
 * the Apache HTTP server
 *
 * Originally by Rob McCool
 *
 * Exit values:
 *  0: Success
 *  1: Failure; file access/permission problem
 *  2: Failure; command line syntax problem (usage message issued)
 *  3: Failure; password verification failure
 *  4: Failure; operation interrupted (such as with CTRL/C)
 *  5: Failure; buffer would overflow (username, filename, or computed
 *     record too long)
 *  6: Failure; username contains illegal or reserved characters
 *  7: Failure; file is not a valid htpasswd file
 */

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_errno.h"
#include "apr_file_io.h"
#include "apr_general.h"
#include "apr_signal.h"

#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif

#include "apr_md5.h"
#include "apr_sha1.h"
#include <time.h>

#if APR_HAVE_CRYPT_H
#include <crypt.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STRING_H
#include <string.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef WIN32
#include <conio.h>
#define unlink _unlink
#endif

#if !APR_CHARSET_EBCDIC
#define LF 10
#define CR 13
#else /*APR_CHARSET_EBCDIC*/
#define LF '\n'
#define CR '\r'
#endif /*APR_CHARSET_EBCDIC*/

#define MAX_STRING_LEN 256
#define ALG_PLAIN 0
#define ALG_CRYPT 1
#define ALG_APMD5 2
#define ALG_APSHA 3

#define ERR_FILEPERM 1
#define ERR_SYNTAX 2
#define ERR_PWMISMATCH 3
#define ERR_INTERRUPTED 4
#define ERR_OVERFLOW 5
#define ERR_BADUSER 6
#define ERR_INVALID 7

#define APHTP_NEWFILE        1
#define APHTP_NOFILE         2
#define APHTP_NONINTERACTIVE 4
#define APHTP_DELUSER        8

apr_file_t *errfile;
apr_file_t *ftemp = NULL;

#define NL APR_EOL_STR

static void to64(char *s, unsigned long v, int n)
{
    static unsigned char itoa64[] =         /* 0 ... 63 => ASCII - 64 */
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    while (--n >= 0) {
        *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

static void generate_salt(char *s, size_t size)
{
    static unsigned char tbl[] = 
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    size_t i;
    for (i = 0; i < size; ++i) {
        int idx = (int) (64.0 * rand() / (RAND_MAX + 1.0));
        s[i] = tbl[idx];
    }
}

static apr_status_t seed_rand(void)
{
    int seed = 0;
    apr_status_t rv;
    rv = apr_generate_random_bytes((unsigned char*) &seed, sizeof(seed));
    if (rv) {
        apr_file_printf(errfile, "Unable to generate random bytes: %pm" NL, &rv);
        return rv;
    }
    srand(seed);
    return rv;
}

static void putline(apr_file_t *f, const char *l)
{
    apr_file_puts(l, f);
}

/*
 * Make a password record from the given information.  A zero return
 * indicates success; failure means that the output buffer contains an
 * error message instead.
 */
static int mkrecord(char *user, char *record, apr_size_t rlen, char *passwd,
                    int alg)
{
    char *pw;
    char cpw[120];
    char pwin[MAX_STRING_LEN];
    char pwv[MAX_STRING_LEN];
    char salt[9];
    apr_size_t bufsize;

    if (passwd != NULL) {
        pw = passwd;
    }
    else {
        bufsize = sizeof(pwin);
        if (apr_password_get("New password: ", pwin, &bufsize) != 0) {
            apr_snprintf(record, (rlen - 1), "password too long (>%"
                         APR_SIZE_T_FMT ")", sizeof(pwin) - 1);
            return ERR_OVERFLOW;
        }
        bufsize = sizeof(pwv);
        apr_password_get("Re-type new password: ", pwv, &bufsize);
        if (strcmp(pwin, pwv) != 0) {
            apr_cpystrn(record, "password verification error", (rlen - 1));
            return ERR_PWMISMATCH;
        }
        pw = pwin;
        memset(pwv, '\0', sizeof(pwin));
    }
    switch (alg) {

    case ALG_APSHA:
        /* XXX cpw >= 28 + strlen(sha1) chars - fixed len SHA */
        apr_sha1_base64(pw,strlen(pw),cpw);
        break;

    case ALG_APMD5:
        if (seed_rand()) {
            break;
        }
        generate_salt(&salt[0], 8);
        salt[8] = '\0';

        apr_md5_encode((const char *)pw, (const char *)salt,
                     cpw, sizeof(cpw));
        break;

    case ALG_PLAIN:
        /* XXX this len limitation is not in sync with any HTTPd len. */
        apr_cpystrn(cpw,pw,sizeof(cpw));
        break;

#if !(defined(WIN32) || defined(NETWARE))
    case ALG_CRYPT:
    default:
        if (seed_rand()) {
            break;
        }
        to64(&salt[0], rand(), 8);
        salt[8] = '\0';

        apr_cpystrn(cpw, (char *)crypt(pw, salt), sizeof(cpw) - 1);
        break;
#endif
    }
    memset(pw, '\0', strlen(pw));

    /*
     * Check to see if the buffer is large enough to hold the username,
     * hash, and delimiters.
     */
    if ((strlen(user) + 1 + strlen(cpw)) > (rlen - 1)) {
        apr_cpystrn(record, "resultant record too long", (rlen - 1));
        return ERR_OVERFLOW;
    }
    strcpy(record, user);
    strcat(record, ":");
    strcat(record, cpw);
    strcat(record, "\n");
    return 0;
}

static void usage(void)
{
    apr_file_printf(errfile, "Usage:" NL);
    apr_file_printf(errfile, "\thtpasswd [-cmdpsD] passwordfile username" NL);
    apr_file_printf(errfile, "\thtpasswd -b[cmdpsD] passwordfile username "
                    "password" NL NL);
    apr_file_printf(errfile, "\thtpasswd -n[mdps] username" NL);
    apr_file_printf(errfile, "\thtpasswd -nb[mdps] username password" NL);
    apr_file_printf(errfile, " -c  Create a new file." NL);
    apr_file_printf(errfile, " -n  Don't update file; display results on "
                    "stdout." NL);
    apr_file_printf(errfile, " -m  Force MD5 encryption of the password"
#if defined(WIN32) || defined(TPF) || defined(NETWARE)
        " (default)"
#endif
        "." NL);
    apr_file_printf(errfile, " -d  Force CRYPT encryption of the password"
#if (!(defined(WIN32) || defined(TPF) || defined(NETWARE)))
            " (default)"
#endif
            "." NL);
    apr_file_printf(errfile, " -p  Do not encrypt the password (plaintext)." NL);
    apr_file_printf(errfile, " -s  Force SHA encryption of the password." NL);
    apr_file_printf(errfile, " -b  Use the password from the command line "
            "rather than prompting for it." NL);
    apr_file_printf(errfile, " -D  Delete the specified user." NL);
    apr_file_printf(errfile,
            "On Windows, NetWare and TPF systems the '-m' flag is used by "
            "default." NL);
    apr_file_printf(errfile,
            "On all other systems, the '-p' flag will probably not work." NL);
    exit(ERR_SYNTAX);
}

/*
 * Check to see if the specified file can be opened for the given
 * access.
 */
static int accessible(apr_pool_t *pool, char *fname, int mode)
{
    apr_file_t *f = NULL;

    if (apr_file_open(&f, fname, mode, APR_OS_DEFAULT, pool) != APR_SUCCESS) {
        return 0;
    }
    apr_file_close(f);
    return 1;
}

/*
 * Return true if the named file exists, regardless of permissions.
 */
static int exists(char *fname, apr_pool_t *pool)
{
    apr_finfo_t sbuf;
    apr_status_t check;

    check = apr_stat(&sbuf, fname, APR_FINFO_TYPE, pool);
    return ((check || sbuf.filetype != APR_REG) ? 0 : 1);
}

static void terminate(void)
{
    apr_terminate();
#ifdef NETWARE
    pressanykey();
#endif
}

static void check_args(apr_pool_t *pool, int argc, const char *const argv[],
                       int *alg, int *mask, char **user, char **pwfilename,
                       char **password)
{
    const char *arg;
    int args_left = 2;
    int i;

    /*
     * Preliminary check to make sure they provided at least
     * three arguments, we'll do better argument checking as
     * we parse the command line.
     */
    if (argc < 3) {
        usage();
    }

    /*
     * Go through the argument list and pick out any options.  They
     * have to precede any other arguments.
     */
    for (i = 1; i < argc; i++) {
        arg = argv[i];
        if (*arg != '-') {
            break;
        }
        while (*++arg != '\0') {
            if (*arg == 'c') {
                *mask |= APHTP_NEWFILE;
            }
            else if (*arg == 'n') {
                *mask |= APHTP_NOFILE;
                args_left--;
            }
            else if (*arg == 'm') {
                *alg = ALG_APMD5;
            }
            else if (*arg == 's') {
                *alg = ALG_APSHA;
            }
            else if (*arg == 'p') {
                *alg = ALG_PLAIN;
            }
            else if (*arg == 'd') {
                *alg = ALG_CRYPT;
            }
            else if (*arg == 'b') {
                *mask |= APHTP_NONINTERACTIVE;
                args_left++;
            }
            else if (*arg == 'D') {
                *mask |= APHTP_DELUSER;
            }
            else {
                usage();
            }
        }
    }

    if ((*mask & APHTP_NEWFILE) && (*mask & APHTP_NOFILE)) {
        apr_file_printf(errfile, "%s: -c and -n options conflict" NL, argv[0]);
        exit(ERR_SYNTAX);
    }
    if ((*mask & APHTP_NEWFILE) && (*mask & APHTP_DELUSER)) {
        apr_file_printf(errfile, "%s: -c and -D options conflict" NL, argv[0]);
        exit(ERR_SYNTAX);
    }
    if ((*mask & APHTP_NOFILE) && (*mask & APHTP_DELUSER)) {
        apr_file_printf(errfile, "%s: -n and -D options conflict" NL, argv[0]);
        exit(ERR_SYNTAX);
    }
    /*
     * Make sure we still have exactly the right number of arguments left
     * (the filename, the username, and possibly the password if -b was
     * specified).
     */
    if ((argc - i) != args_left) {
        usage();
    }

    if (*mask & APHTP_NOFILE) {
        i--;
    }
    else {
        if (strlen(argv[i]) > (APR_PATH_MAX - 1)) {
            apr_file_printf(errfile, "%s: filename too long" NL, argv[0]);
            exit(ERR_OVERFLOW);
        }
        *pwfilename = apr_pstrdup(pool, argv[i]);
        if (strlen(argv[i + 1]) > (MAX_STRING_LEN - 1)) {
            apr_file_printf(errfile, "%s: username too long (> %d)" NL,
                argv[0], MAX_STRING_LEN - 1);
            exit(ERR_OVERFLOW);
        }
    }
    *user = apr_pstrdup(pool, argv[i + 1]);
    if ((arg = strchr(*user, ':')) != NULL) {
        apr_file_printf(errfile, "%s: username contains illegal "
                        "character '%c'" NL, argv[0], *arg);
        exit(ERR_BADUSER);
    }
    if (*mask & APHTP_NONINTERACTIVE) {
        if (strlen(argv[i + 2]) > (MAX_STRING_LEN - 1)) {
            apr_file_printf(errfile, "%s: password too long (> %d)" NL,
                argv[0], MAX_STRING_LEN);
            exit(ERR_OVERFLOW);
        }
        *password = apr_pstrdup(pool, argv[i + 2]);
    }
}

/*
 * Let's do it.  We end up doing a lot of file opening and closing,
 * but what do we care?  This application isn't run constantly.
 */
int main(int argc, const char * const argv[])
{
    apr_file_t *fpw = NULL;
    char record[MAX_STRING_LEN];
    char line[MAX_STRING_LEN];
    char *password = NULL;
    char *pwfilename = NULL;
    char *user = NULL;
    char tn[] = "htpasswd.tmp.XXXXXX";
    char *dirname;
    char *scratch, cp[MAX_STRING_LEN];
    int found = 0;
    int i;
    int alg = ALG_CRYPT;
    int mask = 0;
    apr_pool_t *pool;
    int existing_file = 0;
#if APR_CHARSET_EBCDIC
    apr_status_t rv;
    apr_xlate_t *to_ascii;
#endif

    apr_app_initialize(&argc, &argv, NULL);
    atexit(terminate);
    apr_pool_create(&pool, NULL);
    apr_file_open_stderr(&errfile, pool);

#if APR_CHARSET_EBCDIC
    rv = apr_xlate_open(&to_ascii, "ISO-8859-1", APR_DEFAULT_CHARSET, pool);
    if (rv) {
        apr_file_printf(errfile, "apr_xlate_open(to ASCII)->%d" NL, rv);
        exit(1);
    }
    rv = apr_SHA1InitEBCDIC(to_ascii);
    if (rv) {
        apr_file_printf(errfile, "apr_SHA1InitEBCDIC()->%d" NL, rv);
        exit(1);
    }
    rv = apr_MD5InitEBCDIC(to_ascii);
    if (rv) {
        apr_file_printf(errfile, "apr_MD5InitEBCDIC()->%d" NL, rv);
        exit(1);
    }
#endif /*APR_CHARSET_EBCDIC*/

    check_args(pool, argc, argv, &alg, &mask, &user, &pwfilename, &password);


#if defined(WIN32) || defined(NETWARE)
    if (alg == ALG_CRYPT) {
        alg = ALG_APMD5;
        apr_file_printf(errfile, "Automatically using MD5 format." NL);
    }
#endif

#if (!(defined(WIN32) || defined(TPF) || defined(NETWARE)))
    if (alg == ALG_PLAIN) {
        apr_file_printf(errfile,"Warning: storing passwords as plain text "
                        "might just not work on this platform." NL);
    }
#endif

    /*
     * Only do the file checks if we're supposed to frob it.
     */
    if (!(mask & APHTP_NOFILE)) {
        existing_file = exists(pwfilename, pool);
        if (existing_file) {
            /*
             * Check that this existing file is readable and writable.
             */
            if (!accessible(pool, pwfilename, APR_READ | APR_APPEND)) {
                apr_file_printf(errfile, "%s: cannot open file %s for "
                                "read/write access" NL, argv[0], pwfilename);
                exit(ERR_FILEPERM);
            }
        }
        else {
            /*
             * Error out if -c was omitted for this non-existant file.
             */
            if (!(mask & APHTP_NEWFILE)) {
                apr_file_printf(errfile,
                        "%s: cannot modify file %s; use '-c' to create it" NL,
                        argv[0], pwfilename);
                exit(ERR_FILEPERM);
            }
            /*
             * As it doesn't exist yet, verify that we can create it.
             */
            if (!accessible(pool, pwfilename, APR_CREATE | APR_WRITE)) {
                apr_file_printf(errfile, "%s: cannot create file %s" NL,
                                argv[0], pwfilename);
                exit(ERR_FILEPERM);
            }
        }
    }

    /*
     * All the file access checks (if any) have been made.  Time to go to work;
     * try to create the record for the username in question.  If that
     * fails, there's no need to waste any time on file manipulations.
     * Any error message text is returned in the record buffer, since
     * the mkrecord() routine doesn't have access to argv[].
     */
    if (!(mask & APHTP_DELUSER)) {
        i = mkrecord(user, record, sizeof(record) - 1,
                     password, alg);
        if (i != 0) {
            apr_file_printf(errfile, "%s: %s" NL, argv[0], record);
            exit(i);
        }
        if (mask & APHTP_NOFILE) {
            printf("%s" NL, record);
            exit(0);
        }
    }

    /*
     * We can access the files the right way, and we have a record
     * to add or update.  Let's do it..
     */
    if (apr_temp_dir_get((const char**)&dirname, pool) != APR_SUCCESS) {
        apr_file_printf(errfile, "%s: could not determine temp dir" NL,
                        argv[0]);
        exit(ERR_FILEPERM);
    }
    dirname = apr_psprintf(pool, "%s/%s", dirname, tn);

    if (apr_file_mktemp(&ftemp, dirname, 0, pool) != APR_SUCCESS) {
        apr_file_printf(errfile, "%s: unable to create temporary file %s" NL,
                        argv[0], dirname);
        exit(ERR_FILEPERM);
    }

    /*
     * If we're not creating a new file, copy records from the existing
     * one to the temporary file until we find the specified user.
     */
    if (existing_file && !(mask & APHTP_NEWFILE)) {
        if (apr_file_open(&fpw, pwfilename, APR_READ | APR_BUFFERED,
                          APR_OS_DEFAULT, pool) != APR_SUCCESS) {
            apr_file_printf(errfile, "%s: unable to read file %s" NL,
                            argv[0], pwfilename);
            exit(ERR_FILEPERM);
        }
        while (apr_file_gets(line, sizeof(line), fpw) == APR_SUCCESS) {
            char *colon;

            strcpy(cp, line);
            scratch = cp;
            while (apr_isspace(*scratch)) {
                ++scratch;
            }

            if (!*scratch || (*scratch == '#')) {
                putline(ftemp, line);
                continue;
            }
            /*
             * See if this is our user.
             */
            colon = strchr(scratch, ':');
            if (colon != NULL) {
                *colon = '\0';
            }
            else {
                /*
                 * If we've not got a colon on the line, this could well
                 * not be a valid htpasswd file.
                 * We should bail at this point.
                 */
                apr_file_printf(errfile, "%s: The file %s does not appear "
                                         "to be a valid htpasswd file." NL,
                                argv[0], pwfilename);
                apr_file_close(fpw);
                exit(ERR_INVALID);
            }
            if (strcmp(user, scratch) != 0) {
                putline(ftemp, line);
                continue;
            }
            else {
                if (!(mask & APHTP_DELUSER)) {
                    /* We found the user we were looking for.
                     * Add him to the file.
                    */
                    apr_file_printf(errfile, "Updating ");
                    putline(ftemp, record);
                    found++;
                }
                else {
                    /* We found the user we were looking for.
                     * Delete them from the file.
                     */
                    apr_file_printf(errfile, "Deleting ");
                    found++;
                }
            }
        }
        apr_file_close(fpw);
    }
    if (!found && !(mask & APHTP_DELUSER)) {
        apr_file_printf(errfile, "Adding ");
        putline(ftemp, record);
    }
    else if (!found && (mask & APHTP_DELUSER)) {
        apr_file_printf(errfile, "User %s not found" NL, user);
        exit(0);
    }
    apr_file_printf(errfile, "password for user %s" NL, user);

    /* The temporary file has all the data, just copy it to the new location.
     */
    if (apr_file_copy(dirname, pwfilename, APR_FILE_SOURCE_PERMS, pool) !=
        APR_SUCCESS) {
        apr_file_printf(errfile, "%s: unable to update file %s" NL,
                        argv[0], pwfilename);
        exit(ERR_FILEPERM);
    }
    apr_file_close(ftemp);
    return 0;
}
