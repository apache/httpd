/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
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
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
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

#define APHTP_NEWFILE        1
#define APHTP_NOFILE         2
#define APHTP_NONINTERACTIVE 4

apr_file_t *errfile;
apr_file_t *ftemp = NULL;

static void to64(char *s, unsigned long v, int n)
{
    static unsigned char itoa64[] =         /* 0 ... 63 => ASCII - 64 */
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    while (--n >= 0) {
        *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
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
        (void) srand((int) time((time_t *) NULL));
        to64(&salt[0], rand(), 8);
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
        (void) srand((int) time((time_t *) NULL));
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
    apr_file_printf(errfile, "Usage:\n");
    apr_file_printf(errfile, "\thtpasswd [-cmdps] passwordfile username\n");
    apr_file_printf(errfile, "\thtpasswd -b[cmdps] passwordfile username "
                    "password\n\n");
    apr_file_printf(errfile, "\thtpasswd -n[mdps] username\n");
    apr_file_printf(errfile, "\thtpasswd -nb[mdps] username password\n");
    apr_file_printf(errfile, " -c  Create a new file.\n");
    apr_file_printf(errfile, " -n  Don't update file; display results on "
                    "stdout.\n");
    apr_file_printf(errfile, " -m  Force MD5 encryption of the password"
#if defined(WIN32) || defined(TPF) || defined(NETWARE)
        " (default)"
#endif
        ".\n");
    apr_file_printf(errfile, " -d  Force CRYPT encryption of the password"
#if (!(defined(WIN32) || defined(TPF) || defined(NETWARE)))
            " (default)"
#endif
            ".\n");
    apr_file_printf(errfile, " -p  Do not encrypt the password (plaintext).\n");
    apr_file_printf(errfile, " -s  Force SHA encryption of the password.\n");
    apr_file_printf(errfile, " -b  Use the password from the command line "
            "rather than prompting for it.\n");
    apr_file_printf(errfile,
            "On Windows, NetWare and TPF systems the '-m' flag is used by "
            "default.\n");
    apr_file_printf(errfile,
            "On all other systems, the '-p' flag will probably not work.\n");
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

#ifdef NETWARE
void nwTerminate()
{
    pressanykey();
}
#endif

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
            else {
                usage();
            }
        }
    }

    if ((*mask & APHTP_NEWFILE) && (*mask & APHTP_NOFILE)) {
        apr_file_printf(errfile, "%s: -c and -n options conflict\n", argv[0]);
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
            apr_file_printf(errfile, "%s: filename too long\n", argv[0]);
            exit(ERR_OVERFLOW);
        }
        *pwfilename = apr_pstrdup(pool, argv[i]);
        if (strlen(argv[i + 1]) > (MAX_STRING_LEN - 1)) {
            apr_file_printf(errfile, "%s: username too long (> %d)\n",
                argv[0], MAX_STRING_LEN - 1);
            exit(ERR_OVERFLOW);
        }
    }
    *user = apr_pstrdup(pool, argv[i + 1]);
    if ((arg = strchr(*user, ':')) != NULL) {
        apr_file_printf(errfile, "%s: username contains illegal "
                        "character '%c'\n", argv[0], *arg);
        exit(ERR_BADUSER);
    }
    if (*mask & APHTP_NONINTERACTIVE) {
        if (strlen(argv[i + 2]) > (MAX_STRING_LEN - 1)) {
            apr_file_printf(errfile, "%s: password too long (> %d)\n",
                argv[0], MAX_STRING_LEN);
            exit(ERR_OVERFLOW);
        }
        *password = apr_pstrdup(pool, argv[i + 2]);
    }
}

static char *get_tempname(apr_pool_t *p)
{
    char tn[] = "htpasswd.tmp.XXXXXX";
    char *dirname;

    if (!(dirname = getenv("TEMP")) && !(dirname = getenv("TMPDIR"))) {
            dirname = P_tmpdir;
    }
    dirname = apr_psprintf(p, "%s/%s", dirname, tn);
    return dirname;
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
    char *tn;
    char scratch[MAX_STRING_LEN];
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
    atexit(apr_terminate);
#ifdef NETWARE
    atexit(nwTerminate);
#endif
    apr_pool_create(&pool, NULL);
    apr_file_open_stderr(&errfile, pool);

#if APR_CHARSET_EBCDIC
    rv = apr_xlate_open(&to_ascii, "ISO8859-1", APR_DEFAULT_CHARSET, pool);
    if (rv) {
        apr_file_printf(errfile, "apr_xlate_open(to ASCII)->%d\n", rv);
        exit(1);
    }
    rv = apr_SHA1InitEBCDIC(to_ascii);
    if (rv) {
        apr_file_printf(errfile, "apr_SHA1InitEBCDIC()->%d\n", rv);
        exit(1);
    }
    rv = apr_MD5InitEBCDIC(to_ascii);
    if (rv) {
        apr_file_printf(errfile, "apr_MD5InitEBCDIC()->%d\n", rv);
        exit(1);
    }
#endif /*APR_CHARSET_EBCDIC*/

    check_args(pool, argc, argv, &alg, &mask, &user, &pwfilename, &password);


#if defined(WIN32) || defined(NETWARE)
    if (alg == ALG_CRYPT) {
        alg = ALG_APMD5;
        apr_file_printf(errfile, "Automatically using MD5 format.\n");
    }
#endif

#if (!(defined(WIN32) || defined(TPF) || defined(NETWARE)))
    if (alg == ALG_PLAIN) {
        apr_file_printf(errfile,"Warning: storing passwords as plain text "
                        "might just not work on this platform.\n");
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
                                "read/write access\n", argv[0], pwfilename);
                exit(ERR_FILEPERM);
            }
        }
        else {
            /*
             * Error out if -c was omitted for this non-existant file.
             */
            if (!(mask & APHTP_NEWFILE)) {
                apr_file_printf(errfile,
                        "%s: cannot modify file %s; use '-c' to create it\n",
                        argv[0], pwfilename);
                exit(ERR_FILEPERM);
            }
            /*
             * As it doesn't exist yet, verify that we can create it.
             */
            if (!accessible(pool, pwfilename, APR_CREATE | APR_WRITE)) {
                apr_file_printf(errfile, "%s: cannot create file %s\n",
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
    i = mkrecord(user, record, sizeof(record) - 1,
                 password, alg);
    if (i != 0) {
        apr_file_printf(errfile, "%s: %s\n", argv[0], record);
        exit(i);
    }
    if (mask & APHTP_NOFILE) {
        printf("%s\n", record);
        exit(0);
    }

    /*
     * We can access the files the right way, and we have a record
     * to add or update.  Let's do it..
     */
    tn = get_tempname(pool);
    if (apr_file_mktemp(&ftemp, tn, 0, pool) != APR_SUCCESS) {
        apr_file_printf(errfile, "%s: unable to create temporary file %s\n", 
                        argv[0], tn);
        exit(ERR_FILEPERM);
    }

    /*
     * If we're not creating a new file, copy records from the existing
     * one to the temporary file until we find the specified user.
     */
    if (existing_file && !(mask & APHTP_NEWFILE)) {
        if (apr_file_open(&fpw, pwfilename, APR_READ | APR_BUFFERED,
                          APR_OS_DEFAULT, pool) != APR_SUCCESS) {
            apr_file_printf(errfile, "%s: unable to read file %s\n", 
                            argv[0], pwfilename);
            exit(ERR_FILEPERM);
        }
        while (apr_file_gets(line, sizeof(line), fpw) == APR_SUCCESS) {
            char *colon;

            if ((line[0] == '#') || (line[0] == '\0')) {
                putline(ftemp, line);
                continue;
            }
            strcpy(scratch, line);
            /*
             * See if this is our user.
             */
            colon = strchr(scratch, ':');
            if (colon != NULL) {
                *colon = '\0';
            }
            if (strcmp(user, scratch) != 0) {
                putline(ftemp, line);
                continue;
            }
            else {
                /* We found the user we were looking for, add him to the file.
                 */
                apr_file_printf(errfile, "Updating ");
                putline(ftemp, record);
                found++;
            }
        }
        apr_file_close(fpw);
    }
    if (!found) {
        apr_file_printf(errfile, "Adding ");
        putline(ftemp, record);
    }
    apr_file_printf(errfile, "password for user %s\n", user);

    /* The temporary file has all the data, just copy it to the new location.
     */
    if (apr_file_copy(tn, pwfilename, APR_FILE_SOURCE_PERMS, pool) !=
        APR_SUCCESS) {
        apr_file_printf(errfile, "%s: unable to update file %s\n", 
                        argv[0], pwfilename);
        exit(ERR_FILEPERM);
    }
    apr_file_close(ftemp);
    return 0;
}
