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

#include "passwd_common.h"
#include "apr_signal.h"
#include "apr_getopt.h"

#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif

#include "apr_md5.h"
#include "apr_sha1.h"

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

#define APHTP_NEWFILE        1
#define APHTP_NOFILE         2
#define APHTP_DELUSER        4
#define APHTP_VERIFY         8

apr_file_t *ftemp = NULL;

static int mkrecord(struct passwd_ctx *ctx, char *user)
{
    char hash_str[MAX_STRING_LEN];
    int ret;

    ctx->out = hash_str;
    ctx->out_len = sizeof(hash_str);

    ret = mkhash(ctx);
    if (ret) {
        ctx->out = NULL;
        ctx->out_len = 0;
        return ret;
    }

    ctx->out = apr_pstrcat(ctx->pool, user, ":", hash_str, NL, NULL);
    ctx->out_len = strlen(ctx->out);
    if (ctx->out_len >= MAX_STRING_LEN) {
        ctx->errstr = "resultant record too long";
        return ERR_OVERFLOW;
    }
    return 0;
}

static void usage(void)
{
    apr_file_printf(errfile, "Usage:" NL
        "\thtpasswd [-cimBdpsDv] [-C cost] passwordfile username" NL
        "\thtpasswd -b[cmBdpsDv] [-C cost] passwordfile username password" NL
        NL
        "\thtpasswd -n[imBdps] [-C cost] username" NL
        "\thtpasswd -nb[mBdps] [-C cost] username password" NL
        " -c  Create a new file." NL
        " -n  Don't update file; display results on stdout." NL
        " -b  Use the password from the command line rather than prompting "
            "for it." NL
        " -i  Read password from stdin without verification (for script usage)." NL
        " -m  Force MD5 encryption of the password (default)." NL
        " -B  Force bcrypt encryption of the password (very secure)." NL
        " -C  Set the computing time used for the bcrypt algorithm" NL
        "     (higher is more secure but slower, default: %d, valid: 4 to 17)." NL
        " -d  Force CRYPT encryption of the password (8 chars max, insecure)." NL
        " -s  Force SHA encryption of the password (insecure)." NL
        " -p  Do not encrypt the password (plaintext, insecure)." NL
        " -D  Delete the specified user." NL
        " -v  Verify password for the specified user." NL
        "On other systems than Windows and NetWare the '-p' flag will "
            "probably not work." NL
        "The SHA algorithm does not use a salt and is less secure than the "
            "MD5 algorithm." NL,
        BCRYPT_DEFAULT_COST
    );
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

static void check_args(int argc, const char *const argv[],
                       struct passwd_ctx *ctx, unsigned *mask, char **user,
                       char **pwfilename)
{
    const char *arg;
    int args_left = 2;
    int i, ret;
    apr_getopt_t *state;
    apr_status_t rv;
    char opt;
    const char *opt_arg;
    apr_pool_t *pool = ctx->pool;

    rv = apr_getopt_init(&state, pool, argc, argv);
    if (rv != APR_SUCCESS)
        exit(ERR_SYNTAX);

    while ((rv = apr_getopt(state, "cnmspdBbDiC:v", &opt, &opt_arg)) == APR_SUCCESS) {
        switch (opt) {
        case 'c':
            *mask |= APHTP_NEWFILE;
            break;
        case 'n':
            args_left--;
            *mask |= APHTP_NOFILE;
            break;
        case 'D':
            *mask |= APHTP_DELUSER;
            break;
        case 'v':
            *mask |= APHTP_VERIFY;
            break;
        default:
            ret = parse_common_options(ctx, opt, opt_arg);
            if (ret) {
                apr_file_printf(errfile, "%s: %s" NL, argv[0], ctx->errstr);
                exit(ret);
            }
        }
    }
    if (ctx->passwd_src == PW_ARG)
        args_left++;
    if (rv != APR_EOF)
        usage();

    if ((*mask) & (*mask - 1)) {
        /* not a power of two, i.e. more than one flag specified */
        apr_file_printf(errfile, "%s: only one of -c -n -v -D may be specified" NL,
            argv[0]);
        exit(ERR_SYNTAX);
    }
    if ((*mask & APHTP_VERIFY) && ctx->passwd_src == PW_PROMPT)
        ctx->passwd_src = PW_PROMPT_VERIFY;

    /*
     * Make sure we still have exactly the right number of arguments left
     * (the filename, the username, and possibly the password if -b was
     * specified).
     */
    i = state->ind;
    if ((argc - i) != args_left) {
        usage();
    }

    if (!(*mask & APHTP_NOFILE)) {
        if (strlen(argv[i]) > (APR_PATH_MAX - 1)) {
            apr_file_printf(errfile, "%s: filename too long" NL, argv[0]);
            exit(ERR_OVERFLOW);
        }
        *pwfilename = apr_pstrdup(pool, argv[i++]);
    }
    if (strlen(argv[i]) > (MAX_STRING_LEN - 1)) {
        apr_file_printf(errfile, "%s: username too long (> %d)" NL,
                        argv[0], MAX_STRING_LEN - 1);
        exit(ERR_OVERFLOW);
    }
    *user = apr_pstrdup(pool, argv[i++]);
    if ((arg = strchr(*user, ':')) != NULL) {
        apr_file_printf(errfile, "%s: username contains illegal "
                        "character '%c'" NL, argv[0], *arg);
        exit(ERR_BADUSER);
    }
    if (ctx->passwd_src == PW_ARG) {
        if (strlen(argv[i]) > (MAX_STRING_LEN - 1)) {
            apr_file_printf(errfile, "%s: password too long (> %d)" NL,
                argv[0], MAX_STRING_LEN);
            exit(ERR_OVERFLOW);
        }
        ctx->passwd = apr_pstrdup(pool, argv[i]);
    }
}

static int verify(struct passwd_ctx *ctx, const char *hash)
{
    apr_status_t rv;
    int ret;

    if (ctx->passwd == NULL && (ret = get_password(ctx)) != 0)
       return ret;
    rv = apr_password_validate(ctx->passwd, hash);
    if (rv == APR_SUCCESS)
        return 0;
    if (APR_STATUS_IS_EMISMATCH(rv)) {
        ctx->errstr = "password verification failed";
        return ERR_PWMISMATCH;
    }
    ctx->errstr = apr_psprintf(ctx->pool, "Could not verify password: %pm",
                               &rv);
    return ERR_GENERAL;
}

/*
 * Let's do it.  We end up doing a lot of file opening and closing,
 * but what do we care?  This application isn't run constantly.
 */
int main(int argc, const char * const argv[])
{
    apr_file_t *fpw = NULL;
    char line[MAX_STRING_LEN];
    char *pwfilename = NULL;
    char *user = NULL;
    char tn[] = "htpasswd.tmp.XXXXXX";
    char *dirname;
    char *scratch, cp[MAX_STRING_LEN];
    int found = 0;
    int i;
    unsigned mask = 0;
    apr_pool_t *pool;
    int existing_file = 0;
    struct passwd_ctx ctx = { 0 };
#if APR_CHARSET_EBCDIC
    apr_status_t rv;
    apr_xlate_t *to_ascii;
#endif

    apr_app_initialize(&argc, &argv, NULL);
    atexit(terminate);
    apr_pool_create(&pool, NULL);
    apr_pool_abort_set(abort_on_oom, pool);
    apr_file_open_stderr(&errfile, pool);
    ctx.pool = pool;
    ctx.alg = ALG_APMD5;

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

    check_args(argc, argv, &ctx, &mask, &user, &pwfilename);

    /*
     * Only do the file checks if we're supposed to frob it.
     */
    if (!(mask & APHTP_NOFILE)) {
        existing_file = exists(pwfilename, pool);
        if (existing_file && (mask & APHTP_VERIFY) == 0) {
            /*
             * Check that this existing file is readable and writable.
             */
            if (!accessible(pool, pwfilename, APR_FOPEN_READ|APR_FOPEN_WRITE)) {
                apr_file_printf(errfile, "%s: cannot open file %s for "
                                "read/write access" NL, argv[0], pwfilename);
                exit(ERR_FILEPERM);
            }
        }
        else if (existing_file && (mask & APHTP_VERIFY) != 0) {
            /*
             * Check that this existing file is readable.
             */
            if (!accessible(pool, pwfilename, APR_FOPEN_READ)) {
                apr_file_printf(errfile, "%s: cannot open file %s for "
                                "read access" NL, argv[0], pwfilename);
                exit(ERR_FILEPERM);
            }
        }
        else {
            /*
             * Error out if -c was omitted for this non-existent file.
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
            if (!accessible(pool, pwfilename, APR_FOPEN_WRITE|APR_FOPEN_CREATE)) {
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
    if ((mask & (APHTP_DELUSER|APHTP_VERIFY)) == 0) {
        i = mkrecord(&ctx, user);
        if (i != 0) {
            apr_file_printf(errfile, "%s: %s" NL, argv[0], ctx.errstr);
            exit(i);
        }
        if (mask & APHTP_NOFILE) {
            printf("%s" NL, ctx.out);
            exit(0);
        }
    }

    if ((mask & APHTP_VERIFY) == 0) {
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
                /* We found the user we were looking for */
                found++;
                if ((mask & APHTP_DELUSER)) {
                    /* Delete entry from the file */
                    apr_file_printf(errfile, "Deleting ");
                }
                else if ((mask & APHTP_VERIFY)) {
                    /* Verify */
                    char *hash = colon + 1;
                    size_t len;

                    len = strcspn(hash, "\r\n");
                    if (len == 0) {
                        apr_file_printf(errfile, "Empty hash for user %s" NL,
                                        user);
                        exit(ERR_INVALID);
                    }
                    hash[len] = '\0';

                    i = verify(&ctx, hash);
                    if (i != 0) {
                        apr_file_printf(errfile, "%s" NL, ctx.errstr);
                        exit(i);
                    }
                }
                else {
                    /* Update entry */
                    apr_file_printf(errfile, "Updating ");
                    putline(ftemp, ctx.out);
                }
            }
        }
        apr_file_close(fpw);
    }
    if (!found) {
        if (mask & APHTP_DELUSER) {
            apr_file_printf(errfile, "User %s not found" NL, user);
            exit(0);
        }
        else if (mask & APHTP_VERIFY) {
            apr_file_printf(errfile, "User %s not found" NL, user);
            exit(ERR_BADUSER);
        }
        else {
            apr_file_printf(errfile, "Adding ");
            putline(ftemp, ctx.out);
        }
    }
    if (mask & APHTP_VERIFY) {
        apr_file_printf(errfile, "Password for user %s correct." NL, user);
        exit(0);
    }

    apr_file_printf(errfile, "password for user %s" NL, user);

    /* The temporary file has all the data, just copy it to the new location.
     */
    if (apr_file_copy(dirname, pwfilename, APR_OS_DEFAULT, pool) !=
        APR_SUCCESS) {
        apr_file_printf(errfile, "%s: unable to update file %s" NL,
                        argv[0], pwfilename);
        exit(ERR_FILEPERM);
    }
    apr_file_close(ftemp);
    return 0;
}
