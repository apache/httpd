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
 */

#include "ap_config.h"
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include "ap.h"
#include "ap_md5.h"

#ifdef WIN32
#include <conio.h>
#include "../os/win32/getopt.h"
#define unlink _unlink
#endif

#ifndef CHARSET_EBCDIC
#define LF 10
#define CR 13
#else /*CHARSET_EBCDIC*/
#define LF '\n'
#define CR '\r'
#endif /*CHARSET_EBCDIC*/

#define MAX_STRING_LEN 256
#define ALG_CRYPT 1
#define ALG_APMD5 2

#define ERR_FILEPERM 1
#define ERR_SYNTAX 2
#define ERR_PWMISMATCH 3
#define ERR_INTERRUPTED 4
#define ERR_OVERFLOW 5

/*
 * This needs to be declared statically so the signal handler can
 * access it.
 */
static char *tempfilename;

/*
 * Duplicate a string into memory malloc()ed for it.
 */
static char *strd(char *s)
{
    char *d;

    d = (char *) malloc(strlen(s) + 1);
    strcpy(d, s);
    return (d);
}

static int getline(char *s, int n, FILE *f)
{
    register int i = 0;

    while (1) {
	s[i] = (char) fgetc(f);

	if (s[i] == CR) {
	    s[i] = fgetc(f);
	}

	if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
	    s[i] = '\0';
	    return (feof(f) ? 1 : 0);
	}
	++i;
    }
}

static void putline(FILE *f, char *l)
{
    int x;

    for (x = 0; l[x]; x++) {
	fputc(l[x], f);
    }
    fputc('\n', f);
}


/* From local_passwd.c (C) Regents of Univ. of California blah blah */
static unsigned char itoa64[] =	/* 0 ... 63 => ascii - 64 */
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void to64(register char *s, register long v, register int n)
{
    while (--n >= 0) {
	*s++ = itoa64[v & 0x3f];
	v >>= 6;
    }
}

#ifdef MPE
/*
 * MPE lacks getpass() and a way to suppress stdin echo.  So for now, just
 * issue the prompt and read the results with echo.  (Ugh).
 */

static char *getpass(const char *prompt)
{
    static char password[81];

    fputs(prompt, stderr);
    gets((char *) &password);

    if (strlen((char *) &password) > 8) {
	password[8] = '\0';
    }

    return (char *) &password;
}

#endif

#ifdef WIN32
/*
 * Windows lacks getpass().  So we'll re-implement it here.
 */

static char *getpass(const char *prompt)
{
    static char password[81];
    int n = 0;

    fputs(prompt, stderr);
    
    while ((password[n] = _getch()) != '\r') {
        if (password[n] >= ' ' && password[n] <= '~') {
            n++;
            printf("*");
        }
	else {
            printf("\n");
            fputs(prompt, stderr);
            n = 0;
        }
    }
 
    password[n] = '\0';
    printf("\n");

    if (n > 8) {
        password[8] = '\0';
    }

    return (char *) &password;
}
#endif

/*
 * Make a password record from the given information.  A zero return
 * indicates success; failure means that the output buffer contains an
 * error message instead.
 */
static int mkrecord(char *user, char *record, size_t rlen, int alg)
{
    char *pw;
    char cpw[120];
    char salt[9];

    pw = strd((char *) getpass("New password: "));
    if (strcmp(pw, (char *) getpass("Re-type new password: "))) {
	ap_cpystrn(record, "password verification error", (rlen - 1));
	return ERR_PWMISMATCH;
    }
    (void) srand((int) time((time_t *) NULL));
    to64(&salt[0], rand(), 8);
    salt[8] = '\0';

    switch (alg) {
    case ALG_APMD5:
	ap_MD5Encode(pw, salt, cpw, sizeof(cpw));
	break;
    case ALG_CRYPT:
	ap_cpystrn(cpw, (char *)crypt(pw, salt), sizeof(cpw) - 1);
	break;
    }
    /*
     * Now that we have the smashed password, we don't need the
     * plaintext one any more.
     */
    free(pw);
    /*
     * Check to see if the buffer is large enough to hold the username,
     * hash, and delimiters.
     */
    if ((strlen(user) + 1 + strlen(cpw)) > (rlen - 1)) {
	ap_cpystrn(record, "resultant record too long", (rlen - 1));
	return ERR_OVERFLOW;
    }
    strcpy(record, user);
    strcat(record, ":");
    strcat(record, cpw);
    return 0;
}

static int usage(void)
{
    fprintf(stderr, "Usage: htpasswd [-cm] passwordfile username\n");
    fprintf(stderr, "The -c flag creates a new file.\n");
    fprintf(stderr, "The -m flag forces MD5 encryption of the password.\n");
    fprintf(stderr, "On Windows systems the -m flag is used by default.\n");
    return ERR_SYNTAX;
}

static void interrupted(void)
{
    fprintf(stderr, "Interrupted.\n");
    if (tempfilename != NULL) {
	unlink(tempfilename);
    }
    exit(ERR_INTERRUPTED);
}

/*
 * Check to see if the specified file can be opened for the given
 * access.
 */
static int accessible(char *fname, char *mode)
{
    FILE *s;

    s = fopen(fname, mode);
    if (s == NULL) {
	return 0;
    }
    fclose(s);
    return 1;
}

/*
 * Return true if a file is readable.
 */
static int readable(char *fname)
{
    return accessible(fname, "r");
}

/*
 * Return true if the specified file can be opened for write access.
 */
static int writable(char *fname)
{
    return accessible(fname, "a");
}

/*
 * Return true if the named file exists, regardless of permissions.
 */
static int exists(char *fname)
{
#ifdef WIN32
    struct _stat sbuf;
#else
    struct stat sbuf;
#endif
    int check;

#ifdef WIN32
    check = _stat(fname, &sbuf);
#else
    check = stat(fname, &sbuf);
#endif
    return ((check == -1) && (errno == ENOENT)) ? 0 : 1;
}

/*
 * Copy from the current position of one file to the current position
 * of another.
 */
static void copy_file(FILE *target, FILE *source)
{
    static char line[MAX_STRING_LEN];

    while (fgets(line, sizeof(line), source) != NULL) {
	fputs(line, target);
    }
}

/*
 * Let's do it.  We end up doing a lot of file opening and closing,
 * but what do we care?  This application isn't run constantly.
 */
int main(int argc, char *argv[])
{
    FILE *ftemp = NULL;
    FILE *fpw = NULL;
    char user[MAX_STRING_LEN];
    char record[MAX_STRING_LEN];
    char line[MAX_STRING_LEN];
    char pwfilename[MAX_STRING_LEN];
    char *arg;
    int found = 0;
    int alg = ALG_CRYPT;
    int newfile = 0;
    int i;

    tempfilename = NULL;
    signal(SIGINT, (void (*)(int)) interrupted);

    /*
     * Preliminary check to make sure they provided at least
     * three arguments, we'll do better argument checking as 
     * we parse the command line.
     */
    if (argc < 3) {
	return usage();
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
		newfile++;
	    }
	    else if (*arg == 'm') {
		alg = ALG_APMD5;
	    }
	    else {
		return usage();
	    }
	}
    }

    /*
     * Make sure we still have exactly two arguments left (the filename
     * and the username).
     */
    if ((argc - i) != 2) {
	return usage();
    }
    if (strlen(argv[i]) > (sizeof(pwfilename) - 1)) {
	fprintf(stderr, "%s: filename too long\n", argv[0]);
	return ERR_OVERFLOW;
    }
    strcpy(pwfilename, argv[i]);
    if (strlen(argv[i + 1]) > (sizeof(user) - 1)) {
	fprintf(stderr, "%s: username too long\n", argv[0]);
	return ERR_OVERFLOW;
    }
    strcpy(user, argv[i + 1]);

#ifdef WIN32
    if (alg == ALG_CRYPT) {
	alg = ALG_APMD5;
	fprintf(stderr, "Automatically using MD5 format on Windows.\n");
    }
#endif

    /*
     * Verify that the file exists if -c was omitted.  We give a special
     * message if it doesn't.
     */
    if ((! newfile) && (! exists(pwfilename))) {
	fprintf(stderr, "%s: cannot modify file %s; use '-c' to create it\n",
		argv[0], pwfilename);
	perror("fopen");
	exit(ERR_FILEPERM);
    }
    /*
     * Verify that we can read the existing file in the case of an update
     * to it (rather than creation of a new one).
     */
    if ((! newfile) && (! readable(pwfilename))) {
	fprintf(stderr, "%s: cannot open file %s for read access\n",
		argv[0], pwfilename);
	perror("fopen");
	exit(ERR_FILEPERM);
    }
    /*
     * Now check to see if we can preserve an existing file in case
     * of password verification errors on a -c operation.
     */
    if (newfile && exists(pwfilename) && (! readable(pwfilename))) {
	fprintf(stderr, "%s: cannot open file %s for read access\n"
		"%s: existing auth data would be lost on password mismatch",
		argv[0], pwfilename, argv[0]);
	perror("fopen");
	exit(ERR_FILEPERM);
    }
    /*
     * Now verify that the file is writable!
     */
    if (! writable(pwfilename)) {
	fprintf(stderr, "%s: cannot open file %s for write access\n",
		argv[0], pwfilename);
	perror("fopen");
	exit(ERR_FILEPERM);
    }

    /*
     * All the file access checks have been made.  Time to go to work;
     * try to create the record for the username in question.  If that
     * fails, there's no need to waste any time on file manipulations.
     * Any error message text is returned in the record buffer, since
     * the mkrecord() routine doesn't have access to argv[].
     */
    if ((i = mkrecord(user, record, sizeof(record) - 1, alg)) != 0) {
	fprintf(stderr, "%s: %s\n", argv[0], record);
	exit(i);
    }

    /*
     * We can access the files the right way, and we have a record
     * to add or update.  Let's do it..
     */
    tempfilename = tmpnam(NULL);
    ftemp = fopen(tempfilename, "w+");
    if (ftemp == NULL) {
	fprintf(stderr, "%s: unable to create temporary file\n", argv[0]);
	perror("fopen");
	exit(ERR_FILEPERM);
    }
    /*
     * If we're not creating a new file, copy records from the existing
     * one to the temporary file until we find the specified user.
     */
    if (! newfile) {
	char scratch[MAX_STRING_LEN];

	fpw = fopen(pwfilename, "r");
	while (! (getline(line, sizeof(line), fpw))) {
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
	    found++;
	    break;
	}
    }
    if (found) {
	fprintf(stderr, "Updating ");
    }
    else {
	fprintf(stderr, "Adding ");
    }
    fprintf(stderr, "password for user %s\n", user);
    /*
     * Now add the user record we created.
     */
    putline(ftemp, record);
    /*
     * If we're updating an existing file, there may be additional
     * records beyond the one we're updating, so copy them.
     */
    if (! newfile) {
	copy_file(ftemp, fpw);
	fclose(fpw);
    }
    /*
     * The temporary file now contains the information that should be
     * in the actual password file.  Close the open files, re-open them
     * in the appropriate mode, and copy them file to the real one.
     */
    fclose(ftemp);
    fpw = fopen(pwfilename, "w+");
    ftemp = fopen(tempfilename, "r");
    copy_file(fpw, ftemp);
    fclose(fpw);
    fclose(ftemp);
    unlink(tempfilename);
    return 0;
}
