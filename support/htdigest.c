/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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

/* DELONCLOSE is quite cool, but:
 * we need to close the file before we can copy it.
 * otherwise it's locked by the system ;-(
 *
 * XXX: Other systems affected? (Netware?, OS2?)
 */
#if (defined(WIN32))
#define OMIT_DELONCLOSE 1
#endif

apr_file_t *tfp = NULL;
apr_pool_t *cntxt;
#if APR_CHARSET_EBCDIC
apr_xlate_t *to_ascii;
#endif

static void cleanup_tempfile_and_exit(int rc)
{
    if (tfp) {
#ifdef OMIT_DELONCLOSE
        const char *cfilename;
        char *filename = NULL;

        if (apr_file_name_get(&cfilename, tfp) == APR_SUCCESS) {
            filename = apr_pstrdup(cntxt, cfilename);
        }
#endif
	apr_file_close(tfp);

#ifdef OMIT_DELONCLOSE
        if (filename) {
            apr_file_remove(filename, cntxt);
        }
#endif
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
	fprintf(stderr, "password too long");
	cleanup_tempfile_and_exit(5);
    }
    len = sizeof(pwin);
    apr_password_get("Re-type new password: ", pwv, &len);
    if (strcmp(pwin, pwv) != 0) {
	fprintf(stderr, "They don't match, sorry.\n");
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
    fprintf(stderr, "Usage: htdigest [-c] passwordfile realm username\n");
    fprintf(stderr, "The -c flag creates a new file.\n");
    exit(1);
}

static void interrupted(void)
{
    fprintf(stderr, "Interrupted.\n");
    cleanup_tempfile_and_exit(1);
}

static void terminate(void)
{
#ifdef NETWARE
    pressanykey();
#endif
    apr_terminate();
}

int main(int argc, const char * const argv[])
{
    apr_file_t *f;
    apr_status_t rv;
    char tn[] = "htdigest.tmp.XXXXXX";
    char user[MAX_STRING_LEN];
    char realm[MAX_STRING_LEN];
    char line[MAX_STRING_LEN];
    char l[MAX_STRING_LEN];
    char w[MAX_STRING_LEN];
    char x[MAX_STRING_LEN];
    char command[MAX_STRING_LEN];
    int found;
   
    apr_app_initialize(&argc, &argv, NULL);
    atexit(terminate); 
    apr_pool_create(&cntxt, NULL);

#if APR_CHARSET_EBCDIC
    rv = apr_xlate_open(&to_ascii, "ISO8859-1", APR_DEFAULT_CHARSET, cntxt);
    if (rv) {
        fprintf(stderr, "apr_xlate_open(): %s (%d)\n",
                apr_strerror(rv, line, sizeof(line)), rv);
        exit(1);
    }
#endif
    
    apr_signal(SIGINT, (void (*)(int)) interrupted);
    if (argc == 5) {
	if (strcmp(argv[1], "-c"))
	    usage();
	rv = apr_file_open(&f, argv[2], APR_WRITE | APR_CREATE, -1, cntxt);
        if (rv != APR_SUCCESS) {
            char errmsg[120];

	    fprintf(stderr, "Could not open passwd file %s for writing: %s\n",
		    argv[2],
                    apr_strerror(rv, errmsg, sizeof errmsg));
	    exit(1);
	}
	printf("Adding password for %s in realm %s.\n", argv[4], argv[3]);
	add_password(argv[4], argv[3], f);
	apr_file_close(f);
	exit(0);
    }
    else if (argc != 4)
	usage();

    if (apr_file_mktemp(&tfp, tn,
#ifdef OMIT_DELONCLOSE
    APR_CREATE | APR_READ | APR_WRITE | APR_EXCL
#else
    0
#endif
    , cntxt) != APR_SUCCESS) {
	fprintf(stderr, "Could not open temp file.\n");
	exit(1);
    }

    if (apr_file_open(&f, argv[1], APR_READ, -1, cntxt) != APR_SUCCESS) {
	fprintf(stderr,
		"Could not open passwd file %s for reading.\n", argv[1]);
	fprintf(stderr, "Use -c option to create new one.\n");
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
	    printf("Changing password for user %s in realm %s\n", user, realm);
	    add_password(user, realm, tfp);
	    found = 1;
	}
    }
    if (!found) {
	printf("Adding user %s in realm %s\n", user, realm);
	add_password(user, realm, tfp);
    }
    apr_file_close(f);
#if defined(OS2) || defined(WIN32)
    sprintf(command, "copy \"%s\" \"%s\"", tn, argv[1]);
#else
    sprintf(command, "cp %s %s", tn, argv[1]);
#endif

#ifdef OMIT_DELONCLOSE
    apr_file_close(tfp);
    system(command);
    apr_file_remove(tn, cntxt);
#else
    system(command);
    apr_file_close(tfp);
#endif

    return 0;
}
