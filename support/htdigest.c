/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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

#include "apr_lib.h"
#include "apr_md5.h"

#ifdef HAVE_SYS_TYPES_H
 #include <sys/types.h>
#endif

#ifdef HAVE_SYS_SIGNAL_H
#include <sys/signal.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include <stdlib.h>

#ifdef WIN32
#include <conio.h>
#endif

#if 'A' == 0xC1
#define CHARSET_EBCDIC
#endif

#ifdef CHARSET_EBCDIC
#define LF '\n'
#define CR '\r'
#else
#define LF 10
#define CR 13
#endif /* CHARSET_EBCDIC */

#define MAX_STRING_LEN 256

char *tn;
apr_pool_t *cntxt;
#ifdef CHARSET_EBCDIC
apr_xlate_t *to_ascii;
#endif

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

static int getline(char *s, int n, apr_file_t *f)
{
    register int i = 0;
    char ch;

    while (1) {
	apr_getc(&ch, f);
            s[i] = ch;

	if (s[i] == CR)
	    apr_getc(&ch, f);
            s[i] = ch;

	if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
	    s[i] = '\0';
            if (apr_eof(f) == APR_EOF) {
                return 1;
            }
            return 0;
	}
	++i;
    }
}

static void putline(apr_file_t *f, char *l)
{
    int x;

    for (x = 0; l[x]; x++)
	apr_putc(l[x], f);
    apr_putc('\n', f);
}


static void add_password(char *user, char *realm, apr_file_t *f)
{
    char *pw;
    ap_md5_ctx_t context;
    unsigned char digest[16];
    char string[MAX_STRING_LEN];
    char pwin[MAX_STRING_LEN];
    char pwv[MAX_STRING_LEN];
    unsigned int i;
    size_t len = sizeof(pwin);

    if (apr_getpass("New password: ", pwin, &len) != APR_SUCCESS) {
	fprintf(stderr, "password too long");
	exit(5);
    }
    len = sizeof(pwin);
    apr_getpass("Re-type new password: ", pwv, &len);
    if (strcmp(pwin, pwv) != 0) {
	fprintf(stderr, "They don't match, sorry.\n");
	if (tn) {
	    apr_remove_file(tn, cntxt);
	}
	exit(1);
    }
    pw = pwin;
    apr_fprintf(f, "%s:%s:", user, realm);

    /* Do MD5 stuff */
    sprintf(string, "%s:%s:%s", user, realm, pw);

    apr_MD5Init(&context);
#ifdef CHARSET_EBCDIC
    ap_MD5SetXlate(&context, to_ascii);
#endif
    apr_MD5Update(&context, (unsigned char *) string, strlen(string));
    apr_MD5Final(digest, &context);

    for (i = 0; i < 16; i++)
	apr_fprintf(f, "%02x", digest[i]);

    apr_fprintf(f, "\n");
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
    if (tn)
	apr_remove_file(tn, cntxt);
    exit(1);
}

int main(int argc, char *argv[])
{
    apr_file_t *tfp = NULL, *f;
    apr_status_t rv;
    char user[MAX_STRING_LEN];
    char realm[MAX_STRING_LEN];
    char line[MAX_STRING_LEN];
    char l[MAX_STRING_LEN];
    char w[MAX_STRING_LEN];
    char x[MAX_STRING_LEN];
    char command[MAX_STRING_LEN];
    int found;
   
    rv = apr_initialize();
    if (rv) {
        fprintf(stderr, "apr_initialize(): %s (%d)\n",
                apr_strerror(rv, line, sizeof(line)), rv);
        exit(1);
    }
    atexit(apr_terminate); 
    apr_create_pool(&cntxt, NULL);

#ifdef CHARSET_EBCDIC
    rv = ap_xlate_open(&to_ascii, "ISO8859-1", APR_DEFAULT_CHARSET, cntxt);
    if (rv) {
        fprintf(stderr, "ap_xlate_open(): %s (%d)\n",
                apr_strerror(rv, line, sizeof(line)), rv);
        exit(1);
    }
#endif
    
    tn = NULL;
    apr_signal(SIGINT, (void (*)(int)) interrupted);
    if (argc == 5) {
	if (strcmp(argv[1], "-c"))
	    usage();
	if (apr_open(&tfp, argv[2], APR_WRITE | APR_CREATE, -1, cntxt) != APR_SUCCESS) {
	    fprintf(stderr, "Could not open passwd file %s for writing.\n",
		    argv[2]);
	    perror("apr_open");
	    exit(1);
	}
	printf("Adding password for %s in realm %s.\n", argv[4], argv[3]);
	add_password(argv[4], argv[3], tfp);
	apr_close(tfp);
	exit(0);
    }
    else if (argc != 4)
	usage();

    tn = tmpnam(NULL);
    if (apr_open(&tfp, tn, APR_WRITE | APR_CREATE, -1, cntxt)!= APR_SUCCESS) {
	fprintf(stderr, "Could not open temp file.\n");
	exit(1);
    }

    if (apr_open(&f, argv[1], APR_READ, -1, cntxt) != APR_SUCCESS) {
	fprintf(stderr,
		"Could not open passwd file %s for reading.\n", argv[1]);
	fprintf(stderr, "Use -c option to create new one.\n");
	exit(1);
    }
    strcpy(user, argv[3]);
    strcpy(realm, argv[2]);

    found = 0;
    while (!(getline(line, MAX_STRING_LEN, f))) {
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
    apr_close(f);
    apr_close(tfp);
#if defined(OS2) || defined(WIN32)
    sprintf(command, "copy \"%s\" \"%s\"", tn, argv[1]);
#else
    sprintf(command, "cp %s %s", tn, argv[1]);
#endif
    system(command);
    apr_remove_file(tn, cntxt);
    return 0;
}
