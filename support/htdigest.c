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

#ifdef CHARSET_EBCDIC
#define LF '\n'
#define CR '\r'
#else
#define LF 10
#define CR 13
#endif /* CHARSET_EBCDIC */

#define MAX_STRING_LEN 256

char *tn;
ap_pool_t *cntxt;

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

static int getline(char *s, int n, ap_file_t *f)
{
    register int i = 0;
    char ch;

    while (1) {
	ap_getc(&ch, f);
            s[i] = ch;

	if (s[i] == CR)
	    ap_getc(&ch, f);
            s[i] = ch;

	if ((s[i] == 0x4) || (s[i] == LF) || (i == (n - 1))) {
	    s[i] = '\0';
            if (ap_eof(f) == APR_EOF) {
                return 1;
            }
            return 0;
	}
	++i;
    }
}

static void putline(ap_file_t *f, char *l)
{
    int x;

    for (x = 0; l[x]; x++)
	ap_putc(l[x], f);
    ap_putc('\n', f);
}


static void add_password(char *user, char *realm, ap_file_t *f)
{
    char *pw;
    ap_md5_ctx_t context;
    unsigned char digest[16];
    char string[MAX_STRING_LEN];
    char pwin[MAX_STRING_LEN];
    char pwv[MAX_STRING_LEN];
    unsigned int i;
    size_t len = sizeof(pwin);

    if (ap_getpass("New password: ", pwin, &len) != APR_SUCCESS) {
	fprintf(stderr, "password too long");
	exit(5);
    }
    len = sizeof(pwin);
    ap_getpass("Re-type new password: ", pwv, &len);
    if (strcmp(pwin, pwv) != 0) {
	fprintf(stderr, "They don't match, sorry.\n");
	if (tn) {
	    ap_remove_file(tn, cntxt);
	}
	exit(1);
    }
    pw = pwin;
    ap_fprintf(f, "%s:%s:", user, realm);

    /* Do MD5 stuff */
    sprintf(string, "%s:%s:%s", user, realm, pw);

    ap_MD5Init(&context);
    ap_MD5Update(&context, (unsigned char *) string, strlen(string));
    ap_MD5Final(digest, &context);

    for (i = 0; i < 16; i++)
	ap_fprintf(f, "%02x", digest[i]);

    ap_fprintf(f, "\n");
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
	ap_remove_file(tn, cntxt);
    exit(1);
}

int main(int argc, char *argv[])
{
    ap_file_t *tfp, *f;
    char user[MAX_STRING_LEN];
    char realm[MAX_STRING_LEN];
    char line[MAX_STRING_LEN];
    char l[MAX_STRING_LEN];
    char w[MAX_STRING_LEN];
    char x[MAX_STRING_LEN];
    char command[MAX_STRING_LEN];
    int found;
   
    ap_initialize();
    atexit(ap_terminate); 
    ap_create_pool(&cntxt, NULL);

    tn = NULL;
    ap_signal(SIGINT, (void (*)(int)) interrupted);
    if (argc == 5) {
	if (strcmp(argv[1], "-c"))
	    usage();
	if (ap_open(&tfp, argv[2], APR_WRITE | APR_CREATE, -1, cntxt) != APR_SUCCESS) {
	    fprintf(stderr, "Could not open passwd file %s for writing.\n",
		    argv[2]);
	    perror("ap_open");
	    exit(1);
	}
	printf("Adding password for %s in realm %s.\n", argv[4], argv[3]);
	add_password(argv[4], argv[3], tfp);
	ap_close(tfp);
	exit(0);
    }
    else if (argc != 4)
	usage();

    tn = tmpnam(NULL);
    if (ap_open(&tfp, tn, APR_WRITE | APR_CREATE, -1, cntxt)!= APR_SUCCESS) {
	fprintf(stderr, "Could not open temp file.\n");
	exit(1);
    }

    if (ap_open(&f, argv[1], APR_READ, -1, cntxt) != APR_SUCCESS) {
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
    ap_close(f);
    ap_close(tfp);
#if defined(OS2) || defined(WIN32)
    sprintf(command, "copy \"%s\" \"%s\"", tn, argv[1]);
#else
    sprintf(command, "cp %s %s", tn, argv[1]);
#endif
    system(command);
    ap_remove_file(tn, cntxt);
    return 0;
}
