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

#include "ap_config.h"
#ifndef NETWARE
#include <sys/types.h>
#endif
#include "ap.h"
#include "ap_md5.h"
#if defined(MPE) || defined(QNX) || defined(WIN32) || defined(__TANDEM) || defined(OS390) || defined(BEOS) || defined(BONE)
#include <signal.h>
#else
#include <sys/signal.h>
#endif

#ifdef WIN32
#include <conio.h>
#define unlink _unlink
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

static int getline(char *s, int n, FILE *f)
{
    register int i = 0;

    while (1) {
	s[i] = (char) fgetc(f);

	if (s[i] == CR)
	    s[i] = fgetc(f);

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

    for (x = 0; l[x]; x++)
	fputc(l[x], f);
    fputc('\n', f);
}


static void add_password(char *user, char *realm, FILE *f)
{
    char *pw;
    AP_MD5_CTX context;
    unsigned char digest[16];
    char string[MAX_STRING_LEN];
    char pwin[MAX_STRING_LEN];
    char pwv[MAX_STRING_LEN];
    unsigned int i;

    if (ap_getpass("New password: ", pwin, sizeof(pwin)) != 0) {
	fprintf(stderr, "password too long");
	exit(5);
    }
    ap_getpass("Re-type new password: ", pwv, sizeof(pwv));
    if (strcmp(pwin, pwv) != 0) {
	fprintf(stderr, "They don't match, sorry.\n");
	if (tn) {
	    unlink(tn);
	}
	exit(1);
    }
    pw = pwin;
    fprintf(f, "%s:%s:", user, realm);

    /* Do MD5 stuff */
    sprintf(string, "%s:%s:%s", user, realm, pw);

    ap_MD5Init(&context);
    ap_MD5Update(&context, (unsigned char *) string, strlen(string));
    ap_MD5Final(digest, &context);

    for (i = 0; i < 16; i++)
	fprintf(f, "%02x", digest[i]);

    fprintf(f, "\n");
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
	unlink(tn);
    exit(1);
}


#ifdef NETWARE
static void copy_file(FILE *target, FILE *source)
{
    static char line[MAX_STRING_LEN];

    while (!(getline(line, MAX_STRING_LEN, source))) {  
	putline(target, line);
    }
}
#endif

int main(int argc, char *argv[])
{
    FILE *tfp, *f;
    char user[MAX_STRING_LEN];
    char realm[MAX_STRING_LEN];
    char line[MAX_STRING_LEN];
    char l[MAX_STRING_LEN];
    char w[MAX_STRING_LEN];
    char x[MAX_STRING_LEN];
    char command[MAX_STRING_LEN];
    int found;

    tn = NULL;
    signal(SIGINT, (void (*)(int)) interrupted);
    if (argc == 5) {
	if (strcmp(argv[1], "-c"))
	    usage();
#ifdef NETWARE
    UnAugmentAsterisk(TRUE);
    SetCurrentNameSpace(NW_NS_LONG);
    SetTargetNameSpace(NW_NS_LONG);
#endif
	if (!(tfp = fopen(argv[2], "w"))) {
	    fprintf(stderr, "Could not open passwd file %s for writing.\n",
		    argv[2]);
	    perror("fopen");
	    exit(1);
	}
	printf("Adding password for %s in realm %s.\n", argv[4], argv[3]);
	add_password(argv[4], argv[3], tfp);
	fclose(tfp);
	exit(0);
    }
    else if (argc != 4)
	usage();

    tn = tmpnam(NULL);
    if (!(tfp = fopen(tn, "w"))) {
	fprintf(stderr, "Could not open temp file.\n");
	exit(1);
    }

    if (!(f = fopen(argv[1], "r"))) {
	fprintf(stderr,
		"Could not open passwd file %s for reading.\n", argv[1]);
	fprintf(stderr, "Use -c option to create new one.\n");
	exit(1);
    }
    ap_cpystrn(user, argv[3], sizeof(user));
    ap_cpystrn(realm, argv[2], sizeof(realm));

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
    fclose(f);
    fclose(tfp);
#ifndef NETWARE
#if defined(OS2) || defined(WIN32)
    sprintf(command, "copy \"%s\" \"%s\"", tn, argv[1]);
#else
    sprintf(command, "cp %s %s", tn, argv[1]);
#endif
    system(command);
#else
    if (!(tfp = fopen(tn, "r"))) {
    fprintf(stderr, "Could not open temp file.\n");
    exit(1);
    }
    
    if (!(f = fopen(argv[1], "w"))) {
    fprintf(stderr, "Could not open %s.\n", argv[1]);    
    exit(1);    
    }
    
    copy_file(f, tfp);
#endif
    unlink(tn);
    return 0;
}
