/******************************************************************************
 ******************************************************************************
 * NOTE! This program is not safe as a setuid executable!  Do not make it
 * setuid!
 ******************************************************************************
 *****************************************************************************/
/*
 * htpasswd.c: simple program for manipulating password file for NCSA httpd
 * 
 * Rob McCool
 */

#include "ap_config.h"
#include <sys/types.h>
#include <signal.h>
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

char *tn;

static char *strd(char *s)
{
    char *d;

    d = (char *) malloc(strlen(s) + 1);
    strcpy(d, s);
    return (d);
}

static void getword(char *word, char *line, char stop)
{
    int x = 0, y;

    for (x = 0; ((line[x]) && (line[x] != stop)); x++) {
	word[x] = line[x];
    }

    word[x] = '\0';
    if (line[x]) {
	++x;
    }
    y = 0;

    while ((line[y++] = line[x++]))
	;
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
/* MPE lacks getpass() and a way to suppress stdin echo.  So for now, just
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
/* Windows lacks getpass().  So we'll re-implement it here.
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

static void add_password(char *user, FILE *f, int use_md5)
{
    char *pw, cpw[120], salt[9];

    pw = strd((char *) getpass("New password:"));
    if (strcmp(pw, (char *) getpass("Re-type new password:"))) {
	fprintf(stderr, "They don't match, sorry.\n");
	if (tn) {
	    unlink(tn);
	}
	exit(1);
    }
    (void) srand((int) time((time_t *) NULL));
    to64(&salt[0], rand(), 8);
    salt[8] = '\0';

    if (use_md5) {
        ap_MD5Encode(pw, salt, cpw, sizeof(cpw));
    }
    else {
	ap_cpystrn(cpw, (char *)crypt(pw, salt), sizeof(cpw) - 1);
    }
    free(pw);
    fprintf(f, "%s:%s\n", user, cpw);
}

static void usage(void)
{
    fprintf(stderr, "Usage: htpasswd [-cm] passwordfile username\n");
    fprintf(stderr, "The -c flag creates a new file.\n");
    fprintf(stderr, "The -m flag creates a md5 encrypted file.\n");
    fprintf(stderr, "On Windows systems the -m flag is used by default.\n");
    exit(1);
}

static void interrupted(void)
{
    fprintf(stderr, "Interrupted.\n");
    if (tn) {
	unlink(tn);
    }
    exit(1);
}

int main(int argc, char *argv[])
{
    FILE *tfp, *f;
    char user[MAX_STRING_LEN];
    char line[MAX_STRING_LEN];
    char l[MAX_STRING_LEN];
    char w[MAX_STRING_LEN];
    char command[MAX_STRING_LEN];
    char filename[MAX_STRING_LEN];
    int found;
    int use_md5 = 0;
    int newfile = 0;
    int currarg = 1;
    int filearg;

    tn = NULL;
    signal(SIGINT, (void (*)(int)) interrupted);

    /* preliminary check to make sure they provided at least
     * three arguments, we'll do better argument checking as 
     * we parse the command line.
     */
    if (argc < 3) {
	    usage();
    }

    /* I would rather use getopt, but Windows and UNIX seem to handle getopt
     * differently, so I am doing the argument checking by hand.
     */
    
    if (!strcmp(argv[1],"-c") || !strcmp(argv[2],"-c")) {
        newfile = 1;
        currarg++;
    }
    if (!strcmp(argv[1],"-m") || !strcmp(argv[2],"-m")) {
        use_md5 = 1;
        currarg++;
    }

    if (!strcmp(argv[1], "-cm") || !strcmp(argv[2], "-mc")) {
        use_md5 = 1;
        newfile = 1;
        currarg++;
    }

    strcpy(filename, argv[currarg]);
    filearg = currarg++;

    if (argc <= filearg + 1) {
        usage();
    }

#ifdef WIN32
    if (!use_md5) {
	use_md5 = 1;
	fprintf(stderr,"Automatically using md5 format on Windows.\n");
    }
#endif
    if (newfile) {
        if (!(tfp = fopen(filename, "w+"))) {
            fprintf(stderr, "Could not open password file %s for writing.\n",
                    filename);
	    perror("fopen");
	    exit(1);
	}
	printf("Adding password for %s.\n", argv[currarg]);
	add_password(argv[currarg], tfp, use_md5);
	fclose(tfp);
	return(0);
    }

    tn = tmpnam(NULL);
    if (!(tfp = fopen(tn, "w+"))) {
	fprintf(stderr, "Could not open temp file.\n");
	exit(1);
    }

    if (!(f = fopen(argv[filearg], "r+"))) {
        fprintf(stderr, "Could not open password file %s for reading.\n",
                argv[filearg]);
        fprintf(stderr, "Use -c option to create a new one\n");
	fclose(tfp);
	unlink(tn);
	exit(1);
    }
    strcpy(user, argv[currarg]);

    found = 0;
    while (!(getline(line, MAX_STRING_LEN, f))) {
	if (found || (line[0] == '#') || (!line[0])) {
	    putline(tfp, line);
	    continue;
	}
	strcpy(l, line);
	getword(w, l, ':');
	if (strcmp(user, w)) {
	    putline(tfp, line);
	    continue;
        }
	else {
	    printf("Changing password for user %s\n", user);
            add_password(user, tfp, use_md5);
	    found = 1;
	}
    }
    if (!found) {
	printf("Adding user %s\n", user);
        add_password(user, tfp, use_md5);
    }
/*
 * make a copy from the tmp file to the actual file
 */  
    f = fopen(filename, "w+");
    rewind(tfp);
    while (fgets(command, MAX_STRING_LEN, tfp) != NULL) {
	fputs(command, f);
    }

    fclose(f);
    fclose(tfp);
    unlink(tn);
    return(0);
}
