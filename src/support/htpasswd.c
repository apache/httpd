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

static void add_password(char *user, FILE *f)
{
    char *pw, *cpw, salt[3];

    pw = strd((char *) getpass("New password:"));
    if (strcmp(pw, (char *) getpass("Re-type new password:"))) {
	fprintf(stderr, "They don't match, sorry.\n");
	if (tn)
	    unlink(tn);
	exit(1);
    }
    (void) srand((int) time((time_t *) NULL));
    to64(&salt[0], rand(), 2);
    salt[2] = '\0';
    cpw = (char *)crypt(pw, salt);
    free(pw);
    fprintf(f, "%s:%s\n", user, cpw);
}

static void usage(void)
{
    fprintf(stderr, "Usage: htpasswd [-c] passwordfile username\n");
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

int main(int argc, char *argv[])
{
    FILE *tfp, *f;
    char user[MAX_STRING_LEN];
    char line[MAX_STRING_LEN];
    char l[MAX_STRING_LEN];
    char w[MAX_STRING_LEN];
    char command[MAX_STRING_LEN];
    int found;

    tn = NULL;
    signal(SIGINT, (void (*)()) interrupted);
    if (argc == 4) {
	if (strcmp(argv[1], "-c"))
	    usage();
      if (!(tfp = fopen(argv[2], "w+"))) {
	    fprintf(stderr, "Could not open passwd file %s for writing.\n",
		    argv[2]);
	    perror("fopen");
	    exit(1);
	}
	printf("Adding password for %s.\n", argv[3]);
	add_password(argv[3], tfp);
	fclose(tfp);
	exit(0);
    }
    else if (argc != 3)
	usage();

    tn = tmpnam(NULL);
    if (!(tfp = fopen(tn, "w+"))) {
	fprintf(stderr, "Could not open temp file.\n");
	exit(1);
    }

    if (!(f = fopen(argv[1], "r+"))) {
	fprintf(stderr,
		"Could not open passwd file %s for reading.\n", argv[1]);
	fprintf(stderr, "Use -c option to create new one.\n");
	exit(1);
    }
    strcpy(user, argv[2]);

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
	    add_password(user, tfp);
	    found = 1;
	}
    }
    if (!found) {
	printf("Adding user %s\n", user);
	add_password(user, tfp);
    }
/*
* make a copy from the tmp file to the actual file
*/  
        rewind(f);
        rewind(tfp);
        while ( fgets(command,MAX_STRING_LEN,tfp) != NULL)
        {
                fputs(command,f);
        } 

    fclose(f);
    fclose(tfp);
    unlink(tn);
    exit(0);
}
