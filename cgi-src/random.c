/*
 * A simple randomizer script
 *
 * Jim Jagielski (jim@jaguNET.com)
 *
 * v1.0: 12/95
 *	Simple script / initial coding
 *      Based on animate.c code
 */

/*
 * Method of use:
 *   Assuming that 'random' is placed in /cgi-bin, the CGI "script"
 *   should be called as:
 *
 *        "/cgi-bin/random/pathname-of-randomfile"
 *
 *   The pathname must be a "user-type" pathname (i.e. "~user"). A full
 *   pathname or relative will NOT work.
 *
 *   The "randomfile" must contain a list of complete URLs to the
 *   random locations you'd like to jump to.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/file.h>
#include <pwd.h>
#include <time.h>

/*
 * WEB_USER is the user who "owns" the web pages and who's $HOME
 * is the ServerRoot
 *
 * WEB_GIFS is the location of the system-wide gifs/images directory.
 * Can be relative to ~WEB_USER
 *
 * PUBLIC_HTML is the directory in ~user that the server "looks into"
 * when it sees a ~user path
 */
#define WEB_USER	"web"
#define WEB_GIFS	"images"
#define PUBLIC_HTML	"public_html"

#define FN_STDOUT	1

#define ALL_OK	"HTTP/1.0 200 Ok\n"

#define MAX_RAND_NUM	32767

/*
 * Print out an error message and die
 */
int
dodie(what)
char *what;
{
    extern int errno;
    extern char *sys_errlist[];

    printf("Content-Type: text/plain\n\n");

    printf(" Random Error: %s \n", what);
    printf(" Last Error  : %s [%d]\n", sys_errlist[errno], errno);

    exit(1);
}

/*
 *  Clean up a username and script name -
 *  removing non printables and whitespace.
 *
 *  Also, strip out any '..' chars as well.
 */
void
sanitize(string)
char *string;
{
    int len, in;

    len = strlen(string);
    if (string)
	for (in = 0; in < len; in++) {
	    if (!isprint(string[in]) || isspace(string[in]))
		string[in] = '_';
	    if (string[in] == '.' && string[in + 1] == '.')
		string[in] = '_';
	}
}

/*
 * Chop off the newline and skim off the front white-space.
 *
 */
char *
cleanup(fname)
char *fname;
{
    int len;
    char *fptr;

    len = strlen(fname)-1;
    if (fname[len] == '\n')
	fname[len] = '\0';
    for (fptr=fname; isspace(*fptr); fptr++)
	;
    return(fptr);
}
/*
 * The main program
 */
int
main(argc, argv)
int argc;
char *argv[];
{
    char *pathstr;		/* pathname randomfile */
    char *thefile;		/* the actual filename */
    char *iam;			/* "real" name of program */
#define BUFFER	256
    char fname[BUFFER];		/* the actual files in randomfile */
    char *fptr;			/* and a pointer to it */
    FILE *randfile;		/* the randomfile pointer */
    int numfiles;		/* number of files in the randomfile */
    int randnum;		/* guess... */
    struct passwd *user;	/* For getting uid from name */
    unsigned seed;

    char *getenv();

#define NPH_PREFIX	"nph-"

/*
 *   Check to make sure a query was actually made
 */
    if (!getenv("QUERY_STRING"))
	dodie("No query string was specified, check your URL.");

    if ((pathstr = getenv("PATH_INFO")) == NULL)
	dodie("No path entered, check your URL.");

    if (*++pathstr != '~')
	dodie("Non-user relative path, check your URL.");
    pathstr++;


/*
 * Now, clean up and sanitize the input request
 */
    sanitize(pathstr);

/*
 * Now, time to get the username entered
 */
    if ((thefile = strchr(pathstr, '/')) == NULL)
	dodie("No pathname entered, check your URL.");

    *thefile++ = '\0';

/*
 * and look them up and move on in
 */
    if (!(user = getpwnam(pathstr)))
	dodie("User not found.");

    if (chdir(user->pw_dir))
	dodie("Could not chdir to home directory!");

/*
 * now go into their PUBLIC_HTML directory... Don't do this
 * for the user WEB_USER, but instead go into where the system
 * GIFs are.
 */

    if (strcmp(pathstr, WEB_USER)) {
	if (chdir(PUBLIC_HTML))
	    dodie("Could not chdir to public directory!");
    }

/*
 * Now let's open randomfile if we can. First we need to seed the
 * random number generator
 */
    seed = time((long*)0);
    srand(seed);


    if ((randfile = fopen(thefile, "r")) == NULL)
	dodie("Can't find randomfile or can't read it.");
    
    for (numfiles=0; fgets(fname, sizeof(fname)-1, randfile); numfiles++)
	;

    rewind(randfile);
    randnum = (numfiles*(rand()+1))/MAX_RAND_NUM;

/*
 * If I am running as 'nph-<whatever>' then return the OK Status
 * message before I do anything
 */
    iam = strrchr(argv[0], '/');
    if (!iam++)
	iam = argv[0];
    if (!(strncmp(iam, NPH_PREFIX, strlen(NPH_PREFIX))))
	if (printf("%s", ALL_OK) == -1)
	    exit(1);
    for (numfiles=0;
     numfiles<=randnum && fgets(fname, sizeof(fname)-1, randfile);
     numfiles++)
	;
    fptr = cleanup(fname);
    printf("Location: %s\n\n", fptr);
    exit(0);
}
