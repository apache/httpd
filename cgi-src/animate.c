/*
 * A simple server-push animation script.
 *
 * Jim Jagielski (jim@jaguNET.com)
 *
 * v1.0: 5/95
 *	Simple script / initial coding
 *
 * v1.1: 7/95
 *	Check for Netscape for "multipart"
 *
 * v1.2: 8/95
 *	Allow for nph-animate
 *	interpret extension
 *
 * v1.3: 9/95
 *	Use array (multi_yes[]) that includes list of
 *	 browsers that accept/use multipart
 *
 * v1.4: 12/95
 *	We now use a "framefile" that contains the listing of all the
 *	 frames to animate
 */

/*
 * Method of use:
 *   Assuming that 'animate' is placed in /cgi-bin, the CGI "script"
 *   should be called as:
 *
 *        <IMG SRC="/cgi-bin/animate/pathname-of-framefile?sleep=?">
 *
 *   The pathname must be a "user-type" pathname (i.e. "~user"). A full
 *   pathname or relative will NOT work. The 'sleep' argument says how
 *   many seconds to sleep until we push another time (default is 5 seconds).
 *
 *   For example, if I have a set of gifs, called a-fly.gif -> k-fly.gif,
 *   and I would like them displayed every 5 seconds.
 *   I would call the following URL:
 *
 *        <IMG SRC="/cgi-bin/animate/~jim/ani.list?sleep=5>
 *
 *   Where ani.list contains the list of files
 *
 *   If the browser does not support multipart extensions, then just display
 *   the final gif and DON'T send the "multipart" stuff
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/file.h>
#include <pwd.h>

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

#define CONT_TYPE	"Content-type: "
#define HEADER \
"Content-type: multipart/x-mixed-replace;boundary=EndOfTheDataDudeJim\n"

#define RBOUND "\n--EndOfTheDataDudeJim\n"
#define EBOUND "\n--EndOfTheDataDudeJim--\n"

#define FN_STDOUT	1

#define ALL_OK	"HTTP/1.0 200 Ok\n"

#define A_BUFSIZ	8192
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

    printf(" Animate Error: %s \n", what);
    printf(" Last Error   : %s [%d]\n", sys_errlist[errno], errno);

    exit(1);
}

/*
 * Parse the input tokens
 */
char *
parseit(keyword, string)
char *keyword, *string;
{
#define CP_SZ	256
    char mycopy[CP_SZ];
    char *data;
    char *pointer;

    strncpy(mycopy, string, CP_SZ-1);
    mycopy[CP_SZ-1] = '\0';
    pointer = strtok(mycopy, "&");
    while (pointer) {
	data = strstr(pointer, keyword);
	if (data == pointer) {
	    pointer = strchr(data, '=') + 1;
	    pointer = strdup(pointer);
	    return (pointer);
	} else
	    pointer = strtok(NULL, "&");
    }
    return (NULL);
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
 * Open the file "giffile" and print out the contents
 *  NOTE: we use the filename extension to, in fact, really
 *  determine what kind of file it is (i.e. GIF, JPEG, etc...)
 */
int
printgif(giffile)
char *giffile;
{
    int fd;			/* the file descript. */
    int n_chars;		/* number of chars in/out */
    char buff[A_BUFSIZ];	/* the input/output buffer */
    char *extnsn;		/* the filename extension */
    static struct {
	char *ext;
	char *contype;
    } *tptr, tlist[] = {
	"gif",	"image/gif\n\n",
	"jpg",	"image/jpeg\n\n",
	"jpeg",	"image/jpeg\n\n",
	"jpe",	"image/jpeg\n\n",
	"tiff",	"image/tiff\n\n",
	"tif",	"image/tiff\n\n",
	"rgb",	"image/x-rgb\n\n",
	"xbm",	"image/x-xbitmap\n\n",
	"xpm",	"image/w-xpixmap\n\n",
	"html",	"text/html\n\n",
	"htm",	"text/html\n\n",
	"txt",	"text/plain\n\n",
	"text",	"text/plain\n\n",
	NULL,	NULL
    };

    /*
     * Look at the extension on the file. If one doesn't exist,
     * assume it's a GIF
     */
    extnsn = strrchr(giffile, '.');
    if (!extnsn++)
	extnsn = "gif";

    tptr = tlist;
    while (tptr->ext) {
	if (strcasecmp(extnsn, tptr->ext) == 0)
	    break;
	tptr++;
    }
    if (!tptr->ext)
	tptr = tlist;	/* get 1st entry, which is GIF */
    if ((fd = open(giffile, O_RDONLY)) == -1)
	return(1);
    if (write(FN_STDOUT, CONT_TYPE, strlen(CONT_TYPE)) == -1)
	exit(1);
    if (write(FN_STDOUT, tptr->contype, strlen(tptr->contype)) == -1)
	exit(1);
    while ((n_chars = read(fd, buff, A_BUFSIZ)) > 0)
	if (write(FN_STDOUT, buff, n_chars) == -1)
	    exit(1);
    close(fd);
    return(0);
}

/*
 * Chop off the newline and skim off the front white-space.
 * We also cut off a starting "/" char too
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
    if (*fptr == '/')
	fptr++;
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
    char *pathstr;		/* pathname of the gif */
    char *sleepstr;		/* the time to sleep */
    char *thefile;		/* the actual filename */
    char *browser;		/* the browser used to look at us */
    char *iam;			/* "real" name of program */
#define BUFFER	256
    char fname[BUFFER];		/* the actual files in framefile */
    char *fptr;			/* and a pointer to it */
    struct passwd *user;	/* For getting uid from name */
    int slptime = 5;		/* time to sleep */
    FILE *framefile;		/* the framefile pointer */

    char *getenv();

    static char *multi_yes[] = {
	"Mozilla/1.1",
	"Mozilla/1.2",
	"Mozilla/2.",
	NULL
    };
    char **pmulti = multi_yes;

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

    browser = getenv("HTTP_USER_AGENT");
/*
 * Now get the inputs... we most probably have none but may have 1
 */
    sleepstr = parseit("sleep", getenv("QUERY_STRING"));

/*
 * Now, how long to sleep?
 */
    if (sleepstr)
	slptime = atoi(sleepstr);

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
 * Now let's open framefile if we can
 */
    if ((framefile = fopen(thefile, "r")) == NULL)
	dodie("Can't find framefile or can't read it.");

/*
 * If I am running as 'nph-<whatever>' then return the OK Status
 * message before I do anything
 */
    iam = strrchr(argv[0], '/');
    if (!iam++)
	iam = argv[0];
    if (!(strncmp(iam, NPH_PREFIX, strlen(NPH_PREFIX))))
	if (write(FN_STDOUT, ALL_OK, strlen(ALL_OK)) == -1)
	    exit(1);

/*
 * Check to see if the browser being used supports multipart
 */
    if (browser)
	while (*pmulti) {
	    if (strncmp(browser, *pmulti, strlen(*pmulti)))
		pmulti++;
	    else
		break;
	}
    if (!browser || !*pmulti) {
	/*
	 * Hmmm... They must not be using a multipart-aware client.
	 * Grab the last file and print it out. We do this by reading
	 * through framefile until we hit eof
	 */
	while (fgets(fname, sizeof(fname) - 1, framefile))
	    ;
	fptr = cleanup(fname);
	(void) printgif(fptr);
    }
    else {
	if (write(FN_STDOUT, HEADER, strlen(HEADER)) == -1)
	    exit(1);
	if (write(FN_STDOUT, RBOUND, strlen(RBOUND)) == -1)
	    exit(1);

	while (fgets(fname, sizeof(fname) - 1, framefile)) {
	    fptr = cleanup(fname);
	    (void) printgif(fptr);
	    if (write(FN_STDOUT, RBOUND, strlen(RBOUND)) == -1)
		exit(1);
	    sleep(slptime);
	}
    }
    exit(0);
}
