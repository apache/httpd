/*
 * A simple WebPage counter
 *
 * Based on an original Perl script by Roman Czyborra
 * Script modified by Jim Jagielski (jim@jaguNET.com)
 *
 * Port to C by Jim Jagielski
 */

/*
 * Method of use:
 *   Assuming that 'count' is placed in /cgi-bin, the CGI "script"
 *   should be called as:
 *
 *        <IMG SRC="/cgi-bin/count/pathname-of-webpage"
 *         ALT="[some bitmapped number]">
 *
 *   Thus, a page in jim's directory would be refered to as:
 *
 *        <IMG SRC="/cgi-bin/count/~jim/page.html"
 *         ALT="[some bitmapped number]">
 *
 */

/*
 * Program methodology:
 *    o Open the lockfile (should exist first)
 *    o and FLOCK it
 *    o Now open and use the dbm file that contains the key and content
 *      where the 'key' is the pathname included in the URL
 *    o increment and store the counter
 *    o return the x-bitmap that is the count
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <dbm.h>
#include <strings.h>

#define COUNT_DIR	"/staff/httpd/counter/data"
#define COUNT_LOCK	"Count"
#define COUNT_FILE	"Count"

main(argc, argv)
int argc;
char *argv[];
{
    datum key, content;
    int fd;
    char *path, *getenv();
    int count, i, j;
    char cntstr[10];
    char *iam;
    int bval;
    char reverse = 0;
    int bitmap[10][10] = {
	{ 0x3c, 0x10, 0x3c, 0x3c, 0x60, 0x7e, 0x3c, 0x7e, 0x3c, 0x3c },
	{ 0x42, 0x1c, 0x42, 0x42, 0x50, 0x02, 0x42, 0x40, 0x42, 0x42 },
	{ 0x42, 0x10, 0x42, 0x42, 0x48, 0x02, 0x02, 0x20, 0x42, 0x42 },
	{ 0x42, 0x10, 0x20, 0x40, 0x48, 0x02, 0x02, 0x20, 0x42, 0x42 },
	{ 0x42, 0x10, 0x10, 0x38, 0x44, 0x3e, 0x3a, 0x10, 0x3c, 0x42 },
	{ 0x42, 0x10, 0x08, 0x40, 0x42, 0x40, 0x46, 0x10, 0x42, 0x7c },
	{ 0x42, 0x10, 0x04, 0x40, 0xfe, 0x40, 0x42, 0x08, 0x42, 0x40 },
	{ 0x42, 0x10, 0x02, 0x42, 0x40, 0x42, 0x42, 0x08, 0x42, 0x42 },
	{ 0x42, 0x10, 0x02, 0x42, 0x40, 0x42, 0x42, 0x04, 0x42, 0x42 },
	{ 0x3c, 0x10, 0x7e, 0x3c, 0x40, 0x3c, 0x3c, 0x04, 0x3c, 0x3c }
    };

    if (!(iam = strrchr(argv[0], '/')))
	iam = argv[0];

    if (strcmp(iam, "ccount") == 0)
	reverse = 1;

    if ((path = getenv("PATH_INFO")) == NULL)
	exit(1);
 
    if (*path == '/')
	path++;
    key.dptr = path;
    key.dsize = strlen(path);

    if (chdir(COUNT_DIR) < 0)
	dodie("count chdir");

    if ((fd = open(COUNT_LOCK, O_RDWR|O_CREAT, 0644)) < 0)
	dodie("count open");

    if (flock(fd, LOCK_EX))
	dodie("count flock");

    if (dbminit(COUNT_FILE))
	dodie("count dbminit");

    content = fetch(key);
    if (!content.dptr) {
	count = 1;
	strcpy(cntstr, "1");
    } else {
	count = (content.dsize < 9) ? content.dsize : 9;
	strncpy(cntstr, content.dptr, count);
	cntstr[count] = '\0';
	count = atoi(cntstr);
	if (++count > 999999999)
	    count = 1;
	sprintf(cntstr, "%d", count);
    }
    content.dptr = cntstr;
    content.dsize = strlen(cntstr);

    if (store(key, content))
	dodie("count store");
    
    if (flock(fd, LOCK_UN))
	dodie("count unflock");

    if (close(fd))
	dodie("count close");

    /*
     * Okey dokey... Got the count, so let's generate the bitmap
     */
    count = strlen(cntstr);	/* for later */
    printf("Content-Type: image/x-xbitmap\n\n");
    printf("#define count_width %d\n", 8*count--);
    printf("#define count_height 10\n");
    printf("static char count_bits[] = {\n");
    for (i=0; i<=9; i++) {
	for(j=0; j<=count; j++) {
	    bval = bitmap[i][cntstr[j]-'0'];
	    if (reverse)
		bval = 0xff - bval;
	    printf(" 0x%02x,", bval);
	}
	printf("\n");
    }
    printf("};\n");
    exit(0);

}

dodie(what)
char *what;
{
    perror(what);
    exit(1);
}
