/*
 * Simple program to rotate Apache logs without having to kill the server.
 *
 * Contributed by Ben Laurie <ben@algroup.co.uk>
 *
 * 12 Mar 1996
 */


#define BUFSIZE		65536
#define MAX_PATH	1024

#include "ap_config.h"
#include <time.h>
#include <errno.h>
#include <fcntl.h>

int main (int argc, char **argv)
{
    char buf[BUFSIZE], buf2[MAX_PATH];
    time_t tLogEnd = 0;
    time_t tRotation;
    int nLogFD = -1;
    int nRead;
    char *szLogRoot;

    if (argc != 3) {
	fprintf(stderr,
		"%s <logfile> <rotation time in seconds>\n\n",
		argv[0]);
#ifdef OS2
	fprintf(stderr,
		"Add this:\n\nTransferLog \"|%s.exe /some/where 86400\"\n\n",
		argv[0]);
#else
	fprintf(stderr,
		"Add this:\n\nTransferLog \"|%s /some/where 86400\"\n\n",
		argv[0]);
#endif
	fprintf(stderr,
		"to httpd.conf. The generated name will be /some/where.nnnn "
		"where nnnn is the\nsystem time at which the log nominally "
		"starts (N.B. this time will always be a\nmultiple of the "
		"rotation time, so you can synchronize cron scripts with it).\n"
		"At the end of each rotation time a new log is started.\n");
	exit(1);
    }

    szLogRoot = argv[1];
    tRotation = atoi(argv[2]);
    if (tRotation <= 0) {
	fprintf(stderr, "Rotation time must be > 0\n");
	exit(6);
    }

    for (;;) {
	nRead = read(0, buf, sizeof buf);
	if (nRead == 0)
	    exit(3);
	if (nRead < 0)
	    if (errno != EINTR)
		exit(4);
	if (nLogFD >= 0 && (time(NULL) >= tLogEnd || nRead < 0)) {
	    close(nLogFD);
	    nLogFD = -1;
	}
	if (nLogFD < 0) {
	    time_t tLogStart = (time(NULL) / tRotation) * tRotation;
	    sprintf(buf2, "%s.%010d", szLogRoot, (int) tLogStart);
	    tLogEnd = tLogStart + tRotation;
	    nLogFD = open(buf2, O_WRONLY | O_CREAT | O_APPEND, 0666);
	    if (nLogFD < 0) {
		perror(buf2);
		exit(2);
	    }
	}
	if (write(nLogFD, buf, nRead) != nRead) {
	    perror(buf2);
	    exit(5);
	}
    }
}
