/*
 * Simple program to rotate Apache logs without having to kill the server.
 *
 * Contributed by Ben Laurie <ben@algroup.co.uk>
 *
 * 12 Mar 1996
 */


#include "ap_config.h"
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#if defined(WIN32) || defined(OS2)
#include <io.h>
#endif

#define BUFSIZE        65536
#define ERRMSGSZ       82
#ifndef MAX_PATH
#define MAX_PATH       1024
#endif

int main (int argc, char **argv)
{
    char buf[BUFSIZE], buf2[MAX_PATH], errbuf[ERRMSGSZ];
    time_t tLogEnd = 0, tRotation;
    int nLogFD = -1, nLogFDprev = -1, nMessCount = 0, nRead, nWrite;
    int utc_offset = 0;
    int use_strftime = 0;
    time_t now;
    char *szLogRoot;

#ifdef TPF
    /* set up signal handling to avoid default OPR-I007777 dump */
    signal(SIGPIPE, exit);
    signal(SIGTERM, exit);
#endif

    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s <logfile> <rotation time in seconds> "
                "[offset minutes from UTC]\n\n",
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
    if (argc >= 4) {
        utc_offset = atoi(argv[3]) * 60;
    }
    tRotation = atoi(argv[2]);
    if (tRotation <= 0) {
        fprintf(stderr, "Rotation time must be > 0\n");
        exit(6);
    }

#if defined(WIN32) || defined(OS2)
    setmode(0, O_BINARY);
#endif

    use_strftime = (strstr(szLogRoot, "%") != NULL);
    for (;;) {
        nRead = read(0, buf, sizeof buf);
        now = time(NULL) + utc_offset;
        if (nRead == 0)
            exit(3);
        if (nRead < 0)
            if (errno != EINTR)
                exit(4);
        if (nLogFD >= 0 && (now >= tLogEnd || nRead < 0)) {
            nLogFDprev = nLogFD;
            nLogFD = -1;
        }
        if (nLogFD < 0) {
            time_t tLogStart = (now / tRotation) * tRotation;
            if (use_strftime) {
                struct tm *tm_now;
                tm_now = gmtime(&tLogStart);
                strftime(buf2, sizeof(buf2), szLogRoot, tm_now);
            }
            else {
                sprintf(buf2, "%s.%010d", szLogRoot, (int) tLogStart);
            }
            tLogEnd = tLogStart + tRotation;
            nLogFD = open(buf2, O_WRONLY | O_CREAT | O_APPEND, 0666);
            if (nLogFD < 0) {
                /* Uh-oh. Failed to open the new log file. Try to clear
                 * the previous log file, note the lost log entries,
                 * and keep on truckin'. */
                if (nLogFDprev == -1) {
                    perror(buf2);
                    exit(2);
                }
                else {
                    nLogFD = nLogFDprev;
                    sprintf(errbuf,
                            "Resetting log file due to error opening "
                            "new log file. %10d messages lost.\n",
                            nMessCount); 
                    nWrite = strlen(errbuf);
#ifdef WIN32
                    chsize(nLogFD, 0);
#else
                    ftruncate(nLogFD, 0);
#endif
                    write(nLogFD, errbuf, nWrite);
                }
            }
            else {
                close(nLogFDprev);
            }
            nMessCount = 0;
        }
        do {
            nWrite = write(nLogFD, buf, nRead);
        } while (nWrite < 0 && errno == EINTR);
        if (nWrite != nRead) {
            nMessCount++;
            sprintf(errbuf,
                    "Error writing to log file. "
                    "%10d messages lost.\n",
                    nMessCount);
            nWrite = strlen(errbuf);
#ifdef WIN32
            chsize(nLogFD, 0);
#else
            ftruncate(nLogFD, 0);
#endif
            write (nLogFD, errbuf, nWrite);
        } 
        else {
            nMessCount++; 
        }
    }
    /* We never get here, but suppress the compile warning */
    return (0);
}
