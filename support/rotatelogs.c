/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

/*
 * Simple program to rotate Apache logs without having to kill the server.
 *
 * Contributed by Ben Laurie <ben@algroup.co.uk>
 *
 * 12 Mar 1996
 */


#include "apr.h"
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_IO_H
#include <io.h>
#endif
#if APR_HAVE_FCNTL_H
#include <fcntl.h>
#endif

#define BUFSIZE         65536
#define ERRMSGSZ        82

#ifndef MAX_PATH
#define MAX_PATH        1024
#endif

int main (int argc, char *argv[])
{
    char buf[BUFSIZE], buf2[MAX_PATH], errbuf[ERRMSGSZ];
    time_t tLogEnd = 0, tRotation;
    int nLogFD = -1, nLogFDprev = -1, nMessCount = 0, nRead, nWrite;
    int utc_offset = 0;
    int use_strftime = 0;
    time_t now;
    char *szLogRoot;

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
    /* Of course we never, but prevent compiler warnings */
    return 0;
}
