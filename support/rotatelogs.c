/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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
 *
 * Ported to APR by Mladen Turk <mturk@mappingsoft.com>
 *
 * 23 Sep 2001
 */


#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_errno.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_general.h"
#include "apr_time.h"

#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STRING_H
#include <string.h>
#endif
#if APR_HAVE_STRINGS_H
#include <strings.h>
#endif

#define BUFSIZE         65536
#define ERRMSGSZ        82

#ifndef MAX_PATH
#define MAX_PATH        1024
#endif

int main (int argc, const char * const argv[])
{
    char buf[BUFSIZE], buf2[MAX_PATH], errbuf[ERRMSGSZ];
    int tLogEnd = 0, tRotation = 0, utc_offset = 0;
    unsigned int sRotation = 0;
    int nMessCount = 0;
    apr_size_t nRead, nWrite;
    int use_strftime = 0;
    int now = 0;
    const char *szLogRoot;
    apr_file_t *f_stdin, *nLogFD = NULL, *nLogFDprev = NULL;
    apr_pool_t *pool;
    char *ptr = NULL;

    apr_app_initialize(&argc, &argv, NULL);
    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);
    if (argc < 3 || argc > 4) {
        fprintf(stderr,
                "Usage: %s <logfile> <rotation time in seconds> "
                "[offset minutes from UTC] or <rotation size in megabytes>\n\n",
                argv[0]);
#ifdef OS2
        fprintf(stderr,
                "Add this:\n\nTransferLog \"|%s.exe /some/where 86400\"\n\n",
                argv[0]);
#else
        fprintf(stderr,
                "Add this:\n\nTransferLog \"|%s /some/where 86400\"\n\n",
                argv[0]);
        fprintf(stderr,
                "or \n\nTransferLog \"|%s /some/where 5M\"\n\n", argv[0]);
#endif
        fprintf(stderr,
                "to httpd.conf. The generated name will be /some/where.nnnn "
                "where nnnn is the\nsystem time at which the log nominally "
                "starts (N.B. if using a rotation time,\nthe time will always "
                "be a multiple of the rotation time, so you can synchronize\n"
                "cron scripts with it). At the end of each rotation time or "
                "when the file size\nis reached a new log is started.\n");
        exit(1);
    }

    szLogRoot = argv[1];

    ptr = strchr (argv[2], 'M');
    if (ptr) {
        if (*(ptr+1) == '\0') {
            sRotation = atoi(argv[2]) * 1048576;
        }
        if (sRotation == 0) {
            fprintf(stderr, "Invalid rotation size parameter\n");
            exit(1);
        }
    }
    else {
        if (argc >= 4) {
            utc_offset = atoi(argv[3]) * 60;
        }
        tRotation = atoi(argv[2]);
        if (tRotation <= 0) {
            fprintf(stderr, "Rotation time must be > 0\n");
            exit(6);
        }
    }

    use_strftime = (strchr(szLogRoot, '%') != NULL);
    if (apr_file_open_stdin(&f_stdin, pool) != APR_SUCCESS) {
        fprintf(stderr, "Unable to open stdin\n");
        exit(1);
    }

    for (;;) {
        nRead = sizeof(buf);
        if (apr_file_read(f_stdin, buf, &nRead) != APR_SUCCESS)
            exit(3);
        if (tRotation) {
            now = (int)(apr_time_now() / APR_USEC_PER_SEC) + utc_offset;
            if (nLogFD != NULL && now >= tLogEnd) {
                nLogFDprev = nLogFD;
                nLogFD = NULL;
            }
        }
        else if (sRotation) {
            apr_finfo_t finfo;
            apr_off_t current_size = -1;

            if ((nLogFD != NULL) && 
                (apr_file_info_get(&finfo, APR_FINFO_SIZE, nLogFD) == APR_SUCCESS)) {
                current_size = finfo.size;
            }

            if (current_size > sRotation) {
                nLogFDprev = nLogFD;
                nLogFD = NULL;
            }
        }
        else {
            fprintf(stderr, "No rotation time or size specified\n");
            exit(2);
        }

        if (nLogFD == NULL) {
            int tLogStart;
                
            if (tRotation)
                tLogStart = (now / tRotation) * tRotation;
            else
                tLogStart = (int)apr_time_sec(apr_time_now());

            if (use_strftime) {
                apr_time_t tNow = apr_time_from_sec(tLogStart);
                apr_time_exp_t e;
                apr_size_t rs;

                apr_time_exp_gmt(&e, tNow);
                apr_strftime(buf2, &rs, sizeof(buf2), szLogRoot, &e);
            }
            else {
                sprintf(buf2, "%s.%010d", szLogRoot, tLogStart);
            }
            tLogEnd = tLogStart + tRotation;
            apr_file_open(&nLogFD, buf2, APR_READ | APR_WRITE | APR_CREATE | APR_APPEND,
                          APR_OS_DEFAULT, pool);
            if (nLogFD == NULL) {
                /* Uh-oh. Failed to open the new log file. Try to clear
                 * the previous log file, note the lost log entries,
                 * and keep on truckin'. */
                if (nLogFDprev == NULL) {
                    fprintf(stderr, "1 Previous file handle doesn't exists %s\n", buf2);
                    exit(2);
                }
                else {
                    nLogFD = nLogFDprev;
                    sprintf(errbuf,
                            "Resetting log file due to error opening "
                            "new log file. %10d messages lost.\n",
                            nMessCount);
                    nWrite = strlen(errbuf);
                    apr_file_trunc(nLogFD, 0);
                    if (apr_file_write(nLogFD, errbuf, &nWrite) != APR_SUCCESS) {
                        fprintf(stderr, "Error writing to the file %s\n", buf2);
                        exit(2);
                    }
                }
            }
            else if (nLogFDprev) {
                apr_file_close(nLogFDprev);
            }
            nMessCount = 0;
        }
        nWrite = nRead;
        apr_file_write(nLogFD, buf, &nWrite);
        if (nWrite != nRead) {
            nMessCount++;
            sprintf(errbuf,
                    "Error writing to log file. "
                    "%10d messages lost.\n",
                    nMessCount);
            nWrite = strlen(errbuf);
            apr_file_trunc(nLogFD, 0);
            if (apr_file_write(nLogFD, errbuf, &nWrite) != APR_SUCCESS) {
                fprintf(stderr, "Error writing to the file %s\n", buf2);
                exit(2);
            }
        }
        else {
            nMessCount++;
        }
    }
    /* Of course we never, but prevent compiler warnings */
    return 0;
}
