/* ====================================================================
 * Copyright (c) 1999 Ralf S. Engelschall. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#include "poll.h"

/* 
 * Emulate SysV poll(2) with BSD select(2)
 * Written in June 1999 by Ralf S. Engelschall <rse@engelschall.com>
 */

int poll(struct pollfd *pfd, unsigned int nfd, int timeout)
{
    fd_set rfds, wfds, efds;
    struct timeval tv, *ptv;
    int maxfd, rc, i, ok;
    char data[64];

    /* poll(2) semantics */
    if (pfd == NULL) {
        errno = EFAULT;
        return -1;
    }

    /* convert timeout number into a timeval structure */
    ptv = &tv;
    if (timeout == 0) {
        /* return immediately */
        ptv->tv_sec  = 0;
        ptv->tv_usec = 0;
    }
    else if (timeout == INFTIM) {
        /* wait forever */
        ptv = NULL;
    }
    else {
        /* return after timeout */
        ptv->tv_sec  = timeout / 1000;
        ptv->tv_usec = (timeout % 1000) * 1000;
    }

    /* clean illegal fd set and (re)enter the repeat loop */

    /* create fd sets and determine max fd */
    maxfd = 0;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    for(i = 0; i < nfd; i++) {
        if (pfd[i].fd < 0) {
            continue;
        }
        if (pfd[i].events & POLLIN)
            FD_SET(pfd[i].fd, &rfds);
        if (pfd[i].events & POLLOUT)
            FD_SET(pfd[i].fd, &wfds);
        if (pfd[i].events & POLLPRI)
            FD_SET(pfd[i].fd, &efds);
        if (pfd[i].fd >= maxfd && (pfd[i].events & (POLLIN|POLLOUT|POLLPRI)))
            maxfd = pfd[i].fd;
    }

    /* examine fd sets */
    rc = select(maxfd+1, &rfds, &wfds, &efds, ptv);

    /* establish results */
    if (rc > 0) {
        rc = 0;
        for (i = 0; i < nfd; i++) {
            ok = 0;
            pfd[i].revents = 0;
            if (pfd[i].fd < 0) {
                /* support for POLLNVAL */
                pfd[i].revents |= POLLNVAL;
                continue;
            }
            if (FD_ISSET(pfd[i].fd, &rfds)) {
                pfd[i].revents |= POLLIN;
                ok++;
                /* support for POLLHUP */
                if (recv(pfd[i].fd, data, 0, 0) == -1) {
                    if (   errno == ESHUTDOWN    || errno == ECONNRESET
                        || errno == ECONNABORTED || errno == ENETRESET) {
                        pfd[i].revents &= ~(POLLIN);
                        pfd[i].revents |= POLLHUP;
                        ok--;
                    }
                }
            }
            if (FD_ISSET(pfd[i].fd, &wfds)) {
                pfd[i].revents |= POLLOUT;
                ok++;
            }
            if (FD_ISSET(pfd[i].fd, &efds)) {
                pfd[i].revents |= POLLPRI;
                ok++;
            }
            if (ok)
                rc++;
        }
    }
    return rc;
}

