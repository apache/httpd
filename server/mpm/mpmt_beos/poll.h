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

#ifndef _POLL_H_
#define _POLL_H_

#define LIBPOLL_VERSION 19990812

#ifndef POLLIN
#define POLLIN      0x0001      /* any readable data available */
#endif
#ifndef POLLPRI
#define POLLPRI     0x0002      /* OOB/Urgent readable data */
#endif
#ifndef POLLOUT
#define POLLOUT     0x0004      /* file descriptor is writeable */
#endif

#ifndef POLLERR
#define POLLERR     0x0008      /* some poll error occurred */
#endif
#ifndef POLLHUP
#define POLLHUP     0x0010      /* file descriptor was "hung up" */
#endif
#ifndef POLLNVAL
#define POLLNVAL    0x0020      /* requested events "invalid" */
#endif

#ifndef POLLRDNORM
#define POLLRDNORM  POLLIN
#endif
#ifndef POLLRDBAND
#define POLLRDBAND  POLLIN
#endif
#ifndef POLLWRNORM
#define POLLWRNORM  POLLOUT
#endif
#ifndef POLLWRBAND
#define POLLWRBAND  POLLOUT
#endif

#ifndef INFTIM
#define INFTIM      (-1)
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct pollfd {
    int fd;                     /* which file descriptor to poll */
    short events;               /* events we are interested in */
    short revents;              /* events found on return */
};

int poll(struct pollfd *, unsigned int, int);

#ifdef __cplusplus
}
#endif

#endif /* _POLL_H_ */
