/* ====================================================================
 * Copyright (c) 1995-1998 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#ifndef APACHE_HTTP_LOG_H
#define APACHE_HTTP_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_SYSLOG
#include <syslog.h>

#define APLOG_EMERG     LOG_EMERG     /* system is unusable */
#define APLOG_ALERT     LOG_ALERT     /* action must be taken immediately */
#define APLOG_CRIT      LOG_CRIT      /* critical conditions */
#define APLOG_ERR       LOG_ERR       /* error conditions */
#define APLOG_WARNING   LOG_WARNING   /* warning conditions */
#define APLOG_NOTICE    LOG_NOTICE    /* normal but significant condition */
#define APLOG_INFO      LOG_INFO      /* informational */
#define APLOG_DEBUG     LOG_DEBUG     /* debug-level messages */

#define APLOG_LEVELMASK LOG_PRIMASK   /* mask off the level value */

#else

#define	APLOG_EMERG	0	/* system is unusable */
#define	APLOG_ALERT	1	/* action must be taken immediately */
#define	APLOG_CRIT	2	/* critical conditions */
#define	APLOG_ERR	3	/* error conditions */
#define	APLOG_WARNING	4	/* warning conditions */
#define	APLOG_NOTICE	5	/* normal but significant condition */
#define	APLOG_INFO	6	/* informational */
#define	APLOG_DEBUG	7	/* debug-level messages */

#define	APLOG_LEVELMASK	7	/* mask off the level value */

#endif

#define APLOG_NOERRNO		(APLOG_LEVELMASK + 1)
#ifdef WIN32
/* Set to indicate that error msg should come from Win32's GetLastError(),
 * not errno. */
#define APLOG_WIN32ERROR	((APLOG_LEVELMASK+1) * 2)
#endif

#ifndef DEFAULT_LOGLEVEL
#define DEFAULT_LOGLEVEL	APLOG_WARNING
#endif

#define APLOG_MARK	__FILE__,__LINE__

void ap_open_logs (server_rec *, pool *p);
API_EXPORT(void) ap_log_error(const char *file, int line, int level,
			     const server_rec *s, const char *fmt, ...)
			    __attribute__((format(printf,5,6)));
API_EXPORT(void) ap_log_rerror(const char *file, int line, int level,
			     const request_rec *s, const char *fmt, ...)
			    __attribute__((format(printf,5,6)));
API_EXPORT(void) ap_error_log2stderr (server_rec *);     

void ap_log_pid (pool *p, char *fname);
/* These are for legacy code, new code should use ap_log_error,
 * or ap_log_rerror.
 */
API_EXPORT(void) ap_log_error_old(const char *err, server_rec *s);
API_EXPORT(void) ap_log_unixerr(const char *routine, const char *file,
			     const char *msg, server_rec *s);
API_EXPORT(void) ap_log_printf(const server_rec *s, const char *fmt, ...)
			    __attribute__((format(printf,2,3)));
API_EXPORT(void) ap_log_reason(const char *reason, const char *fname,
			    request_rec *r);

typedef struct piped_log {
    pool *p;
#ifndef NO_RELIABLE_PIPED_LOGS
    char *program;
    int pid;
    int fds[2];
#else
    FILE *write_f;
#endif
} piped_log;

API_EXPORT(piped_log *) ap_open_piped_log (pool *p, const char *program);
API_EXPORT(void) ap_close_piped_log (piped_log *);
#ifndef NO_RELIABLE_PIPED_LOGS
#define ap_piped_log_read_fd(pl)	((pl)->fds[0])
#define ap_piped_log_write_fd(pl)	((pl)->fds[1])
#else
#define ap_piped_log_read_fd(pl)	(-1)
#define ap_piped_log_write_fd(pl)	(fileno((pl)->write_f))
#endif

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_LOG_H */
