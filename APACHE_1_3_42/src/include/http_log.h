/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

API_EXPORT(void) ap_open_logs (server_rec *, pool *p);

/* The two primary logging functions, ap_log_error and ap_log_rerror,
 * use a printf style format string to build the log message.  It is
 * VERY IMPORTANT that you not include any raw data from the network,
 * such as the request-URI or request header fields, within the format
 * string.  Doing so makes the server vulnerable to a denial-of-service
 * attack and other messy behavior.  Instead, use a simple format string
 * like "%s", followed by the string containing the untrusted data.
 */
API_EXPORT_NONSTD(void) ap_log_error(const char *file, int line, int level,
			     const server_rec *s, const char *fmt, ...)
			    __attribute__((format(printf,5,6)));
API_EXPORT_NONSTD(void) ap_log_rerror(const char *file, int line, int level,
			     const request_rec *s, const char *fmt, ...)
			    __attribute__((format(printf,5,6)));
API_EXPORT(void) ap_error_log2stderr (server_rec *);     

API_EXPORT(void) ap_log_pid (pool *p, char *fname);
/* These are for legacy code, new code should use ap_log_error,
 * or ap_log_rerror.
 */
API_EXPORT(void) ap_log_error_old(const char *err, server_rec *s);
API_EXPORT(void) ap_log_unixerr(const char *routine, const char *file,
			     const char *msg, server_rec *s);
API_EXPORT_NONSTD(void) ap_log_printf(const server_rec *s, const char *fmt, ...)
			    __attribute__((format(printf,2,3)));
API_EXPORT(void) ap_log_reason(const char *reason, const char *fname,
			    request_rec *r);

typedef struct piped_log {
    pool *p;
#if !defined(NO_RELIABLE_PIPED_LOGS) || defined(TPF)
    char *program;
    int pid;
    int fds[2];
#else
    FILE *write_f;
#endif
} piped_log;

API_EXPORT(piped_log *) ap_open_piped_log (pool *p, const char *program);
API_EXPORT(void) ap_close_piped_log (piped_log *);
#if !defined(NO_RELIABLE_PIPED_LOGS) || defined(TPF)
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
