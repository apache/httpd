/* ====================================================================
 * Copyright (c) 1998 The Apache Group.  All rights reserved.
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
 * 5. Redistributions of any form whatsoever must retain the following
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
 * This code is based on, and used with the permission of, the
 * SIO stdio-replacement strx_* functions by Panos Tsirigotis
 * <panos@alumni.cs.colorado.edu> for xinetd.
 */

#ifndef APACHE_AP_H
#define APACHE_AP_H

API_EXPORT(char *) ap_cpystrn(char *, const char *, size_t);
int ap_slack(int, int);
API_EXPORT(char *) ap_escape_quotes(pool *, const char *);
API_EXPORT(int) ap_snprintf(char *, size_t, const char *, ...);
API_EXPORT(int) ap_vsnprintf(char *, size_t, const char *, va_list ap);
int ap_execle(const char *, const char *, ...);
int ap_execve(const char *, const char *argv[], const char *envp[]);

/* small utility macros to make things easier to read */

#ifdef WIN32
#define ap_killpg(x, y)
#else
#ifdef NO_KILLPG
#define ap_killpg(x, y)		(kill (-(x), (y)))
#else
#define ap_killpg(x, y)		(killpg ((x), (y)))
#endif
#endif /* WIN32 */

/* apapi_vformatter() is a generic printf-style formatting routine
 * with some extensions.
 *
 * The write_func() is called when there is data available to be
 * output.  write_func() should return 0 when it wishes apapi_vformatter
 * to continue, and non-zero otherwise.  apapi_vformatter will stop
 * immediately and return -1 when a non-zero return from
 * write_func().
 *
 * If write_func() always returns 0 then apapi_vformatter will return
 * the number of characters written.
 */

API_EXPORT(int) apapi_vformatter(
    int (*write_func)(void *write_data, const char *outp, size_t len),
    void *write_data, const char *fmt, va_list ap);

/* These are snprintf implementations based on apapi_vformatter(). */
API_EXPORT(int) ap_snprintf(char *buf, size_t len, const char *format,...)
			    __attribute__((format(printf,3,4)));
API_EXPORT(int) ap_vsnprintf(char *buf, size_t len, const char *format,
			     va_list ap);

#endif	/* !APACHE_AP_H */
