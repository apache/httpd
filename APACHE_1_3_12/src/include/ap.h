/* ====================================================================
 * Copyright (c) 1998-1999 The Apache Group.  All rights reserved.
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
 * The ap_vsnprintf/ap_snprintf functions are based on, and used with the
 * permission of, the  SIO stdio-replacement strx_* functions by Panos
 * Tsirigotis <panos@alumni.cs.colorado.edu> for xinetd.
 */

#ifndef APACHE_AP_H
#define APACHE_AP_H

#ifdef __cplusplus
extern "C" {
#endif

API_EXPORT(char *) ap_cpystrn(char *, const char *, size_t);
int ap_slack(int, int);
int ap_execle(const char *, const char *, ...);
int ap_execve(const char *, char * const argv[], char * const envp[]);
API_EXPORT(int) ap_getpass(const char *prompt, char *pwbuf, size_t bufsiz);

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

/* ap_vformatter() is a generic printf-style formatting routine
 * with some extensions.  The extensions are:
 *
 * %pA	takes a struct in_addr *, and prints it as a.b.c.d
 * %pI	takes a struct sockaddr_in * and prints it as a.b.c.d:port
 * %pp  takes a void * and outputs it in hex
 *
 * The %p hacks are to force gcc's printf warning code to skip
 * over a pointer argument without complaining.  This does
 * mean that the ANSI-style %p (output a void * in hex format) won't
 * work as expected at all, but that seems to be a fair trade-off
 * for the increased robustness of having printf-warnings work.
 *
 * Additionally, ap_vformatter allows for arbitrary output methods
 * using the ap_vformatter_buff and flush_func.
 *
 * The ap_vformatter_buff has two elements curpos and endpos.
 * curpos is where ap_vformatter will write the next byte of output.
 * It proceeds writing output to curpos, and updating curpos, until
 * either the end of output is reached, or curpos == endpos (i.e. the
 * buffer is full).
 *
 * If the end of output is reached, ap_vformatter returns the
 * number of bytes written.
 *
 * When the buffer is full, the flush_func is called.  The flush_func
 * can return -1 to indicate that no further output should be attempted,
 * and ap_vformatter will return immediately with -1.  Otherwise
 * the flush_func should flush the buffer in whatever manner is
 * appropriate, re-initialize curpos and endpos, and return 0.
 *
 * Note that flush_func is only invoked as a result of attempting to
 * write another byte at curpos when curpos >= endpos.  So for
 * example, it's possible when the output exactly matches the buffer
 * space available that curpos == endpos will be true when
 * ap_vformatter returns.
 *
 * ap_vformatter does not call out to any other code, it is entirely
 * self-contained.  This allows the callers to do things which are
 * otherwise "unsafe".  For example, ap_psprintf uses the "scratch"
 * space at the unallocated end of a block, and doesn't actually
 * complete the allocation until ap_vformatter returns.  ap_psprintf
 * would be completely broken if ap_vformatter were to call anything
 * that used a pool.  Similarly http_bprintf() uses the "scratch"
 * space at the end of its output buffer, and doesn't actually note
 * that the space is in use until it either has to flush the buffer
 * or until ap_vformatter returns.
 */

typedef struct {
    char *curpos;
    char *endpos;
} ap_vformatter_buff;

API_EXPORT(int) ap_vformatter(int (*flush_func)(ap_vformatter_buff *),
    ap_vformatter_buff *, const char *fmt, va_list ap);

/* These are snprintf implementations based on ap_vformatter().
 *
 * Note that various standards and implementations disagree on the return
 * value of snprintf, and side-effects due to %n in the formatting string.
 * ap_snprintf behaves as follows:
 *
 * Process the format string until the entire string is exhausted, or
 * the buffer fills.  If the buffer fills then stop processing immediately
 * (so no further %n arguments are processed), and return the buffer
 * length.  In all cases the buffer is NUL terminated.
 *
 * In no event does ap_snprintf return a negative number.  It's not possible
 * to distinguish between an output which was truncated, and an output which
 * exactly filled the buffer.
 */
API_EXPORT(int) ap_snprintf(char *buf, size_t len, const char *format,...)
			    __attribute__((format(printf,3,4)));
API_EXPORT(int) ap_vsnprintf(char *buf, size_t len, const char *format,
			     va_list ap);
/* Simple BASE64 encode/decode functions.
 * 
 * As we might encode binary strings, hence we require the length of
 * the incoming plain source. And return the length of what we decoded.
 *
 * The decoding function takes any non valid char (i.e. whitespace, \0
 * or anything non A-Z,0-9 etc as terminal.
 * 
 * plain strings/binary sequences are not assumed '\0' terminated. Encoded
 * strings are neither. But propably should.
 *
 */
API_EXPORT(int) ap_base64encode_len(int len);
API_EXPORT(int) ap_base64encode(char * coded_dst, const char *plain_src,int len_plain_src);
API_EXPORT(int) ap_base64encode_binary(char * coded_dst, const unsigned char *plain_src,int len_plain_src);

API_EXPORT(int) ap_base64decode_len(const char * coded_src);
API_EXPORT(int) ap_base64decode(char * plain_dst, const char *coded_src);
API_EXPORT(int) ap_base64decode_binary(unsigned char * plain_dst, const char *coded_src);

/* Password validation, as used in AuthType Basic which is able to cope
 * (based on the prefix) with the SHA1, Apache's internal MD5 and (depending
 * on your platform either plain or crypt(3) passwords.
 */
API_EXPORT(char *) ap_validate_password(const char *passwd, const char *hash);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_AP_H */
