
/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
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
 *    prior written permission.
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
 */


/*
 * Prototypes for routines which either talk directly back to the user,
 * or control the ones that eventually do.
 */

/* Read a request and fill in the fields. */

request_rec *read_request (conn_rec *c);

/* Send header for http response */

void send_http_header (request_rec *l);     
     
/* Send error back to client... last arg indicates error status in case
 * we get an error in the process of trying to deal with an ErrorDocument
 * to handle some other error.  In that case, we print the default report
 * for the first thing that went wrong, and more briefly report on the
 * problem with the ErrorDocument.
 */

void send_error_response (request_rec *r, int recursive_error);
     
/* Set last modified header line from the lastmod date of the associated file.
 * Also, set content length.
 *
 * May return an error status, typically USE_LOCAL_COPY (that when the
 * permit_cache argument is set to one).
 */

int set_content_length (request_rec *r, long length);
int set_keepalive (request_rec *r);
int set_last_modified (request_rec *r, time_t mtime);

void add_env_var (array_header *env, char *header_name, char *val);

/* Other ways to send stuff at the client.  All of these keep track
 * of bytes_sent automatically.  This indirection is intended to make
 * it a little more painless to slide things like HTTP-NG packetization
 * underneath the main body of the code later.  In the meantime, it lets
 * us centralize a bit of accounting (bytes_sent).
 *
 * These also return the number of bytes written by the call.
 * They should only be called with a timeout registered, for obvious reaasons.
 * (Ditto the send_header stuff).
 */

long send_fd(FILE *f, request_rec *r);
     
/* Hmmm... could macrofy these for now, and maybe forever, though the
 * definitions of the macros would get a whole lot hairier.
 */
     
#if 0
long rprintf (request_rec *r, char *s, ...);     
#endif
int rputc (int c, request_rec *r);     
int rputs(const char *str, request_rec *r);
int rvputs(request_rec *r, ...);
int rprintf(request_rec *r,const char *fmt,...);
     
/*
 * Index used in custom_responses array for a specific error code
 * (only use outside protocol.c is in getting them configured).
 */

int index_of_response (int status);

/* Reading a block of data from the client connection (e.g., POST arg) */
     
long read_client_block (request_rec *r, char *buffer, int bufsiz);
     
/* Finally, this charming little number is here to encapsulate the
 * degree to which nph- scripts completely escape from any discipline
 * the protocol code might care to impose (this as opposed to other
 * scripts, which *partially* escape to the extent that they may try
 * to explicitly set the status line).
 */

void client_to_stdout (conn_rec *c); 


/* Support for the Basic authentication protocol.  Note that there's
 * nothing that prevents these from being in mod_auth.c, except that other
 * modules which wanted to provide their own variants on finding users and
 * passwords for Basic auth (a fairly common request) would then require
 * mod_auth to be loaded or they wouldn't work.
 *
 * get_basic_auth_pw returns 0 (OK) if it set the 'pw' argument (and assured
 * a correct value in r->connection->user); otherwise it returns an error
 * code, either SERVER_ERROR if things are really confused, AUTH_REQUIRED
 * if no authentication at all seemed to be in use, or DECLINED if there
 * was authentication but it wasn't Basic (in which case, the caller should
 * presumably decline as well).
 *
 * note_basic_auth_failure arranges for the right stuff to be scribbled on
 * the HTTP return so that the client knows how to authenticate itself the
 * next time. As does note_digest_auth_failure for Digest auth.
 *
 * note_auth_failure does the same thing, but will call the correct one
 * based on the authentication type in use.
 *
 */

void note_auth_failure(request_rec *r);
void note_basic_auth_failure(request_rec *r);
void note_digest_auth_failure(request_rec *r);
int get_basic_auth_pw (request_rec *r, char **pw);

/*
 * Setting up the protocol fields for subsidiary requests...
 * Also, a wrapup function to keep the internal accounting straight.
 */

void set_sub_req_protocol (request_rec *rnew, request_rec *r);
void finalize_sub_req_protocol (request_rec *sub_r);

/* This is also useful for putting sub_reqs and internal_redirects together */

void parse_uri (request_rec *r, char *uri);     
