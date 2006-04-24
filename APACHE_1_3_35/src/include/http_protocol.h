/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef APACHE_HTTP_PROTOCOL_H
#define APACHE_HTTP_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Prototypes for routines which either talk directly back to the user,
 * or control the ones that eventually do.
 */

/* Read a request and fill in the fields. */

API_EXPORT(request_rec *) ap_read_request(conn_rec *c);

/* Send a single HTTP header field */

API_EXPORT_NONSTD(int) ap_send_header_field(request_rec *r, const char *fieldname,
                      const char *fieldval);

/* Send the minimal part of an HTTP response header... but modules should be
 * very careful about using this, and should prefer ap_send_http_header().
 * Much of the HTTP/1.1 implementation correctness depends on code in
 * ap_send_http_header().
 */
API_EXPORT(void) ap_basic_http_header(request_rec *r);

/* Send the Status-Line and header fields for HTTP response */

API_EXPORT(void) ap_send_http_header(request_rec *l);

/* Send the response to special method requests */

API_EXPORT(int) ap_send_http_trace(request_rec *r);
API_EXPORT(int) ap_send_http_options(request_rec *r);

/* Finish up stuff after a request */

API_EXPORT(void) ap_finalize_request_protocol(request_rec *r);

/* Send error back to client... last arg indicates error status in case
 * we get an error in the process of trying to deal with an ErrorDocument
 * to handle some other error.  In that case, we print the default report
 * for the first thing that went wrong, and more briefly report on the
 * problem with the ErrorDocument.
 */

API_EXPORT(void) ap_send_error_response(request_rec *r, int recursive_error);

/* Set last modified header line from the lastmod date of the associated file.
 * Also, set content length.
 *
 * May return an error status, typically USE_LOCAL_COPY (that when the
 * permit_cache argument is set to one).
 */

API_EXPORT(int) ap_set_content_length(request_rec *r, long length);
API_EXPORT(int) ap_set_keepalive(request_rec *r);
API_EXPORT(time_t) ap_rationalize_mtime(request_rec *r, time_t mtime);
API_EXPORT(char *) ap_make_etag(request_rec *r, int force_weak);
API_EXPORT(void) ap_set_etag(request_rec *r);
API_EXPORT(void) ap_set_last_modified(request_rec *r);
API_EXPORT(int) ap_meets_conditions(request_rec *r);

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

API_EXPORT(long) ap_send_fd(FILE *f, request_rec *r);
API_EXPORT(long) ap_send_fd_length(FILE *f, request_rec *r, long length);

API_EXPORT(long) ap_send_fb(BUFF *f, request_rec *r);
API_EXPORT(long) ap_send_fb_length(BUFF *f, request_rec *r, long length);

API_EXPORT(size_t) ap_send_mmap(void *mm, request_rec *r, size_t offset,
                             size_t length);

/* Hmmm... could macrofy these for now, and maybe forever, though the
 * definitions of the macros would get a whole lot hairier.
 */

API_EXPORT(int) ap_rputc(int c, request_rec *r);
API_EXPORT(int) ap_rputs(const char *str, request_rec *r);
API_EXPORT(int) ap_rwrite(const void *buf, int nbyte, request_rec *r);
API_EXPORT_NONSTD(int) ap_rvputs(request_rec *r,...);
API_EXPORT(int) ap_vrprintf(request_rec *r, const char *fmt, va_list vlist);
API_EXPORT_NONSTD(int) ap_rprintf(request_rec *r, const char *fmt,...)
				__attribute__((format(printf,2,3)));
API_EXPORT(int) ap_rflush(request_rec *r);

/*
 * Index used in custom_responses array for a specific error code
 * (only use outside protocol.c is in getting them configured).
 */

API_EXPORT(int) ap_index_of_response(int status);

/* Reading a block of data from the client connection (e.g., POST arg) */

API_EXPORT(int) ap_setup_client_block(request_rec *r, int read_policy);
API_EXPORT(int) ap_should_client_block(request_rec *r);
API_EXPORT(long) ap_get_client_block(request_rec *r, char *buffer, int bufsiz);
API_EXPORT(int) ap_discard_request_body(request_rec *r);

/* Sending a byterange */

API_EXPORT(int) ap_set_byterange(request_rec *r);
API_EXPORT(int) ap_each_byterange(request_rec *r, long *offset, long *length);

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

API_EXPORT(void) ap_note_auth_failure(request_rec *r);
API_EXPORT(void) ap_note_basic_auth_failure(request_rec *r);
API_EXPORT(void) ap_note_digest_auth_failure(request_rec *r);
API_EXPORT(int) ap_get_basic_auth_pw(request_rec *r, const char **pw);

/*
 * Setting up the protocol fields for subsidiary requests...
 * Also, a wrapup function to keep the internal accounting straight.
 */

API_EXPORT(void) ap_set_sub_req_protocol(request_rec *rnew, const request_rec *r);
API_EXPORT(void) ap_finalize_sub_req_protocol(request_rec *sub_r);

/* This is also useful for putting sub_reqs and internal_redirects together */

CORE_EXPORT(void) ap_parse_uri(request_rec *r, const char *uri);

/* Get the method number associated with the given string, assumed to
 * contain an HTTP method.  Returns M_INVALID if not recognized.
 */
API_EXPORT(int) ap_method_number_of(const char *method);

API_EXPORT(int) ap_getline(char *s, int n, BUFF *in, int fold);

API_EXPORT(long) ap_get_chunk_size(char *b);


#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_PROTOCOL_H */
