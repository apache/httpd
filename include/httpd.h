/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#ifndef APACHE_HTTPD_H
#define APACHE_HTTPD_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * httpd.h: header for simple (ha! not anymore) http daemon
 */

/* XXX - We need to push more stuff to other .h files, or even .c files, to
 * make this file smaller
 */


/* Headers in which EVERYONE has an interest... */
#include "ap_config.h"
#include "os.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "apr_time.h"
#include "apr_network_io.h"
#include "buff.h"
#include "ap_mmn.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef CORE_PRIVATE

/* ----------------------------- config dir ------------------------------ */

/* Define this to be the default server home dir. Most things later in this
 * file with a relative pathname will have this added.
 */
#ifndef HTTPD_ROOT
#ifdef OS2
/* Set default for OS/2 file system */
#define HTTPD_ROOT "/os2httpd"
#elif defined(WIN32)
/* Set default for Windows file system */
#define HTTPD_ROOT "/apache"
#elif defined (BEOS)
/* Set the default for BeOS */
#define HTTPD_ROOT "/boot/home/apache"
#else
#define HTTPD_ROOT "/usr/local/apache"
#endif
#endif /* HTTPD_ROOT */

/* 
 * --------- You shouldn't have to edit anything below this line ----------
 *
 * Any modifications to any defaults not defined above should be done in the 
 * respective config. file. 
 *
 */

/* Default location of documents.  Can be overridden by the DocumentRoot
 * directive.
 */
#ifndef DOCUMENT_LOCATION
#ifdef OS2
/* Set default for OS/2 file system */
#define DOCUMENT_LOCATION  HTTPD_ROOT "/docs"
#else
#define DOCUMENT_LOCATION  HTTPD_ROOT "/htdocs"
#endif
#endif /* DOCUMENT_LOCATION */

/* Max. number of dynamically loaded modules */
#ifndef DYNAMIC_MODULE_LIMIT
#define DYNAMIC_MODULE_LIMIT 64
#endif

/* Default administrator's address */
#define DEFAULT_ADMIN "[no address given]"

/* The target name of the installed Apache */
#ifndef TARGET
#define TARGET "httpd"
#endif

/* --------- Default user name and group name ----------------------------- */
/* --- These may be specified as numbers by placing a # before a number --- */

#ifndef DEFAULT_USER
#define DEFAULT_USER "#-1"
#endif
#ifndef DEFAULT_GROUP
#define DEFAULT_GROUP "#-1"
#endif

/* The name of the log files */
#ifndef DEFAULT_XFERLOG
#if defined(OS2) || defined(WIN32)
#define DEFAULT_XFERLOG "logs/access.log"
#else
#define DEFAULT_XFERLOG "logs/access_log"
#endif
#endif /* DEFAULT_XFERLOG */

#ifndef DEFAULT_ERRORLOG
#if defined(OS2) || defined(WIN32)
#define DEFAULT_ERRORLOG "logs/error.log"
#else
#define DEFAULT_ERRORLOG "logs/error_log"
#endif
#endif /* DEFAULT_ERRORLOG */

/* Define this to be what your per-directory security files are called */
#ifndef DEFAULT_ACCESS_FNAME
#ifdef OS2
/* Set default for OS/2 file system */
#define DEFAULT_ACCESS_FNAME "htaccess"
#else
#define DEFAULT_ACCESS_FNAME ".htaccess"
#endif
#endif /* DEFAULT_ACCESS_FNAME */

/* The name of the server config file */
#ifndef SERVER_CONFIG_FILE
#define SERVER_CONFIG_FILE "conf/httpd.conf"
#endif

/* Whether we should enable rfc1413 identity checking */
#ifndef DEFAULT_RFC1413
#define DEFAULT_RFC1413 0
#endif

/* The default path for CGI scripts if none is currently set */
#ifndef DEFAULT_PATH
#define DEFAULT_PATH "/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin"
#endif

/* The path to the suExec wrapper, can be overridden in Configuration */
#ifndef SUEXEC_BIN
#define SUEXEC_BIN  HTTPD_ROOT "/sbin/suexec"
#endif

/* The timeout for waiting for messages */
#ifndef DEFAULT_TIMEOUT
#define DEFAULT_TIMEOUT 120000 
#endif

/* The timeout for waiting for keepalive timeout until next request */
#ifndef DEFAULT_KEEPALIVE_TIMEOUT
#define DEFAULT_KEEPALIVE_TIMEOUT 300
#endif

/* The number of requests to entertain per connection */
#ifndef DEFAULT_KEEPALIVE
#define DEFAULT_KEEPALIVE 100
#endif

/* The maximum length of the queue of pending connections, as defined
 * by listen(2).  Under some systems, it should be increased if you
 * are experiencing a heavy TCP SYN flood attack.
 *
 * It defaults to 511 instead of 512 because some systems store it 
 * as an 8-bit datatype; 512 truncated to 8-bits is 0, while 511 is 
 * 255 when truncated.
 */

#ifndef DEFAULT_LISTENBACKLOG
#define DEFAULT_LISTENBACKLOG 511
#endif

/* Limits on the size of various request items.  These limits primarily
 * exist to prevent simple denial-of-service attacks on a server based
 * on misuse of the protocol.  The recommended values will depend on the
 * nature of the server resources -- CGI scripts and database backends
 * might require large values, but most servers could get by with much
 * smaller limits than we use below.  The request message body size can
 * be limited by the per-dir config directive LimitRequestBody.
 *
 * Internal buffer sizes are two bytes more than the DEFAULT_LIMIT_REQUEST_LINE
 * and DEFAULT_LIMIT_REQUEST_FIELDSIZE below, which explains the 8190.
 * These two limits can be lowered (but not raised) by the server config
 * directives LimitRequestLine and LimitRequestFieldsize, respectively.
 *
 * DEFAULT_LIMIT_REQUEST_FIELDS can be modified or disabled (set = 0) by
 * the server config directive LimitRequestFields.
 */
#ifndef DEFAULT_LIMIT_REQUEST_LINE
#define DEFAULT_LIMIT_REQUEST_LINE 8190
#endif /* default limit on bytes in Request-Line (Method+URI+HTTP-version) */
#ifndef DEFAULT_LIMIT_REQUEST_FIELDSIZE
#define DEFAULT_LIMIT_REQUEST_FIELDSIZE 8190
#endif /* default limit on bytes in any one header field  */
#ifndef DEFAULT_LIMIT_REQUEST_FIELDS
#define DEFAULT_LIMIT_REQUEST_FIELDS 100
#endif /* default limit on number of request header fields */


/*
 * The default default character set name to add if AddDefaultCharset is
 * enabled.  Overridden with AddDefaultCharsetName.
 */
#define DEFAULT_ADD_DEFAULT_CHARSET_NAME "iso-8859-1"

/*
 * The below defines the base string of the Server: header. Additional
 * tokens can be added via the ap_add_version_component() API call.
 *
 * The tokens are listed in order of their significance for identifying the
 * application.
 *
 * "Product tokens should be short and to the point -- use of them for 
 * advertizing or other non-essential information is explicitly forbidden."
 *
 * Example: "Apache/1.1.0 MrWidget/0.1-alpha" 
 */

/* Define this to 1 if you want fancy indexing, 0 otherwise */
#ifndef DEFAULT_INDEXING
#define DEFAULT_INDEXING 0
#endif
#endif /* CORE_PRIVATE */

#define AP_SERVER_BASEVENDOR "Apache Software Foundation"
#define AP_SERVER_BASEPRODUCT "Apache"
#define AP_SERVER_BASEREVISION "2.0a5-dev"
#define AP_SERVER_BASEVERSION AP_SERVER_BASEPRODUCT "/" AP_SERVER_BASEREVISION
#define AP_SERVER_VERSION  AP_SERVER_BASEVERSION

#define AP_SERVER_PROTOCOL "HTTP/1.1"


/* ------------------ stuff that modules are allowed to look at ----------- */

/* Define this to be what your HTML directory content files are called */
#ifndef AP_DEFAULT_INDEX
#define AP_DEFAULT_INDEX "index.html"
#endif


/* Define this to be what type you'd like returned for files with unknown */
/* suffixes.  MUST be all lower case. */
#ifndef DEFAULT_CONTENT_TYPE
#define DEFAULT_CONTENT_TYPE "text/plain"
#endif

/* The name of the MIME types file */
#ifndef AP_TYPES_CONFIG_FILE
#define AP_TYPES_CONFIG_FILE "conf/mime.types"
#endif

/*
 * Define the HTML doctype strings centrally.
 */
#define DOCTYPE_HTML_2_0  "<!DOCTYPE HTML PUBLIC \"-//IETF//" \
                          "DTD HTML 2.0//EN\">\n"
#define DOCTYPE_HTML_3_2  "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 3.2 Final//EN\">\n"
#define DOCTYPE_HTML_4_0S "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 4.0//EN\"\n" \
                          "\"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
#define DOCTYPE_HTML_4_0T "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 4.0 Transitional//EN\"\n" \
                          "\"http://www.w3.org/TR/REC-html40/loose.dtd\">\n"
#define DOCTYPE_HTML_4_0F "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                          "DTD HTML 4.0 Frameset//EN\"\n" \
                          "\"http://www.w3.org/TR/REC-html40/frameset.dtd\">\n"

/* -- Internal representation for a HTTP protocol number, e.g., HTTP/1.1 -- */

#define HTTP_VERSION(major,minor) (1000*(major)+(minor))
#define HTTP_VERSION_MAJOR(number) ((number)/1000)
#define HTTP_VERSION_MINOR(number) ((number)%1000)

/* -------------- Port number for server running standalone --------------- */

#define DEFAULT_HTTP_PORT	80
#define DEFAULT_HTTPS_PORT	443
#define ap_is_default_port(port,r)	((port) == ap_default_port(r))
#define ap_http_method(r)	ap_run_http_method(r)
#define ap_default_port(r)	ap_run_default_port(r)

/* The default string lengths */
#define MAX_STRING_LEN HUGE_STRING_LEN
#define HUGE_STRING_LEN 8192

/* The size of the server's internal read-write buffers */
#define IOBUFSIZE 8192

/*
 * Special Apache error codes. These are basically used
 *  in http_main.c so we can keep track of various errors.
 *
 *   APEXIT_OK:
 *     A normal exit
 *   APEXIT_INIT:
 *     A fatal error arising during the server's init sequence
 *   APEXIT_CHILDINIT:
 *     The child died during it's init sequence
 *   APEXIT_CHILDFATAL:
 *     A fatal error, resulting in the whole server aborting.
 *     If a child exits with this error, the parent process
 *     considers this a server-wide fatal error and aborts.
 *                 
 */
#define APEXIT_OK		0x0
#define APEXIT_INIT		0x2
#define APEXIT_CHILDINIT	0x3
#define APEXIT_CHILDFATAL	0xf

API_EXPORT(const char *) ap_get_server_version(void);
API_EXPORT(void) ap_add_version_component(apr_pool_t *pconf, const char *component);
API_EXPORT(const char *) ap_get_server_built(void);

/* Numeric release version identifier: MMNNFFRBB: major minor fix final beta
 * Always increases along the same track as the source branch.
 * For example, Apache 1.4.2 would be '10402100', 2.5b7 would be '20500007'.
 */
#define APACHE_RELEASE 20000005

#define DECLINED -1		/* Module declines to handle */
#define DONE -2			/* Module has served the response completely 
				 *  - it's safe to die() with no more output
				 */
#define OK 0			/* Module has handled this stage. */


/* ----------------------- HTTP Status Codes  ------------------------- */

/* The size of the static array in http_protocol.c for storing
 * all of the potential response status-lines (a sparse table).
 * A future version should dynamically generate the apr_table_t at startup.
 */
#define RESPONSE_CODES 55

#define HTTP_CONTINUE                      100
#define HTTP_SWITCHING_PROTOCOLS           101
#define HTTP_PROCESSING                    102
#define HTTP_OK                            200
#define HTTP_CREATED                       201
#define HTTP_ACCEPTED                      202
#define HTTP_NON_AUTHORITATIVE             203
#define HTTP_NO_CONTENT                    204
#define HTTP_RESET_CONTENT                 205
#define HTTP_PARTIAL_CONTENT               206
#define HTTP_MULTI_STATUS                  207
#define HTTP_MULTIPLE_CHOICES              300
#define HTTP_MOVED_PERMANENTLY             301
#define HTTP_MOVED_TEMPORARILY             302
#define HTTP_SEE_OTHER                     303
#define HTTP_NOT_MODIFIED                  304
#define HTTP_USE_PROXY                     305
#define HTTP_TEMPORARY_REDIRECT            307
#define HTTP_BAD_REQUEST                   400
#define HTTP_UNAUTHORIZED                  401
#define HTTP_PAYMENT_REQUIRED              402
#define HTTP_FORBIDDEN                     403
#define HTTP_NOT_FOUND                     404
#define HTTP_METHOD_NOT_ALLOWED            405
#define HTTP_NOT_ACCEPTABLE                406
#define HTTP_PROXY_AUTHENTICATION_REQUIRED 407
#define HTTP_REQUEST_TIME_OUT              408
#define HTTP_CONFLICT                      409
#define HTTP_GONE                          410
#define HTTP_LENGTH_REQUIRED               411
#define HTTP_PRECONDITION_FAILED           412
#define HTTP_REQUEST_ENTITY_TOO_LARGE      413
#define HTTP_REQUEST_URI_TOO_LARGE         414
#define HTTP_UNSUPPORTED_MEDIA_TYPE        415
#define HTTP_RANGE_NOT_SATISFIABLE         416
#define HTTP_EXPECTATION_FAILED            417
#define HTTP_UNPROCESSABLE_ENTITY          422
#define HTTP_LOCKED                        423
#define HTTP_FAILED_DEPENDENCY             424
#define HTTP_INTERNAL_SERVER_ERROR         500
#define HTTP_NOT_IMPLEMENTED               501
#define HTTP_BAD_GATEWAY                   502
#define HTTP_SERVICE_UNAVAILABLE           503
#define HTTP_GATEWAY_TIME_OUT              504
#define HTTP_VERSION_NOT_SUPPORTED         505
#define HTTP_VARIANT_ALSO_VARIES           506
#define HTTP_INSUFFICIENT_STORAGE          507
#define HTTP_NOT_EXTENDED                  510

#define ap_is_HTTP_INFO(x)         (((x) >= 100)&&((x) < 200))
#define ap_is_HTTP_SUCCESS(x)      (((x) >= 200)&&((x) < 300))
#define ap_is_HTTP_REDIRECT(x)     (((x) >= 300)&&((x) < 400))
#define ap_is_HTTP_ERROR(x)        (((x) >= 400)&&((x) < 600))
#define ap_is_HTTP_CLIENT_ERROR(x) (((x) >= 400)&&((x) < 500))
#define ap_is_HTTP_SERVER_ERROR(x) (((x) >= 500)&&((x) < 600))

#define ap_status_drops_connection(x) \
                                   (((x) == HTTP_BAD_REQUEST)           || \
                                    ((x) == HTTP_REQUEST_TIME_OUT)      || \
                                    ((x) == HTTP_LENGTH_REQUIRED)       || \
                                    ((x) == HTTP_REQUEST_ENTITY_TOO_LARGE) || \
                                    ((x) == HTTP_REQUEST_URI_TOO_LARGE) || \
                                    ((x) == HTTP_INTERNAL_SERVER_ERROR) || \
                                    ((x) == HTTP_SERVICE_UNAVAILABLE) || \
				    ((x) == HTTP_NOT_IMPLEMENTED))

/* Methods recognized (but not necessarily handled) by the server.
 * These constants are used in bit shifting masks of size int, so it is
 * unsafe to have more methods than bits in an int.  HEAD == M_GET.
 */
#define M_GET        0
#define M_PUT        1
#define M_POST       2
#define M_DELETE     3
#define M_CONNECT    4
#define M_OPTIONS    5
#define M_TRACE      6
#define M_PATCH      7
#define M_PROPFIND   8
#define M_PROPPATCH  9
#define M_MKCOL     10
#define M_COPY      11
#define M_MOVE      12
#define M_LOCK      13
#define M_UNLOCK    14
#define M_INVALID   15

#define METHODS     16

#define CGI_MAGIC_TYPE "application/x-httpd-cgi"
#define INCLUDES_MAGIC_TYPE "text/x-server-parsed-html"
#define INCLUDES_MAGIC_TYPE3 "text/x-server-parsed-html3"
#define DIR_MAGIC_TYPE "httpd/unix-directory"
#ifdef CHARSET_EBCDIC
#define ASCIITEXT_MAGIC_TYPE_PREFIX "text/x-ascii-" /* Text files whose content-type starts with this are passed thru unconverted */
#endif /*CHARSET_EBCDIC*/         

/* Just in case your linefeed isn't the one the other end is expecting. */
#ifndef CHARSET_EBCDIC
#define LF 10
#define CR 13
#define CRLF "\015\012"
#else /* CHARSET_EBCDIC */
/* For platforms using the EBCDIC charset, the transition ASCII->EBCDIC is done
 * in the buff package (bread/bputs/bwrite).  Everywhere else, we use
 * "native EBCDIC" CR and NL characters. These are therefore
 * defined as
 * '\r' and '\n'.
 */
#define CR '\r'
#define LF '\n'
#define CRLF "\r\n"
#endif /* CHARSET_EBCDIC */                                   

/* Possible values for request_rec.read_body (set by handling module):
 *    REQUEST_NO_BODY          Send 413 error if message has any body
 *    REQUEST_CHUNKED_ERROR    Send 411 error if body without Content-Length
 *    REQUEST_CHUNKED_DECHUNK  If chunked, remove the chunks for me.
 *    REQUEST_CHUNKED_PASS     Pass the chunks to me without removal.
 */
#define REQUEST_NO_BODY          0
#define REQUEST_CHUNKED_ERROR    1
#define REQUEST_CHUNKED_DECHUNK  2
#define REQUEST_CHUNKED_PASS     3

/* Things which may vary per file-lookup WITHIN a request ---
 * e.g., state of MIME config.  Basically, the name of an object, info
 * about the object, and any other info we may ahve which may need to
 * change as we go poking around looking for it (e.g., overridden by
 * .htaccess files).
 *
 * Note how the default state of almost all these things is properly
 * zero, so that allocating it with pcalloc does the right thing without
 * a whole lot of hairy initialization... so long as we are willing to
 * make the (fairly) portable assumption that the bit pattern of a NULL
 * pointer is, in fact, zero.
 */

/* This represents the result of calling htaccess; these are cached for
 * each request.
 */
struct htaccess_result {
    const char *dir;		/* the directory to which this applies */
    int override;		/* the overrides allowed for the .htaccess file */
    void *htaccess;		/* the configuration directives */
/* the next one, or NULL if no more; N.B. never change this */
    const struct htaccess_result *next;
};

/* The following four types define a hierarchy of activities, so that
 * given a request_rec r you can write r->connection->server->process
 * to get to the process_rec.  While this reduces substantially the
 * number of arguments that various hooks require beware that in
 * threaded versions of the server you must consider multiplexing
 * issues.  */

typedef struct process_rec process_rec;
typedef struct server_rec server_rec;
typedef struct conn_rec conn_rec;
typedef struct request_rec request_rec;

#include "util_uri.h"

#ifdef APACHE_XLATE
#include "apr_xlate.h"

struct ap_rr_xlate {
    /* contents are experimental! expect it to change! */
    apr_xlate_t *to_net;
    int to_net_sb; /* whether or not write translation is single-byte-only */
    apr_xlate_t *from_net;
};
#endif /*APACHE_XLATE*/

struct process_rec {
    apr_pool_t *pool;  /* Global pool. Please try to cleared on _all_ exits */
    apr_pool_t *pconf; /* aka configuration pool, cleared on restarts */
    int argc;
    char *const *argv;
    const char *short_name;
};

struct request_rec {

    apr_pool_t *pool;
    conn_rec *connection;
    server_rec *server;

    request_rec *next;		/* If we wind up getting redirected,
				 * pointer to the request we redirected to.
				 */
    request_rec *prev;		/* If this is an internal redirect,
				 * pointer to where we redirected *from*.
				 */

    request_rec *main;		/* If this is a sub_request (see request.h) 
				 * pointer back to the main request.
				 */

    /* Info about the request itself... we begin with stuff that only
     * protocol.c should ever touch...
     */

    char *the_request;		/* First line of request, so we can log it */
    int assbackwards;		/* HTTP/0.9, "simple" request */
    int proxyreq;		/* A proxy request (calculated during
				 * post_read_request or translate_name) */
    int header_only;		/* HEAD request, as opposed to GET */
    char *protocol;		/* Protocol, as given to us, or HTTP/0.9 */
    int proto_num;		/* Number version of protocol; 1.1 = 1001 */
    const char *hostname;	/* Host, as set by full URI or Host: */

    apr_time_t request_time;	/* When the request started */

    const char *status_line;	/* Status line, if set by script */
    int status;			/* In any case */

    /* Request method, two ways; also, protocol, etc..  Outside of protocol.c,
     * look, but don't touch.
     */

    const char *method;		/* GET, HEAD, POST, etc. */
    int method_number;		/* M_GET, M_POST, etc. */

    /*
	allowed is a bitvector of the allowed methods.

	A handler must ensure that the request method is one that
	it is capable of handling.  Generally modules should DECLINE
	any request methods they do not handle.  Prior to aborting the
	handler like this the handler should set r->allowed to the list
	of methods that it is willing to handle.  This bitvector is used
	to construct the "Allow:" header required for OPTIONS requests,
	and HTTP_METHOD_NOT_ALLOWED and HTTP_NOT_IMPLEMENTED status codes.

	Since the default_handler deals with OPTIONS, all modules can
	usually decline to deal with OPTIONS.  TRACE is always allowed,
	modules don't need to set it explicitly.

	Since the default_handler will always handle a GET, a
	module which does *not* implement GET should probably return
	HTTP_METHOD_NOT_ALLOWED.  Unfortunately this means that a Script GET
	handler can't be installed by mod_actions.
    */
    int allowed;		/* Allowed methods - for 405, OPTIONS, etc */

    int sent_bodyct;		/* byte count in stream is for body */
    long bytes_sent;		/* body byte count, for easy access */
    apr_time_t mtime;		/* Time the resource was last modified */

    /* HTTP/1.1 connection-level features */

    int chunked;		/* sending chunked transfer-coding */
    int byterange;		/* number of byte ranges */
    char *boundary;		/* multipart/byteranges boundary */
    const char *range;		/* The Range: header */
    long clength;		/* The "real" content length */

    long remaining;		/* bytes left to read */
    long read_length;		/* bytes that have been read */
    int read_body;		/* how the request body should be read */
    int read_chunked;		/* reading chunked transfer-coding */
    unsigned expecting_100;	/* is client waiting for a 100 response? */

    /* MIME header environments, in and out.  Also, an array containing
     * environment variables to be passed to subprocesses, so people can
     * write modules to add to that environment.
     *
     * The difference between headers_out and err_headers_out is that the
     * latter are printed even on error, and persist across internal redirects
     * (so the headers printed for ErrorDocument handlers will have them).
     *
     * The 'notes' apr_table_t is for notes from one module to another, with no
     * other set purpose in mind...
     */

    apr_table_t *headers_in;
    apr_table_t *headers_out;
    apr_table_t *err_headers_out;
    apr_table_t *subprocess_env;
    apr_table_t *notes;

    /* content_type, handler, content_encoding, content_language, and all
     * content_languages MUST be lowercased strings.  They may be pointers
     * to static strings; they should not be modified in place.
     */
    const char *content_type;	/* Break these out --- we dispatch on 'em */
    const char *handler;	/* What we *really* dispatch on           */

    const char *content_encoding;
    const char *content_language;	/* for back-compat. only -- do not use */
    apr_array_header_t *content_languages;	/* array of (char*) */

    char *vlist_validator;      /* variant list validator (if negotiated) */
    
    char *user;			/* If an authentication check was made,
				 * this gets set to the user name.
				 */
    char *ap_auth_type;		/* Ditto. */

    int no_cache;
    int no_local_copy;

    /* What object is being requested (either directly, or via include
     * or content-negotiation mapping).
     */

    char *unparsed_uri;		/* the uri without any parsing performed */
    char *uri;			/* the path portion of the URI */
    char *filename;
    char *path_info;
    char *args;			/* QUERY_ARGS, if any */
    apr_finfo_t finfo;		/* ST_MODE set to zero if no such file */
    uri_components parsed_uri;	/* components of uri, dismantled */

    /* Various other config info which may change with .htaccess files
     * These are config vectors, with one void* pointer for each module
     * (the thing pointed to being the module's business).
     */

    void *per_dir_config;	/* Options set in config files, etc. */
    void *request_config;	/* Notes on *this* request */

/*
 * a linked list of the configuration directives in the .htaccess files
 * accessed by this request.
 * N.B. always add to the head of the list, _never_ to the end.
 * that way, a sub request's list can (temporarily) point to a parent's list
 */
    const struct htaccess_result *htaccess;

#ifdef APACHE_XLATE
    struct ap_rr_xlate *rrx;
#endif /*APACHE_XLATE*/

    struct apr_filter_t *filters;

/* Things placed at the end of the record to avoid breaking binary
 * compatibility.  It would be nice to remember to reorder the entire
 * record to improve 64bit alignment the next time we need to break
 * binary compatibility for some other reason.
 */
};


/* Things which are per connection
 */

struct conn_rec {

    apr_pool_t *pool;
    server_rec *base_server;	/* Physical vhost this conn come in on */
    void *vhost_lookup_data;	/* used by http_vhost.c */

    /* Information about the connection itself */

    BUFF *client;		/* Connection to the guy */

    /* Who is the client? */

    struct sockaddr_in local_addr;	/* local address */
    struct sockaddr_in remote_addr;	/* remote address */
    char *remote_ip;		/* Client's IP address */
    char *remote_host;		/* Client's DNS name, if known.
				 * NULL if DNS hasn't been checked,
				 * "" if it has and no address was found.
				 * N.B. Only access this though
				 * get_remote_host() */
    char *remote_logname;	/* Only ever set if doing rfc1413 lookups.
				 * N.B. Only access this through
				 * get_remote_logname() */

    unsigned aborted:1;		/* Are we still talking? */
    signed int keepalive:2;	/* Are we using HTTP Keep-Alive?
				 * -1 fatal error, 0 undecided, 1 yes */
    unsigned keptalive:1;	/* Did we use HTTP Keep-Alive? */
    signed int double_reverse:2;/* have we done double-reverse DNS?
				 * -1 yes/failure, 0 not yet, 1 yes/success */
    int keepalives;		/* How many times have we used it? */
    char *local_ip;		/* server IP address */
    char *local_host;		/* used for ap_get_server_name when
				 * UseCanonicalName is set to DNS
				 * (ignores setting of HostnameLookups) */
    long id;                    /* ID of this connection; unique at any
                                 * point in time */
    void *conn_config;		/* Notes on *this* connection */
    apr_table_t *notes;  /* send note from one module to another, must
                         * remain valid for all requests on this conn */
};

/* Per-vhost config... */

/* The address 255.255.255.255, when used as a virtualhost address,
 * will become the "default" server when the ip doesn't match other vhosts.
 */
#define DEFAULT_VHOST_ADDR 0xfffffffful

typedef struct server_addr_rec server_addr_rec;
struct server_addr_rec {
    server_addr_rec *next;
    apr_in_addr host_addr;	/* The bound address, for this server */
    unsigned short host_port;	/* The bound port, for this server */
    char *virthost;		/* The name given in <VirtualHost> */
};

struct server_rec {
    process_rec *process;
    server_rec *next;

    /* description of where the definition came from */
    const char *defn_name;
    unsigned defn_line_number;

    /* Contact information */

    char *server_admin;
    char *server_hostname;
    unsigned short port;	/* for redirects, etc. */

    /* Log files --- note that transfer log is now in the modules... */

    char *error_fname;
    apr_file_t *error_log;
    int loglevel;

    /* Module-specific configuration for server, and defaults... */

    int is_virtual;		/* true if this is the virtual server */
    void *module_config;	/* Config vector containing pointers to
				 * modules' per-server config structures.
				 */
    void *lookup_defaults;	/* MIME type info, etc., before we start
				 * checking per-directory info.
				 */
    /* Transaction handling */

    server_addr_rec *addrs;
    int timeout;		/* Timeout, in seconds, before we give up */
    int keep_alive_timeout;	/* Seconds we'll wait for another request */
    int keep_alive_max;		/* Maximum requests per connection */
    int keep_alive;		/* Use persistent connections? */

    const char *path;		/* Pathname for ServerPath */
    int pathlen;		/* Length of path */

    apr_array_header_t *names;	/* Normal names for ServerAlias servers */
    apr_array_header_t *wild_names;	/* Wildcarded names for ServerAlias servers */

    uid_t server_uid;        /* effective user id when calling exec wrapper */
    gid_t server_gid;        /* effective group id when calling exec wrapper */

    int limit_req_line;      /* limit on size of the HTTP request line    */
    int limit_req_fieldsize; /* limit on size of any request header field */
    int limit_req_fields;    /* limit on number of request header fields  */
};

/* stuff marked API_EXPORT is part of the API, and intended for use
 * by modules
 */
#ifndef API_EXPORT
#define API_EXPORT(type)    type
#endif

/* Stuff marked API_EXPORT_NONSTD is part of the API, and intended for
 * use by modules.  The difference between API_EXPORT and
 * API_EXPORT_NONSTD is that the latter is required for any functions
 * which use varargs or are used via indirect function call.  This
 * is to accomodate the two calling conventions in windows dlls.
 */
#ifndef API_EXPORT_NONSTD
#define API_EXPORT_NONSTD(type)    type
#endif

#ifndef MODULE_VAR_EXPORT
#define MODULE_VAR_EXPORT
#endif
#ifndef API_VAR_EXPORT
#define API_VAR_EXPORT
#endif

/* modules should not used functions marked CORE_EXPORT
 * or CORE_EXPORT_NONSTD */
#ifndef CORE_EXPORT
#define CORE_EXPORT	API_EXPORT
#endif
#ifndef CORE_EXPORT_NONSTD
#define CORE_EXPORT_NONSTD	API_EXPORT_NONSTD
#endif

/* On Mac OS X Server, symbols that conflict with loaded dylibs
 * (eg. System framework) need to be declared as private symbols with
 * __private_extern__.
 * For other systems, make that a no-op.
 */
#ifndef ap_private_extern
#if (defined(MAC_OS) || defined(MAC_OS_X_SERVER)) && defined(__DYNAMIC__)
#define ap_private_extern __private_extern__
#else
#define ap_private_extern
#endif
#endif

/* Time */

API_EXPORT(char *) ap_field_noparam(apr_pool_t *p, const char *intype);
API_EXPORT(char *) ap_ht_time(apr_pool_t *p, apr_time_t t, const char *fmt, int gmt);

/* String handling. The *_nc variants allow you to use non-const char **s as
   arguments (unfortunately C won't automatically convert a char ** to a const
   char **) */

API_EXPORT(char *) ap_getword(apr_pool_t *p, const char **line, char stop);
API_EXPORT(char *) ap_getword_nc(apr_pool_t *p, char **line, char stop);
API_EXPORT(char *) ap_getword_white(apr_pool_t *p, const char **line);
API_EXPORT(char *) ap_getword_white_nc(apr_pool_t *p, char **line);
API_EXPORT(char *) ap_getword_nulls(apr_pool_t *p, const char **line, char stop);
API_EXPORT(char *) ap_getword_nulls_nc(apr_pool_t *p, char **line, char stop);
API_EXPORT(char *) ap_getword_conf(apr_pool_t *p, const char **line);
API_EXPORT(char *) ap_getword_conf_nc(apr_pool_t *p, char **line);
API_EXPORT(const char *) ap_resolve_env(apr_pool_t *p, const char * word); 

API_EXPORT(const char *) ap_size_list_item(const char **field, int *len);
API_EXPORT(char *) ap_get_list_item(apr_pool_t *p, const char **field);
API_EXPORT(int) ap_find_list_item(apr_pool_t *p, const char *line, const char *tok);

API_EXPORT(char *) ap_get_token(apr_pool_t *p, const char **accept_line, int accept_white);
API_EXPORT(int) ap_find_token(apr_pool_t *p, const char *line, const char *tok);
API_EXPORT(int) ap_find_last_token(apr_pool_t *p, const char *line, const char *tok);

API_EXPORT(int) ap_is_url(const char *u);
API_EXPORT(int) ap_unescape_url(char *url);
API_EXPORT(void) ap_no2slash(char *name);
API_EXPORT(void) ap_getparents(char *name);
API_EXPORT(char *) ap_escape_path_segment(apr_pool_t *p, const char *s);
API_EXPORT(char *) ap_os_escape_path(apr_pool_t *p, const char *path, int partial);
#define ap_escape_uri(ppool,path) ap_os_escape_path(ppool,path,1)
API_EXPORT(char *) ap_escape_html(apr_pool_t *p, const char *s);
API_EXPORT(char *) ap_construct_server(apr_pool_t *p, const char *hostname,
				    unsigned port, const request_rec *r);
API_EXPORT(char *) ap_escape_shell_cmd(apr_pool_t *p, const char *s);

API_EXPORT(int) ap_count_dirs(const char *path);
API_EXPORT(char *) ap_make_dirstr_prefix(char *d, const char *s, int n);
API_EXPORT(char *) ap_make_dirstr_parent(apr_pool_t *p, const char *s);
/* deprecated.  The previous two routines are preferred. */
API_EXPORT(char *) ap_make_dirstr(apr_pool_t *a, const char *s, int n);
API_EXPORT(char *) ap_make_full_path(apr_pool_t *a, const char *dir, const char *f);

API_EXPORT(int) ap_is_matchexp(const char *str);
API_EXPORT(int) ap_strcmp_match(const char *str, const char *exp);
API_EXPORT(int) ap_strcasecmp_match(const char *str, const char *exp);
API_EXPORT(char *) ap_strcasestr(const char *s1, const char *s2);
API_EXPORT(char *) ap_pbase64decode(apr_pool_t *p, const char *bufcoded);
API_EXPORT(char *) ap_pbase64encode(apr_pool_t *p, char *string); 
API_EXPORT(char *) ap_uudecode(apr_pool_t *p, const char *bufcoded);
API_EXPORT(char *) ap_uuencode(apr_pool_t *p, char *string); 

#include "pcreposix.h"

API_EXPORT(regex_t *) ap_pregcomp(apr_pool_t *p, const char *pattern,
				   int cflags);
API_EXPORT(void) ap_pregfree(apr_pool_t *p, regex_t *reg);
API_EXPORT(int)    ap_regexec(regex_t *preg, const char *string,
                              size_t nmatch, regmatch_t pmatch[], int eflags);
API_EXPORT(size_t) ap_regerror(int errcode, const regex_t *preg, 
                               char *errbuf, size_t errbuf_size);
API_EXPORT(char *) ap_pregsub(apr_pool_t *p, const char *input, const char *source,
                              size_t nmatch, regmatch_t pmatch[]);

API_EXPORT(void) ap_content_type_tolower(char *);
API_EXPORT(void) ap_str_tolower(char *);
API_EXPORT(int) ap_ind(const char *, char);	/* Sigh... */
API_EXPORT(int) ap_rind(const char *, char);

API_EXPORT(char *) ap_escape_quotes (apr_pool_t *p, const char *instring);

/* Misc system hackery */

API_EXPORT(uid_t) ap_uname2id(const char *name);
API_EXPORT(gid_t) ap_gname2id(const char *name);
API_EXPORT(int) ap_is_directory(const char *name);
API_EXPORT(void) ap_chdir_file(const char *file);
API_EXPORT(int) ap_get_max_daemons(void);

#ifdef _OSD_POSIX
extern const char *os_set_account(apr_pool_t *p, const char *account);
extern int os_init_job_environment(server_rec *s, const char *user_name, int one_process);
#endif /* _OSD_POSIX */

char *ap_get_local_host(apr_pool_t *);
unsigned long ap_get_virthost_addr(char *hostname, unsigned short *port);

API_EXPORT(char *) ap_escape_quotes(apr_pool_t *p, const char *instr);

/*
 * Redefine assert() to something more useful for an Apache...
 */
API_EXPORT(void) ap_log_assert(const char *szExp, const char *szFile, int nLine)
			    __attribute__((noreturn));
#define ap_assert(exp) ((exp) ? (void)0 : ap_log_assert(#exp,__FILE__,__LINE__))

/* A set of flags which indicate places where the server should raise(SIGSTOP).
 * This is useful for debugging, because you can then attach to that process
 * with gdb and continue.  This is important in cases where one_process
 * debugging isn't possible.
 */
#define SIGSTOP_DETACH			1
#define SIGSTOP_MAKE_CHILD		2
#define SIGSTOP_SPAWN_CHILD		4
#define SIGSTOP_PIPED_LOG_SPAWN		8
#define SIGSTOP_CGI_CHILD		16

#ifdef DEBUG_SIGSTOP
extern int raise_sigstop_flags;
#define RAISE_SIGSTOP(x)	do { \
	if (raise_sigstop_flags & SIGSTOP_##x) raise(SIGSTOP);\
    } while (0)
#else
#define RAISE_SIGSTOP(x)
#endif

API_EXPORT(extern const char *) ap_psignature(const char *prefix, request_rec *r);

/* strtoul does not exist on sunos4. */
#ifdef strtoul
#undef strtoul
#endif
#define strtoul strtoul_is_not_a_portable_function_use_strtol_instead

  /* The C library has functions that allow const to be silently dropped ...
     these macros detect the drop in maintainer mode, but use the native
     methods far narmal builds
  */
#ifdef AP_DEBUG

#undef strchr
# define strchr(s, c)	ap_strchr(s,c)
#undef strrchr
# define strrchr(s, c)  ap_strrchr(s,c)
#undef strstr
# define strstr(s, c)  ap_strstr(s,c)

char *ap_strchr(char *s, int c);
const char *ap_strchr_c(const char *s, int c);
char *ap_strrchr(char *s, int c);
const char *ap_strrchr_c(const char *s, int c);
char *ap_strstr(char *s, char *c);
const char *ap_strstr_c(const char *s, const char *c);

#else

# define ap_strchr(s, c)	strchr(s, c)
# define ap_strchr_c(s, c)	strchr(s, c)
# define ap_strrchr(s, c)	strrchr(s, c)
# define ap_strrchr_c(s, c)	strrchr(s, c)
# define ap_strstr(s, c)	strstr(s, c)
# define ap_strstr_c(s, c)	strstr(s, c)

#endif

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTPD_H */
