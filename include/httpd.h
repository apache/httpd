/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

/*
 * httpd.h: header for simple (ha! not anymore) http daemon
 */

/* XXX - We need to push more stuff to other .h files, or even .c files, to
 * make this file smaller
 */

/**
 * @package HTTP Daemon routines
 */

/* Headers in which EVERYONE has an interest... */
#include "ap_config.h"
#include "ap_mmn.h"

#include "ap_release.h"
#include "os.h"

#include "apr_tables.h"
#include "apr_pools.h"
#include "apr_time.h"
#include "apr_network_io.h"

#include "pcreposix.h"

/* Note: util_uri.h is also included, see below */

#ifdef __cplusplus
extern "C" {
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
 * respective configuration file. 
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

/* Maximum number of dynamically loaded modules */
#ifndef DYNAMIC_MODULE_LIMIT
#define DYNAMIC_MODULE_LIMIT 64
#endif

/* Default administrator's address */
#define DEFAULT_ADMIN "[no address given]"

/* The name of the log files */
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
#define DEFAULT_TIMEOUT 300 
#endif

/* The timeout for waiting for keepalive timeout until next request */
#ifndef DEFAULT_KEEPALIVE_TIMEOUT
#define DEFAULT_KEEPALIVE_TIMEOUT 15
#endif

/* The number of requests to entertain per connection */
#ifndef DEFAULT_KEEPALIVE
#define DEFAULT_KEEPALIVE 100
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

#endif /* CORE_PRIVATE */

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

/**
 * Get the server version string
 * @return The server version string
 * @deffunc const char *ap_get_server_version(void)
 */
AP_DECLARE(const char *) ap_get_server_version(void);

/**
 * Add a component to the version string
 * @param pconf The pool to allocate the component out of
 * @param component The string to add
 * @deffunc void ap_add_version_component(apr_pool_t *pconf, const char *component)
 */
AP_DECLARE(void) ap_add_version_component(apr_pool_t *pconf, const char *component);

/**
 * Get the date a time that the server was built
 * @return The server build time string
 */
AP_DECLARE(const char *) ap_get_server_built(void);

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
 * This list must be tracked by the list in http_protocol.c in routine
 * ap_method_name_of().
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

typedef struct ap_method_list_t ap_method_list_t;
/**
 * Structure for handling HTTP methods.  Methods known to the server are
 * accessed via a bitmask shortcut; extension methods are handled by
 * an array.
 */
struct ap_method_list_t {
    /* The bitmask used for known methods */
    int method_mask;
    /* The array used for extension methods */
    apr_array_header_t *method_list;
};

#define CGI_MAGIC_TYPE "application/x-httpd-cgi"
#define INCLUDES_MAGIC_TYPE "text/x-server-parsed-html"
#define INCLUDES_MAGIC_TYPE3 "text/x-server-parsed-html3"
#define DIR_MAGIC_TYPE "httpd/unix-directory"

/* Just in case your linefeed isn't the one the other end is expecting. */
#if !APR_CHARSET_EBCDIC
#define LF 10
#define CR 13
#define CRLF "\015\012"
#else /* APR_CHARSET_EBCDIC */
/* For platforms using the EBCDIC charset, the transition ASCII->EBCDIC is done
 * in the buff package (bread/bputs/bwrite).  Everywhere else, we use
 * "native EBCDIC" CR and NL characters. These are therefore
 * defined as
 * '\r' and '\n'.
 */
#define CR '\r'
#define LF '\n'
#define CRLF "\r\n"
#endif /* APR_CHARSET_EBCDIC */                                   

/* Possible values for request_rec.read_body (set by handling module):
 *    REQUEST_NO_BODY          Send 413 error if message has any body
 *    REQUEST_CHUNKED_ERROR    Send 411 error if body without Content-Length
 *    REQUEST_CHUNKED_DECHUNK  If chunked, remove the chunks for me.
 */
#define REQUEST_NO_BODY          0
#define REQUEST_CHUNKED_ERROR    1
#define REQUEST_CHUNKED_DECHUNK  2

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

/**
 * This represents the result of calling htaccess; these are cached for
 * each request.
 */
struct htaccess_result {
    /** the directory to which this applies */
    const char *dir;
    /** the overrides allowed for the .htaccess file */
    int override;
    /** the configuration directives */
    void *htaccess;
    /** the next one, or NULL if no more; N.B. never change this */
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

/* ### would be nice to not include this from httpd.h ... */
/* This comes after we have defined the request_rec type */
#include "util_uri.h"

/** A structure that represents one process */
struct process_rec {
    /** Global pool. Please try to cleared on _all_ exits */
    apr_pool_t *pool;
    /** aka configuration pool, cleared on restarts */
    apr_pool_t *pconf;
    /** How many command line arguments were pass to the program */
    int argc;
    /** The command line arguments */
    const char * const *argv;
    /** The program name used to execute the program */
    const char *short_name;
};

/** A structure that represents the current request */
struct request_rec {
    /** The pool associated with the request */
    apr_pool_t *pool;
    /** The connection over which this connection has been read */
    conn_rec *connection;
    /** The virtual host this request is for */
    server_rec *server;

    /** If we wind up getting redirected, pointer to the request we 
     *  redirected to.  */
    request_rec *next;
    /** If this is an internal redirect, pointer to where we redirected 
     *  *from*.  */
    request_rec *prev;

    /** If this is a sub_request (see request.h) pointer back to the 
     *  main request.  */
    request_rec *main;

    /* Info about the request itself... we begin with stuff that only
     * protocol.c should ever touch...
     */
    /** First line of request, so we can log it */
    char *the_request;
    /** HTTP/0.9, "simple" request */
    int assbackwards;
    /** A proxy request (calculated during post_read_request/translate_name) */
    int proxyreq;
    /** HEAD request, as opposed to GET */
    int header_only;
    /** Protocol, as given to us, or HTTP/0.9 */
    char *protocol;
    /** Number version of protocol; 1.1 = 1001 */
    int proto_num;
    /** Host, as set by full URI or Host: */
    const char *hostname;

    /** When the request started */
    apr_time_t request_time;

    /** Status line, if set by script */
    const char *status_line;
    /** In any case */
    int status;

    /* Request method, two ways; also, protocol, etc..  Outside of protocol.c,
     * look, but don't touch.
     */

    /** GET, HEAD, POST, etc. */
    const char *method;
    /** M_GET, M_POST, etc. */
    int method_number;

    /** <PRE>
     *  allowed is a bitvector of the allowed methods.
     *
     *  A handler must ensure that the request method is one that
     *  it is capable of handling.  Generally modules should DECLINE
     *  any request methods they do not handle.  Prior to aborting the
     *  handler like this the handler should set r->allowed to the list
     *  of methods that it is willing to handle.  This bitvector is used
     *  to construct the "Allow:" header required for OPTIONS requests,
     *  and HTTP_METHOD_NOT_ALLOWED and HTTP_NOT_IMPLEMENTED status codes.
     *
     *  Since the default_handler deals with OPTIONS, all modules can
     *  usually decline to deal with OPTIONS.  TRACE is always allowed,
     *  modules don't need to set it explicitly.
     *
     *  Since the default_handler will always handle a GET, a
     *  module which does *not* implement GET should probably return
     *  HTTP_METHOD_NOT_ALLOWED.  Unfortunately this means that a Script GET
     *  handler can't be installed by mod_actions. </PRE>
     */
    /** Allowed methods - for 405, OPTIONS, etc */
    int allowed;
    /** Array of extension methods */
    apr_array_header_t *allowed_xmethods; 
    /** List of allowed methods */
    ap_method_list_t *allowed_methods; 

    /** byte count in stream is for body */
    int sent_bodyct;
    /** body byte count, for easy access */
    long bytes_sent;
    /** Time the resource was last modified */
    apr_time_t mtime;

    /* HTTP/1.1 connection-level features */

    /** sending chunked transfer-coding */
    int chunked;
    /** multipart/byteranges boundary */
    const char *boundary;
    /** The Range: header */
    const char *range;
    /** The "real" content length */
    apr_off_t clength;

    /** bytes left to read */
    long remaining;
    /** bytes that have been read */
    long read_length;
    /** how the request body should be read */
    int read_body;
    /** reading chunked transfer-coding */
    int read_chunked;
    /** is client waiting for a 100 response? */
    unsigned expecting_100;

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

    /** MIME header environment from the request */
    apr_table_t *headers_in;
    /** MIME header environment for the response */
    apr_table_t *headers_out;
    /** MIME header environment for the response, printed even on errors and
     * persist across internal redirects */
    apr_table_t *err_headers_out;
    /** Array of environment variables to be used for sub processes */
    apr_table_t *subprocess_env;
    /** Notes from one module to another */
    apr_table_t *notes;

    /* content_type, handler, content_encoding, content_language, and all
     * content_languages MUST be lowercased strings.  They may be pointers
     * to static strings; they should not be modified in place.
     */
    /** The content-type for the current request */
    const char *content_type;	/* Break these out --- we dispatch on 'em */
    /** The handler string that we use to call a handler function */
    const char *handler;	/* What we *really* dispatch on           */

    /** How to encode the data */
    const char *content_encoding;
    /** for back-compat. only -- do not use */
    const char *content_language;
    /** array of (char*) representing the content languages */
    apr_array_header_t *content_languages;

    /** variant list validator (if negotiated) */
    char *vlist_validator;
    
    /** If an authentication check was made, this gets set to the user name. */
    char *user;	
    /** If an authentication check was made, this gets set to the auth type. */
    char *ap_auth_type;

    /** This response is non-cache-able */
    int no_cache;
    /** There is no local copy of this response */
    int no_local_copy;

    /* What object is being requested (either directly, or via include
     * or content-negotiation mapping).
     */

    /** the uri without any parsing performed */
    char *unparsed_uri;	
    /** the path portion of the URI */
    char *uri;
    /** The filename on disk that this response corresponds to */
    char *filename;
    /** The path_info for this request if there is any. */
    char *path_info;
    /** QUERY_ARGS, if any */
    char *args;	
    /** ST_MODE set to zero if no such file */
    apr_finfo_t finfo;
    /** components of uri, dismantled */
    uri_components parsed_uri;

    /* Various other config info which may change with .htaccess files
     * These are config vectors, with one void* pointer for each module
     * (the thing pointed to being the module's business).
     */

    /** Options set in config files, etc. */
    void *per_dir_config;
    /** Notes on *this* request */
    void *request_config;

/**
 * a linked list of the configuration directives in the .htaccess files
 * accessed by this request.
 * N.B. always add to the head of the list, _never_ to the end.
 * that way, a sub request's list can (temporarily) point to a parent's list
 * @defvar const htaccess_result *htaccess
 */
    const struct htaccess_result *htaccess;

    /** A list of output filters to be used for this request 
     *  @defvar ap_filter_t *output_filters */
    struct ap_filter_t *output_filters;
    /** A list of input filters to be used for this request 
     *  @defvar ap_filter_t *input_filters */
    struct ap_filter_t *input_filters;
    /** A flag to determine if the eos bucket has been sent yet
     *  @defvar int eos_sent */
    int eos_sent;

/* Things placed at the end of the record to avoid breaking binary
 * compatibility.  It would be nice to remember to reorder the entire
 * record to improve 64bit alignment the next time we need to break
 * binary compatibility for some other reason.
 */
};


/** Structure to store things which are per connection */
struct conn_rec {
    /** Pool associated with this connection */
    apr_pool_t *pool;
    /** Physical vhost this conn come in on */
    server_rec *base_server;
    /** used by http_vhost.c */
    void *vhost_lookup_data;

    /* Information about the connection itself */

    /** Connection to the client */
    apr_socket_t *client_socket;

    /* Who is the client? */

    /** local address */
    apr_sockaddr_t *local_addr;
    /** remote address */
    apr_sockaddr_t *remote_addr;
    /** Client's IP address */
    char *remote_ip;
    /** Client's DNS name, if known.  NULL if DNS hasn't been checked,
     *  "" if it has and no address was found.  N.B. Only access this though
     * get_remote_host() */
    char *remote_host;
    /** Only ever set if doing rfc1413 lookups.  N.B. Only access this through
     *  get_remote_logname() */
    char *remote_logname;

    /** Are we still talking? */
    unsigned aborted:1;
    /** Are we using HTTP Keep-Alive?  -1 fatal error, 0 undecided, 1 yes */
    signed int keepalive:2;
    /** Did we use HTTP Keep-Alive? */
    unsigned keptalive:1;
    /** have we done double-reverse DNS? -1 yes/failure, 0 not yet, 
     *  1 yes/success */
    signed int double_reverse:2;

    /** How many times have we used it? */
    int keepalives;
    /** server IP address */
    char *local_ip;
    /** used for ap_get_server_name when UseCanonicalName is set to DNS
     *  (ignores setting of HostnameLookups) */
    char *local_host;

    /** ID of this connection; unique at any point in time */
    long id; 
    /** Notes on *this* connection */
    void *conn_config;
    /** send note from one module to another, must remain valid for all
     *  requests on this conn */
    apr_table_t *notes;
    /** A list of input filters to be used for this connection
     *  @defvar ap_filter_t *input_filters */
    struct ap_filter_t *input_filters;
    /** A list of output filters to be used for this connection
     *  @defvar ap_filter_t *filters */
    struct ap_filter_t *output_filters;
    /** The length of the current request body
     *  @defvar long remain */
    long remain;
};

/* Per-vhost config... */

/* The address 255.255.255.255, when used as a virtualhost address,
 * will become the "default" server when the ip doesn't match other vhosts.
 */
#define DEFAULT_VHOST_ADDR 0xfffffffful

typedef struct server_addr_rec server_addr_rec;

/** A structure to be used for Per-vhost config */
struct server_addr_rec {
    /** The next server in the list */
    server_addr_rec *next;
    /** The bound address, for this server */
    apr_sockaddr_t *host_addr;
    /** The bound port, for this server */
    apr_port_t host_port;
    /** The name given in <VirtualHost> */
    char *virthost;
};

/** A structure to store information for each virtual server */
struct server_rec {
    /** The process this server is running in */
    process_rec *process;
    /** The next server in the list */
    server_rec *next;

    /** The name of the server */
    const char *defn_name;
    /** The line of the config file that the server was defined on */
    unsigned defn_line_number;

    /* Contact information */

    /** The admin's contact information */
    char *server_admin;
    /** The server hostname */
    char *server_hostname;
    /** for redirects, etc. */
    apr_port_t port;

    /* Log files --- note that transfer log is now in the modules... */

    /** The name of the error log */
    char *error_fname;
    /** A file descriptor that references the error log */
    apr_file_t *error_log;
    /** The log level for this server */
    int loglevel;

    /* Module-specific configuration for server, and defaults... */

    /** true if this is the virtual server */
    int is_virtual;
    /** Config vector containing pointers to modules' per-server config 
     *  structures. */
    void *module_config; 
    /** MIME type info, etc., before we start checking per-directory info */
    void *lookup_defaults;

    /* Transaction handling */

    /** I haven't got a clue */
    server_addr_rec *addrs;
    /** Timeout, in seconds, before we give up */
    int timeout;
    /** Seconds we'll wait for another request */
    int keep_alive_timeout;
    /** Maximum requests per connection */
    int keep_alive_max;
    /** Use persistent connections? */
    int keep_alive;

    /** Pathname for ServerPath */
    const char *path;
    /** Length of path */
    int pathlen;

    /** Normal names for ServerAlias servers */
    apr_array_header_t *names;
    /** Wildcarded names for ServerAlias servers */
    apr_array_header_t *wild_names;

    /** limit on size of the HTTP request line    */
    int limit_req_line;
    /** limit on size of any request header field */
    int limit_req_fieldsize;
    /** limit on number of request header fields  */
    int limit_req_fields; 
};

/* stuff marked AP_DECLARE is part of the API, and intended for use
 * by modules
 */
#ifndef AP_DECLARE
#define AP_DECLARE(type)    type
#endif

/* Stuff marked AP_DECLARE_NONSTD is part of the API, and intended for
 * use by modules.  The difference between AP_DECLARE and
 * AP_DECLARE_NONSTD is that the latter is required for any functions
 * which use varargs or are used via indirect function call.  This
 * is to accomodate the two calling conventions in windows dlls.
 */
#ifndef AP_DECLARE_NONSTD
#define AP_DECLARE_NONSTD(type)    type
#endif

#ifndef AP_MODULE_DECLARE_DATA
#define AP_MODULE_DECLARE_DATA
#endif
#ifndef AP_DECLARE_DATA
#define AP_DECLARE_DATA
#endif

/* modules should not used functions marked AP_CORE_DECLARE
 * or AP_CORE_DECLARE_NONSTD */
#ifndef AP_CORE_DECLARE
#define AP_CORE_DECLARE	AP_DECLARE
#endif
#ifndef AP_CORE_DECLARE_NONSTD
#define AP_CORE_DECLARE_NONSTD	AP_DECLARE_NONSTD
#endif

/**
 * Examine a field value (such as a media-/content-type) string and return
 * it sans any parameters; e.g., strip off any ';charset=foo' and the like.
 * @param p Pool to allocate memory out of
 * @param intype The field to examine
 * @return the field minus any parameters
 * @deffunc char *ap_field_noparam(apr_pool_t *p, const char *intype);
 */
AP_DECLARE(char *) ap_field_noparam(apr_pool_t *p, const char *intype);

/**
 * Convert a time from an integer into a string in a specified format
 * @param p The pool to allocate memory out of
 * @param t The time to convert
 * @param fmt The format to use for the conversion
 * @param gmt Convert the time for GMT?
 * @return The string that represents the specified time
 * @deffunc char *ap_ht_time(apr_pool_t *p, apr_time_t t, const char *fmt, int gmt)
 */
AP_DECLARE(char *) ap_ht_time(apr_pool_t *p, apr_time_t t, const char *fmt, int gmt);

/* String handling. The *_nc variants allow you to use non-const char **s as
   arguments (unfortunately C won't automatically convert a char ** to a const
   char **) */

/**
 * Get the characters until the first occurance of a specified character
 * @param p The pool to allocate memory out of
 * @param line The string to get the characters from
 * @param stop The character to stop at
 * @return A copy of the characters up to the first stop character
 * @deffunc char *ap_getword(apr_pool_t *p, const char **line, char stop);
 */
AP_DECLARE(char *) ap_getword(apr_pool_t *p, const char **line, char stop);
/**
 * Get the characters until the first occurance of a specified character
 * @param p The pool to allocate memory out of
 * @param line The string to get the characters from
 * @param stop The character to stop at
 * @return A copy of the characters up to the first stop character
 * @tip This is the same as ap_getword, except it doesn't use const char **.
 * @deffunc char *ap_getword_nc(apr_pool_t *p, char **line, char stop);
 */
AP_DECLARE(char *) ap_getword_nc(apr_pool_t *p, char **line, char stop);

/**
 * Get the first word from a given string.  A word is defined as all characters
 * up to the first whitespace.
 * @param p The pool to allocate memory from
 * @param line The string to traverse
 * @retrn The first word in the line
 * @deffunc char *ap_getword_white(apr_pool_t *p, const char **line)
 */
AP_DECLARE(char *) ap_getword_white(apr_pool_t *p, const char **line);
/**
 * Get the first word from a given string.  A word is defined as all characters
 * up to the first whitespace.
 * @param p The pool to allocate memory from
 * @param line The string to traverse
 * @retrn The first word in the line
 * @tip The same as ap_getword_white, except it doesn't use const char **.
 * @deffunc char *ap_getword_white_nc(apr_pool_t *p, const char **line)
 */
AP_DECLARE(char *) ap_getword_white_nc(apr_pool_t *p, char **line);

/**
 * Get all characters from the first occurance of stop to the first '\0'
 * @param p The pool to allocate memory out of
 * @param line The line to traverse
 * @param stop The character to start at
 * @return A copy of all caracters after the first occurance of the specified
 *         character
 * @deffunc char *ap_getword_nulls(apr_pool_t *p, const char **line, char stop)
 */
AP_DECLARE(char *) ap_getword_nulls(apr_pool_t *p, const char **line, char stop);
/**
 * Get all characters from the first occurance of stop to the first '\0'
 * @param p The pool to allocate memory out of
 * @param line The line to traverse
 * @param stop The character to start at
 * @return A copy of all caracters after the first occurance of the specified
 *         character
 * @tip The same as ap_getword_nulls, except it doesn't use const char **.
 * @deffunc char *ap_getword_nulls_nc(apr_pool_t *p, char **line, char stop)
 */
AP_DECLARE(char *) ap_getword_nulls_nc(apr_pool_t *p, char **line, char stop);

/**
 * Get the second word in the string paying attention to quoting
 * @param p The pool to allocate out of
 * @param line The line to traverse
 * @return A copy of the string
 * @deffunc char *ap_getword_conf(apr_pool_t *p, const char **line)
 */
AP_DECLARE(char *) ap_getword_conf(apr_pool_t *p, const char **line);
/**
 * Get the second word in the string paying attention to quoting
 * @param p The pool to allocate out of
 * @param line The line to traverse
 * @return A copy of the string
 * @tip The same as ap_getword_conf, except it doesn't use const char **.
 * @deffunc char *ap_getword_conf_nc(apr_pool_t *p, char **line)
 */
AP_DECLARE(char *) ap_getword_conf_nc(apr_pool_t *p, char **line);

/**
 * Check a string for any ${ENV} environment variable construct and replace 
 * each them by the value of that environment variable, if it exists. If the 
 * environment value does not exist, leave the ${ENV} construct alone; it 
 * means something else.
 * @param p The pool to allocate out of
 * @param word The string to check
 * @return The string with the replaced environment variables
 * @deffunc const char *ap_resolve_env(apr_pool_t *p, const char *word)
 */
AP_DECLARE(const char *) ap_resolve_env(apr_pool_t *p, const char * word); 

/**
 * Size an HTTP header field list item, as separated by a comma.
 * @param field The field to size
 * @param len The length of the field
 * @return The return value is a pointer to the beginning of the non-empty 
 * list item within the original string (or NULL if there is none) and the 
 * address of field is shifted to the next non-comma, non-whitespace 
 * character.  len is the length of the item excluding any beginning whitespace.
 * @deffunc const char *ap_size_list_item(const char **field, int *len)
 */
AP_DECLARE(const char *) ap_size_list_item(const char **field, int *len);

/**
 * Retrieve an HTTP header field list item, as separated by a comma,
 * while stripping insignificant whitespace and lowercasing anything not in
 * a quoted string or comment.  
 * @param p The pool to allocate out of
 * @param field The field to retrieve
 * @return The return value is a new string containing the converted list 
 *         item (or NULL if none) and the address pointed to by field is 
 *         shifted to the next non-comma, non-whitespace.
 * @deffunc char *ap_get_list_item(apr_pool_t *p, const char **field)
 */
AP_DECLARE(char *) ap_get_list_item(apr_pool_t *p, const char **field);

/**
 * Find an item in canonical form (lowercase, no extra spaces) within
 * an HTTP field value list.  
 * @param p The pool to allocate out of
 * @param line The field value list to search
 * @param tok The token to search for
 * @return 1 if found, 0 if not found.
 * @deffunc int ap_find_list_item(apr_pool_t *p, const char *line, const char *tok)
 */
AP_DECLARE(int) ap_find_list_item(apr_pool_t *p, const char *line, const char *tok);

/**
 * Retrieve a token, spacing over it and returning a pointer to
 * the first non-white byte afterwards.  Note that these tokens
 * are delimited by semis and commas; and can also be delimited
 * by whitespace at the caller's option.
 * @param p The pool to allocate out of
 * @param accept_line The line to retrieve the token from
 * @param accept_white Is it delimited by whitespace
 * @return the first non-white byte after the token
 * @deffunc char *ap_get_token(apr_pool_t *p, const char **accept_line, int accept_white)
 */
AP_DECLARE(char *) ap_get_token(apr_pool_t *p, const char **accept_line, int accept_white);

/**
 * find http tokens, see the definition of token from RFC2068 
 * @param p The pool to allocate out of
 * @param line The line to find the token
 * @param tok The token to find
 * @return 1 if the token is found, 0 otherwise
 * @deffunc int ap_find_token(apr_pool_t *p, const char *line, const char *tok)
 */
AP_DECLARE(int) ap_find_token(apr_pool_t *p, const char *line, const char *tok);

/**
 * find http tokens from the end of the line
 * @param p The pool to allocate out of
 * @param line The line to find the token
 * @param tok The token to find
 * @return 1 if the token is found, 0 otherwise
 * @deffunc int ap_find_last_token(apr_pool_t *p, const char *line, const char *tok)
 */
AP_DECLARE(int) ap_find_last_token(apr_pool_t *p, const char *line, const char *tok);

/**
 * Check for an Absolute URI syntax
 * @param u The string to check
 * @return 1 if URI, 0 otherwise
 * @deffunc int ap_is_url(const char *u)
 */
AP_DECLARE(int) ap_is_url(const char *u);

/**
 * Unescape a URL
 * @param url The url to unescapte
 * @return 0 on success, non-zero otherwise
 * @deffunc int ap_unescape_url(char *url)
 */
AP_DECLARE(int) ap_unescape_url(char *url);
/**
 * Remove all double slashes from a string
 * @param name The string to parse
 * @deffunc void ap_no2slash(char *name)
 */
AP_DECLARE(void) ap_no2slash(char *name);

/**
 * Remove all ./ and ../ substrings from a file name
 * @param name the file name to parse
 * @deffunc void ap_getparents(char *name)
 */
AP_DECLARE(void) ap_getparents(char *name);

/**
 * Escape a path segment, as defined in RFC 1808
 * @param p The pool to allocate out of
 * @param s The path to convert
 * @return The converted URL
 * @deffunc char *ap_escape_path_segment(apr_pool_t *p, const char *s)
 */
AP_DECLARE(char *) ap_escape_path_segment(apr_pool_t *p, const char *s);
/**
 * convert an OS path to a URL in an OS dependant way.
 * @param p The pool to allocate out of
 * @param path The path to convert
 * @param partial if set, assume that the path will be appended to something
 *        with a '/' in it (and thus does not prefix "./")
 * @return The converted URL
 * @deffunc char *ap_os_escape_path(apr_pool_t *p, const char *path, int partial)
 */
AP_DECLARE(char *) ap_os_escape_path(apr_pool_t *p, const char *path, int partial);
#define ap_escape_uri(ppool,path) ap_os_escape_path(ppool,path,1)

/**
 * Escape an html string
 * @param p The pool to allocate out of
 * @param s The html to escape
 * @return The escaped string
 * @deffunc char *ap_escape_html(apr_pool_t *p, const char *s)
 */
AP_DECLARE(char *) ap_escape_html(apr_pool_t *p, const char *s);

/**
 * Construct a full hostname
 * @param p The pool to allocate out of
 * @param hostname The hostname of the server
 * @param port The port the server is running on
 * @param r The current request
 * @return The server's hostname
 * @deffunc char *ap_construct_server(apr_pool_t *p, const char *hostname, apr_port_t port, const request_rec *r)
 */
AP_DECLARE(char *) ap_construct_server(apr_pool_t *p, const char *hostname,
				    apr_port_t port, const request_rec *r);
/**
 * Escape a shell command
 * @param p The pool to allocate out of
 * @param s The command to escape
 * @return The escaped hostname
 * @deffunc char *ap_escape_shell_cmd(apr_pool_t *p, const char *s)
 */
AP_DECLARE(char *) ap_escape_shell_cmd(apr_pool_t *p, const char *s);

/**
 * Count the number of directories in a path
 * @param The path to count
 * @return The number of directories
 * @deffunc int ap_count_dirs(const char *path)
 */
AP_DECLARE(int) ap_count_dirs(const char *path);

/**
 * Copy at most n leading directories of s into d d should be at least as 
 * large as s plus 1 extra byte
 * @param d The location to copy to
 * @param s The location to copy from
 * @param n The number of directories to copy
 * @return value is the ever useful pointer to the trailing \0 of d
 * @deffunc char *ap_make_dirstr_prefix(char *d, const char *s, int n)
 * @tip on platforms with drive letters, n = 0 returns the "/" root, 
 * whereas n = 1 returns the "d:/" root.  On all other platforms, n = 0
 * returns the empty string.
 */
AP_DECLARE(char *) ap_make_dirstr_prefix(char *d, const char *s, int n);

/**
 * return the parent directory name including trailing / of the file s
 * @param p The pool to allocate out of
 * @param s The file to get the parent of
 * @return A copy of the file's parent directory
 * @deffunc char *ap_make_dirstr_parent(apr_pool_t *p, const char *s)
 */
AP_DECLARE(char *) ap_make_dirstr_parent(apr_pool_t *p, const char *s);

/**
 * Given a directory and filename, create a single path out of them.  This
 * function is smart enough to ensure that there is a sinlge '/' between the
 * directory and file names
 * @param a The pool to allocate out of
 * @param dir The directory name
 * @param f The filename
 * @return A copy of the full path
 * @deffunc char *ap_make_full_path(apr_pool_t *a, const char *dir, const char *f)
 */
AP_DECLARE(char *) ap_make_full_path(apr_pool_t *a, const char *dir, const char *f);

/**
 * Does the provided string contain wildcard characters?  This is useful
 * for determining if the string should be passed to strcmp_match or to strcmp.
 * The only wildcard characters recognized are '?' and '*'
 * @param str The string to check
 * @return 1 if the string has wildcards, 0 otherwise
 * @deffunc int ap_is_matchexp(const char *str)
 */
AP_DECLARE(int) ap_is_matchexp(const char *str);

/**
 * Determine if a string matches a patterm containing the wildcards '?' or '*'
 * @param str The string to check
 * @param exp The pattern to match against
 * @return 1 if the two strings match, 0 otherwise
 * @deffunc int ap_strcmp_match(const char *str, const char *exp)
 */
AP_DECLARE(int) ap_strcmp_match(const char *str, const char *exp);
/**
 * Determine if a string matches a patterm containing the wildcards '?' or '*',
 * ignoring case
 * @param str The string to check
 * @param exp The pattern to match against
 * @return 1 if the two strings match, 0 otherwise
 * @deffunc int ap_strcasecmp_match(const char *str, const char *exp)
 */
AP_DECLARE(int) ap_strcasecmp_match(const char *str, const char *exp);

/**
 * Find the first occurrence of the substring s2 in s1, regardless of case
 * @param s1 The string to search
 * @param s2 The substring to search for
 * @return A pointer to the beginning of the substring
 * @deffunc char *ap_strcasestr(const char *s1, const char *s2)
 */
AP_DECLARE(char *) ap_strcasestr(const char *s1, const char *s2);

/**
 * Return a pointer to the location inside of bigstring immediately after prefix
 * @param bigstring The input string
 * @param prefix The prefix to strip away
 * @return A pointer relative to bigstring after prefix
 * deffunc const char *ap_stripprefix(const char *bigstring, const char *prefix);
 */
AP_DECLARE(const char *) ap_stripprefix(const char *bigstring,
                                        const char *prefix);

/**
 * Decode a base64 encoded string into memory allocated out of a pool
 * @param p The pool to allocate out of
 * @param bufcoded The encoded string
 * @return The decoded string
 * @deffunc char *ap_pbase64decode(apr_pool_t *p, const char *bufcoded)
 */
AP_DECLARE(char *) ap_pbase64decode(apr_pool_t *p, const char *bufcoded);

/**
 * Encode a string into memory allocated out of a pool in base 64 format
 * @param p The pool to allocate out of
 * @param strin The plaintext string
 * @return The encoded string
 * @deffunc char *ap_pbase64encode(apr_pool_t *p, char *string)
 */
AP_DECLARE(char *) ap_pbase64encode(apr_pool_t *p, char *string); 


/**
 * Compile a regular expression to be used later
 * @param p The pool to allocate out of
 * @param pattern the regular expression to compile
 * @param cflags The bitwise or of one or more of the following:
 * <PRE>
 *       REG_EXTENDED - Use POSIX extended Regular Expressions
 *       REG_ICASE    - Ignore case
 *       REG_NOSUB    - Support for substring addressing of matches not required
 *       REG_NEWLINE  - Match-any-character operators don't match new-line
 * </PRE>
 * @return The compiled regular expression
 * @deffunc regex_t *ap_pregcomp(apr_pool_t *p, const char *pattern, int cflags)
 */
AP_DECLARE(regex_t *) ap_pregcomp(apr_pool_t *p, const char *pattern,
				   int cflags);

/**
 * Free the memory associated with a compiled regular expression
 * @param p The pool the regex was allocated out of
 * @param reg The regular expression to free
 * @deffunc void ap_pregfree(apr_pool_t *p, regex_t *reg)
 */
AP_DECLARE(void) ap_pregfree(apr_pool_t *p, regex_t *reg);

/**
 * Match a null-terminated string against a pre-compiled regex.
 * @param preg The pre-compiled regex
 * @param string The string to match
 * @param nmatch Provide information regarding the location of any matches
 * @param pmatch Provide information regarding the location of any matches
 * @param eflags Bitwise or of one or both of:
 * <PRE>
 *        REG_NOTBOL - match-beginning-of-line operator always fails to match
 *        REG_NOTEOL - match-end-of-line operator always fails to match
 * </PRE>
 * @return 0 for successful match, REG_NOMATCH otherwise
 * @deffunc int ap_regexec(regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags)
 */ 
AP_DECLARE(int)    ap_regexec(regex_t *preg, const char *string,
                              size_t nmatch, regmatch_t pmatch[], int eflags);

/**
 * Return the error code returned by regcomp or regexec into error messages
 * @param errocode the error code returned by regexec or regcomp
 * @param preg The precompiled regex
 * @param errbuf A buffer to store the error in
 * @param errbuf_size The size of the buffer
 * @deffunc size_t ap_regerror(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size)
 */
AP_DECLARE(size_t) ap_regerror(int errcode, const regex_t *preg, 
                               char *errbuf, size_t errbuf_size);

/**
 * After performing a successful regex match, you may use this function to 
 * perform a series of string substitutions based on subexpressions that were
 * matched during the call to ap_regexec
 * @param p The pool to allocate out of
 * @param input An arbitrary string containing $1 through $9.  These are 
 *              replaced with the corresponding matched sub-expressions
 * @param source The string that was originally matched to the regex
 * @param nmatch the nmatch returned from ap_pregex
 * @param pmatch the pmatch array returned from ap_pregex
 * @deffunc char *ap_pregsub(apr_pool_t *p, const char *input, const char *source, size_t nmatch, regmatch_t pmatch[])
 */
AP_DECLARE(char *) ap_pregsub(apr_pool_t *p, const char *input, const char *source,
                              size_t nmatch, regmatch_t pmatch[]);

/**
 * we want to downcase the type/subtype for comparison purposes
 * but nothing else because ;parameter=foo values are case sensitive.
 * @param s The content-type to convert to lowercase
 * @deffunc void ap_content_type_tolower(char *s)
 */
AP_DECLARE(void) ap_content_type_tolower(char *s);

/**
 * convert a string to all lowercase
 * @param s The string to convert to lowercase 
 * @deffunc void ap_str_tolower(char *s) 
 */
AP_DECLARE(void) ap_str_tolower(char *s);

/**
 * Search a string from left to right for the first occurrence of a 
 * specific character
 * @param str The string to search
 * @param c The character to search for
 * @return The index of the first occurrence of c in str
 * @deffunc int ap_ind(const char *str, char c)
 */
AP_DECLARE(int) ap_ind(const char *str, char c);	/* Sigh... */

/**
 * Search a string from right to left for the first occurrence of a 
 * specific character
 * @param str The string to search
 * @param c The character to search for
 * @return The index of the first occurrence of c in str
 * @deffunc int ap_rind(const char *str, char c)
 */
AP_DECLARE(int) ap_rind(const char *str, char c);

/**
 * Given a string, replace any bare " with \" .
 * @param p The pool to allocate memory out of
 * @param instring The string to search for "
 * @return A copy of the string with escaped quotes 
 * @deffunc char * ap_escape_quotes(apr_pool_t *p, const char *instring) 
 */
AP_DECLARE(char *) ap_escape_quotes(apr_pool_t *p, const char *instring);

/* Misc system hackery */
/**
 * Given the name of an object in the file system determine if it is a directory
 * @param p The pool to allocate out of 
 * @param name The name of the object to check
 * @return 1 if it is a directory, 0 otherwise
 * @deffunc int ap_is_rdirectory(apr_pool_t *p, const char *name)
 */
AP_DECLARE(int) ap_is_rdirectory(apr_pool_t *p, const char *name);

/**
 * Given the name of an object in the file system determine if it is a directory - this version is symlink aware
 * @param p The pool to allocate out of 
 * @param name The name of the object to check
 * @return 1 if it is a directory, 0 otherwise
 * @deffunc int ap_is_directory(apr_pool_t *p, const char *name)
 */
AP_DECLARE(int) ap_is_directory(apr_pool_t *p, const char *name);

#ifdef _OSD_POSIX
extern const char *os_set_account(apr_pool_t *p, const char *account);
extern int os_init_job_environment(server_rec *s, const char *user_name, int one_process);
#endif /* _OSD_POSIX */

/**
 * determine the local host name for the current machine
 * @param p The pool to allocate out of
 * @return A copy of the local host name
 * @deffunc char *ap_get_local_host(apr_pool_t *p)
 */
char *ap_get_local_host(apr_pool_t *p);

/*
 * Redefine assert() to something more useful for an Apache...
 *
 * Use ap_assert() if the condition should always be checked.
 * Use AP_DEBUG_ASSERT() if the condition should only be checked when AP_DEBUG
 * is defined.
 */
/**
 * Log an assertion to the error log
 * @param szExp The assertion that failed
 * @param szFile The file the assertion is in
 * @param nLine The line the assertion is defined on
 * @deffunc void ap_log_assert(const char *szExp, const char *szFile, int nLine)
 */
AP_DECLARE(void) ap_log_assert(const char *szExp, const char *szFile, int nLine)
			    __attribute__((noreturn));
#define ap_assert(exp) ((exp) ? (void)0 : ap_log_assert(#exp,__FILE__,__LINE__))

#ifdef AP_DEBUG
#define AP_DEBUG_ASSERT(exp) ap_assert(exp)
#else
#define AP_DEBUG_ASSERT(exp) ((void)0)
#endif

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

AP_DECLARE(extern const char *) ap_psignature(const char *prefix, request_rec *r);

/* strtoul does not exist on sunos4. */
#ifdef strtoul
#undef strtoul
#endif
#define strtoul strtoul_is_not_a_portable_function_use_strtol_instead

  /* The C library has functions that allow const to be silently dropped ...
     these macros detect the drop in maintainer mode, but use the native
     methods for normal builds

     Note that on some platforms (e.g., AIX with gcc, Solaris with gcc), string.h needs 
     to be included before the macros are defined or compilation will fail.
  */
#include <string.h>

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
