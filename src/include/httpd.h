/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

/* Headers in which EVERYONE has an interest... */

#include "ap_config.h"
#include "ap_alloc.h"
#include "buff.h"
#include "ap.h"

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
#elif defined(BEOS) || defined(BONE)
#define HTTPD_ROOT "/boot/home/apache"
#elif defined(NETWARE)
#define HTTPD_ROOT "sys:/apache"
#else
#define HTTPD_ROOT "/usr/local/apache"
#endif
#endif /* HTTPD_ROOT */

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

/* 
 * --------- You shouldn't have to edit anything below this line ----------
 *
 * Any modifications to any defaults not defined above should be done in the 
 * respective config. file. 
 *
 */


/* -- Internal representation for a HTTP protocol number, e.g., HTTP/1.1 -- */

#define HTTP_VERSION(major,minor) (1000*(major)+(minor))
#define HTTP_VERSION_MAJOR(number) ((number)/1000)
#define HTTP_VERSION_MINOR(number) ((number)%1000)


/* -------------- Port number for server running standalone --------------- */

#define DEFAULT_HTTP_PORT	80
#define DEFAULT_HTTPS_PORT	443
#define ap_is_default_port(port,r)	((port) == ap_default_port(r))
#ifdef NETWARE
#define ap_http_method(r) ap_os_http_method((void*)r)
#define ap_default_port(r) ap_os_default_port((void*)r)
#else
#define ap_http_method(r)	"http"
#define ap_default_port(r)	DEFAULT_HTTP_PORT
#endif

/* --------- Default user name and group name running standalone ---------- */
/* --- These may be specified as numbers by placing a # before a number --- */

#ifndef DEFAULT_USER
#define DEFAULT_USER "#-1"
#endif
#ifndef DEFAULT_GROUP
#define DEFAULT_GROUP "#-1"
#endif

#ifndef DEFAULT_ERRORLOG
#if defined(OS2) || defined(WIN32)
#define DEFAULT_ERRORLOG "logs/error.log"
#else
#define DEFAULT_ERRORLOG "logs/error_log"
#endif
#endif /* DEFAULT_ERRORLOG */

#ifndef DEFAULT_PIDLOG
#define DEFAULT_PIDLOG "logs/httpd.pid"
#endif
#ifndef DEFAULT_SCOREBOARD
#define DEFAULT_SCOREBOARD "logs/apache_runtime_status"
#endif
#ifndef DEFAULT_LOCKFILE
#define DEFAULT_LOCKFILE "logs/accept.lock"
#endif

/* Define this to be what your HTML directory content files are called */
#ifndef DEFAULT_INDEX
#define DEFAULT_INDEX "index.html"
#endif

/* Define this to 1 if you want fancy indexing, 0 otherwise */
#ifndef DEFAULT_INDEXING
#define DEFAULT_INDEXING 0
#endif

/* Define this to be what type you'd like returned for files with unknown */
/* suffixes.  MUST be all lower case. */
#ifndef DEFAULT_CONTENT_TYPE
#define DEFAULT_CONTENT_TYPE "text/plain"
#endif

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

/* The name of the document config file */
#ifndef RESOURCE_CONFIG_FILE
#define RESOURCE_CONFIG_FILE "conf/srm.conf"
#endif

/* The name of the MIME types file */
#ifndef TYPES_CONFIG_FILE
#define TYPES_CONFIG_FILE "conf/mime.types"
#endif

/* The name of the access file */
#ifndef ACCESS_CONFIG_FILE
#define ACCESS_CONFIG_FILE "conf/access.conf"
#endif

/* Whether we should enable rfc1413 identity checking */
#ifndef DEFAULT_RFC1413
#define DEFAULT_RFC1413 0
#endif
/* The default directory in user's home dir */
#ifndef DEFAULT_USER_DIR
#define DEFAULT_USER_DIR "public_html"
#endif

/* The default path for CGI scripts if none is currently set */
#ifndef DEFAULT_PATH
#define DEFAULT_PATH "/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin"
#endif

/* The path to the shell interpreter, for parsed docs */
#ifndef SHELL_PATH
#if defined(OS2) || defined(WIN32)
/* Set default for OS/2 and Windows file system */
#define SHELL_PATH "CMD.EXE"
#else
#define SHELL_PATH "/bin/sh"
#endif
#endif /* SHELL_PATH */

/* The path to the suExec wrapper, can be overridden in Configuration */
#ifndef SUEXEC_BIN
#define SUEXEC_BIN  HTTPD_ROOT "/bin/suexec"
#endif

/* The default string lengths */
#define MAX_STRING_LEN HUGE_STRING_LEN
#define HUGE_STRING_LEN 8192

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

/* The size of the server's internal read-write buffers */
#define IOBUFSIZE 8192

/* Number of servers to spawn off by default --- also, if fewer than
 * this free when the caretaker checks, it will spawn more.
 */
#ifndef DEFAULT_START_DAEMON
#define DEFAULT_START_DAEMON 5
#endif

/* Maximum number of *free* server processes --- more than this, and
 * they will die off.
 */

#ifndef DEFAULT_MAX_FREE_DAEMON
#define DEFAULT_MAX_FREE_DAEMON 10
#endif

/* Minimum --- fewer than this, and more will be created */

#ifndef DEFAULT_MIN_FREE_DAEMON
#define DEFAULT_MIN_FREE_DAEMON 5
#endif

/* Limit on the total --- clients will be locked out if more servers than
 * this are needed.  It is intended solely to keep the server from crashing
 * when things get out of hand.
 *
 * We keep a hard maximum number of servers, for two reasons --- first off,
 * in case something goes seriously wrong, we want to stop the fork bomb
 * short of actually crashing the machine we're running on by filling some
 * kernel table.  Secondly, it keeps the size of the scoreboard file small
 * enough that we can read the whole thing without worrying too much about
 * the overhead.
 */
#ifndef HARD_SERVER_LIMIT
#ifdef WIN32
#define HARD_SERVER_LIMIT 1024
#elif defined(NETWARE)
#define HARD_SERVER_LIMIT 2048
#else
#define HARD_SERVER_LIMIT 256
#endif
#endif

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

/*
 * (Unix, OS/2 only)
 * Interval, in microseconds, between scoreboard maintenance.  During
 * each scoreboard maintenance cycle the parent decides if it needs to
 * spawn a new child (to meet MinSpareServers requirements), or kill off
 * a child (to meet MaxSpareServers requirements).  It will only spawn or
 * kill one child per cycle.  Setting this too low will chew cpu.  The
 * default is probably sufficient for everyone.  But some people may want
 * to raise this on servers which aren't dedicated to httpd and where they
 * don't like the httpd waking up each second to see what's going on.
 */
#ifndef SCOREBOARD_MAINTENANCE_INTERVAL
#define SCOREBOARD_MAINTENANCE_INTERVAL 1000000
#endif

/* Number of requests to try to handle in a single process.  If <= 0,
 * the children don't die off.  That's the default here, since I'm still
 * interested in finding and stanching leaks.
 */

#ifndef DEFAULT_MAX_REQUESTS_PER_CHILD
#define DEFAULT_MAX_REQUESTS_PER_CHILD 0
#endif

#ifndef DEFAULT_THREADS_PER_CHILD
#define DEFAULT_THREADS_PER_CHILD 50
#endif
#ifndef DEFAULT_EXCESS_REQUESTS_PER_CHILD
#define DEFAULT_EXCESS_REQUESTS_PER_CHILD 0
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

#define SERVER_BASEVENDOR   "Apache Group"
#define SERVER_BASEPRODUCT  "Apache"
#define SERVER_BASEREVISION "1.3.28"
#define SERVER_BASEVERSION  SERVER_BASEPRODUCT "/" SERVER_BASEREVISION

#define SERVER_PRODUCT  SERVER_BASEPRODUCT
#define SERVER_REVISION SERVER_BASEREVISION
#define SERVER_VERSION  SERVER_PRODUCT "/" SERVER_REVISION
enum server_token_type {
    SrvTk_MIN,		/* eg: Apache/1.3.0 */
    SrvTk_OS,		/* eg: Apache/1.3.0 (UNIX) */
    SrvTk_FULL,		/* eg: Apache/1.3.0 (UNIX) PHP/3.0 FooBar/1.2b */
    SrvTk_PRODUCT_ONLY	/* eg: Apache */
};

API_EXPORT(const char *) ap_get_server_version(void);
API_EXPORT(void) ap_add_version_component(const char *component);
API_EXPORT(const char *) ap_get_server_built(void);

/* Numeric release version identifier: MMNNFFRBB: major minor fix final beta
 * Always increases along the same track as the source branch.
 * For example, Apache 1.4.2 would be '10402100', 2.5b7 would be '20500007'.
 */
#define APACHE_RELEASE 10328100

#define SERVER_PROTOCOL "HTTP/1.1"
#ifndef SERVER_SUPPORT
#define SERVER_SUPPORT "http://www.apache.org/"
#endif

#define DECLINED -1		/* Module declines to handle */
#define DONE -2			/* Module has served the response completely 
				 *  - it's safe to die() with no more output
				 */
#define OK 0			/* Module has handled this stage. */


/* ----------------------- HTTP Status Codes  ------------------------- */

/* The size of the static array in http_protocol.c for storing
 * all of the potential response status-lines (a sparse table).
 * A future version should dynamically generate the table at startup.
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

#define DOCUMENT_FOLLOWS    HTTP_OK
#define PARTIAL_CONTENT     HTTP_PARTIAL_CONTENT
#define MULTIPLE_CHOICES    HTTP_MULTIPLE_CHOICES
#define MOVED               HTTP_MOVED_PERMANENTLY
#define REDIRECT            HTTP_MOVED_TEMPORARILY
#define USE_LOCAL_COPY      HTTP_NOT_MODIFIED
#define BAD_REQUEST         HTTP_BAD_REQUEST
#define AUTH_REQUIRED       HTTP_UNAUTHORIZED
#define FORBIDDEN           HTTP_FORBIDDEN
#define NOT_FOUND           HTTP_NOT_FOUND
#define METHOD_NOT_ALLOWED  HTTP_METHOD_NOT_ALLOWED
#define NOT_ACCEPTABLE      HTTP_NOT_ACCEPTABLE
#define LENGTH_REQUIRED     HTTP_LENGTH_REQUIRED
#define PRECONDITION_FAILED HTTP_PRECONDITION_FAILED
#define SERVER_ERROR        HTTP_INTERNAL_SERVER_ERROR
#define NOT_IMPLEMENTED     HTTP_NOT_IMPLEMENTED
#define BAD_GATEWAY         HTTP_BAD_GATEWAY
#define VARIANT_ALSO_VARIES HTTP_VARIANT_ALSO_VARIES

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
#ifdef CHARSET_EBCDIC
#define ASCIITEXT_MAGIC_TYPE_PREFIX "text/x-ascii-" /* Text files whose content-type starts with this are passed thru unconverted */
#endif /*CHARSET_EBCDIC*/
#define MAP_FILE_MAGIC_TYPE "application/x-type-map"
#define ASIS_MAGIC_TYPE "httpd/send-as-is"
#define DIR_MAGIC_TYPE "httpd/unix-directory"
#define STATUS_MAGIC_TYPE "application/x-httpd-status"

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

/* Just in case your linefeed isn't the one the other end is expecting. */
#ifndef CHARSET_EBCDIC
#define LF 10
#define CR 13
#define CRLF "\015\012"
#define OS_ASC(c) (c)
#else /* CHARSET_EBCDIC */
#include "ap_ebcdic.h"
/* OSD_POSIX uses the EBCDIC charset. The transition ASCII->EBCDIC is done in
 * the buff package (bread/bputs/bwrite), so everywhere else, we use
 * "native EBCDIC" CR and NL characters. These are therefore defined as
 * '\r' and '\n'.
 * NB: this is not the whole truth - sometimes \015 and \012 are contained
 * in literal (EBCDIC!) strings, so these are not converted but passed.
 */
#define CR '\r'
#define LF '\n'
#define CRLF "\r\n"
#define OS_ASC(c) (os_toascii[c])
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
    char *dir;			/* the directory to which this applies */
    int override;		/* the overrides allowed for the .htaccess file */
    void *htaccess;		/* the configuration directives */
/* the next one, or NULL if no more; N.B. never change this */
    const struct htaccess_result *next;
};

typedef struct conn_rec conn_rec;
typedef struct server_rec server_rec;
typedef struct request_rec request_rec;
typedef struct listen_rec listen_rec;

#include "util_uri.h"

enum proxyreqtype {
    NOT_PROXY=0,
    STD_PROXY,
    PROXY_PASS
};

struct request_rec {

    ap_pool *pool;
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
    enum proxyreqtype proxyreq;/* A proxy request (calculated during
				 * post_read_request or translate_name) */
    int header_only;		/* HEAD request, as opposed to GET */
    char *protocol;		/* Protocol, as given to us, or HTTP/0.9 */
    int proto_num;		/* Number version of protocol; 1.1 = 1001 */
    const char *hostname;	/* Host, as set by full URI or Host: */

    time_t request_time;	/* When the request started */

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
	and METHOD_NOT_ALLOWED and NOT_IMPLEMENTED status codes.

	Since the default_handler deals with OPTIONS, all modules can
	usually decline to deal with OPTIONS.  TRACE is always allowed,
	modules don't need to set it explicitly.

	Since the default_handler will always handle a GET, a
	module which does *not* implement GET should probably return
	METHOD_NOT_ALLOWED.  Unfortunately this means that a Script GET
	handler can't be installed by mod_actions.
    */
    int allowed;		/* Allowed methods - for 405, OPTIONS, etc */

    int sent_bodyct;		/* byte count in stream is for body */
    long bytes_sent;		/* body byte count, for easy access */
    time_t mtime;		/* Time the resource was last modified */

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
     * The 'notes' table is for notes from one module to another, with no
     * other set purpose in mind...
     */

    table *headers_in;
    table *headers_out;
    table *err_headers_out;
    table *subprocess_env;
    table *notes;

    /* content_type, handler, content_encoding, content_language, and all
     * content_languages MUST be lowercased strings.  They may be pointers
     * to static strings; they should not be modified in place.
     */
    const char *content_type;	/* Break these out --- we dispatch on 'em */
    const char *handler;	/* What we *really* dispatch on           */

    const char *content_encoding;
    const char *content_language;	/* for back-compat. only -- do not use */
    array_header *content_languages;	/* array of (char*) */

    char *vlist_validator;      /* variant list validator (if negotiated) */

    int no_cache;
    int no_local_copy;

    /* What object is being requested (either directly, or via include
     * or content-negotiation mapping).
     */

    char *unparsed_uri;		/* the uri without any parsing performed */
    char *uri;			/* the path portion of the URI */
    char *filename;		/* filename if found, otherwise NULL */
    char *path_info;
    char *args;			/* QUERY_ARGS, if any */
    struct stat finfo;		/* ST_MODE set to zero if no such file */
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

    /* On systems with case insensitive file systems (Windows, OS/2, etc.), 
     * r->filename is case canonicalized (folded to either lower or upper 
     * case, depending on the specific system) to accomodate file access
     * checking. case_preserved_filename is the same as r->filename 
     * except case is preserved. There is at least one instance where Apache 
     * needs access to the case preserved filename: Java class files published 
     * with WebDAV need to preserve filename case to make the Java compiler 
     * happy.
     */
    char *case_preserved_filename;

#ifdef CHARSET_EBCDIC
    /* We don't want subrequests to modify our current conversion flags.
     * These flags save the state of the conversion flags when subrequests
     * are run.
     */
    struct {
        unsigned conv_in:1;    /* convert ASCII->EBCDIC when read()ing? */
        unsigned conv_out:1;   /* convert EBCDIC->ASCII when write()ing? */
    } ebcdic;
#endif

/* Things placed at the end of the record to avoid breaking binary
 * compatibility.  It would be nice to remember to reorder the entire
 * record to improve 64bit alignment the next time we need to break
 * binary compatibility for some other reason.
 */
};


/* Things which are per connection
 */

struct conn_rec {

    ap_pool *pool;
    server_rec *server;
    server_rec *base_server;	/* Physical vhost this conn come in on */
    void *vhost_lookup_data;	/* used by http_vhost.c */

    /* Information about the connection itself */

    int child_num;		/* The number of the child handling conn_rec */
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
    char *user;			/* If an authentication check was made,
				 * this gets set to the user name.  We assume
				 * that there's only one user per connection(!)
				 */
    char *ap_auth_type;		/* Ditto. */

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
};

/* Per-vhost config... */

/* The address 255.255.255.255, when used as a virtualhost address,
 * will become the "default" server when the ip doesn't match other vhosts.
 */
#define DEFAULT_VHOST_ADDR 0xfffffffful

typedef struct server_addr_rec server_addr_rec;
struct server_addr_rec {
    server_addr_rec *next;
    struct in_addr host_addr;	/* The bound address, for this server */
    unsigned short host_port;	/* The bound port, for this server */
    char *virthost;		/* The name given in <VirtualHost> */
};

struct server_rec {

    server_rec *next;

    /* description of where the definition came from */
    const char *defn_name;
    unsigned defn_line_number;

    /* Full locations of server config info */

    char *srm_confname;
    char *access_confname;

    /* Contact information */

    char *server_admin;
    char *server_hostname;
    unsigned short port;	/* for redirects, etc. */

    /* Log files --- note that transfer log is now in the modules... */

    char *error_fname;
    FILE *error_log;
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
    int send_buffer_size;	/* size of TCP send buffer (in bytes) */

    char *path;			/* Pathname for ServerPath */
    int pathlen;		/* Length of path */

    array_header *names;	/* Normal names for ServerAlias servers */
    array_header *wild_names;	/* Wildcarded names for ServerAlias servers */

    uid_t server_uid;        /* effective user id when calling exec wrapper */
    gid_t server_gid;        /* effective group id when calling exec wrapper */

    int limit_req_line;      /* limit on size of the HTTP request line    */
    int limit_req_fieldsize; /* limit on size of any request header field */
    int limit_req_fields;    /* limit on number of request header fields  */
};

/* These are more like real hosts than virtual hosts */
struct listen_rec {
    listen_rec *next;
    struct sockaddr_in local_addr;	/* local IP address and port */
    int fd;
    int used;			/* Only used during restart */        
/* more stuff here, like which protocol is bound to the port */
};

/* Prototypes for utilities... util.c.
 */

extern void ap_util_init(void);

/* Time */
extern API_VAR_EXPORT const char ap_month_snames[12][4];
extern API_VAR_EXPORT const char ap_day_snames[7][4];

API_EXPORT(struct tm *) ap_get_gmtoff(int *tz);
API_EXPORT(char *) ap_get_time(void);
API_EXPORT(char *) ap_field_noparam(pool *p, const char *intype);
API_EXPORT(char *) ap_ht_time(pool *p, time_t t, const char *fmt, int gmt);
API_EXPORT(char *) ap_gm_timestr_822(pool *p, time_t t);

/* String handling. The *_nc variants allow you to use non-const char **s as
   arguments (unfortunately C won't automatically convert a char ** to a const
   char **) */

API_EXPORT(char *) ap_getword(pool *p, const char **line, char stop);
API_EXPORT(char *) ap_getword_nc(pool *p, char **line, char stop);
API_EXPORT(char *) ap_getword_white(pool *p, const char **line);
API_EXPORT(char *) ap_getword_white_nc(pool *p, char **line);
API_EXPORT(char *) ap_getword_nulls(pool *p, const char **line, char stop);
API_EXPORT(char *) ap_getword_nulls_nc(pool *p, char **line, char stop);
API_EXPORT(char *) ap_getword_conf(pool *p, const char **line);
API_EXPORT(char *) ap_getword_conf_nc(pool *p, char **line);

API_EXPORT(const char *) ap_size_list_item(const char **field, int *len);
API_EXPORT(char *) ap_get_list_item(pool *p, const char **field);
API_EXPORT(int) ap_find_list_item(pool *p, const char *line, const char *tok);

API_EXPORT(char *) ap_get_token(pool *p, const char **accept_line, int accept_white);
API_EXPORT(int) ap_find_token(pool *p, const char *line, const char *tok);
API_EXPORT(int) ap_find_last_token(pool *p, const char *line, const char *tok);

API_EXPORT(int) ap_is_url(const char *u);
API_EXPORT(int) ap_unescape_url(char *url);
API_EXPORT(void) ap_no2slash(char *name);
API_EXPORT(void) ap_getparents(char *name);
API_EXPORT(char *) ap_escape_path_segment(pool *p, const char *s);
API_EXPORT(char *) ap_os_escape_path(pool *p, const char *path, int partial);
#define ap_escape_uri(ppool,path) ap_os_escape_path(ppool,path,1)
API_EXPORT(char *) ap_escape_html(pool *p, const char *s);
API_EXPORT(char *) ap_construct_server(pool *p, const char *hostname,
				    unsigned port, const request_rec *r);
API_EXPORT(char *) ap_escape_logitem(pool *p, const char *str);
API_EXPORT(char *) ap_escape_shell_cmd(pool *p, const char *s);

API_EXPORT(int) ap_count_dirs(const char *path);
API_EXPORT(char *) ap_make_dirstr_prefix(char *d, const char *s, int n);
API_EXPORT(char *) ap_make_dirstr_parent(pool *p, const char *s);
/* deprecated.  The previous two routines are preferred. */
API_EXPORT(char *) ap_make_dirstr(pool *a, const char *s, int n);
API_EXPORT(char *) ap_make_full_path(pool *a, const char *dir, const char *f);

API_EXPORT(int) ap_is_matchexp(const char *str);
API_EXPORT(int) ap_strcmp_match(const char *str, const char *exp);
API_EXPORT(int) ap_strcasecmp_match(const char *str, const char *exp);
API_EXPORT(char *) ap_stripprefix(const char *bigstring, const char *prefix);
API_EXPORT(char *) ap_strcasestr(const char *s1, const char *s2);
API_EXPORT(char *) ap_pbase64decode(pool *p, const char *bufcoded);
API_EXPORT(char *) ap_pbase64encode(pool *p, char *string); 
API_EXPORT(char *) ap_uudecode(pool *p, const char *bufcoded);
API_EXPORT(char *) ap_uuencode(pool *p, char *string); 

#if defined(OS2) || defined(WIN32)
API_EXPORT(char *) ap_double_quotes(pool *p, const char *str);
API_EXPORT(char *) ap_caret_escape_args(pool *p, const char *str);
#endif

#ifdef OS2
void os2pathname(char *path);
#endif

API_EXPORT(int)    ap_regexec(const regex_t *preg, const char *string,
                              size_t nmatch, regmatch_t pmatch[], int eflags);
API_EXPORT(size_t) ap_regerror(int errcode, const regex_t *preg, 
                               char *errbuf, size_t errbuf_size);
API_EXPORT(char *) ap_pregsub(pool *p, const char *input, const char *source,
                              size_t nmatch, regmatch_t pmatch[]);

API_EXPORT(void) ap_content_type_tolower(char *);
API_EXPORT(void) ap_str_tolower(char *);
API_EXPORT(int) ap_ind(const char *, char);	/* Sigh... */
API_EXPORT(int) ap_rind(const char *, char);

API_EXPORT(char *) ap_escape_quotes (pool *p, const char *instring);
API_EXPORT(void) ap_remove_spaces(char *dest, char *src);

/* Common structure for reading of config files / passwd files etc. */
typedef struct {
    int (*getch) (void *param);	/* a getc()-like function */
    void *(*getstr) (void *buf, size_t bufsiz, void *param); /* a fgets()-like function */
    int (*close) (void *param);	/* a close hander function */
    void *param;		/* the argument passed to getch/getstr/close */
    const char *name;		/* the filename / description */
    unsigned line_number;	/* current line number, starting at 1 */
} configfile_t;

/* Open a configfile_t as FILE, return open configfile_t struct pointer */
API_EXPORT(configfile_t *) ap_pcfg_openfile(pool *p, const char *name);

/* Allocate a configfile_t handle with user defined functions and params */
API_EXPORT(configfile_t *) ap_pcfg_open_custom(pool *p, const char *descr,
    void *param,
    int(*getc_func)(void*),
    void *(*gets_func) (void *buf, size_t bufsiz, void *param),
    int(*close_func)(void *param));

/* Read one line from open configfile_t, strip LF, increase line number */
API_EXPORT(int) ap_cfg_getline(char *buf, size_t bufsize, configfile_t *cfp);

/* Read one char from open configfile_t, increase line number upon LF */
API_EXPORT(int) ap_cfg_getc(configfile_t *cfp);

/* Detach from open configfile_t, calling the close handler */
API_EXPORT(int) ap_cfg_closefile(configfile_t *cfp);

#ifdef NEED_STRERROR
char *strerror(int err);
#endif

/* Misc system hackery */

API_EXPORT(uid_t) ap_uname2id(const char *name);
API_EXPORT(gid_t) ap_gname2id(const char *name);
API_EXPORT(int) ap_is_directory(const char *name);
API_EXPORT(int) ap_is_rdirectory(const char *name);
API_EXPORT(int) ap_can_exec(const struct stat *);
API_EXPORT(void) ap_chdir_file(const char *file);

#ifndef HAVE_CANONICAL_FILENAME
/*
 *  We can't define these in os.h because of dependence on pool pointer.
 */
#define ap_os_canonical_filename(p,f)  (f)
#define ap_os_case_canonical_filename(p,f)  (f)
#define ap_os_systemcase_filename(p,f)  (f)
#else
API_EXPORT(char *) ap_os_canonical_filename(pool *p, const char *file);
#ifdef WIN32
API_EXPORT(char *) ap_os_case_canonical_filename(pool *pPool, const char *szFile);
API_EXPORT(char *) ap_os_systemcase_filename(pool *pPool, const char *szFile);
#elif defined(OS2)
API_EXPORT(char *) ap_os_case_canonical_filename(pool *pPool, const char *szFile);
API_EXPORT(char *) ap_os_systemcase_filename(pool *pPool, const char *szFile);
#elif defined(NETWARE)
API_EXPORT(char *) ap_os_case_canonical_filename(pool *pPool, const char *szFile);
#define ap_os_systemcase_filename(p,f) ap_os_case_canonical_filename(p,f)
#else
#define ap_os_case_canonical_filename(p,f) ap_os_canonical_filename(p,f)
#define ap_os_systemcase_filename(p,f) ap_os_canonical_filename(p,f)
#endif
#endif

#ifdef CHARSET_EBCDIC
API_EXPORT(int)    ap_checkconv(struct request_rec *r);    /* for downloads */
API_EXPORT(int)    ap_checkconv_in(struct request_rec *r); /* for uploads */
#endif /*#ifdef CHARSET_EBCDIC*/

API_EXPORT(char *) ap_get_local_host(pool *);
API_EXPORT(unsigned long) ap_get_virthost_addr(char *hostname, unsigned short *port);

extern API_VAR_EXPORT time_t ap_restart_time;

/*
 * Apache tries to keep all of its long term filehandles (such as log files,
 * and sockets) above this number.  This is to workaround problems in many
 * third party libraries that are compiled with a small FD_SETSIZE.  There
 * should be no reason to lower this, because it's only advisory.  If a file
 * can't be allocated above this number then it will remain in the "slack"
 * area.
 *
 * Only the low slack line is used by default.  If HIGH_SLACK_LINE is defined
 * then an attempt is also made to keep all non-FILE * files above the high
 * slack line.  This is to work around a Solaris C library limitation, where it
 * uses an unsigned char to store the file descriptor.
 */
#ifndef LOW_SLACK_LINE
#define LOW_SLACK_LINE	15
#endif
/* #define HIGH_SLACK_LINE      255 */

/*
 * The ap_slack() function takes a fd, and tries to move it above the indicated
 * line.  It returns an fd which may or may not have moved above the line, and
 * never fails.  If the high line was requested and it fails it will also try
 * the low line.
 */
#ifdef NO_SLACK
#define ap_slack(fd,line)   (fd)
#else
int ap_slack(int fd, int line);
#define AP_SLACK_LOW	1
#define AP_SLACK_HIGH	2
#endif

API_EXPORT(char *) ap_escape_quotes(pool *p, const char *instr);

/*
 * Redefine assert() to something more useful for an Apache...
 */
API_EXPORT(void) ap_log_assert(const char *szExp, const char *szFile, int nLine)
			    __attribute__((noreturn));
#define ap_assert(exp) ((exp) ? (void)0 : ap_log_assert(#exp,__FILE__,__LINE__))

/* The optimized timeout code only works if we're not MULTITHREAD and we're
 * also not using a scoreboard file
 */
#if !defined (MULTITHREAD) && \
    (defined (USE_MMAP_SCOREBOARD) || defined (USE_SHMGET_SCOREBOARD))
#define OPTIMIZE_TIMEOUTS
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

API_EXPORT(extern const char *) ap_psignature(const char *prefix, request_rec *r);

/* strtoul does not exist on sunos4. */
#ifdef strtoul
#undef strtoul
#endif
#define strtoul strtoul_is_not_a_portable_function_use_strtol_instead

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTPD_H */
