/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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
 * httpd.h: header for simple (ha! not anymore) http daemon
 */

/* Headers in which EVERYONE has an interest... */

#include "conf.h"
#include "alloc.h"
#include "buff.h"

/* ----------------------------- config dir ------------------------------ */

/* Define this to be the default server home dir. Anything later in this
 * file with a relative pathname will have this added.
 */
#ifdef __EMX__
/* Set default for OS/2 file system */ 
#define HTTPD_ROOT "/os2httpd"
#else
#define HTTPD_ROOT "/usr/local/etc/httpd"
#endif

/* Root of server */
#ifdef __EMX__
/* Set default for OS/2 file system */ 
#define DOCUMENT_LOCATION "/os2httpd/docs"
#else
#define DOCUMENT_LOCATION "/usr/local/etc/httpd/htdocs"
#endif

/* Max. number of dynamically loaded modules */
#define DYNAMIC_MODULE_LIMIT 64

/* Default administrator's address */
#define DEFAULT_ADMIN "[no address given]"

/* 
 * --------- You shouldn't have to edit anything below this line ----------
 *
 * Any modifications to any defaults not defined above should be done in the 
 * respective config. file. 
 *
 */


/* -------------- Port number for server running standalone --------------- */

#define DEFAULT_PORT 80

/* --------- Default user name and group name running standalone ---------- */
/* --- These may be specified as numbers by placing a # before a number --- */

#ifndef DEFAULT_USER
#define DEFAULT_USER "#-1"
#endif
#ifndef DEFAULT_GROUP
#define DEFAULT_GROUP "#-1"
#endif

/* The name of the log files */
#ifdef __EMX__
/* Set default for OS/2 file system */ 
#define DEFAULT_XFERLOG "logs/access.log"
#else
#define DEFAULT_XFERLOG "logs/access_log"
#endif
#ifdef __EMX__
/* Set default for OS/2 file system */ 
#define DEFAULT_ERRORLOG "logs/error.log"
#else
#define DEFAULT_ERRORLOG "logs/error_log"
#endif
#define DEFAULT_PIDLOG "logs/httpd.pid"
#define DEFAULT_SCOREBOARD "logs/apache_runtime_status"

/* Define this to be what your HTML directory content files are called */
#define DEFAULT_INDEX "index.html"

/* Define this to 1 if you want fancy indexing, 0 otherwise */
#define DEFAULT_INDEXING 0

/* Define this to be what type you'd like returned for files with unknown */
/* suffixes */
#define DEFAULT_TYPE "text/html"

/* Define this to be what your per-directory security files are called */
#ifdef __EMX__
/* Set default for OS/2 file system */ 
#define DEFAULT_ACCESS_FNAME "htaccess"
#else
#define DEFAULT_ACCESS_FNAME ".htaccess"
#endif

/* The name of the server config file */
#define SERVER_CONFIG_FILE "conf/httpd.conf"

/* The name of the document config file */
#define RESOURCE_CONFIG_FILE "conf/srm.conf"

/* The name of the MIME types file */
#define TYPES_CONFIG_FILE "conf/mime.types"

/* The name of the access file */
#define ACCESS_CONFIG_FILE "conf/access.conf"

/* Whether we should enable rfc1413 identity checking */
#define DEFAULT_RFC1413 0
/* The default directory in user's home dir */
#define DEFAULT_USER_DIR "public_html"

/* The default path for CGI scripts if none is currently set */
#define DEFAULT_PATH "/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin"

/* The path to the Bourne shell, for parsed docs */
#ifdef __EMX__
/* Set default for OS/2 file system */ 
#define SHELL_PATH "CMD.EXE"
#else
#define SHELL_PATH "/bin/sh"
#endif

/* The path to the suExec wrapper, can be overridden in Configuration */
#ifndef SUEXEC_BIN
#define SUEXEC_BIN "/usr/local/etc/httpd/sbin/suexec"
#endif

/* The default string lengths */
#define MAX_STRING_LEN HUGE_STRING_LEN
#define HUGE_STRING_LEN 8192

/* The timeout for waiting for messages */
#define DEFAULT_TIMEOUT 1200

/* The timeout for waiting for keepalive timeout until next request */
#define DEFAULT_KEEPALIVE_TIMEOUT 15

/* The number of requests to entertain per connection */
#define DEFAULT_KEEPALIVE 100

/* The size of the server's internal read-write buffers */
#define IOBUFSIZE 8192

/* The number of header lines we will accept from a client */
#define MAX_HEADERS 200

/* Number of servers to spawn off by default --- also, if fewer than
 * this free when the caretaker checks, it will spawn more.
 */
#define DEFAULT_START_DAEMON 5

/* Maximum number of *free* server processes --- more than this, and
 * they will die off.
 */

#define DEFAULT_MAX_FREE_DAEMON 10

/* Minimum --- fewer than this, and more will be created */

#define DEFAULT_MIN_FREE_DAEMON 5

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
#define HARD_SERVER_LIMIT 256

/* Number of requests to try to handle in a single process.  If <= 0,
 * the children don't die off.  That's the default here, since I'm still
 * interested in finding and stanching leaks.
 */

#define DEFAULT_MAX_REQUESTS_PER_CHILD 0

/* If you have altered Apache and wish to change the SERVER_VERSION
 * identifier below, please keep to the HTTP specification.  This states that
 * the identification string should consist of product tokens with an optional
 * slash and version designator.  Sub-products which form a significant part 
 * of the application can be listed, separated by whitespace, by adding
 * their product tokens to EXTRA_CFLAGS in the Configuration file like so.
 *
 * EXTRA_CFLAGS="-DSERVER_SUBVERSION="MrWidget/0.1-alpha"
 *
 * The tokens are listed in order of their significance for identifying the
 * application.
 *
 * "Product tokens should be short and to the point -- use of them for 
 * advertizing or other non-essential information is explicitly forbidden."
 *
 * Example: "Apache/1.1.0 MrWidget/0.1-alpha" 
 */

#define SERVER_BASEVERSION "Apache/1.2b7-dev" /* SEE COMMENTS ABOVE */
#ifdef SERVER_SUBVERSION
#define SERVER_VERSION	SERVER_BASEVERSION " " SERVER_SUBVERSION
#else
#define SERVER_VERSION	SERVER_BASEVERSION
#endif

#define SERVER_PROTOCOL "HTTP/1.1"
#define SERVER_SUPPORT "http://www.apache.org/"

#define DECLINED -1		/* Module declines to handle */
#define OK 0			/* Module has handled this stage. */

/* ----------------------- HTTP Status Codes  ------------------------- */

#define RESPONSE_CODES 38

#define HTTP_CONTINUE                      100
#define HTTP_SWITCHING_PROTOCOLS           101
#define HTTP_OK                            200
#define HTTP_CREATED                       201
#define HTTP_ACCEPTED                      202
#define HTTP_NON_AUTHORITATIVE             203
#define HTTP_NO_CONTENT                    204
#define HTTP_RESET_CONTENT                 205
#define HTTP_PARTIAL_CONTENT               206
#define HTTP_MULTIPLE_CHOICES              300
#define HTTP_MOVED_PERMANENTLY             301
#define HTTP_MOVED_TEMPORARILY             302
#define HTTP_SEE_OTHER                     303
#define HTTP_NOT_MODIFIED                  304
#define HTTP_USE_PROXY                     305
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
#define HTTP_INTERNAL_SERVER_ERROR         500
#define HTTP_NOT_IMPLEMENTED               501
#define HTTP_BAD_GATEWAY                   502
#define HTTP_SERVICE_UNAVAILABLE           503
#define HTTP_GATEWAY_TIME_OUT              504
#define HTTP_VERSION_NOT_SUPPORTED         505
#define HTTP_VARIANT_ALSO_VARIES           506

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

#define is_HTTP_INFO(x)         (((x) >= 100)&&((x) < 200))
#define is_HTTP_SUCCESS(x)      (((x) >= 200)&&((x) < 300))
#define is_HTTP_REDIRECT(x)     (((x) >= 300)&&((x) < 400))
#define is_HTTP_ERROR(x)        (((x) >= 400)&&((x) < 600))
#define is_HTTP_CLIENT_ERROR(x) (((x) >= 400)&&((x) < 500))
#define is_HTTP_SERVER_ERROR(x) (((x) >= 500)&&((x) < 600))


#define METHODS 8
#define M_GET 0
#define M_PUT 1
#define M_POST 2
#define M_DELETE 3
#define M_CONNECT 4
#define M_OPTIONS 5
#define M_TRACE 6
#define M_INVALID 7

#define CGI_MAGIC_TYPE "application/x-httpd-cgi"
#define INCLUDES_MAGIC_TYPE "text/x-server-parsed-html"
#define INCLUDES_MAGIC_TYPE3 "text/x-server-parsed-html3"
#define MAP_FILE_MAGIC_TYPE "application/x-type-map"
#define ASIS_MAGIC_TYPE "httpd/send-as-is"
#define DIR_MAGIC_TYPE "httpd/unix-directory"
#define STATUS_MAGIC_TYPE "application/x-httpd-status"

/* Just in case your linefeed isn't the one the other end is expecting. */
#define LF 10
#define CR 13

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
struct htaccess_result
{
    char *dir;              /* the directory to which this applies */
    int override;           /* the overrides allowed for the .htaccess file */
    void *htaccess;         /* the configuration directives */
/* the next one, or NULL if no more; N.B. never change this */
    const struct htaccess_result *next;
};


typedef struct conn_rec conn_rec;
typedef struct server_rec server_rec;
typedef struct request_rec request_rec;
typedef struct listen_rec listen_rec;

struct request_rec {

  pool *pool;
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
  int proxyreq;                 /* A proxy request */
  int header_only;		/* HEAD request, as opposed to GET */
  char *protocol;		/* Protocol, as given to us, or HTTP/0.9 */
  int proto_num;		/* Number version of protocol; 1.1 = 1001 */
  char *hostname;		/* Host, as set by full URI or Host: */
  int hostlen;			/* Length of http://host:port in full URI */

  time_t request_time;		/* When the request started */

  char *status_line;		/* Status line, if set by script */
  int status;			/* In any case */
  
  /* Request method, two ways; also, protocol, etc..  Outside of protocol.c,
   * look, but don't touch.
   */
  
  char *method;			/* GET, HEAD, POST, etc. */
  int method_number;		/* M_GET, M_POST, etc. */
  int allowed;			/* Allowed methods - for 405, OPTIONS, etc */

  int sent_bodyct;		/* byte count in stream is for body */
  long bytes_sent;		/* body byte count, for easy access */

  /* HTTP/1.1 connection-level features */

  int chunked;			/* sending chunked transfer-coding */
  int byterange;		/* number of byte ranges */
  char *boundary;		/* multipart/byteranges boundary */
  char *range;			/* The Range: header */
  long clength;			/* The "real" content length */

  long remaining;		/* bytes left to read */
  long read_length;		/* bytes that have been read */
  int read_body;   		/* how the request body should be read */
  int read_chunked;		/* reading chunked transfer-coding */

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

  char *content_type;		/* Break these out --- we dispatch on 'em */
  char *handler;		/* What we *really* dispatch on           */

  char *content_encoding;
  char *content_language;	/* for back-compat. only -- do not use */
  array_header *content_languages; /* array of (char*) */
  
  int no_cache;
  int no_local_copy;
  
  /* What object is being requested (either directly, or via include
   * or content-negotiation mapping).
   */

  char *uri;                    /* complete URI for a proxy req, or
                                   URL path for a non-proxy req */
  char *filename;
  char *path_info;
  char *args;			/* QUERY_ARGS, if any */
  struct stat finfo;		/* ST_MODE set to zero if no such file */
  
  /* Various other config info which may change with .htaccess files
   * These are config vectors, with one void* pointer for each module
   * (the thing pointed to being the module's business).
   */
  
  void *per_dir_config;		/* Options set in config files, etc. */
  void *request_config;		/* Notes on *this* request */

/*
 * a linked list of the configuration directives in the .htaccess files
 * accessed by this request.
 * N.B. always add to the head of the list, _never_ to the end.
 * that way, a sub request's list can (temporarily) point to a parent's list
 */
  const struct htaccess_result *htaccess;
};


/* Things which are per connection
 */

struct conn_rec {
  
  pool *pool;
  server_rec *server;
  
  /* Information about the connection itself */

  int child_num;                /* The number of the child handling conn_rec */
  BUFF *client;			/* Connetion to the guy */
  int aborted;			/* Are we still talking? */
  
  /* Who is the client? */
  
  struct sockaddr_in local_addr; /* local address */
  struct sockaddr_in remote_addr;/* remote address */
  char *remote_ip;		/* Client's IP address */
  char *remote_host;		/* Client's DNS name, if known.
                                 * NULL if DNS hasn't been checked,
                                 * "" if it has and no address was found.
                                 * N.B. Only access this though
				 * get_remote_host() */
  char *remote_logname;		/* Only ever set if doing_rfc931
                                 * N.B. Only access this through
				 * get_remote_logname() */
    char *user;			/* If an authentication check was made,
				 * this gets set to the user name.  We assume
				 * that there's only one user per connection(!)
				 */
  char *auth_type;		/* Ditto. */

  int keepalive;		/* Are we using HTTP Keep-Alive? */
  int keptalive;		/* Did we use HTTP Keep-Alive? */
  int keepalives;		/* How many times have we used it? */
};

/* Per-vhost config... */

typedef struct server_addr_rec server_addr_rec;
struct server_addr_rec {
    server_addr_rec *next;
    struct in_addr host_addr;	/* The bound address, for this server */
    short host_port;         	/* The bound port, for this server */   
    char *virthost;		/* The name given in <VirtualHost> */
};


struct server_rec {

    server_rec *next;
  
    /* Full locations of server config info */
  
    char *srm_confname;
    char *access_confname;
  
    /* Contact information */
  
    char *server_admin;
    char *server_hostname;
    short port;                    /* for redirects, etc. */
  
    /* Log files --- note that transfer log is now in the modules... */
  
    char *error_fname;
    FILE *error_log;
  
    /* Module-specific configuration for server, and defaults... */

    int is_virtual;             /* true if this is the virtual server */
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
    int send_buffer_size;       /* size of TCP send buffer (in bytes) */

    char *path;			/* Pathname for ServerPath */
    int pathlen;		/* Length of path */

    char *names;		/* Wildcarded names for ServerAlias servers */

    uid_t server_uid;		/* effective user id when calling exec wrapper */
    gid_t server_gid;		/* effective group id when calling exec wrapper */
};

/* These are more like real hosts than virtual hosts */
struct listen_rec {
    listen_rec *next;
    struct sockaddr_in local_addr; /* local IP address and port */
    int fd;
    int used;	/* Only used during restart */
/* more stuff here, like which protocol is bound to the port */
};

/* Prototypes for utilities... util.c.
 */

/* Time */
extern const char month_snames[12][4];

struct tm *get_gmtoff(int *tz);
char *get_time();
char *ht_time (pool *p, time_t t, const char *fmt, int gmt);     
char *gm_timestr_822(pool *p, time_t t);
     
/* String handling. The *_nc variants allow you to use non-const char **s as
arguments (unfortunately C won't automatically convert a char ** to a const
char **) */     
     
char *getword(pool *p, const char **line, char stop);
char *getword_nc(pool *p, char **line, char stop);
char *getword_white(pool *p, const char **line);
char *getword_white_nc(pool *p, char **line);
char *getword_nulls (pool *p, const char **line, char stop);
char *getword_nulls_nc (pool *p, char **line, char stop);
char *getword_conf (pool *p, const char **line);      
char *getword_conf_nc (pool *p, char **line);      

char *get_token (pool *p, char **accept_line, int accept_white);
int find_token (pool *p, const char *line, const char *tok);
     
int is_url(const char *u);
extern int unescape_url(char *url);
void no2slash(char *name);
void getparents(char *name);
char *escape_path_segment(pool *p, const char *s);
char *os_escape_path(pool *p,const char *path,int partial);
#define escape_uri(ppool,path) os_escape_path(ppool,path,1)
extern char *escape_html(pool *p, const char *s);
char *construct_server(pool *p, const char *hostname, int port);
char *construct_url (pool *p, const char *path, const server_rec *s);     
char *escape_shell_cmd (pool *p, const char *s);
     
int count_dirs(const char *path);
char *make_dirstr(pool *a, const char *s, int n);
char *make_full_path(pool *a, const char *dir, const char *f);
     
int is_matchexp(const char *str);
int strcmp_match(const char *str, const char *exp);
int strcasecmp_match(const char *str, const char *exp);
char *uudecode (pool *, const char *);

char *pregsub(pool *p, const char *input, const char *source,
	      size_t nmatch, regmatch_t pmatch[]);

void str_tolower (char *);
int ind (const char *, char);	/* Sigh... */
int rind (const char *, char);     

int cfg_getline(char *s, int n, FILE *f);
     
/* Misc system hackery */
     
uid_t uname2id(const char *name);
gid_t gname2id(const char *name);
int is_directory(const char *name);
int can_exec(const struct stat *);     
void chdir_file(const char *file);
     
char *get_local_host(pool *);
unsigned long get_virthost_addr (const char *hostname, short int *port);

extern time_t restart_time;
