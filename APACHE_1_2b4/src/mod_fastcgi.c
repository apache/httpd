/* 
 * mod_fastcgi.c --
 *
 *      Apache server module for FastCGI
 *
 *
 *
 *  Copyright (c) 1995-1996 Open Market, Inc.
 *
 *  See the file "LICENSE.TERMS" for information on usage and redistribution
 *  of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 *
 *  Patches for Apache-1.1 provided by
 *  Ralf S. Engelschall
 *  <rse@en.muc.de>
 *
 *  Patches for Linux provided by
 *  Scott Langley
 *  <langles@vote-smart.org>
 */

/*
 * TODO list
 *
 *  * Test cleanup of FastCGI processes more thoroughly.
 *    We still have a problem getting them all killed off
 *    for the config file re-read.  How many processes can
 *    be killed off (reliably) in 3 seconds?  This would
 *    work much better if the process manager had its own
 *    process group.
 *
 *  * On Solaris, the process manager gets killed when you re-link
 *    the server, so you always need to move the executable out of the
 *    build directory before you use it.  Is there any way the process
 *    manager can handle this exception?
 *
 *  * Implement application timeouts.  Request timeouts are done.
 *
 *  * Investigate using more Apache core code for response header
 *    generation, etc.
 *
 *  * Investigate using the optional module mod_env for setting
 *    initial environment variables (suggested by Michael Smith).
 *
 *  * [Major] Support running FastCGI apps without AppClass.
 *    Design notes below.  A side-effect of implementing
 *    this feature is that the module will correctly handle
 *    a DocumentRoot with a slash at the end.
 *
 */

/*
 * Module design notes.
 *
 * 1. Restart cleanup.
 *
 *   mod_fastcgi spawns several processes: one process manager process
 *   and several application processes.  None of these processes
 *   handle SIGHUP, so they just go away when the Web server performs
 *   a restart (as Apache does every time it starts.)
 *
 *   Of course, the Apache parent process survives SIGHUP, so
 *   mod_fastcgi must re-initialize its data structures in that
 *   process on restart.  The mod_fastcgi global variable
 *   'readingConfig' is FALSE initially; it is also set FALSE by
 *   ModuleInit, the module
 *   initialization procedure that runs after the Web server config
 *   has been processed.  In AppClassCmd, if 'readingConfig' is
 *   FALSE, the command frees all data structures and file descriptors
 *   allocated by previous AppClass commands and module initializations.
 *   Then AppClass sets 'readingConfig' to TRUE.
 *
 *   XXX: How does Apache 1.2 implement "gentle" restart
 *   that does not disrupt current connections?  How does
 *   gentle restart interact with restart cleanup?
 *
 * 2. Request timeouts.
 *
 *   The Apache TimeOut directive specifies a timeout not for the entire
 *   request, but a timeout that applies separately to each thing that
 *   might time out.  In the case of CGI:
 *
 *     reading the request from the client
 *     sending the request to a CGI application
 *     reading the response from a CGI application
 *     sending the response to the client.
 *
 *  FastCGI pipelines the I/O (can be sending the response to the
 *  client while still reading the request from the client) so this
 *  model breaks down.  mod_fastcgi applies the timeout to the entire
 *  request.
 *
 *  mod_fastcgi uses the Apache soft_timeout function for its
 *  timeouts.  In case of a timeout, soft_timeout breaks the
 *  client connection by calling shutdown from the signal handler.
 *  This means that subsequent attempts to do client I/O will fail.
 *  mod_fastcgi continues request processing until the FastCGI application
 *  finishes its work, then cleans up the request.  (Shutting down early
 *  would require the FastCGI application to handle SIGPIPE.)
 *
 *  XXX: If the application hangs after reading all input and producing
 *  no output, you need to time out the application.  That's not
 *  currently implemented for the lack of a clean way to get the timeout
 *  information.
 *
 * 3. On-demand FastCGI apps (future)
 *
 *  First, change the naming scheme for the Unix-domain sockets.  Name
 *  a socket using the MD5 hash of the "canonical" path name of the
 *  executable.  The canonical path name of the executable is the
 *  pathname with "//", ".", "..", and symlinks removed.
 *
 *  The effect of this change is that the process manager
 *  has no need to communicate with its children, other than
 *  implicitly by starting application processes.
 *
 *  A channel of communcation from the children to the process manager is
 *  still required.  It will be adequate to use a file with POSIX file
 *  locking.  A mapped file might improve performance slightly,
 *  but this communication is not part of the fast path.  Call
 *  this file the mbox.
 *
 *  To communicate, a child
 *      locks mbox, appends a record, unlocks mbox
 *      signals the process manager with SIGUSR1 if the child needs
 *       immediate attention
 *
 *  The process manager
 *      locks mbox, copies content, truncates mbox, unlocks mbox
 *      processes copied content
 *  It does this in response to SIGUSR1 or every N seconds
 *
 *  The ASCII records a child places in mbox are:
 *      Please-start <exec-path>
 *      Conn-failed  <sock-name>
 *      Conn-timeout <sock-name> <seconds>
 *      Req-complete <sock-name> <queued-time> <connected-time>
 *  The opcodes ("Please-start", etc.) can be represented as single
 *  characters.  A <sock-name> is 22 Ascii characters (16 * (8/6)).
 *  Records are newline-terminated.
 *
 *  The child sends Please-start because no socket exists: the very
 *   first request for an application.
 *  The child sends Conn-failed because the socket exists but
 *   connect failed: the app needs to be restarted.
 *   (It might have been killed off for lack of activity.)
 *  The child sends Conn-timeout because the socket exists but
 *   connect is not completing quickly enough: Perhaps another
 *   process should be started.
 *  The child sends Req-complete at the end of each request, to let
 *   the process manager know how the application is performing.
 *   The child does not signal SIGUSR1 since it needs no immediate
 *   response from the process manager.
 *
 *  It is far from clear how to implement an effective set of policies
 *  to manage the on-demand apps.  Some parameters that might
 *  turn out to be useful:
 *      Limit number of app processes per on-demand app
 *      Limit total number of app processes used for on-demand apps
 *      How long a child waits to connect to an app process before
 *       sending Conn-timeout to the process manager
 *      How long a child waits to connect to an app process before
 *       giving up and returning SERVER_ERROR
 *      How often the process manager wakes up to process
 *       Req-complete records.
 *      App idle time before killing an app process
 *  These could be set via a new configuration directive.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>

#ifdef __EMX__
/* If this value is changed. Make sure you also change it in conf.h */
#define MAXSOCKETS 4096
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <signal.h>
/*
 * Apache header files
 */
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"
#include "http_conf_globals.h"

#define TRUE 1
#define FALSE 0
#define ASSERT assert
#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))

static void *Malloc(size_t size)
{
    void *result = malloc(size);
    ASSERT(size == 0 || result != NULL);
    memset(result, 0, size);
    return result;
}

static void Free(void *ptr)
{
    if(ptr != NULL) {
        free(ptr);
    }
}

/*-----------------------Include fastcgi.h definitions ----------*/

/*
 * Listening socket file number
 */
#define FCGI_LISTENSOCK_FILENO 0

/*
 * Value for version component of FCGI_Header
 */
#define FCGI_VERSION_1           1

/*
 * FastCGI protocol version.
 */
#define FCGI_VERSION   FCGI_VERSION_1
/*
 * Values for type component of FCGI_Header
 */
#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)

/*
 * The length of the FastCGI packet header.
 */
#define FCGI_HEADER_LEN 8

#define FCGI_MAX_LENGTH 0xffff


/*
 * This structure defines the layout of FastCGI packet headers.  ANSI C
 * compilers will guarantee the linear layout of this structure.
 */
typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} FCGI_Header;


/*
 * Value for requestId component of FCGI_Header
 */
#define FCGI_NULL_REQUEST_ID     0


typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGI_BeginRequestBody;

typedef struct {
    FCGI_Header header;
    FCGI_BeginRequestBody body;
} FCGI_BeginRequestRecord;

/*
 * Mask for flags component of FCGI_BeginRequestBody
 */
#define FCGI_KEEP_CONN  1

/*
 * Values for role component of FCGI_BeginRequestBody
 */
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3


typedef struct {
    unsigned char appStatusB3;
    unsigned char appStatusB2;
    unsigned char appStatusB1;
    unsigned char appStatusB0;
    unsigned char protocolStatus;
    unsigned char reserved[3];
} FCGI_EndRequestBody;

typedef struct {
    FCGI_Header header;
    FCGI_EndRequestBody body;
} FCGI_EndRequestRecord;

/*
 * Values for protocolStatus component of FCGI_EndRequestBody
 */
#define FCGI_REQUEST_COMPLETE 0
#define FCGI_CANT_MPX_CONN    1
#define FCGI_OVERLOADED       2
#define FCGI_UNKNOWN_ROLE     3


/*
 * Variable names for FCGI_GET_VALUES / FCGI_GET_VALUES_RESULT records
 */
#define FCGI_MAX_CONNS  "FCGI_MAX_CONNS"
#define FCGI_MAX_REQS   "FCGI_MAX_REQS"
#define FCGI_MPXS_CONNS "FCGI_MPXS_CONNS"


typedef struct {
    unsigned char type;    
    unsigned char reserved[7];
} FCGI_UnknownTypeBody;

typedef struct {
    FCGI_Header header;
    FCGI_UnknownTypeBody body;
} FCGI_UnknownTypeRecord;

/*--------------Include Tcl dynamic string definitions-----------*/

/*
 *  Copyright (c) 1987-1994 The Regents of the University of California.
 *  Copyright (c) 1994-1995 Sun Microsystems, Inc.
 *
 * This software is copyrighted by the Regents of the University of
 * California, Sun Microsystems, Inc., and other parties.  The following
 * terms apply to all files associated with the software unless explicitly
 * disclaimed in individual files.
 *
 * The authors hereby grant permission to use, copy, modify, distribute,
 * and license this software and its documentation for any purpose, provided
 * that existing copyright notices are retained in all copies and that this
 * notice is included verbatim in any distributions. No written agreement,
 * license, or royalty fee is required for any of the authorized uses.
 * Modifications to this software may be copyrighted by their authors
 * and need not follow the licensing terms described here, provided that
 * the new terms are clearly indicated on the first page of each file where
 * they apply.
 * 
 * IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY
 * FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE, ITS DOCUMENTATION, OR ANY
 * DERIVATIVES THEREOF, EVEN IF THE AUTHORS HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.  THIS SOFTWARE
 * IS PROVIDED ON AN "AS IS" BASIS, AND THE AUTHORS AND DISTRIBUTORS HAVE
 * NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 * 
 * RESTRICTED RIGHTS: Use, duplication or disclosure by the government
 * is subject to the restrictions as set forth in subparagraph (c) (1) (ii)
 * of the Rights in Technical Data and Computer Software Clause as DFARS
 * 252.227-7013 and FAR 52.227-19.
 *
 */

/*
 *  Tcl has a nice dynamic string library, but we want to insulate ourselves
 *  from the library names (we might not always be linked with Tcl, and we
 *  may want to implement our own dynamic string library in the future.)
 */
/*
 * The structure defined below is used to hold dynamic strings.  The only
 * field that clients should use is the string field, and they should
 * never modify it.
 */

#define TCL_DSTRING_STATIC_SIZE 200
typedef struct Tcl_DString {
    char *string;               /* Points to beginning of string:  either
                                 * staticSpace below or a malloc'ed array. */
    int length;                 /* Number of non-NULL characters in the
                                 * string. */
    int spaceAvl;               /* Total number of bytes available for the
                                 * string and its terminating NULL char. */
    char staticSpace[TCL_DSTRING_STATIC_SIZE];
                                /* Space to use in common case where string
                                 * is small. */
} Tcl_DString;

#define Tcl_DStringLength(dsPtr) ((dsPtr)->length)
#define Tcl_DStringValue(dsPtr) ((dsPtr)->string)
#define Tcl_DStringTrunc Tcl_DStringSetLength


#define DString                 Tcl_DString
#define DStringAppend           Tcl_DStringAppend
#define DStringTrunc            Tcl_DStringSetLength
#define DStringValue            Tcl_DStringValue
#define DStringFree             Tcl_DStringFree
#define DStringLength           Tcl_DStringLength
#define DStringInit             Tcl_DStringInit
#define DStringAppendElement    Tcl_DStringAppendElement
#define DStringStartSublist     Tcl_DStringStartSublist
#define DStringEndSublist       Tcl_DStringEndSublist

/*-----------------------Include buffer.h definitions -----------*/

/*
 * This structure implements ring buffers, used to buffer data between
 * various processes and connections in the server.
 */
typedef struct Buffer {
    int size;               /* size of entire buffer */
    int length;             /* number of bytes in current buffer */
    char *begin;            /* begining of valid data */
    char *end;              /* end of valid data */
    char data[1];           /* buffer data */
} Buffer;

/*
 * Size of the ring buffers used to read/write the FastCGI application server.
 */
#define SERVER_BUFSIZE      8192
#define BufferLength(b)     ((b)->length)
#define BufferFree(b)       ((b)->size - (b)->length)
#define BufferSize(b)       ((b)->size)

/*--------------Include Tcl dynamic string library---------------*/

/*
 *----------------------------------------------------------------------
 *
 * Tcl_DStringInit --
 *
 *      Initializes a dynamic string, discarding any previous contents
 *      of the string (Tcl_DStringFree should have been called already
 *      if the dynamic string was previously in use).
 * Input: dsptr 
 *              Pointer to structure for dynamic string. 
 * 
 * Results:
 *      None.
 *
 * Side effects:
 *      The dynamic string is initialized to be empty.
 *
 *----------------------------------------------------------------------
 */

void
Tcl_DStringInit(Tcl_DString *dsPtr)

{
    dsPtr->string = dsPtr->staticSpace;
    dsPtr->length = 0;
    dsPtr->spaceAvl = TCL_DSTRING_STATIC_SIZE;
    dsPtr->staticSpace[0] = 0;
}

/*
 *----------------------------------------------------------------------
 *
 * Tcl_DStringAppend --
 *
 *      Append more characters to the current value of a dynamic string.
 * Input
 *   Tcl_DString *dsPtr;        Structure describing dynamic
 *                              string.
 *   char *string;               String to append.  If length is
 *                               -1 then this must be
 *                               null-terminated.
 *   int length;                 Number of characters from string
 *                              to append.  If < 0, then append all
 *                               of string, up to null at end.
 *
 *
 * Results:
 *      The return value is a pointer to the dynamic string's new value.
 *
 * Side effects:
 *      Length bytes from string (or all of string if length is less
 *      than zero) are added to the current value of the string.  Memory
 *      gets reallocated if needed to accomodate the string's new size.
 *
 *----------------------------------------------------------------------
 */

char *
Tcl_DStringAppend(Tcl_DString *dsPtr, char *string, int length)
{
    int newSize;
    char *newString, *dst, *end;

    if (length < 0) {
        length = strlen(string);
    }
    newSize = length + dsPtr->length;

    /*
     * Allocate a larger buffer for the string if the current one isn't
     * large enough.  Allocate extra space in the new buffer so that there
     * will be room to grow before we have to allocate again.
     */

    if (newSize >= dsPtr->spaceAvl) {
        dsPtr->spaceAvl = newSize*2;
        newString = (char *) Malloc((unsigned) dsPtr->spaceAvl);
        memcpy((void *)newString, (void *) dsPtr->string,
                (size_t) dsPtr->length);
        if (dsPtr->string != dsPtr->staticSpace) {
            free(dsPtr->string);
        }
        dsPtr->string = newString;
    }

    /*
     * Copy the new string into the buffer at the end of the old
     * one.
     */

    for (dst = dsPtr->string + dsPtr->length, end = string+length;
            string < end; string++, dst++) {
        *dst = *string;
    }
    *dst = 0;
    dsPtr->length += length;
    return dsPtr->string;
}

/*
 *----------------------------------------------------------------------
 *
 * Tcl_DStringSetLength --
 *
 *      Change the length of a dynamic string.  This can cause the
 *      string to either grow or shrink, depending on the value of
 *      length.
 * Input:
 *      Tcl_DString *dsPtr;     Structure describing dynamic string
 *      int length;             New length for dynamic string.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      The length of dsPtr is changed to length and a null byte is
 *      stored at that position in the string.  If length is larger
 *      than the space allocated for dsPtr, then a panic occurs.
 *
 *----------------------------------------------------------------------
 */

void
Tcl_DStringSetLength(Tcl_DString *dsPtr, int length)
{
    if (length < 0) {
        length = 0;
    }
    if (length >= dsPtr->spaceAvl) {
        char *newString;

        dsPtr->spaceAvl = length+1;
        newString = (char *) Malloc((unsigned) dsPtr->spaceAvl);

        /*
         * SPECIAL NOTE: must use memcpy, not strcpy, to copy the string
         * to a larger buffer, since there may be embedded NULLs in the
         * string in some cases.
         */

        memcpy((void *) newString, (void *) dsPtr->string,
                (size_t) dsPtr->length);
        if (dsPtr->string != dsPtr->staticSpace) {
            free(dsPtr->string);
        }
        dsPtr->string = newString;
    }
    dsPtr->length = length;
    dsPtr->string[length] = 0;
}

/*
 *----------------------------------------------------------------------
 *
 * Tcl_DStringFree --
 *
 *      Frees up any memory allocated for the dynamic string and
 *      reinitializes the string to an empty state.
 * Input:
 *     Tcl_DString *dsPtr;      Structure describing dynamic string
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      The previous contents of the dynamic string are lost, and
 *      the new value is an empty string.
 *
 *----------------------------------------------------------------------
 */

void
Tcl_DStringFree(Tcl_DString *dsPtr)
{
    if (dsPtr->string != dsPtr->staticSpace) {
        free(dsPtr->string);
    }
    dsPtr->string = dsPtr->staticSpace;
    dsPtr->length = 0;
    dsPtr->spaceAvl = TCL_DSTRING_STATIC_SIZE;
    dsPtr->staticSpace[0] = 0;
}

/*--------------Include OS library-------------------------------*/

int OS_Bind(unsigned int sock, struct sockaddr *addr, int namelen)
{
    return(bind(sock, addr, namelen));
}

int OS_Listen(unsigned int sock, int backlog)
{
    return(listen(sock, backlog));
}

int OS_Socket(int addr_family, int type, int protocol)
{
    return (socket(addr_family, type, protocol));
}

int OS_Close(int fd)
{
    return close(fd);
}

int OS_Dup2(int oldd,int newd)
{
    int fd;

    fd = dup2(oldd, newd);
    return fd;
}

int OS_Read(int fd, void *buf, size_t numBytes)
{
    int result;

    while (1) {
        result = read(fd, buf, (size_t) numBytes);
        if ((result != -1) || (errno != EINTR)) {
            return result;
        }
    }
}

int OS_Write(int fd, void *buf, size_t numBytes)
{
    int result;

    while (1) {
        result = write(fd, buf, (size_t) numBytes);
        if ((result != -1) || (errno != EINTR)) {
            return result;
        }
    }
}

/*
 *----------------------------------------------------------------------
 *
 * OS_Signal --
 *
 *      Reliable implementation of the Posix signal function
 *      Makes no attempt either to restart or to prevent restart
 *      of system calls.
 *
 *----------------------------------------------------------------------
 */
typedef void Sigfunc(int);

Sigfunc *OS_Signal(int signo, Sigfunc *func)
{
    struct sigaction act, oact;
    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if(sigaction(signo, &act, &oact) < 0) {
        return(SIG_ERR);
    }
    return oact.sa_handler;
}

/*
 * XXX: why is this defined as void * not OS_IpcAddr * ?
 */
typedef void *OS_IpcAddress;

typedef struct _OS_IpcAddr {
    DString bindPath;              /* Path used for the socket bind point */
    struct sockaddr *serverAddr;   /* server address (for connect) */
    int addrLen;                   /* length of server address (for connect) */
} OS_IpcAddr;


/*
 *----------------------------------------------------------------------
 *
 * OS_InitIpcAddr --
 *
 *      Allocate and initialize an OS-specific IPC address structure.
 *
 * Results:
 *      IPC Address is initialized.
 *
 * Side effects:  
 *      Memory allocated.
 *
 *----------------------------------------------------------------------
 */  
OS_IpcAddress OS_InitIpcAddr(void)
{
    OS_IpcAddr *ipcAddrPtr = (OS_IpcAddr *)Malloc(sizeof(OS_IpcAddr));
    DStringInit(&ipcAddrPtr->bindPath);
    ipcAddrPtr->serverAddr = NULL;
    ipcAddrPtr->addrLen = 0;
    return (OS_IpcAddress)ipcAddrPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * OS_BuildSockAddrUn --
 *
 *      Using the pathname bindPath, fill in the sockaddr_un structure
 *      *servAddrPtr and the length of this structure *servAddrLen.
 *
 *      The format of the sockaddr_un structure changed incompatibly in
 *      4.3BSD Reno.
 *
 * Results:
 *      0 for normal return, -1 for failure (bindPath too long).
 *
 *----------------------------------------------------------------------
 */

static int OS_BuildSockAddrUn(char *bindPath,
                              struct sockaddr_un *servAddrPtr,
                              int *servAddrLen)
{
    int bindPathLen = strlen(bindPath);

#ifdef HAVE_SOCKADDR_UN_SUN_LEN /* 4.3BSD Reno and later: BSDI */
    if(bindPathLen >= sizeof(servAddrPtr->sun_path))
        return -1;
#else                           /* 4.3 BSD Tahoe: Solaris, HPUX, DEC, ... */
    if(bindPathLen > sizeof(servAddrPtr->sun_path))
        return -1;
#endif
    memset((char *) servAddrPtr, 0, sizeof(*servAddrPtr));
    servAddrPtr->sun_family = AF_UNIX;
    memcpy(servAddrPtr->sun_path, bindPath, bindPathLen);
#ifdef HAVE_SOCKADDR_UN_SUN_LEN /* 4.3BSD Reno and later: BSDI */
    *servAddrLen = sizeof(servAddrPtr->sun_len)
            + sizeof(servAddrPtr->sun_family)
            + bindPathLen + 1;
    servAddrPtr->sun_len = *servAddrLen;
#else                           /* 4.3 BSD Tahoe: Solaris, HPUX, DEC, ... */
    *servAddrLen = sizeof(servAddrPtr->sun_family) + bindPathLen;
#endif
    return 0;
}

/*
 *----------------------------------------------------------------------
 *
 * OS_CreateLocalIpcFd --
 *
 *   This procedure is responsible for creating the listener socket
 *   on Unix for local process communication.  It will create a Unix
 *   domain socket, bind it, and return a file descriptor to it to the
 *   caller.
 *
 * Results:
 *      Listener socket created.  This call returns either a valid
 *      file descriptor or -1 on error.
 *
 *----------------------------------------------------------------------
 */
typedef char *MakeSocketNameProc(Tcl_DString *dsPtr);

int OS_CreateLocalIpcFd(OS_IpcAddress ipcAddress, int listenQueueDepth,
        uid_t uid, gid_t gid, MakeSocketNameProc makeSocketName)
{
    OS_IpcAddr *ipcAddrPtr = (OS_IpcAddr *)ipcAddress;
    char bindPathExt[32];
    struct sockaddr_un *addrPtr = NULL;
    int listenSock = -1;

    makeSocketName(&ipcAddrPtr->bindPath);
    /*
     * Build the domain socket address.
     */
    addrPtr = (struct sockaddr_un *) Malloc(sizeof(struct sockaddr_un));
    ipcAddrPtr->serverAddr = (struct sockaddr *) addrPtr;

    if (OS_BuildSockAddrUn(DStringValue(&ipcAddrPtr->bindPath), addrPtr,
                           &ipcAddrPtr->addrLen)) {
        goto GET_IPC_ERROR_EXIT;
    }

    /*
     * Create the listening socket to be used by the fcgi server.
     */
    if((listenSock = OS_Socket(ipcAddrPtr->serverAddr->sa_family,
                               SOCK_STREAM, 0)) < 0) {
        goto GET_IPC_ERROR_EXIT;
    }

    /*
     * Bind the listening socket and set it to listen.
     */
    if(OS_Bind(listenSock, ipcAddrPtr->serverAddr, ipcAddrPtr->addrLen) < 0
       || OS_Listen(listenSock, listenQueueDepth) < 0) {
        goto GET_IPC_ERROR_EXIT;
    }
#ifndef __EMX__
    /* OS/2 dosen't support changing ownership. */
    chown(DStringValue(&ipcAddrPtr->bindPath), uid, gid);
#endif    
    chmod(DStringValue(&ipcAddrPtr->bindPath), S_IRUSR | S_IWUSR);
    return listenSock;

GET_IPC_ERROR_EXIT:
    if(listenSock != -1)
        OS_Close(listenSock);
    if(addrPtr != NULL) {
        free(addrPtr);
        ipcAddrPtr->serverAddr = NULL;
    }
    return -1;
}

/*
 *----------------------------------------------------------------------
 *
 * OS_FreeIpcAddr --
 *
 *      Free up and clean up an OS IPC address.
 *
 * Results:
 *      IPC Address is freed.
 *
 * Side effects:  
 *      More memory.
 *
 *----------------------------------------------------------------------
 */  
void OS_FreeIpcAddr(OS_IpcAddress ipcAddress)
{
    OS_IpcAddr *ipcAddrPtr = (OS_IpcAddr *)ipcAddress;
    
    DStringFree(&ipcAddrPtr->bindPath); 
    Free(ipcAddrPtr->serverAddr);
    ipcAddrPtr->addrLen = 0;
    Free(ipcAddrPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * OS_CleanupFcgiProgram --
 *
 *      Perform OS cleanup on a server managed process.
 *      XXX: odd name, really more like inverse of OS_CreateLocalIpcFd
 *
 * Results:
 *      None.
 *
 * Side effects:  
 *      Domain socket bindPath is unlinked.
 *
 *----------------------------------------------------------------------
 */  
void OS_CleanupFcgiProgram(OS_IpcAddress ipcAddress)
{
    OS_IpcAddr *ipcAddrPtr = (OS_IpcAddr *)ipcAddress;
    unlink(DStringValue(&ipcAddrPtr->bindPath));
}

/* XXX: where does this number come from? */
#define ht_openmax (128)

/*
 *----------------------------------------------------------------------
 *
 * OS_ExecFcgiProgram --
 *
 *      Fork and exec the specified fcgi process.
 *
 * Results:
 *      0 for successful fork, -1 for failed fork.
 *      Child process exits in case of failure, with exit
 *      status = errno of failed system call.
 *
 * Side effects:  
 *      Child process created.
 *
 *----------------------------------------------------------------------
 */
static int OS_ExecFcgiProgram(pid_t *childPid, int listenFd, int priority,
        char *programName, char **envPtr)
{
    int i;
    DString dirName;
    char *dnEnd;
    /*
     * Fork the fcgi process.
     */
    *childPid = fork();
    if(*childPid < 0) {
        return -1;
    } else if(*childPid != 0) {
        return 0;
    }
    /*
     * We're the child; no return.
     */
    if(!geteuid() && setuid(user_id) == -1) {
        exit(errno);
    }
    if(listenFd != FCGI_LISTENSOCK_FILENO) {
        OS_Dup2(listenFd, FCGI_LISTENSOCK_FILENO);
        OS_Close(listenFd);
    }
    DStringInit(&dirName);
    dnEnd = strrchr(programName, '/');
    if(dnEnd == NULL) {
        DStringAppend(&dirName, "./", 1);
    } else {
        DStringAppend(&dirName, programName, dnEnd - programName);
    }
    if(chdir(DStringValue(&dirName)) < 0) {
        exit(errno);
    }
    DStringFree(&dirName);
#ifndef __EMX__    
    /* OS/2 dosen't support nice() */
    if(priority != 0) {
        if(nice (priority) == -1) {
            exit(errno);
        }
    }
#endif    
    /*
     * Close any file descriptors we may have gotten from the parent
     * process.  The only FD left open is the FCGI listener socket.
     */
    for(i=0; i < ht_openmax; i++) {
        if(i != FCGI_LISTENSOCK_FILENO)
            OS_Close(i);
    }
    if(envPtr != NULL) {
        execle(programName, programName, NULL, envPtr);
    } else {
        execl(programName, programName, NULL);
    }
    /*
     * exec failed
     */
    exit(errno);
}

/*
 *----------------------------------------------------------------------
 * OS_Environ*
 *
 *      Allocate, fill in, and free a conventional environ structure
 *
 *----------------------------------------------------------------------
 */

static char **OS_EnvironInit(int envCount)
{
    return Malloc(sizeof(char *) * envCount);
}

static void OS_EnvString(char **envPtr, char *name, char *value)
{
    char *buf;
    ASSERT(name != NULL && value != NULL);
    buf = Malloc(strlen(name) + strlen(value) + 2);
    sprintf(buf, "%s=%s", name, value);
    ASSERT(*envPtr == NULL);
    *envPtr = buf;
}

static void OS_EnvironFree(char **envHead)
{
    char **envPtr = envHead;
    while(*envPtr != NULL) {
        Free(*envPtr);
        envPtr++;
  }
  Free(envHead);
}

/*
 *----------------------------------------------------------------------
 *
 * WS_Access --
 *
 *	Determine if a user with the specified user and group id
 *	will be able to access the specified file.  This routine depends
 *	on being called with enough permission to stat the file
 *	(e.g. root).
 *
 *	'mode' is the bitwise or of R_OK, W_OK, or X_OK.
 *
 *	This call is similar to the POSIX access() call, with extra
 *	options for specifying the user and group ID to use for 
 *	checking.
 *
 * Results:
 *      -1 if no access or error accessing, 0 otherwise.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */
#define WS_SET_errno(x) errno = x
int WS_Access(const char *path, int mode, uid_t uid, gid_t gid)
{
    struct stat statBuf;
    char **names;
    struct group *grp;
    struct passwd *usr;

    if(stat(path, &statBuf) < 0)
	return -1;

    /*
     * If the user owns this file, check the owner bits.
     */
    if(uid == statBuf.st_uid) {
	WS_SET_errno(EACCES);
	if((mode & R_OK) && !(statBuf.st_mode & S_IRUSR))
	    goto no_access;

	if((mode & W_OK) && !(statBuf.st_mode & S_IWUSR))
	    goto no_access;

	if((mode & X_OK) && !(statBuf.st_mode & S_IXUSR))
	    goto no_access;

	return 0;	
    }

    /*
     * If the user's group owns this file, check the group bits.
     */
    if(gid == statBuf.st_gid) {
	WS_SET_errno(EACCES);
	if((mode & R_OK) && !(statBuf.st_mode & S_IRGRP))
	    goto no_access;

	if((mode & W_OK) && !(statBuf.st_mode & S_IWGRP))
	    goto no_access;

	if((mode & X_OK) && !(statBuf.st_mode & S_IXGRP))
	    goto no_access;

	return 0;	
    }

    /*
     * Get the group information for the file group owner.  If the
     * user is a member of that group, apply the group permissions.
     */
    grp = getgrgid(statBuf.st_gid);
    if(grp == NULL)
	return -1;

    usr = getpwuid(uid);
    if(usr == NULL)
	return -1;

    for(names = grp->gr_mem; *names != NULL; names++) {
	if(!strcmp(*names, usr->pw_name)) {
	    WS_SET_errno(EACCES);
	    if((mode & R_OK) && !(statBuf.st_mode & S_IRGRP))
		goto no_access;

	    if((mode & W_OK) && !(statBuf.st_mode & S_IWGRP))
		goto no_access;

	    if((mode & X_OK) && !(statBuf.st_mode & S_IXGRP))
		goto no_access;

	    return 0;
        }
    }

    /*
     * If no matching user or group information, use 'other'
     * access information.  
     */
    if((mode & R_OK) && !(statBuf.st_mode & S_IROTH))
	goto no_access;

    if((mode & W_OK) && !(statBuf.st_mode & S_IWOTH))
	goto no_access;

    if((mode & X_OK) && !(statBuf.st_mode & S_IXOTH))
	goto no_access;

    return 0;

no_access:
    WS_SET_errno(EACCES);
    return -1;
}

/*--------------Include buffer library---------------------------*/

/*
 *----------------------------------------------------------------------
 *
 * BufferCheck --
 *
 *      Checks buffer for consistency with a set of assertions.
 *
 *      If assert() is a no-op, this routine should be optimized away
 *      in most C compilers.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
void BufferCheck(Buffer *bufPtr)
{
    ASSERT(bufPtr->size > 0);
    ASSERT(bufPtr->length >= 0);
    ASSERT(bufPtr->length <= bufPtr->size);

    ASSERT(bufPtr->begin >= bufPtr->data);
    ASSERT(bufPtr->begin < bufPtr->data + bufPtr->size);
    ASSERT(bufPtr->end >= bufPtr->data);
    ASSERT(bufPtr->end < bufPtr->data + bufPtr->size);

    ASSERT(((bufPtr->end - bufPtr->begin + bufPtr->size) % bufPtr->size) 
            == (bufPtr->length % bufPtr->size));
}

/*
 *----------------------------------------------------------------------
 *
 * BufferReset --
 *
 *      Reset a buffer, losing any data that's in it.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
void BufferReset(Buffer *bufPtr)
{
    bufPtr->length = 0;
    bufPtr->begin = bufPtr->end = bufPtr->data;
}

/*
 *----------------------------------------------------------------------
 *
 * BufferCreate --
 *
 *      Allocate an intialize a new buffer of the specified size.
 *
 * Results:
 *      Pointer to newly allocated buffer.
 *
 * Side effects:
 *      None.                     
 *
 *----------------------------------------------------------------------
 */
Buffer *BufferCreate(int size)
{
    Buffer *bufPtr;

    bufPtr = (Buffer *)Malloc(sizeof(Buffer) + size);
    bufPtr->size = size;
    BufferReset(bufPtr);
    return bufPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * BufferDelete --
 *
 *      Delete a buffer, freeing up any associated storage.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
void BufferDelete(Buffer *bufPtr)
{
    BufferCheck(bufPtr);
    free(bufPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferRead --
 *
 *      Read bytes from an open file descriptor into a buffer.
 *
 * Results:
 *      Returns number of bytes read.
 *
 * Side effects:
 *      Data stored in buffer.
 *
 *----------------------------------------------------------------------
 */
int BufferRead(Buffer *bufPtr, int fd)
{
    int len;

    BufferCheck(bufPtr);
    len = min(bufPtr->size - bufPtr->length, 
            bufPtr->data + bufPtr->size - bufPtr->end);

    if (len > 0) {
        OS_Signal(SIGPIPE, SIG_IGN);
        len = OS_Read(fd, bufPtr->end, len);
        if(len > 0) {
            bufPtr->end += len;
            if(bufPtr->end >= (bufPtr->data + bufPtr->size))
                bufPtr->end -= bufPtr->size;
            bufPtr->length += len;
        }
    }
    return len;
}

/*
 *----------------------------------------------------------------------
 *
 * BufferWrite --
 *
 *      Write any bytes from the buffer to a file descriptor open for
 *      writing.
 *
 * Results:
 *      Returns number of bytes written.
 *
 * Side effects:
 *      Data "removed" from buffer.
 *
 *----------------------------------------------------------------------
 */

/*
 * XXX: Why did Trung find it necessary to limit the length of writes to
 * the FastCGI application?  This looks like a misunderstanding.
 */
#define MAX_WRITE 4000

int BufferWrite(Buffer *bufPtr, int fd)
{
    int len;

    ASSERT(fd >= 0);
    BufferCheck(bufPtr);
    len = min(bufPtr->length, bufPtr->data + bufPtr->size - bufPtr->begin);

    if(len > MAX_WRITE) {
      len = MAX_WRITE;
    }
    if(len > 0) {
        len = OS_Write(fd, bufPtr->begin, len);
        if(len > 0) {
            bufPtr->begin += len;
            if(bufPtr->begin >= (bufPtr->data + bufPtr->size))
                bufPtr->begin -= bufPtr->size;
            bufPtr->length -= len;
        }
    }
    return len;
}

/*
 *----------------------------------------------------------------------
 *
 * BufferPeekToss --
 *
 *      Return (via pointer parameters) a pointer to the first occupied
 *      byte in the buffer, and a count of the number of sequential
 *      occupied bytes starting with that byte.  The caller can access
 *      these bytes as long as BufferWrite, BufferToss, etc are not
 *      called.
 *
 * Results:
 *      *beginPtr (first occupied byte) and *countPtr (byte count).
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
void BufferPeekToss(Buffer *bufPtr, char **beginPtr, int *countPtr)
{
    BufferCheck(bufPtr);
    *beginPtr = bufPtr->begin;
    *countPtr = min(bufPtr->length,
                    bufPtr->data + bufPtr->size - bufPtr->begin);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferToss --
 *
 *      Throw away the specified number of bytes from a buffer, as if
 *      they had been written out.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Data "removed" from the buffer.
 *
 *----------------------------------------------------------------------
 */
void BufferToss(Buffer *bufPtr, int count)
{
    BufferCheck(bufPtr);
    ASSERT(count >= 0 && count <= bufPtr->length);

    bufPtr->length -= count;
    bufPtr->begin += count;
    if(bufPtr->begin >= bufPtr->data + bufPtr->size)
        bufPtr->begin -= bufPtr->size;
}

/*
 *----------------------------------------------------------------------
 *
 * BufferPeekExpand --
 *
 *      Return (via pointer parameters) a pointer to the first free byte
 *      in the buffer, and a count of the number of sequential free bytes
 *      available starting with that byte.  The caller can write
 *      these bytes as long as BufferRead, BufferExpand, etc are
 *      not called.
 *
 * Results:
 *      *endPtr (first free byte) and *countPtr (byte count).
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
void BufferPeekExpand(Buffer *bufPtr, char **endPtr, int *countPtr)
{
    BufferCheck(bufPtr);
    *endPtr = bufPtr->end;
    *countPtr = min(bufPtr->size - bufPtr->length, 
                    bufPtr->data + bufPtr->size - bufPtr->end);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferExpand --
 *
 *      Expands the buffer by the specified number of bytes.  Assumes that
 *      the caller has added the data to the buffer.  This is typically
 *      used after a BufferAsyncRead() call completes, to update the buffer
 *      size with the number of bytes read.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Data "added" to the buffer.
 *
 *----------------------------------------------------------------------
 */
void BufferExpand(Buffer *bufPtr, int count)
{
    BufferCheck(bufPtr);
    ASSERT(count >= 0 && count <= BufferFree(bufPtr));

    bufPtr->length += count;
    bufPtr->end += count;
    if(bufPtr->end >= bufPtr->data + bufPtr->size)
        bufPtr->end -= bufPtr->size;

    BufferCheck(bufPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferAddData --
 *
 *      Adds data to a buffer, returning the number of bytes added.
 *
 * Results:
 *      Number of bytes added to the buffer.
 *
 * Side effects:
 *      Characters added to the buffer.
 *
 *----------------------------------------------------------------------
 */
int BufferAddData(Buffer *bufPtr, char *data, int datalen)
{
    char *end;
    int copied = 0;     /* Number of bytes actually copied. */
    int canCopy;                /* Number of bytes to copy in a given op. */

    ASSERT(data != NULL);
    if(datalen == 0)
        return 0;

    ASSERT(datalen > 0);

    BufferCheck(bufPtr);
    end = bufPtr->data + bufPtr->size;

    /*
     * Copy the first part of the data:  from here to the end of the
     * buffer, or the end of the data, whichever comes first.
     */
    datalen = min(BufferFree(bufPtr), datalen);
    canCopy = min(datalen, end - bufPtr->end);
    memcpy(bufPtr->end, data, canCopy);
    bufPtr->length += canCopy;
    bufPtr->end += canCopy;
    copied += canCopy;
    if (bufPtr->end >= end)
        bufPtr->end = bufPtr->data;
    datalen -= canCopy;

    /*
     * If there's more to go, copy the second part starting from the
     * beginning of the buffer.
     */
    if (datalen > 0) {
        data += canCopy;
        memcpy(bufPtr->end, data, datalen);
        bufPtr->length += datalen;
        bufPtr->end += datalen;
        copied += datalen;
    }
    return(copied);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferAdd --
 *
 *      Adds a string into a buffer, returning the number of bytes added.
 *
 * Results:
 *      Number of bytes added to the buffer.
 *
 * Side effects:
 *      Characters added to the buffer.
 *
 *----------------------------------------------------------------------
 */
int BufferAdd(Buffer *bufPtr, char *str)
{
    return BufferAddData(bufPtr, str, strlen(str));
}

/*
 *----------------------------------------------------------------------
 *
 * BufferGetData --
 *
 *      Gets data from a buffer, returning the number of bytes copied.
 *
 * Results:
 *      Number of bytes copied from the buffer.
 *
 * Side effects:
 *      Updates the buffer pointer.
 *
 *----------------------------------------------------------------------
 */
int BufferGetData(Buffer *bufPtr, char *data, int datalen)
{
    char *end;
    int copied = 0;                /* Number of bytes actually copied. */
    int canCopy;                   /* Number of bytes to copy in a given op. */

    ASSERT(data != NULL);
    ASSERT(datalen > 0);
    BufferCheck(bufPtr);
    end = bufPtr->data + bufPtr->size;

    /*
     * Copy the first part out of the buffer: from here to the end
     * of the buffer, or all of the requested data.
     */
    canCopy = min(bufPtr->length, datalen);
    canCopy = min(canCopy, end - bufPtr->begin);
    memcpy(data, bufPtr->begin, canCopy);
    bufPtr->length -= canCopy;
    bufPtr->begin += canCopy;
    copied += canCopy;
    if (bufPtr->begin >= end)
        bufPtr->begin = bufPtr->data;

    /*
     * If there's more to go, copy the second part starting from the
     * beginning of the buffer.
     */
    if (copied < datalen && bufPtr->length > 0) {
        data += copied;
        canCopy = min(bufPtr->length, datalen - copied);
        memcpy(data, bufPtr->begin, canCopy);
        bufPtr->length -= canCopy;
        bufPtr->begin += canCopy;
        copied += canCopy;
    }
    BufferCheck(bufPtr);
    return(copied);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferMove --
 *
 *      Move the specified number of bytes from one buffer to another.
 *      There must be at least 'len' bytes available in the source buffer,
 *      and space for 'len' bytes in the destination buffer.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Bytes moved.
 *
 *----------------------------------------------------------------------
 */
void BufferMove(Buffer *toPtr, Buffer *fromPtr, int len)
{
    int fromLen, toLen, toMove;
    
    ASSERT(len > 0);
    ASSERT(BufferLength(fromPtr) >= len);
    ASSERT(BufferFree(toPtr) >= len);

    BufferCheck(toPtr);
    BufferCheck(fromPtr);

    for(;;) {
        fromLen = min(fromPtr->length, 
                fromPtr->data + fromPtr->size - fromPtr->begin);

        toLen = min(toPtr->size - toPtr->length, 
                toPtr->data + toPtr->size - toPtr->end);

        toMove = min(fromLen, toLen);
        toMove = min(toMove, len);

        ASSERT(toMove >= 0);
        if(toMove == 0)
            return;

        memcpy(toPtr->end, fromPtr->begin, toMove);
        BufferToss(fromPtr, toMove);
        BufferExpand(toPtr, toMove);
        len -= toMove;
    }
}

/*
 *----------------------------------------------------------------------
 *
 * BufferDStringAppend --
 *
 *      Append the specified number of bytes from a buffer onto the 
 *      end of a DString.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Bytes moved.
 *
 *----------------------------------------------------------------------
 */
void BufferDStringAppend(DString *strPtr, Buffer *bufPtr, int len)
{
    int fromLen;

    BufferCheck(bufPtr);
    ASSERT(len > 0);
    ASSERT(len <= BufferLength(bufPtr));

    while(len > 0) {
        fromLen = min(len, bufPtr->data + bufPtr->size - bufPtr->begin);

        ASSERT(fromLen > 0);
        DStringAppend(strPtr, bufPtr->begin, fromLen);
        BufferToss(bufPtr, fromLen);
        len -= fromLen;
    }
}

/*
 * Done with the generic stuff.  Here starts the FastCGI stuff.
 */


typedef request_rec WS_Request;

#define FCGI_MAGIC_TYPE "application/x-httpd-fcgi"
#define FCGI_DEFAULT_LISTEN_Q 5
#define FCGI_DEFAULT_RESTART_DELAY 5
#define FCGI_MAX_PROCESSES 20
#define FCGI_ERRMSG_LEN 200
/*
 * If the exec of a FastCGI app fails, this is the minimum number
 * of seconds to wait before retrying the exec.
 */
#define FCGI_MIN_EXEC_RETRY_DELAY 10

/* 
 * FcgiProcessInfo holds info for each process specified in
 * an AppClass directive.  It is embedded in FastCgiServerInfo
 * below.
 */
typedef struct _FcgiProcessInfo {
    pid_t pid;                       /* pid of associated process */
    int listenFd;                    /* Listener socket */
    int fcgiFd;                      /* fcgi IPC file descriptor for
                                      * persistent connections.
                                      * Not used by Apache. */
    OS_IpcAddress ipcAddr;           /* IPC Address of FCGI app server */
    struct _FastCgiServerInfo *serverInfoPtr;   /* Pointer to class parent */
} FcgiProcessInfo;

/*
 * FastCgiServerInfo holds info for each AppClass specified in this
 * Web server's configuration.
 */
typedef struct _FastCgiServerInfo {
    DString execPath;               /* pathname of executable */
    char      **envp;               /* if NOT NULL, this is the env to send
                                     * to the fcgi app when starting a server
                                     * managed app.
                                     */
    int listenQueueDepth;           /* size of listen queue for IPC */
    int maxProcesses;               /* max allowed processes of this class */
    time_t restartTime;             /* most recent time when the process
                                     * manager started a process in this
                                     * class. */
    int restartDelay;               /* number of seconds to wait between
                                     * restarts after failure.  Can be zero.
                                     */
    int restartOnExit;              /* = TRUE = restart. else terminate/free.
                                     * Always TRUE for Apache. */
    int numRestarts;                /* Total number of restarts */
    int numFailures;                /* num restarts due to exit failure */
    OS_IpcAddress ipcAddr;          /* IPC Address of FCGI app server class.
                                     * Used to connect to an app server. */
    int listenFd;                   /* Listener socket of FCGI app server
                                     * class.  Passed to app server process
                                     * at process creation. */
    int processPriority;            /* If locally server managed process,
                                     * this is the priority to run the
                                     * processes in this class at. */
    struct _FcgiProcessInfo *procInfo; /* Pointer to array of
                                     * processes belonging to this class. */
    int reqRefCount;                /* Number of requests active for this
                                     * server class.  Not used by Apache,
                                     * always zero. */
    int freeOnZero;                 /* Deferred free; free this structure
                                     * when refCount = 0.  Not used
                                     * by Apache. */
    int restartTimerQueued;         /* = TRUE = restart timer queued.
                                     * Not used by Apache. */
    int keepConnection;             /* = 1 = maintain connection to app. */
    int fcgiFd;                     /* fcgi IPC file descriptor for
                                     * persistent connections.  Not used
                                     * by Apache. */
    struct _FastCgiServerInfo *next;
} FastCgiServerInfo;

/*
 * FastCgiInfo holds the state of a particular FastCGI request.
 */
typedef struct {
    int fd;                         /* connection to FastCGI server */
    int gotHeader;                  /* TRUE if reading content bytes */
    unsigned char packetType;       /* type of packet */
    int dataLen;                    /* length of data bytes */
    int paddingLen;                 /* record padding after content */
    FastCgiServerInfo *serverPtr;   /* FastCGI server info */
    Buffer *inbufPtr;               /* input buffer from server */
    Buffer *outbufPtr;              /* output buffer to server */
    Buffer *reqInbufPtr;            /* client input buffer */
    Buffer *reqOutbufPtr;           /* client output buffer */
    char *errorMsg;                 /* error message from failed request */
    int expectingClientContent;     /* >0 => more content, <=0 => no more */
    DString *header;
    DString *errorOut;
    int parseHeader;                /* TRUE iff parsing response headers */
    WS_Request *reqPtr;
    int readingEndRequestBody;
    FCGI_EndRequestBody endRequestBody;
    Buffer *erBufPtr;
    int exitStatus;
    int exitStatusSet;
    int requestId;
    int eofSent;
} FastCgiInfo;

/*
 * Global variables
 *
 * A global that is really "own" to a single procedure
 * is declared with the procedure.
 */
static int readingConfig = FALSE;                /* AppClass but not init */
static FastCgiServerInfo *fastCgiServers = NULL; /* AppClasses */
static char *ipcDir = "/tmp";

/*
 *----------------------------------------------------------------------
 *
 * Code related to the FastCgiIpcDir and AppClass commands.
 *
 *----------------------------------------------------------------------
 */

/*
 *----------------------------------------------------------------------
 *
 * FastCgiIpcDirCmd --
 *
 *----------------------------------------------------------------------
 */
static char *FastCgiIpcDirCmd(cmd_parms *cmd, void *dummy, char *arg)
{
    uid_t uid;
    gid_t gid;
    int len;
    ASSERT(arg != NULL);
    len = strlen(arg);
    ASSERT(len > 0);
    if(*arg != '/') {
        return "FastCgiIpcDir: Directory path must be absolute\n";
    }
    uid = (user_id == (uid_t) -1)  ? geteuid() : user_id;
    gid = (group_id == (gid_t) -1) ? getegid() : group_id;
    if(WS_Access(arg, R_OK | W_OK | X_OK, uid, gid)) {
        return 
          "FastCgiIpcDir: Need read/write/exec permission on directory\n";
    }
    ipcDir = Malloc(len + 1);
    strcpy(ipcDir, arg);
    while(len > 1 && ipcDir[len-1] == '/') {
        ipcDir[len-1] = '\0';
        len--;
    }
    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * MakeSocketName --
 *
 *      Appends a socket path name to an empty DString.
 *      The name is formed from the directory specified to
 *      the FastCgiIpcDir directive, followed by
 *      "OM_WS_N.pid" where N is a sequence number and pid
 *      is the current process ID.
 *
 * Results:
 *      The value of the socket path name.
 *
 * Side effects:
 *      Appends to the DString, increments the sequence number.
 *
 *----------------------------------------------------------------------
 */
static int bindPathExtInt = 1;

char *MakeSocketName(Tcl_DString *dsPtr)
{
    char bindPathExt[32];
    ASSERT(DStringLength(dsPtr) == 0);
    DStringAppend(dsPtr, ipcDir, -1);
    DStringAppend(dsPtr, "/OM_WS_", -1);
    sprintf(bindPathExt, "%d.%d", bindPathExtInt, (int)getpid());
    bindPathExtInt++;
    return DStringAppend(dsPtr, bindPathExt, -1);
} 

/*
 *----------------------------------------------------------------------
 *
 * LookupFcgiServerInfo --
 *
 *      Looks up the FastCgiServerInfo structure with info->execPath
 *      equal to ePath.
 *
 * Results:
 *      Pointer to the structure, or NULL if no such structure exists.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
FastCgiServerInfo *LookupFcgiServerInfo(char *ePath)
{
    FastCgiServerInfo *info;
    for(info = fastCgiServers; info != NULL; info = info->next) {
        const char *execPath = DStringValue(&info->execPath);
        if(execPath != NULL && strcmp(execPath, ePath) == 0) {
            return info;
        }
    }
    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * CreateFcgiServerInfo --
 *
 *      This routine allocates and initializes a fast cgi server info
 *      structure.  It's called from AppClass, ExternalAppClass and
 *      __SendFcgiScript.  This routine is responsible for adding the
 *      new entry to the appClassTable also.
 *
 * Results:
 *      NULL pointer is returned if the class has already been defined
 *      or a valid fast cgi server info pointer.
 *
 * Side effects:
 *      FastCGI server info structure is allocated and initialized.
 *      This includes allocation and initialization of the per 
 *      connection information.
 *
 *----------------------------------------------------------------------
 */
static FastCgiServerInfo *CreateFcgiServerInfo(int numInstances, char *ePath)
{
    FastCgiServerInfo *serverInfoPtr = NULL;
    FcgiProcessInfo *procInfoPtr;
    int i, new;

    serverInfoPtr = LookupFcgiServerInfo(ePath);
    if(serverInfoPtr != NULL) {
        return NULL;
    }
    /*
     * Create an info structure for the FastCGI server
     */
    serverInfoPtr = (FastCgiServerInfo *) Malloc(sizeof(FastCgiServerInfo));
    DStringInit(&serverInfoPtr->execPath);
    serverInfoPtr->envp = NULL;
    serverInfoPtr->listenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
    serverInfoPtr->maxProcesses = numInstances;
    serverInfoPtr->restartDelay = FCGI_DEFAULT_RESTART_DELAY;
    serverInfoPtr->restartOnExit = FALSE;
    serverInfoPtr->numRestarts = 0;
    serverInfoPtr->numFailures = 0;
    serverInfoPtr->ipcAddr = OS_InitIpcAddr();
    serverInfoPtr->processPriority = 0;
    serverInfoPtr->listenFd = -1;
    serverInfoPtr->reqRefCount = 0;
    serverInfoPtr->freeOnZero = FALSE;
    serverInfoPtr->restartTimerQueued = FALSE;
    serverInfoPtr->keepConnection = FALSE;
    serverInfoPtr->fcgiFd = -1;
    
    serverInfoPtr->procInfo = 
      (FcgiProcessInfo *) Malloc(sizeof(FcgiProcessInfo) * numInstances);

    procInfoPtr = serverInfoPtr->procInfo;
    for(i = 0; i < numInstances; i++) {
        procInfoPtr->pid = -1;
        procInfoPtr->listenFd = -1;
        procInfoPtr->fcgiFd = -1;
        procInfoPtr->ipcAddr = OS_InitIpcAddr();
        procInfoPtr->serverInfoPtr = serverInfoPtr;
        procInfoPtr++;
    }
    serverInfoPtr->next = fastCgiServers;
    fastCgiServers = serverInfoPtr;
    return serverInfoPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * FreeFcgiServerInfo --
 *
 *      This routine frees up all resources associated with a FastCGI
 *      application server.  It's called on error cleanup and as a result
 *      of a shutdown or restart.
 *
 * Results:
 *      FastCgi server and process structures freed.
 *
 * Side effects:
 *      FastCGI info structure is deallocated and unavailable.
 *
 *----------------------------------------------------------------------
 */
static void FreeFcgiServerInfo(FastCgiServerInfo *serverInfoPtr)
{
    FcgiProcessInfo *processInfoPtr;
    int i;

    /*
     * Free up process/connection info.
     */
    processInfoPtr = serverInfoPtr->procInfo;
    for(i = 0; i < serverInfoPtr->maxProcesses; i ++, processInfoPtr++) {
        if(processInfoPtr->pid != -1) {
            kill(processInfoPtr->pid, SIGTERM);
            processInfoPtr->pid = -1;
        }
        OS_FreeIpcAddr(processInfoPtr->ipcAddr);
    }
    /*
     * Clean up server info structure resources.
     */
    OS_CleanupFcgiProgram(serverInfoPtr->ipcAddr);
    OS_FreeIpcAddr(serverInfoPtr->ipcAddr);
    DStringFree(&serverInfoPtr->execPath);
    if(serverInfoPtr->listenFd != -1) {
        OS_Close(serverInfoPtr->listenFd);
        serverInfoPtr->listenFd = -1;
    }
    Free(serverInfoPtr->procInfo);
    serverInfoPtr->procInfo = NULL;
    if(serverInfoPtr->envp != NULL) {
        OS_EnvironFree(serverInfoPtr->envp);
        serverInfoPtr->envp = NULL;
    }
    /*
     * If serverInfoPtr is part of fastCgiServers list, unlink it
     */
    if (serverInfoPtr == fastCgiServers) {
        fastCgiServers = fastCgiServers->next;
    } else {
        FastCgiServerInfo *tmpPtr = fastCgiServers;
        while(tmpPtr->next != NULL && tmpPtr->next != serverInfoPtr) {
            tmpPtr = tmpPtr->next;
        }
        if(tmpPtr->next == serverInfoPtr) {
            tmpPtr->next = serverInfoPtr->next;
        }
    }
    Free(serverInfoPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * ParseApacheRawArgs --
 *
 * Turns an Apache RAW_ARGS input into argc and argv.
 *
 * Input: rawArgs 
 *      The RAW_ARGS input (everything but the command name.)
 *      Arguments are separated by whitespace (sequences of
 *      space or tab characters.)
 *
 * Results:
 *      Returns argv; assigns argc to *argcPtr.  argv[0]
 *      is NULL; argv[1] is the first argument.
 *
 * Side effects:
 *      If argc > 0 then Mallocs argv and argv[1], which the client
 *      is responsible for freeing.
 *
 *----------------------------------------------------------------------
 */
char **ParseApacheRawArgs(char *rawArgs, int *argcPtr) 
{
    char *input, *p;
    int i;
    int argc = 0;
    char **argv = NULL;

    /*
     * Apache doesn't specify that rawArgs starts with a
     * non-whitespace, so be sure.
     */
    rawArgs += strspn(rawArgs, " \t");
    if(*rawArgs == '\0') {
        goto Done;
    }
    input = Malloc(strlen(rawArgs) + 1);
    strcpy(input, rawArgs);
    /*
     * Make one pass over the input, null-terminating each argument and
     * computing argc.  Then allocate argv, with argc entries.  argc
     * starts at 1 since Apache does not pass the command name with the input.
     */
    p = input;
    argc = 1;
    for(;;) {
        /*
         * *p is a non-whitespace character.  Look for a whitespace character.
         */
        p += strcspn(p, " \t");
        argc++;
        if(*p == '\0') {
            break;
        }
        *p++ = '\0';
        /*
         * Look for a non-whitespace character.
         */
        p += strspn(p, " \t");
        if(*p == '\0') {
            break;
        }
    }
    argv = Malloc(sizeof(char *) * argc);
    /*
     * Make a second pass over the input to fill in argv.
     */
    p = input;
    i = 1;
    for(;;) {
        argv[i++] = p;
        if(i == argc) {
            break;
	}
        p += strlen(p) + 1;
        p += strspn(p, " \t");
    }
  Done:
    *argcPtr = argc;
    return argv;
}

/*
 *----------------------------------------------------------------------
 *
 * AppClassCmd --
 *
 *      Implements the FastCGI AppClass configuration directive.  This
 *      command adds a fast cgi program class which will be used by the
 *      httpd parent to start/stop/maintain fast cgi server apps.
 *
 *      AppClass <exec-path> [-processes N] \
 *               [-restart-delay N] [-priority N] \
 *               [-initial-env name1=value1] \
 *               [-initial-env name2=value2]
 *
 * Default values:
 *
 * o numProcesses will be set to 1
 * o restartDelay will be set to 5 which means the application will not
 *   be restarted any earlier than 5 seconds from when it was last
 *   invoked.  If the application has been up for longer than 5 seconds
 *   and it fails, a single copy will be restarted immediately.  Other
 *   restarts within that group will be inhibited until the restart-delay
 *   has elapsed.
 * o affinity will be set to FALSE (ie. no process affinity) if not
 *   specified.
 *
 * Results:
 *      TCL_OK or TCL_ERROR.
 *
 * Side effects:
 *      Registers a new AppClass handler for FastCGI.
 *
 *----------------------------------------------------------------------
 */
static char *AppClassCmd(cmd_parms *cmd, void *dummy, char *arg)
{
    int argc;
    char **argv = NULL;
    char *execPath;
    FastCgiServerInfo *serverInfoPtr = NULL;
    int i, n;
    uid_t uid;
    gid_t gid;
    char *cvtPtr;
    char **envHead = NULL;
    char **envPtr;
    int envCount;
    char *namePtr;
    char *valuePtr;
    int numProcesses = 1;
    int restartDelay = FCGI_DEFAULT_RESTART_DELAY;
    int processPriority = 0;
    int listenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
    int affinity = FALSE;
    char *errMsg = Malloc(1024);

    /*
     * If this is the first call to AppClassCmd since a
     * server restart, clean up structures created by the previous
     * sequence of AppClassCmds.
     */
    if(!readingConfig) {
        while(fastCgiServers != NULL) {
            /*
             * Let FreeFcgiServerInfo know that it should not try
             * to kill the application processes (they were killed
             * by SIGHUP).
             */
            for(i = 0; i < fastCgiServers->maxProcesses; i++) {
                fastCgiServers->procInfo[i].pid = -1;
	    }
            FreeFcgiServerInfo(fastCgiServers);
	}
        readingConfig = TRUE;
    }
   /*
    * Parse the raw arguments into tokens.
    * argv[0] is empty and argv[1] is the exec path.
    * Validate the exec path.
    */
    argv = ParseApacheRawArgs(arg, &argc);
    if(argc < 2) {
        sprintf(errMsg, "AppClass: Too few args\n");
        goto ErrorReturn;
    }
    execPath = argv[1];
    serverInfoPtr = LookupFcgiServerInfo(execPath);
    if(serverInfoPtr != NULL) {
        sprintf(errMsg,
                "AppClass: Redefinition of previously defined class %s\n",
                execPath);
        goto ErrorReturn;
    }
    uid = (user_id == (uid_t) -1)  ? geteuid() : user_id;
    gid = (group_id == (gid_t) -1) ? getegid() : group_id;
    if(WS_Access(execPath, X_OK, uid, gid)) {
        sprintf(errMsg, "AppClass: Could not access file %s\n", execPath);
        goto ErrorReturn;
    }
    /*
     * You'd like to create the server info structure now, but
     * you can't because you don't know numProcesses.  So
     * parse the options now.  Make a conservative over-estimate
     * of the number of -initial-env options so that an environment
     * structure can be allocated now.
     */
    envCount = argc/2 + 1;
    envHead = OS_EnvironInit(envCount);
    envPtr = envHead;
    for(i = 2; i < argc; i++) {
        if((strcmp(argv[i], "-processes") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            n = strtol(argv[i], &cvtPtr, 10);
            if(*cvtPtr != '\0' || n < 1 || n > FCGI_MAX_PROCESSES) {
                goto BadValueReturn;
            }
            numProcesses = n;
            continue;
        } else if((strcmp(argv[i], "-restart-delay") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            n = strtol(argv[i], &cvtPtr, 10);
            if(*cvtPtr != '\0' || n < 0) {
                goto BadValueReturn;
            }
            restartDelay = n;
            continue;
        } else if((strcmp(argv[i], "-priority") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            n = strtol(argv[i], &cvtPtr, 10);
            if(*cvtPtr != '\0' || n < 0 || n > 20) {
                goto BadValueReturn;
	    }
            processPriority = n;
	    continue;
	} else if((strcmp(argv[i], "-listen-queue-depth") == 0)) {
	    if((i + 1) == argc) {
                goto MissingValueReturn;
	    }
	    i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1) {
                goto BadValueReturn;
            }
            listenQueueDepth = n;
            continue;
        } else if((strcmp(argv[i], "-initial-env") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            namePtr = argv[i];
            valuePtr = strchr(namePtr, '=');
            if(valuePtr != NULL) {
                *valuePtr = '\0';
                valuePtr++;
            } else {
                goto BadValueReturn;
            }
            OS_EnvString(envPtr, namePtr, valuePtr);
            envPtr++;
            valuePtr--;
            *valuePtr = '=';
            continue;
        } else {
            sprintf(errMsg, "AppClass: Unknown option %s\n", argv[i]);
            goto ErrorReturn;
        }
    } /* for */
    serverInfoPtr = CreateFcgiServerInfo(numProcesses, execPath);
    ASSERT(serverInfoPtr != NULL);
    DStringAppend(&serverInfoPtr->execPath, execPath, -1);
    serverInfoPtr->restartOnExit = TRUE;
    serverInfoPtr->restartDelay = restartDelay;
    serverInfoPtr->processPriority = processPriority;
    serverInfoPtr->listenQueueDepth = listenQueueDepth;
    serverInfoPtr->envp = envHead;
    /*
     * Set envHead to NULL so that if there is an error below we don't
     * free the environment structure twice.
     */
    envHead = NULL;
    /*
     * Create an IPC path for the AppClass.
     */
    if(affinity == FALSE) {
        int listenFd = OS_CreateLocalIpcFd(serverInfoPtr->ipcAddr,
                serverInfoPtr->listenQueueDepth, uid, gid, MakeSocketName);
        if(listenFd < 0) {
            sprintf(errMsg, "AppClass: could not create local IPC socket\n");
            goto ErrorReturn;
        } else {
            serverInfoPtr->listenFd = listenFd;
            /*
             * Propagate listenFd to each process so that process manager
             * doesn't have to understand affinity.
             */
            for(i = 0; i < serverInfoPtr->maxProcesses; i++) {
                serverInfoPtr->procInfo[i].listenFd = listenFd;
            }
        }
    }
    Free(argv[1]);
    Free(argv);
    Free(errMsg);
    return NULL;
  MissingValueReturn:
    sprintf(errMsg, "AppClass: missing value for %s\n", argv[i]);
    goto ErrorReturn;
  BadValueReturn:
    sprintf(errMsg, "AppClass: bad value \"%s\" for %s\n", argv[i], argv[i-1]);
    goto ErrorReturn;
  ErrorReturn:
    if(serverInfoPtr != NULL) {
        FreeFcgiServerInfo(serverInfoPtr);
    }
    if(envHead != NULL) {
        OS_EnvironFree(envHead);
    }
    if(argv != NULL) {
        Free(argv[1]);
        Free(argv);
    }
    return errMsg;
}

/*
 *----------------------------------------------------------------------
 *
 * Code related to the FastCGI process manager.
 *
 *----------------------------------------------------------------------
 */

/*
 *----------------------------------------------------------------------
 * 
 * FastCgiProcMgr
 * 
 *      The FastCGI process manager, which runs as a separate
 *      process responsible for:
 *        - Starting all the FastCGI proceses.
 *        - Restarting any of these processes that die (indicated
 *          by SIGCHLD).
 *        - Catching SIGTERM and relaying it to all the FastCGI
 *          processes before exiting.
 *
 * Inputs:
 *      Uses global variable fastCgiServers.
 *
 * Results:
 *      Does not return.
 *
 * Side effects:
 *      Described above.
 *
 *----------------------------------------------------------------------
 */
static int caughtSigTerm = FALSE;
static int caughtSigChld = FALSE;
static char *errorLogPathname = NULL;
static sigset_t signalsToBlock;

static void FastCgiProcMgrSignalHander(int signo)
{
    if(signo == SIGTERM) {
        caughtSigTerm = TRUE;
    } else if(signo == SIGCHLD) {
        caughtSigChld = TRUE;
    }
}

static int CaughtSigTerm(void)
{
    int result;
    /*
     * Start of critical region for caughtSigTerm
     */
    sigprocmask(SIG_BLOCK, &signalsToBlock, NULL);
    result = caughtSigTerm;
    sigprocmask(SIG_UNBLOCK, &signalsToBlock, NULL);
    /*
     * End of critical region for caughtSigTerm
     */
    return result;
}

void FastCgiProcMgr(void *data)
{
    FastCgiServerInfo *s;
    int i;
    time_t now;
    int sleepSeconds = INT_MAX;
    pid_t childPid;
    int waitStatus, status, callWaitPid;
    sigset_t sigMask;
    pid_t myPid = getpid();
    FILE *errorLogFile = NULL;

    if(errorLogPathname != NULL) {
        /*
         * errorLogFile = fopen(errorLogPathname, "a"),
         * but work around faulty implementations of fopen (SunOS)
         */
        int fd = open(errorLogPathname, O_WRONLY | O_APPEND | O_CREAT,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if (fd >= 0) {
            errorLogFile = fdopen(fd, "a");
        }
    }
    if(errorLogFile == NULL) {
        errorLogFile = fopen("/dev/null", "a");
    }
    /*
     * If the Apache parent process is running as root,
     * consider reducing privileges now.
     */
    if(geteuid() == 0 && setuid(user_id) == -1) {
        fprintf(errorLogFile,
                "[%s] mod_fastcgi: Unable to change uid\n",
                get_time());
        fflush(errorLogFile);
        exit(1);
    }
    /*
     * Set up to handle SIGTERM, SIGCHLD, and SIGALRM.
     */
    sigemptyset(&signalsToBlock);
    sigaddset(&signalsToBlock, SIGTERM);
    sigaddset(&signalsToBlock, SIGCHLD);
    sigaddset(&signalsToBlock, SIGALRM);
    sigprocmask(SIG_BLOCK, NULL, &sigMask);
    sigdelset(&sigMask, SIGTERM);
    sigdelset(&sigMask, SIGCHLD);
    sigdelset(&sigMask, SIGALRM);
    ASSERT(OS_Signal(SIGTERM, FastCgiProcMgrSignalHander) != SIG_ERR);
    ASSERT(OS_Signal(SIGCHLD, FastCgiProcMgrSignalHander) != SIG_ERR);
    ASSERT(OS_Signal(SIGALRM, FastCgiProcMgrSignalHander) != SIG_ERR);
    /*
     * s->procInfo[i].pid == 0 means we've never tried to start this one.
     */
    for(s = fastCgiServers; s != NULL; s = s->next) {
        s->restartTime = 0;
        for(i = 0; i < s->maxProcesses; i++) {
            s->procInfo[i].pid = 0;
	}
    }
    /*
     * Loop until SIGTERM
     */
    for (;;) {
        time_t now;
        int sleepSeconds = INT_MAX;
        pid_t childPid;
        int waitStatus;
        /*
         * Examine each configured AppClass for a process that needs
         * starting.  Compute the earliest time when the start should
         * be attempted, starting it now if the time has passed.
         */
        for(s = fastCgiServers; s != NULL; s = s->next) {
            for(i = 0; i < s->maxProcesses; i++) {
                if(s->procInfo[i].pid <= 0) {
                    time_t restartTime = s->restartTime + s->restartDelay;
                    time_t now = time(NULL);
                    if(s->procInfo[i].pid == 0 || restartTime <= now) {
                        int restart = (s->procInfo[i].pid < 0);
                        if(restart) {
                            s->numRestarts++;
		        }
                        s->restartTime = now;
                        if(CaughtSigTerm()) {
                            goto ProcessSigTerm;
			}
                        status = OS_ExecFcgiProgram(
                                &s->procInfo[i].pid,
                                s->procInfo[i].listenFd,
                                s->processPriority,
                                DStringValue(&s->execPath),
                                s->envp);
                        if(status != 0) {
                            fprintf(errorLogFile,
                                    "[%s] mod_fastcgi: AppClass %s"
                                    " fork failed, errno = %s.\n",
                                    get_time(),
                                    DStringValue(&s->execPath), 
                                    strerror(errno));
                            fflush(errorLogFile);
                            sleepSeconds = min(sleepSeconds,
                                    max(s->restartDelay,
                                        FCGI_MIN_EXEC_RETRY_DELAY));
                            ASSERT(s->procInfo[i].pid < 0);
                            break;
			}
                        if(restart) {
                            fprintf(errorLogFile,
                                    "[%s] mod_fastcgi: AppClass %s"
                                    " restarted with pid %d.\n",
                                    get_time(),
                                    DStringValue(&s->execPath), 
                                    s->procInfo[i].pid);
                            fflush(errorLogFile);
			}
                        ASSERT(s->procInfo[i].pid > 0);
		    } else {
                        sleepSeconds = min(sleepSeconds, restartTime - now);
		    }
		}
	    }
	}
        /*
         * Start of critical region for caughtSigChld and caughtSigTerm.
         */
        sigprocmask(SIG_BLOCK, &signalsToBlock, NULL);
        if(caughtSigTerm) {
            goto ProcessSigTerm;
	}
        if(!caughtSigChld) {
            /*
             * Enable signals and wait.  The call to sigsuspend
             * breaks the critical region into two, so caughtSigChld
             * may have a new value after the wait.
             */
            ASSERT(sleepSeconds > 0);
            alarm(sleepSeconds);
            sigsuspend(&sigMask);
	}
        callWaitPid = caughtSigChld;
        caughtSigChld = FALSE;
        sigprocmask(SIG_UNBLOCK, &signalsToBlock, NULL);
        /*
         * End of critical region for caughtSigChld and caughtSigTerm.
         */
        if(!callWaitPid) {
            /*
             * Must be time to restart somebody.
             */
            continue;
	}
        /*
         * We've caught SIGCHLD, so poll for signal notifications
         * using waitpid.  If a child has died, write a log message
         * and update the data structure so we'll restart the child.
         */
        for (;;) {
            if(CaughtSigTerm()) {
                goto ProcessSigTerm;
	    }
            childPid = waitpid(-1, &waitStatus, WNOHANG);
            if(childPid == -1 || childPid == 0) {
                break;
	    }
            for(s = fastCgiServers; s != NULL; s = s->next) {
                for(i = 0; i < s->maxProcesses; i++) {
                    if(s->procInfo[i].pid == childPid) {
                        goto ChildFound;
		    }
	        }
	    }
            ASSERT(FALSE);
	  ChildFound:
            if(WIFEXITED(waitStatus)) {
                fprintf(errorLogFile,
                        "[%s] mod_fastcgi: AppClass %s pid %d terminated"
                        " by calling exit with status = %d.\n",
                        get_time(), DStringValue(&s->execPath), childPid,
                        WEXITSTATUS(waitStatus));
	    } else {
                ASSERT(WIFSIGNALED(waitStatus));
                fprintf(errorLogFile,
                        "[%s] mod_fastcgi: AppClass %s pid %d terminated"
                        " due to uncaught signal %d.\n",
                        get_time(), DStringValue(&s->execPath), childPid,
                        WTERMSIG(waitStatus));
	    }
            s->procInfo[i].pid = -1;
            s->numFailures++;
            fflush(errorLogFile);
        } /* for (;;) */
    } /* for (;;) */
 ProcessSigTerm:
    /*
     * Kill off the children, then exit.
     */
    for(s = fastCgiServers; s != NULL; s = s->next) {
        for(i = 0; i < s->maxProcesses; i++) {
            if(s->procInfo[i].pid > 0) {
                kill(s->procInfo[i].pid, SIGTERM);
                s->procInfo[i].pid = -1;
	    }
        }
    }
    exit(0);
}

/*
 *----------------------------------------------------------------------
 * 
 * ModFastCgiInit
 *
 *      An Apache module initializer, called by the Apache core
 *      after reading the server config.
 *
 *      If any AppClass directives are included in the server config,
 *      starts a FastCGI process manager.
 *
 *----------------------------------------------------------------------
 */
static pid_t procMgr = -1;

void ModFastCgiInit(server_rec *s, pool *p)
{
    if(s->error_fname != NULL) {
        errorLogPathname = server_root_relative(p, s->error_fname);
    }
    if(fastCgiServers != NULL) {
        ASSERT(readingConfig);
        procMgr = spawn_child(p, FastCgiProcMgr, NULL, 
                kill_after_timeout, NULL, NULL);
        ASSERT(procMgr >= 0);
    }
    readingConfig = FALSE;
}

/*
 *----------------------------------------------------------------------
 *
 * Code related to the FastCGI request handler.
 *
 *----------------------------------------------------------------------
 */

/*
 *----------------------------------------------------------------------
 * 
 * SendPacketHeader --
 *
 *      Assembles and sends the FastCGI packet header for a given 
 *      request.  It is the caller's responsibility to make sure that
 *      there's enough space in the buffer, and that the data bytes
 *      (specified by 'len') are queued immediately following this
 *      header.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Packet header queued.
 * 
 *----------------------------------------------------------------------
 */
#define MSB(x) ((x)/256)
#define LSB(x) ((x)%256)

static void SendPacketHeader(FastCgiInfo *infoPtr, int type, int len)
{
    FCGI_Header header;

    ASSERT(type > 0 && type <= FCGI_MAXTYPE);
    ASSERT(len >= 0 && len <= 0xffff);
    ASSERT(BufferFree(infoPtr->outbufPtr) > sizeof(FCGI_Header));

    /*
     * Assemble and queue the packet header.
     */
    header.version = FCGI_VERSION;
    header.type = type;
    header.requestIdB1 = (infoPtr->requestId >> 8) & 0xff;
    header.requestIdB0 = (infoPtr->requestId) & 0xff;
    header.contentLengthB1 = MSB(len);
    header.contentLengthB0 = LSB(len);
    header.paddingLength = 0;
    header.reserved = 0;
    BufferAddData(infoPtr->outbufPtr, (char *) &header, sizeof(FCGI_Header));
}

/*
 *----------------------------------------------------------------------
 *
 * MakeBeginRequestBody --
 *
 *      Constructs an FCGI_BeginRequestBody record.
 *
 *----------------------------------------------------------------------
 */
static void MakeBeginRequestBody(int role,
                                 int keepConnection,
                                 FCGI_BeginRequestBody *body)
{
    ASSERT((role >> 16) == 0);
    body->roleB1 = (role >>  8) & 0xff;
    body->roleB0 = (role      ) & 0xff;
    body->flags = (keepConnection) ? FCGI_KEEP_CONN : 0;
    memset(body->reserved, 0, sizeof(body->reserved));
}

/*
 *----------------------------------------------------------------------
 * 
 * SendBeginRequest - 
 *
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Begin request queued.
 * 
 *----------------------------------------------------------------------
 */
static void SendBeginRequest(FastCgiInfo *infoPtr)
{
  FCGI_BeginRequestBody body;
  unsigned int bodySize;

  /*
   * We should be the first ones to use this buffer.
   */
  ASSERT(BufferLength(infoPtr->outbufPtr) == 0);

  bodySize = sizeof(FCGI_BeginRequestBody);
  /*
   * XXX: need infoPtr->keepConnection field, hard-coding FALSE below
   */
  MakeBeginRequestBody(FCGI_RESPONDER, FALSE, &body);
  SendPacketHeader(infoPtr, FCGI_BEGIN_REQUEST, bodySize);
  BufferAddData(infoPtr->outbufPtr, (char *) &body, bodySize);
}

/*
 *----------------------------------------------------------------------
 *
 * FCGIUtil_BuildNameValueHeader --
 *
 *      Builds a name-value pair header from the name length
 *      and the value length.  Stores the header into *headerBuffPtr,
 *      and stores the length of the header into *headerLenPtr.
 *
 * Side effects:
 *      Stores header's length (at most 8) into *headerLenPtr,
 *      and stores the header itself into
 *      headerBuffPtr[0 .. *headerLenPtr - 1].
 *
 *----------------------------------------------------------------------
 */
static void FCGIUtil_BuildNameValueHeader(
        int nameLen,
        int valueLen,
        unsigned char *headerBuffPtr,
        int *headerLenPtr) {
    unsigned char *startHeaderBuffPtr = headerBuffPtr;

    ASSERT(nameLen >= 0);
    if(nameLen < 0x80) {
        *headerBuffPtr++ = nameLen;
    } else {
        *headerBuffPtr++ = (nameLen >> 24) | 0x80;
        *headerBuffPtr++ = (nameLen >> 16);
        *headerBuffPtr++ = (nameLen >> 8);
        *headerBuffPtr++ = nameLen;
    }
    ASSERT(valueLen >= 0);
    if(valueLen < 0x80) {
        *headerBuffPtr++ = valueLen;
    } else {
        *headerBuffPtr++ = (valueLen >> 24) | 0x80;
        *headerBuffPtr++ = (valueLen >> 16);
        *headerBuffPtr++ = (valueLen >> 8);
        *headerBuffPtr++ = valueLen;
    }
    *headerLenPtr = headerBuffPtr - startHeaderBuffPtr;
}

/*
 *----------------------------------------------------------------------
 * 
 * SendEnvironment --
 *
 *      Queue the environment variables to a FastCGI server.  Assumes that
 *      there's enough space in the output buffer to hold the variables.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Environment variables queued for delivery.
 * 
 *----------------------------------------------------------------------
 */
static void SendEnvironment(WS_Request *reqPtr, FastCgiInfo *infoPtr)
{
    int headerLen, nameLen, valueLen;
    char *equalPtr;
    unsigned char headerBuff[8];
    char **envp;

    /*
     * Send each environment item to the FastCGI server as a 
     * FastCGI format name-value pair.
     *
     * XXX: this code will break with the environment format used on NT.
     */

    add_common_vars(reqPtr);
    add_cgi_vars(reqPtr);
    envp = create_environment(reqPtr->pool, reqPtr->subprocess_env);
    for (; *envp ; envp++) {
        equalPtr = strchr(*envp, '=');
        ASSERT(equalPtr != NULL);
        nameLen = equalPtr - *envp;
        valueLen = strlen(equalPtr + 1);
        FCGIUtil_BuildNameValueHeader(
                nameLen,
                valueLen,
                &headerBuff[0],
                &headerLen);
        SendPacketHeader(
                infoPtr,
                FCGI_PARAMS,
                headerLen + nameLen + valueLen);
        BufferAddData(infoPtr->outbufPtr, (char *) &headerBuff[0], headerLen);
        BufferAddData(infoPtr->outbufPtr, *envp, nameLen);
        BufferAddData(infoPtr->outbufPtr, equalPtr + 1, valueLen);
    }
    SendPacketHeader(infoPtr, FCGI_PARAMS, 0);
}


/*
 *----------------------------------------------------------------------
 *   
 * ClientToCgiBuffer --
 *
 *      Move data from the client (buffer: reqInbuf) to the FastCGI
 *      application (buffer: outbuf).  This involves encapsulating
 *      the client data in FastCGI protocol records.
 *
 *      ClientToCgiBuffer has no preconditions.  When it returns,
 *      BufferFree(reqInbuf) > 0 || BufferFree(outbuf) < sizeof(FCGI_header)
 *             
 * Results:
 *      None.
 *
 * Side effects:
 *      Bytes moved from client input to FastCGI server output.
 *
 *----------------------------------------------------------------------
 */
static void ClientToCgiBuffer(FastCgiInfo *infoPtr)
{
    int movelen;
    int in_len, out_free;

    /*
     * If a previous call put an EOF indication in the output buffer,
     * nothing left to do.
     */
    if(infoPtr->eofSent) {
        return;
    }
    /*
     * If there's some client data and room for at least one byte
     * of data in the output buffer (after protocol overhead), then
     * move some data to the output buffer.
     */
    in_len = BufferLength(infoPtr->reqInbufPtr);
    out_free = max(0, BufferFree(infoPtr->outbufPtr) - sizeof(FCGI_Header));
    movelen = min(in_len, out_free);
    if(movelen > 0) {
        SendPacketHeader(infoPtr, FCGI_STDIN, movelen);
        BufferMove(infoPtr->outbufPtr, infoPtr->reqInbufPtr, movelen);
    }
    /*
     * If all the client data has been sent, and there's room
     * in the output buffer, indicate EOF.
     */
    if(movelen == in_len
            && infoPtr->expectingClientContent <= 0
            && BufferFree(infoPtr->outbufPtr) >= sizeof(FCGI_Header)) {
        SendPacketHeader(infoPtr, FCGI_STDIN, 0);
        infoPtr->eofSent = TRUE;
    }
}

/*
 *----------------------------------------------------------------------
 *   
 * CgiToClientBuffer --
 *
 *      Move data from FastCGI application (buffer: infoPtr->inbufPtr)
 *      to the client (buffer: infoPtr->header when parsing headers,
 *      infoPtr->reqOutbufPtr after parsing headers) or to the error log
 *      (buffer: infoPtr->errorOut).  This involves interpreting
 *      FastCGI protocol records.
 *             
 * Results:
 *      OK or SERVER_ERROR
 *
 * Side effects:
 *      Many.
 *
 *----------------------------------------------------------------------
 */
static int CgiToClientBuffer(FastCgiInfo *infoPtr)
{
    FCGI_Header header;
    int len;

    while(BufferLength(infoPtr->inbufPtr) > 0) {
        /*
         * State #1:  looking for the next complete packet header.
         */
        if(infoPtr->gotHeader == FALSE) {
            if(BufferLength(infoPtr->inbufPtr) < sizeof(FCGI_Header))
                return OK;
            BufferGetData(infoPtr->inbufPtr, (char *) &header, 
                    sizeof(FCGI_Header));
            /*
             * XXX: Better handling of packets with other version numbers
             * and other packet problems.
             */
            ASSERT(header.version == FCGI_VERSION);
            ASSERT(header.type <= FCGI_MAXTYPE);

            infoPtr->packetType = header.type;
            infoPtr->dataLen = (header.contentLengthB1 << 8)
                    + header.contentLengthB0; 
            infoPtr->gotHeader = TRUE;
            infoPtr->paddingLen = header.paddingLength;
        }
        /*
         * State #2:  got a header, and processing packet bytes.
         */
        len = min(infoPtr->dataLen, BufferLength(infoPtr->inbufPtr));
        ASSERT(len >= 0);
        switch(infoPtr->packetType) {
            case FCGI_STDOUT:
                if(len > 0) {
                    if(infoPtr->parseHeader)
                        BufferDStringAppend(infoPtr->header, 
                                infoPtr->inbufPtr, len);
                    else {
                        len = min(BufferFree(infoPtr->reqOutbufPtr), len);
                        if (len > 0)
                            BufferMove(infoPtr->reqOutbufPtr,
                                infoPtr->inbufPtr, len);
                        else
                          return OK;
                    }
                    infoPtr->dataLen -= len;
                }
                break;
            case FCGI_STDERR:
                if(len > 0) {
                    BufferDStringAppend(infoPtr->errorOut,
                            infoPtr->inbufPtr, len);
                    infoPtr->dataLen -= len;
                }
                break;
            case FCGI_END_REQUEST:
                if(!infoPtr->readingEndRequestBody) {
                  if(infoPtr->dataLen != sizeof(FCGI_EndRequestBody)) {
                    infoPtr->errorMsg = Malloc(FCGI_ERRMSG_LEN);
                    sprintf(infoPtr->errorMsg,
                        "mod_fastcgi: FastCGI protocol error -"
                        " FCGI_END_REQUEST record body size %d !="
                        " sizeof(FCGI_EndRequestBody)", infoPtr->dataLen);
                    return SERVER_ERROR;
                  }
                  infoPtr->readingEndRequestBody = TRUE;
                }
                BufferMove(infoPtr->erBufPtr, infoPtr->inbufPtr, len);
                infoPtr->dataLen -= len;                
                if(infoPtr->dataLen == 0) {
                  FCGI_EndRequestBody *erBody = &infoPtr->endRequestBody;
                  BufferGetData(
                      infoPtr->erBufPtr, (char *) &infoPtr->endRequestBody, 
                      sizeof(FCGI_EndRequestBody));
                  if(erBody->protocolStatus != FCGI_REQUEST_COMPLETE) {
                    /*
                     * XXX: What to do with FCGI_OVERLOADED?
                     */
                    infoPtr->errorMsg = Malloc(FCGI_ERRMSG_LEN);
                    sprintf(infoPtr->errorMsg,
                        "mod_fastcgi: FastCGI protocol error -"
                        " FCGI_END_REQUEST record protocolStatus %d !="
                        " FCGI_REQUEST_COMPLETE", erBody->protocolStatus);
                    return SERVER_ERROR;
                  }
                  infoPtr->exitStatus = (erBody->appStatusB3 << 24)
                    + (erBody->appStatusB2 << 16)
                      + (erBody->appStatusB1 <<  8)
                        + (erBody->appStatusB0 );
                  infoPtr->exitStatusSet = TRUE;
                  infoPtr->readingEndRequestBody = FALSE;
                }
                break;
              case FCGI_GET_VALUES_RESULT:
                /* coming soon */
              case FCGI_UNKNOWN_TYPE:
                /* coming soon */

                /*
                 * Ignore unknown packet types from the FastCGI server.
                 */
            default:
                BufferToss(infoPtr->inbufPtr, len);
                infoPtr->dataLen -= len;            
                break;
        } /* switch */
        /*
         * Discard padding, then start looking for 
         * the next header.
         */
        if (infoPtr->dataLen == 0) {
            if (infoPtr->paddingLen > 0) {
                len = min(infoPtr->paddingLen,
                        BufferLength(infoPtr->inbufPtr));
                BufferToss(infoPtr->inbufPtr, infoPtr->paddingLen);
                infoPtr->paddingLen -= len;
            }
            if (infoPtr->paddingLen == 0) {
                infoPtr->gotHeader = FALSE;
	    }
        }
    } /* while */
    return OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ScanLine --
 *
 *      Terminate a line:  scan to the next newline, scan back to the
 *      first non-space character and store a terminating zero.  Return
 *      the next character past the end of the newline.
 *
 *      If the end of the string is reached, return a pointer to the
 *      end of the string.
 *
 *      If continuation is set to 'TRUE', then it parses a (possible)
 *      sequence of RFC-822 continuation lines.
 *
 * Results:
 *      As above.
 *
 * Side effects:
 *      Termination byte stored in string.
 *
 *----------------------------------------------------------------------
 */
char *ScanLine(char *start, int continuation)
{
    char *p = start;
    char *end = start;

    if(*p != '\n') {
        if(continuation) {
            while(*p != '\0') {
                if(*p == '\n' && p[1] != ' ' && p[1] != '\t')
                    break;
                p++;
            }
        } else {
            while(*p != '\0' && *p != '\n')
                p++;
        }
    }

    end = p;
    if(*end != '\0')
        end++;

    /*
     * Trim any trailing whitespace.
     */
    while(isspace(p[-1]) && p > start)
        p--;

    *p = '\0';
    return end;
}

/*    
 *----------------------------------------------------------------------
 *
 * HTTPTime --
 *
 *      Return the current time, in HTTP time format.
 *
 * Results:
 *      Returns pointer to time string, in static allocated array.
 *
 * Side effects:
 *      None.
 *      
 *----------------------------------------------------------------------
 */
#define TIMEBUFSIZE 256
char *HTTPTime(struct tm *when)
{
    static char str[TIMEBUFSIZE];

    strftime(str, TIMEBUFSIZE-1, "%A, %d-%b-%y %T GMT", when);
    return str;
}
#undef TIMEBUFSIZE

/*
 *----------------------------------------------------------------------
 *
 * SendHeader --
 *
 *      Queue an HTTP header line for sending back to the client.  
 *      If this is an old HTTP request (HTTP/0.9) or an inner (nested)
 *      request, ignore and return.
 *
 *      NOTE:  This routine assumes that the sent data will fit in 
 *             remaining space in the output buffer.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Header information queued to be sent to client.
 *
 *----------------------------------------------------------------------
 */
void SendHeader(FastCgiInfo *reqPtr, ...)
{
    va_list argList;
    char *str;

    va_start(argList, reqPtr);
    while (TRUE) {
        str = va_arg(argList, char *);
        if(str == NULL)
            break;
        BufferAdd(reqPtr->reqOutbufPtr, str);
        ASSERT(BufferFree(reqPtr->reqOutbufPtr) > 0);
    }
    BufferAdd(reqPtr->reqOutbufPtr, "\r\n");        /* terminate */
    ASSERT(BufferFree(reqPtr->reqOutbufPtr) > 0);
    va_end(argList);
}

/*
 *----------------------------------------------------------------------
 *
 * AddHeaders --
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
void AddHeaders(FastCgiInfo *reqPtr, char *str)
{
  BufferAdd(reqPtr->reqOutbufPtr, str);
}

/*
 *----------------------------------------------------------------------
 *
 * BeginHeader --
 *
 *      Begin a standard HTTP header:  emits opening message
 *      (i.e. "200 OK") and standard header matter.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
void BeginHeader(FastCgiInfo *reqPtr, char *msg)
{
    time_t now;

    ASSERT(BufferLength(reqPtr->reqOutbufPtr) == 0);

    now = time(NULL);
    SendHeader(reqPtr, SERVER_PROTOCOL, " ", msg, NULL);
    SendHeader(reqPtr, "Date: ", HTTPTime(gmtime(&now)), NULL);
    SendHeader(reqPtr, "Server: ", SERVER_VERSION, NULL);
    SendHeader(reqPtr, "MIME-version: 1.0", NULL);

    /*
     * We shouldn't have run out of space in the output buffer.
     */
    ASSERT(BufferFree(reqPtr->reqOutbufPtr) > 0);
}

/*
 *----------------------------------------------------------------------
 *
 * EndHeader --
 *
 *      Marks the end of the HTTP header:  sends a blank line.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
void EndHeader(FastCgiInfo *reqPtr)
{
    SendHeader(reqPtr, "", NULL);
}

/*
 *----------------------------------------------------------------------
 *
 * ComposeURL --
 *
 *      XXX
 *    
 *----------------------------------------------------------------------
 */
#define HostInfo(x) x->server
#define HostName(x) x->server->server_hostname
#define HostPort(x) x->server->port

void ComposeURL(WS_Request *reqPtr, char *url, DString *result)
{
    if(url[0] == '/') {
      char portStr[10];
      if (HostInfo(reqPtr) && HostName(reqPtr)) {
        sprintf(portStr, "%d", HostPort(reqPtr));
        DStringAppend(result, "http://", -1);
        DStringAppend(result, HostName(reqPtr), -1);    
        DStringAppend(result, ":", -1);
        DStringAppend(result, portStr, -1);
      }
    }
    DStringAppend(result, url, -1);
}

/*
 *----------------------------------------------------------------------
 *
 * ScanCGIHeader --
 *
 *      Scans the CGI header data to see if the CGI program has sent a 
 *      complete header.  If it has, then parse the header and queue
 *      the HTTP response header information back to the client.
 *
 * Results:
 *      TRUE if completed without error, FALSE otherwise.
 *
 * Side effects:
 *      Sets 'reqPtr->parseHeader' to TRUE if the header was parsed
 *      successfully.
 *
 *----------------------------------------------------------------------
 */
int ScanCGIHeader(WS_Request *reqPtr, FastCgiInfo *infoPtr)
{
    DString status;
    DString headers;
    char *line, *next, *p, *data, *name;
    int len, flag, sent;
    int bufFree;

    ASSERT(infoPtr->parseHeader == TRUE);

    /*
     * Do we have the entire header?  Scan for the blank line that
     * terminates the header.
     */
    p = DStringValue(infoPtr->header);
    len = DStringLength(infoPtr->header);
    flag = 0;
    while(len-- && flag < 2) {
        switch(*p) {
            case '\r':  
                break;
            case '\n':
                flag++;
                break;
            default:
                flag = 0;
                break;
        }
        p++;
    }

    /*
     * Return (to be called later when we have more data) if we don't have
     * and entire header.
     */
    if(flag < 2)
        return TRUE;

    infoPtr->parseHeader = FALSE;

    DStringInit(&status);
    DStringAppend(&status, "200 OK", -1);
    DStringInit(&headers);
    next = DStringValue(infoPtr->header);
    for(;;) {
        next = ScanLine(line = next, TRUE);
        if(*line == '\0') {
            break;
        }
        if((p = strpbrk(line, " \t")) != NULL) {
            data = p + 1;
            *p = '\0';
        } else {
            data = "";
        }
        while(isspace(*data)) {
            data++;
        }
        /*
         * Handle "Location:" and "Status:" specially.
         * All other headers get passed through unmodified.
         */
        if(!strcasecmp(line, "Location:")) {
            DStringTrunc(&status, 0);
            DStringAppend(&status, "302 Redirect", -1);
            DStringAppend(&headers, "Location: ", -1);
            /*
             * This is a deviation from the CGI/1.1 spec.
             *
             * The spec says that "virtual paths" should be treated
             * as if the client had accessed the file in the first
             * place.  This usually breaks relative references in the
             * referenced document.
             *
             * XXX: do more research on this?
             */
            ComposeURL(reqPtr, data, &headers);
            DStringAppend(&headers, "\r\n", -1);
        } else if(!strcasecmp(line, "Status:")) {
            DStringTrunc(&status, 0);
            DStringAppend(&status, data, -1);
        } else {
            if(data != NULL) {
                DStringAppend(&headers, line, -1);
                DStringAppend(&headers, " ", 1);
                DStringAppend(&headers, data, -1);
                DStringAppend(&headers, "\r\n", -1);
            }
        }
    }

    /*
     * We're done scanning the CGI script's header output.  Now
     * we have to write to the client:  status, CGI header, and
     * any over-read CGI output.
     */
    BeginHeader(infoPtr, DStringValue(&status));
    DStringFree(&status);

    AddHeaders(infoPtr, DStringValue(&headers));
    DStringFree(&headers);
    EndHeader(infoPtr);

    len = next - DStringValue(infoPtr->header);
    len = DStringLength(infoPtr->header) - len;
    ASSERT(len >= 0);

    bufFree = BufferFree(infoPtr->reqOutbufPtr);

    if (bufFree < len) {
      /* should the same fix be made in core server? */
      int bufLen = BufferLength(infoPtr->reqOutbufPtr);
      Buffer *newBuf = BufferCreate(len + bufLen);
      BufferMove(newBuf, infoPtr->reqOutbufPtr, bufLen);
      BufferDelete(infoPtr->reqOutbufPtr);
      infoPtr->reqOutbufPtr = newBuf;
    }
    bufFree = BufferFree(infoPtr->reqOutbufPtr);
    if(bufFree == 0)
        goto fail;
       
    /*
     * Only send the body for methods other than HEAD.
     */
    if(!infoPtr->reqPtr->header_only) {
        if(len > 0) {
            sent = BufferAddData(infoPtr->reqOutbufPtr, next, len);
            if(sent != len)
                goto fail;
        }
    }
    return TRUE;

fail:
    return FALSE;
}

/*
 *----------------------------------------------------------------------
 * 
 * FillOutbuf --
 *
 *      Reads data from the client and pushes it toward outbuf.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      When FillOutbuf returns, either
 *          both reqInbuf and outbuf are full
 *      or
 *          expectingClientContent <= 0 and either
 *          reqInbuf is empty or outbuf is full.
 *
 *      "outbuf full" means "at most sizeof(FCGI_Header) bytes free."
 *
 *      In case of an error reading from the client, sets
 *      expectingClientContent == -1.
 * 
 *----------------------------------------------------------------------
 */
static void FillOutbuf(WS_Request *reqPtr, FastCgiInfo *infoPtr)
{
    char *end;
    int count, countRead;
    while(BufferFree(infoPtr->reqInbufPtr) > 0
            || BufferFree(infoPtr->outbufPtr) > 0) {
        ClientToCgiBuffer(infoPtr);
        if(infoPtr->expectingClientContent <= 0) {
            break;
        }
        BufferPeekExpand(infoPtr->reqInbufPtr, &end, &count);
        if(count == 0) {
            break;
        }
        countRead = get_client_block(reqPtr, end, count);
        if(countRead > 0) {
            BufferExpand(infoPtr->reqInbufPtr, countRead);
        } else if (countRead == 0) {
            infoPtr->expectingClientContent = 0;
	} else {
            infoPtr->expectingClientContent = -1;
        }
    }
}

/*
 *----------------------------------------------------------------------
 * 
 * DrainReqOutbuf --
 *
 *      Writes some data to the client, if reqOutbuf contains any.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      When DrainReqOutbuf returns, BufferFree(reqOutbuf) > 0.
 *
 *      In case of an error writing to the client, reqOutbuf
 *      is drained anyway, with no error indication.
 * 
 *----------------------------------------------------------------------
 */
static void DrainReqOutbuf(WS_Request *reqPtr, FastCgiInfo *infoPtr)
{
    char *begin;
    int count;
    BufferPeekToss(infoPtr->reqOutbufPtr, &begin, &count);
    if(count == 0) {
        return;
    }
    if(!reqPtr->connection->aborted) {
        bwrite(reqPtr->connection->client, begin, count);
    }
    BufferToss(infoPtr->reqOutbufPtr, count);
}

/*
 *----------------------------------------------------------------------
 * 
 * FastCgiDoWork --
 *
 *      This is the core routine for moving data between the FastCGI
 *      application and the Web server's client.
 *
 *      If the Web server's client closes the connection prematurely,
 *      FastCGIDoWork carries on until the FastCGI application is
 *      done with the request.  This avoids the FastCGI application
 *      receiving SIGPIPE.
 *
 * Results:
 *      OK or SERVER_ERROR
 *
 * Side effects:
 *      many
 * 
 *----------------------------------------------------------------------
 */
static int FastCgiDoWork(WS_Request *reqPtr, FastCgiInfo *infoPtr)
{
    struct timeval timeOut, *timeOutPtr;
    fd_set read_set, write_set;
    int numFDs, status, nBytes;
    int keepReadingFromFcgiApp, doClientWrite;
    char *fromStrerror;

    timeOut.tv_sec = 0;
    timeOut.tv_usec = 100000; /* 0.1 sec */
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    numFDs = infoPtr->fd + 1;
    keepReadingFromFcgiApp = TRUE;
    while(keepReadingFromFcgiApp
            || BufferLength(infoPtr->inbufPtr) > 0
            || BufferLength(infoPtr->reqOutbufPtr) > 0) {
        if(!infoPtr->eofSent) {
            FillOutbuf(reqPtr, infoPtr);
	}
        /*
         * To avoid deadlock, don't do a blocking select to write to
         * the FastCGI application without selecting to read from the
         * FastCGI application.
         */
        doClientWrite = FALSE;
        if(keepReadingFromFcgiApp && BufferFree(infoPtr->inbufPtr) > 0) {
            FD_SET(infoPtr->fd, &read_set);
            if(BufferLength(infoPtr->outbufPtr) > 0) {
                FD_SET(infoPtr->fd, &write_set);
            } else {
                FD_CLR(infoPtr->fd, &write_set);
            }
            /*
             * If there's buffered data to send to the client, don't
             * wait indefinitely for the FastCGI app; the app might
             * be doing server push.
             */
            if(BufferLength(infoPtr->reqOutbufPtr) > 0) {
                timeOutPtr = &timeOut;
	    } else {
                timeOutPtr = NULL;
	    }
            /*
             * XXX: should always set a non-NULL timeout, to survive an
             * application that diverges.
             */
            status = select(
                    numFDs, &read_set, &write_set, NULL, timeOutPtr);
            if(status < 0) {
                goto AppIoError;
	    } else if(status == 0) {
                /*
                 * XXX: select timed out, so go ahead and write to client.
                 */
                doClientWrite = TRUE;
            }
            if(FD_ISSET(infoPtr->fd, &read_set)) {
                status = BufferRead(infoPtr->inbufPtr, infoPtr->fd);
                if(status < 0) {
                    goto AppIoError;
                } else if(status == 0) {
                    keepReadingFromFcgiApp = FALSE;
		}
            }
            if(FD_ISSET(infoPtr->fd, &write_set)) {
                if(BufferWrite(infoPtr->outbufPtr, infoPtr->fd) < 0) {
                    goto AppIoError;
		}
            }
        } else {
            doClientWrite = TRUE;
	}
        if(doClientWrite) {
            DrainReqOutbuf(reqPtr, infoPtr);
        }
        if(CgiToClientBuffer(infoPtr) != OK) {
            return SERVER_ERROR;
        }
        if(infoPtr->exitStatusSet) {
            keepReadingFromFcgiApp = FALSE;
        }
        if(infoPtr->parseHeader) {
            if(!ScanCGIHeader(reqPtr, infoPtr)) {
                goto BadHeader;
            }
        }
    } /* while */
    if(infoPtr->parseHeader) {
        goto BadHeader;
    }
    bflush(reqPtr->connection->client);
    bgetopt(reqPtr->connection->client, BO_BYTECT, &reqPtr->bytes_sent);
    /*
     * XXX: This would be the place to check the error status
     * of the connection to the client, if indeed we care.
     */
    return OK;
  BadHeader:
    infoPtr->errorMsg = Malloc(FCGI_ERRMSG_LEN);
    sprintf(infoPtr->errorMsg,
            "mod_fastcgi: Malformed CGI or HTTP header from FastCGI app");
    return SERVER_ERROR;
  AppIoError:
    /* No strerror prototype on SunOS? */
    fromStrerror = (char *) strerror(errno);
    infoPtr->errorMsg = Malloc(FCGI_ERRMSG_LEN + strlen(fromStrerror));
    sprintf(infoPtr->errorMsg,
            "mod_fastcgi: OS error '%s' while communicating with app",
            strerror(errno));
    return SERVER_ERROR;
}

/*
 * Cleans up data associated with a request.
 */
void FcgiCleanUp(FastCgiInfo *infoPtr)
{
    if(infoPtr == NULL) {
        return;
    }
    if(DStringLength(infoPtr->errorOut) > 0) {
        fprintf(infoPtr->reqPtr->server->error_log,
                "[%s] mod_fastcgi: stderr output from %s: '%s'\n",
                get_time(), infoPtr->reqPtr->filename,
                DStringValue(infoPtr->errorOut));
        fflush(infoPtr->reqPtr->server->error_log);
    }
    BufferDelete(infoPtr->inbufPtr);
    BufferDelete(infoPtr->outbufPtr);
    BufferDelete(infoPtr->reqInbufPtr);
    BufferDelete(infoPtr->reqOutbufPtr);
    BufferDelete(infoPtr->erBufPtr);
    Free(infoPtr->errorMsg);
    DStringFree(infoPtr->header);
    DStringFree(infoPtr->errorOut);
    OS_Close(infoPtr->fd);
    Free(infoPtr);
}

/*
 *----------------------------------------------------------------------
 * 
 * FastCgiHandler --
 *
 *      This routine gets called for a request that corresponds to
 *      a FastCGI connection.  It performs the request synchronously.
 *
 * Results:
 *      Final status of request: OK or NOT_FOUND or SERVER_ERROR.
 *
 * Side effects:
 *      Request performed.
 * 
 *----------------------------------------------------------------------
 */
static int FastCgiHandler(WS_Request *reqPtr)
{
    FastCgiServerInfo *serverInfoPtr;
    FastCgiInfo *infoPtr;
    OS_IpcAddr *ipcAddrPtr;
    char *msg = NULL;
    int status;

    serverInfoPtr = LookupFcgiServerInfo(reqPtr->filename);
    if (serverInfoPtr == NULL) {
        log_reason("mod_fastcgi: No AppClass directive for requested file",
                reqPtr->filename, reqPtr);
        return NOT_FOUND;
    }
    status = setup_client_block(reqPtr, REQUEST_CHUNKED_ERROR);
    if(status != OK) {
        return status;
    }
    /*
     * Allocate and initialize FastCGI private data to augment the request
     * structure.
     */
    infoPtr = (FastCgiInfo *) Malloc(sizeof(FastCgiInfo));
    infoPtr->serverPtr = serverInfoPtr;
    infoPtr->inbufPtr = BufferCreate(SERVER_BUFSIZE);
    infoPtr->outbufPtr = BufferCreate(SERVER_BUFSIZE);
    infoPtr->gotHeader = FALSE;
    infoPtr->reqInbufPtr = BufferCreate(SERVER_BUFSIZE);
    infoPtr->reqOutbufPtr = BufferCreate(SERVER_BUFSIZE);
    infoPtr->errorMsg = NULL;
    infoPtr->parseHeader = TRUE;
    infoPtr->header = (DString *) malloc(sizeof(DString));
    infoPtr->errorOut = (DString *) malloc(sizeof(DString));
    infoPtr->reqPtr = reqPtr;
    DStringInit(infoPtr->header);
    DStringInit(infoPtr->errorOut);
    infoPtr->erBufPtr = BufferCreate(sizeof(FCGI_EndRequestBody) + 1);
    infoPtr->readingEndRequestBody = FALSE;
    infoPtr->exitStatus = 0;
    infoPtr->exitStatusSet = FALSE;
    infoPtr->requestId = 1; /* anything but zero is OK here */
    infoPtr->eofSent = FALSE;
    infoPtr->fd = -1;
    infoPtr->expectingClientContent = (should_client_block(reqPtr) != 0);

    SendBeginRequest(infoPtr);
    SendEnvironment(reqPtr, infoPtr);
    /*
     * Read as much as possible from the client now, before connecting
     * to the FastCGI application.
     */
    soft_timeout("read script input or send script output", reqPtr);
    FillOutbuf(reqPtr, infoPtr);
    /*
     * Open a connection to the FastCGI application.
     */
    ipcAddrPtr = (OS_IpcAddr *) serverInfoPtr->ipcAddr;
    if((infoPtr->fd = OS_Socket(ipcAddrPtr->serverAddr->sa_family, 
            SOCK_STREAM, 0)) < 0) {
        goto ConnectionErrorReturn;
    }
    if(connect(infoPtr->fd, (struct sockaddr *) ipcAddrPtr->serverAddr,
            ipcAddrPtr->addrLen) < 0) {
        goto ConnectionErrorReturn;
    }
    if((status = FastCgiDoWork(reqPtr, infoPtr)) != OK) {
        goto ErrorReturn;
    }
    kill_timeout(reqPtr);
    FcgiCleanUp(infoPtr);
    return OK;
  ConnectionErrorReturn:
    msg = (char *) strerror(errno);
    if (msg == NULL) {
        msg = "errno out of range";
    }
    infoPtr->errorMsg = Malloc(FCGI_ERRMSG_LEN + strlen(msg));
    sprintf(infoPtr->errorMsg,
            "mod_fastcgi: Could not connect to application,"
            " OS error '%s'", msg);
  ErrorReturn:
    log_reason(infoPtr->errorMsg, reqPtr->filename, reqPtr);
    FcgiCleanUp(infoPtr);
    return SERVER_ERROR;
}


command_rec fastcgi_cmds[] = {
{ "FastCgiIpcDir", FastCgiIpcDirCmd, NULL, RSRC_CONF, TAKE1,
    NULL },
{ "AppClass", AppClassCmd, NULL, RSRC_CONF, RAW_ARGS,
    NULL },
{ NULL }
};


handler_rec fastcgi_handlers[] = {
{ FCGI_MAGIC_TYPE, FastCgiHandler },
{ NULL }
};


module fastcgi_module = {
   STANDARD_MODULE_STUFF,
   ModFastCgiInit,              /* initializer */
   NULL,                        /* dir config creater */
   NULL,                        /* dir merger --- default is to override */
   NULL,                        /* server config */
   NULL,                        /* merge server config */
   fastcgi_cmds,                /* command table */
   fastcgi_handlers,            /* handlers */
   NULL,                        /* filename translation */
   NULL,                        /* check_user_id */
   NULL,                        /* check auth */
   NULL,                        /* check access */
   NULL,                        /* type_checker */
   NULL,                        /* fixups */
   NULL                         /* logger */
};
