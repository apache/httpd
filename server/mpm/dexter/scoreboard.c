/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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
 */ 

#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "http_config.h"
#include "unixd.h"
#include "http_conf_globals.h"
#include "mpm_status.h"
#include "scoreboard.h"
#include "dexter.h" /* for max_daemons_limit */
#ifdef USE_SHMGET_SCOREBOARD
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#endif

#ifdef USE_OS2_SCOREBOARD
    /* Add MMAP style functionality to OS/2 */
#define INCL_DOSMEMMGR
#define INCL_DOSEXCEPTIONS
#define INCL_DOSSEMAPHORES
#include <os2.h>
#include <umalloc.h>
#include <stdio.h>
#endif

static scoreboard *ap_scoreboard_image = NULL;

/*****************************************************************
 *
 * Dealing with the scoreboard... a lot of these variables are global
 * only to avoid getting clobbered by the longjmp() that happens when
 * a hard timeout expires...
 *
 * We begin with routines which deal with the file itself... 
 */

#if defined(USE_OS2_SCOREBOARD)

/* The next two routines are used to access shared memory under OS/2.  */
/* This requires EMX v09c to be installed.                           */

caddr_t create_shared_heap(const char *name, size_t size)
{
    ULONG rc;
    void *mem;
    Heap_t h;

    rc = DosAllocSharedMem(&mem, name, size,
			   PAG_COMMIT | PAG_READ | PAG_WRITE);
    if (rc != 0)
	return NULL;
    h = _ucreate(mem, size, !_BLOCK_CLEAN, _HEAP_REGULAR | _HEAP_SHARED,
		 NULL, NULL);
    if (h == NULL)
	DosFreeMem(mem);
    return (caddr_t) h;
}

caddr_t get_shared_heap(const char *Name)
{

    PVOID BaseAddress;		/* Pointer to the base address of
				   the shared memory object */
    ULONG AttributeFlags;	/* Flags describing characteristics
				   of the shared memory object */
    APIRET rc;			/* Return code */

    /* Request read and write access to */
    /*   the shared memory object       */
    AttributeFlags = PAG_WRITE | PAG_READ;

    rc = DosGetNamedSharedMem(&BaseAddress, Name, AttributeFlags);

    if (rc != 0) {
	printf("DosGetNamedSharedMem error: return code = %ld", rc);
	return 0;
    }

    return BaseAddress;
}

static void setup_shared_mem(ap_context_t *p)
{
    caddr_t m;

    int rc;

    m = (caddr_t) create_shared_heap("\\SHAREMEM\\SCOREBOARD", SCOREBOARD_SIZE);
    if (m == 0) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s: Could not create OS/2 Shared memory pool.",
		     ap_server_argv0);
	exit(APEXIT_INIT);
    }

    rc = _uopen((Heap_t) m);
    if (rc != 0) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
		"%s: Could not uopen() newly created OS/2 Shared memory pool.",
		ap_server_argv0);
    }
    ap_scoreboard_image = (scoreboard *) m;
}

API_EXPORT(void) reopen_scoreboard(ap_context_t *p)
{
    caddr_t m;
    int rc;

    m = (caddr_t) get_shared_heap("\\SHAREMEM\\SCOREBOARD");
    if (m == 0) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s: Could not find existing OS/2 Shared memory pool.",
		ap_server_argv0);
	exit(APEXIT_INIT);
    }

    rc = _uopen((Heap_t) m);
    ap_scoreboard_image = (scoreboard *) m;
}

#elif defined(USE_POSIX_SCOREBOARD)
#include <sys/mman.h>
/* 
 * POSIX 1003.4 style
 *
 * Note 1: 
 * As of version 4.23A, shared memory in QNX must reside under /dev/shmem,
 * where no subdirectories allowed.
 *
 * POSIX shm_open() and shm_unlink() will take care about this issue,
 * but to avoid confusion, I suggest to redefine scoreboard file name
 * in httpd.conf to cut "logs/" from it. With default setup actual name
 * will be "/dev/shmem/logs.apache_status". 
 * 
 * If something went wrong and Apache did not unlinked this object upon
 * exit, you can remove it manually, using "rm -f" command.
 * 
 * Note 2:
 * <sys/mman.h> in QNX defines MAP_ANON, but current implementation 
 * does NOT support BSD style anonymous mapping. So, the order of 
 * conditional compilation is important: 
 * this #ifdef section must be ABOVE the next one (BSD style).
 *
 * I tested this stuff and it works fine for me, but if it provides 
 * trouble for you, just comment out USE_MMAP_SCOREBOARD in QNX section
 * of ap_config.h
 *
 * June 5, 1997, 
 * Igor N. Kovalenko -- infoh@mail.wplus.net
 */

static void cleanup_shared_mem(void *d)
{
    shm_unlink(ap_scoreboard_fname);
}

static void setup_shared_mem(ap_context_t *p)
{
    char buf[512];
    caddr_t m;
    int fd;

    fd = shm_open(ap_scoreboard_fname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
	ap_snprintf(buf, sizeof(buf), "%s: could not open(create) scoreboard",
		    ap_server_argv0);
	perror(buf);
	exit(APEXIT_INIT);
    }
    if (ltrunc(fd, (off_t) SCOREBOARD_SIZE, SEEK_SET) == -1) {
	ap_snprintf(buf, sizeof(buf), "%s: could not ltrunc scoreboard",
		    ap_server_argv0);
	perror(buf);
	shm_unlink(ap_scoreboard_fname);
	exit(APEXIT_INIT);
    }
    if ((m = (caddr_t) mmap((caddr_t) 0,
			    (size_t) SCOREBOARD_SIZE, PROT_READ | PROT_WRITE,
			    MAP_SHARED, fd, (off_t) 0)) == (caddr_t) - 1) {
	ap_snprintf(buf, sizeof(buf), "%s: cannot mmap scoreboard",
		    ap_server_argv0);
	perror(buf);
	shm_unlink(ap_scoreboard_fname);
	exit(APEXIT_INIT);
    }
    close(fd);
    ap_register_cleanup(p, NULL, cleanup_shared_mem, ap_null_cleanup);
    ap_scoreboard_image = (scoreboard *) m;
}

API_EXPORT(void) reopen_scoreboard(ap_context_t *p)
{
}

#elif defined(USE_MMAP_SCOREBOARD)

static void setup_shared_mem(ap_context_t *p)
{
    caddr_t m;

#if defined(MAP_ANON)
/* BSD style */
#ifdef CONVEXOS11
    /*
     * 9-Aug-97 - Jeff Venters (venters@convex.hp.com)
     * ConvexOS maps address space as follows:
     *   0x00000000 - 0x7fffffff : Kernel
     *   0x80000000 - 0xffffffff : User
     * Start mmapped area 1GB above start of text.
     *
     * Also, the length requires a pointer as the actual length is
     * returned (rounded up to a page boundary).
     */
    {
	unsigned len = SCOREBOARD_SIZE;

	m = mmap((caddr_t) 0xC0000000, &len,
		 PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, NOFD, 0);
    }
#elif defined(MAP_TMPFILE)
    {
	char mfile[] = "/tmp/apache_shmem_XXXX";
	int fd = mkstemp(mfile);
	if (fd == -1) {
	    perror("open");
	    ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                         "%s: Could not open %s", ap_server_argv0, mfile);
	    exit(APEXIT_INIT);
	}
	m = mmap((caddr_t) 0, SCOREBOARD_SIZE,
		PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (m == (caddr_t) - 1) {
	    perror("mmap");
	    ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                         "%s: Could not mmap %s", ap_server_argv0, mfile);
	    exit(APEXIT_INIT);
	}
	close(fd);
	unlink(mfile);
    }
#else
    m = mmap((caddr_t) 0, SCOREBOARD_SIZE,
	     PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
#endif
    if (m == (caddr_t) - 1) {
	perror("mmap");
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s: Could not mmap memory", ap_server_argv0);
	exit(APEXIT_INIT);
    }
#else
/* Sun style */
    int fd;

    fd = open("/dev/zero", O_RDWR);
    if (fd == -1) {
	perror("open");
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s: Could not open /dev/zero", ap_server_argv0);
	exit(APEXIT_INIT);
    }
    m = mmap((caddr_t) 0, SCOREBOARD_SIZE,
	     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == (caddr_t) - 1) {
	perror("mmap");
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s: Could not mmap /dev/zero", ap_server_argv0);
	exit(APEXIT_INIT);
    }
    close(fd);
#endif
    ap_scoreboard_image = (scoreboard *) m;
}

API_EXPORT(void) reopen_scoreboard(ap_context_t *p)
{
}

#elif defined(USE_SHMGET_SCOREBOARD)
static key_t shmkey = IPC_PRIVATE;
static int shmid = -1;

static void setup_shared_mem(ap_context_t *p)
{
    struct shmid_ds shmbuf;
    const server_rec * server_conf = ap_get_server_conf();
#ifdef MOVEBREAK
    char *obrk;
#endif

    if ((shmid = shmget(shmkey, SCOREBOARD_SIZE, IPC_CREAT | SHM_R | SHM_W)) == -1) {
#ifdef LINUX
	if (errno == ENOSYS) {
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, errno,
                         server_conf,
			 "Your kernel was built without CONFIG_SYSVIPC\n"
			 "%s: Please consult the Apache FAQ for details",
			 ap_server_argv0);
	}
#endif
	ap_log_error(APLOG_MARK, APLOG_EMERG, errno, server_conf,
		    "could not call shmget");
	exit(APEXIT_INIT);
    }

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, errno, server_conf,
		"created shared memory segment #%d", shmid);

#ifdef MOVEBREAK
    /*
     * Some SysV systems place the shared segment WAY too close
     * to the dynamic memory break point (sbrk(0)). This severely
     * limits the use of malloc/sbrk in the program since sbrk will
     * refuse to move past that point.
     *
     * To get around this, we move the break point "way up there",
     * attach the segment and then move break back down. Ugly
     */
    if ((obrk = sbrk(MOVEBREAK)) == (char *) -1) {
	ap_log_error(APLOG_MARK, APLOG_ERR, errno, server_conf,
	    "sbrk() could not move break");
    }
#endif

#define BADSHMAT	((scoreboard *)(-1))
    if ((ap_scoreboard_image = (scoreboard *) shmat(shmid, 0, 0)) == BADSHMAT) {
	ap_log_error(APLOG_MARK, APLOG_EMERG, errno, server_conf,
                     "shmat error");
	/*
	 * We exit below, after we try to remove the segment
	 */
    }
    else {			/* only worry about permissions if we attached the segment */
	if (shmctl(shmid, IPC_STAT, &shmbuf) != 0) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, errno, server_conf,
		"shmctl() could not stat segment #%d", shmid);
	}
	else {
	    shmbuf.shm_perm.uid = unixd_config.user_id;
	    shmbuf.shm_perm.gid = unixd_config.group_id;
	    if (shmctl(shmid, IPC_SET, &shmbuf) != 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, server_conf,
		    "shmctl() could not set segment #%d", shmid);
	    }
	}
    }
    /*
     * We must avoid leaving segments in the kernel's
     * (small) tables.
     */
    if (shmctl(shmid, IPC_RMID, NULL) != 0) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf,
		"shmctl: IPC_RMID: could not remove shared memory segment #%d",
		shmid);
    }
    if (ap_scoreboard_image == BADSHMAT)	/* now bailout */
	exit(APEXIT_INIT);

#ifdef MOVEBREAK
    if (obrk == (char *) -1)
	return;			/* nothing else to do */
    if (sbrk(-(MOVEBREAK)) == (char *) -1) {
	ap_log_error(APLOG_MARK, APLOG_ERR, errno, server_conf,
	    "sbrk() could not move break back");
    }
#endif
}

API_EXPORT(void) reopen_scoreboard(ap_context_t *p)
{
}

#endif

/* Called by parent process */
void reinit_scoreboard(ap_context_t *p)
{
    if (ap_scoreboard_image == NULL) {
	setup_shared_mem(p);
    }
    memset(ap_scoreboard_image, 0, SCOREBOARD_SIZE);
}

/****
 * Above code is shmem code. Below code is interacting with the shmem
 ****/

static int maintain_connection_status = 1;

void ap_dexter_set_maintain_connection_status(int flag) {
    maintain_connection_status = flag;
    return;
}

/* Useful to erase the status of children that might be from previous
 * generations */
void ap_dexter_force_reset_connection_status(long conn_id)
{
    int i;

    for (i = 0; i < STATUSES_PER_CONNECTION; i++) {
        ap_scoreboard_image->table[conn_id][i].key[0] = '\0';
    }
}

void ap_reset_connection_status(long conn_id)
{
    if (maintain_connection_status) {
        ap_dexter_force_reset_connection_status(conn_id);
    }
}

/* Don't mess with the string you get back from this function */
const char *ap_get_connection_status(long conn_id, const char *key)
{
    int i = 0;
    status_table_entry *ss;

    if (!maintain_connection_status) return "";
    while (i < STATUSES_PER_CONNECTION) {
        ss = &(ap_scoreboard_image->table[conn_id][i]);
        if (ss->key[0] == '\0') {
            break;
        }
        if (0 == strcmp(ss->key, key)) {
            return ss->value;
        }
    }

    return NULL;
}

ap_array_header_t *ap_get_connections(ap_context_t *p)
{
    int i;
    ap_array_header_t *connection_list;
    long *array_slot;

    connection_list = ap_make_array(p, 0, sizeof(long));
    /* We assume that there is a connection iff it has an entry in the status
     * table. Connections without any status sound problematic to me, so this
     * is probably for the best. - manoj */
    for (i = 0; i < max_daemons_limit*HARD_THREAD_LIMIT; i++) {
	if (ap_scoreboard_image->table[i][0].key[0] != '\0') {
            array_slot = ap_push_array(connection_list);
            *array_slot = i;
        }
    }
    return connection_list;
}

ap_array_header_t *ap_get_connection_keys(ap_context_t *p, long conn_id)
{
    int i = 0;
    status_table_entry *ss;
    ap_array_header_t *key_list;
    char **array_slot;

    key_list = ap_make_array(p, 0, KEY_LENGTH * sizeof(char));
    while (i < STATUSES_PER_CONNECTION) {
        ss = &(ap_scoreboard_image->table[conn_id][i]);
        if (ss->key[0] == '\0') {
            break;
        }
        array_slot = ap_push_array(key_list);
        *array_slot = ap_pstrdup(p, ss->key);
        i++;
    }
    return key_list;
}

/* Note: no effort is made here to prevent multiple threads from messing with
 * a single connection at the same time. ap_update_connection_status should
 * only be called by the thread that owns the connection */

void ap_update_connection_status(long conn_id, const char *key,
                                 const char *value)
{
    int i = 0;
    status_table_entry *ss;

    if (!maintain_connection_status) return;
    while (i < STATUSES_PER_CONNECTION) {
        ss = &(ap_scoreboard_image->table[conn_id][i]);
        if (ss->key[0] == '\0') {
            break;
        }
        if (0 == strcmp(ss->key, key)) {
            ap_cpystrn(ss->value, value, VALUE_LENGTH);
            return;
        }
	i++;
    }
    /* Not found. Add an entry for this value */
    if (i >= STATUSES_PER_CONNECTION) {
        /* No room. Oh well, not much anyone can do about it. */
        return;
    }
    ap_cpystrn(ss->key, key, KEY_LENGTH);
    ap_cpystrn(ss->value, value, VALUE_LENGTH);
    return;
}

ap_array_header_t *ap_get_status_table(ap_context_t *p)
{
    int i, j;
    ap_array_header_t *server_status;
    ap_status_table_row_t *array_slot;
    status_table_entry *ss;

    server_status = ap_make_array(p, 0, sizeof(ap_status_table_row_t));

    /* Go ahead and return what's in the connection status table even if we
     * aren't maintaining it. We can at least look at what children from
     * previous generations are up to. */

    for (i = 0; i < max_daemons_limit*HARD_THREAD_LIMIT; i++) {
	if (ap_scoreboard_image->table[i][0].key[0] == '\0')
	    continue;
        array_slot = ap_push_array(server_status);
        array_slot->data = ap_make_table(p, 0);
        array_slot->conn_id = i;
        
        for (j = 0; j < STATUSES_PER_CONNECTION; j++) {
	    ss = &(ap_scoreboard_image->table[i][j]);
            if (ss->key[0] != '\0') {
                ap_table_add(array_slot->data, ss->key, ss->value);
            }
            else {
                break;
            }
        }
    }
    return server_status;
}
