
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
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
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
 * httpd.c: simple http daemon for answering WWW file requests
 *
 * 
 * 03-21-93  Rob McCool wrote original code (up to NCSA HTTPd 1.3)
 * 
 * 03-06-95  blong
 *  changed server number for child-alone processes to 0 and changed name
 *   of processes
 *
 * 03-10-95  blong
 * 	Added numerous speed hacks proposed by Robert S. Thau (rst@ai.mit.edu) 
 *	including set group before fork, and call gettime before to fork
 * 	to set up libraries.
 *
 * 04-14-95  rst / rh
 *      Brandon's code snarfed from NCSA 1.4, but tinkered to work with the
 *      Apache server, and also to have child processes do accept() directly.
 *
 * April-July '95 rst
 *      Extensive rework for Shambhala.
 */


#define CORE_PRIVATE

#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"	/* for read_config */
#include "http_protocol.h"	/* for read_request */
#include "http_request.h"	/* for process_request */
#include "http_conf_globals.h"
#include "scoreboard.h"
#include <setjmp.h>

/*
 * Actual definitions of config globals... here because this is
 * for the most part the only code that acts on 'em.  (Hmmm... mod_main.c?)
 */

int standalone;
uid_t user_id;
char *user_name;
gid_t group_id;
int max_requests_per_child;
char *pid_fname;
char *server_argv0;
struct in_addr bind_address;
int daemons_to_start;
int daemons_min_free;
int daemons_max_free;
int daemons_limit;

char server_root[MAX_STRING_LEN];
char server_confname[MAX_STRING_LEN];

/* *Non*-shared http_main globals... */

server_rec *server_conf;
JMP_BUF jmpbuffer;
JMP_BUF restart_buffer;
int sd;
pid_t pgrp;

/* one_process --- debugging mode variable; can be set from the command line
 * with the -X flag.  If set, this gets you the child_main loop running
 * in the process which originally started up (no detach, no make_child),
 * which is a pretty nice debugging environment.  (You'll get a SIGHUP
 * early in standalone_main; just continue through.  This is the server
 * trying to kill off any child processes which it might have lying
 * around --- Shambhala doesn't keep track of their pids, it just sends
 * SIGHUP to the process group, ignoring it in the root process.
 * Continue through and you'll be fine.).
 */

int one_process = 0;

#ifdef FCNTL_SERIALIZED_ACCEPT
static struct flock lock_it = { F_WRLCK, 0, 0, 0 };
static struct flock unlock_it = { F_UNLCK, 0, 0, 0 };

static int lock_fd=-1;

/*
 * Initialise mutex lock.
 * Must be safe to call this on a restart.
 */
void
accept_mutex_init(pool *p)
{
    char lock_fname[30];

    strcpy(lock_fname, "/usr/tmp/htlock.XXXXXX");
    
    if (mktemp(lock_fname) == NULL || lock_fname[0] == '\0')
    {
	fprintf (stderr, "Cannot assign name to lock file!\n");
	exit (1);
    }

    lock_fd = popenf(p, lock_fname, O_CREAT | O_WRONLY, 0644);
    if (lock_fd == -1)
    {
	perror ("open");
	fprintf (stderr, "Cannot open lcok file\n");
	exit (1);
    }
    unlink(lock_fname);
}

void accept_mutex_on()
{
    int ret;
    
    while ((ret = fcntl(lock_fd, F_SETLKW, &lock_it)) < 0 && errno == EINTR)
	continue;

    if (ret < 0) {
	log_error ("Unknown failure grabbing accept lock.  Exiting!",
		   server_conf);
	exit(1);
    }
}

void accept_mutex_off()
{
    if (fcntl (lock_fd, F_SETLKW, &unlock_it) < 0)
    {
	log_error("Error freeing accept lock.  Exiting!", server_conf);
	exit(1);
    }
}
#else
/* Default --- no serialization.  Other methods *could* go here,
 * as #elifs...
 */
#define accept_mutex_init(x)
#define accept_mutex_on()
#define accept_mutex_off()
#endif

void usage(char *bin)
{
    fprintf(stderr,"Usage: %s [-d directory] [-f file] [-v]\n",bin);
    fprintf(stderr,"-d directory : specify an alternate initial ServerRoot\n");
    fprintf(stderr,"-f file : specify an alternate ServerConfigFile\n");
    exit(1);
}

/*****************************************************************
 *
 * Timeout handling.  DISTINCTLY not thread-safe, but all this stuff
 * has to change for threads anyway.  Note that this code allows only
 * one timeout in progress at a time...
 */

static conn_rec *current_conn;
static request_rec *timeout_req;
static char *timeout_name;
static int alarms_blocked = 0;
static int alarm_pending = 0;

void abort_connection (conn_rec *);

void timeout(sig)			/* Also called on SIGPIPE */
int sig;
{
    char errstr[MAX_STRING_LEN];

    if (alarms_blocked) {
	alarm_pending = 1;
	return;
    }
    
    if (!current_conn) {
#ifdef NEXT
	longjmp(jmpbuffer,1);
#else
	siglongjmp(jmpbuffer,1);
#endif
    }
    
    sprintf(errstr,"%s timed out for %s",
	    timeout_name ? timeout_name : "request",
	    current_conn->remote_name);
    
    log_error(errstr, current_conn->server);
      
    if (timeout_req) {
	/* Someone has asked for this transaction to just be aborted
	 * if it times out...
	 */
	
	request_rec *log_req = timeout_req;
	
	while (log_req->main || log_req->prev) {
	    /* Get back to original request... */
	    if (log_req->main) log_req = log_req->main;
	    else log_req = log_req->prev;
	}
	
	log_transaction(log_req);

	pfclose (timeout_req->connection->pool,
		 timeout_req->connection->client);
	pfclose (timeout_req->connection->pool,
	         timeout_req->connection->request_in);
    
	if (!standalone) exit(0);
#ifdef NEXT
	longjmp(jmpbuffer,1);
#else
	siglongjmp(jmpbuffer,1);
#endif
    }
    else {
	abort_connection (current_conn);
    }
}

/*
 * These two called from alloc.c to protect its critical sections...
 * Note that they can nest (as when destroying the sub_pools of a pool
 * which is itself being cleared); we have to support that here.
 */

void block_alarms() {
    ++alarms_blocked;
}

void unblock_alarms() {
    --alarms_blocked;
    if (alarms_blocked == 0 && alarm_pending) {
	alarm_pending = 0;
	timeout(0);
    }
}

void hard_timeout (char *name, request_rec *r)
{
    timeout_req = r;
    timeout_name = name;
    
    signal(SIGALRM,(void (*)())timeout);
    alarm (r->server->timeout);
}

void soft_timeout (char *name, request_rec *r)
{
    timeout_name = name;
    
    signal(SIGALRM,(void (*)())timeout);
    alarm (r->server->timeout);
}

void kill_timeout (request_rec *dummy) {
    alarm (0);
    timeout_req = NULL;
    timeout_name = NULL;
}
 
/*****************************************************************
 *
 * Dealing with the scoreboard... a lot of these variables are global
 * only to avoid getting clobbered by the longjmp() that happens when
 * a hard timeout expires...
 *
 * We begin with routines which deal with the file itself... 
 */

static short_score scoreboard_image[HARD_SERVER_MAX];
static char scoreboard_fname[] = "/tmp/htstatus.XXXXXX";
static int have_scoreboard_fname = 0;
static int scoreboard_fd;

static int force_write (int fd, char *buffer, int bufsz)
{
    int rv, orig_sz = bufsz;
    
    do {
	rv = write (fd, buffer, bufsz);
	if (rv > 0) {
	    buffer += rv;
	    bufsz -= rv;
	}
    } while (rv > 0 && bufsz > 0);

    return rv < 0? rv : orig_sz - bufsz;
}

static int force_read (int fd, char *buffer, int bufsz)
{
    int rv, orig_sz = bufsz;
    
    do {
	rv = read (fd, buffer, bufsz);
	if (rv > 0) {
	    buffer += rv;
	    bufsz -= rv;
	}
    } while (rv > 0 && bufsz > 0);
    
    return rv < 0? rv : orig_sz - bufsz;
}

void reinit_scoreboard (pool *p)
{
    if (!have_scoreboard_fname && (mktemp(scoreboard_fname) == NULL ||
				   scoreboard_fname[0] == '\0')) {
	fprintf (stderr, "Cannot assign name to scoreboard file!\n");
	exit (1);
    }
    
    have_scoreboard_fname = 1;
    
    scoreboard_fd = popenf(p, scoreboard_fname, O_CREAT|O_RDWR, 0644);
    if (scoreboard_fd == -1)
    {
	fprintf (stderr, "Cannot open scoreboard file:\n");
	perror (scoreboard_fname);
	exit (1);
    }

    memset ((char*)scoreboard_image, 0, sizeof(scoreboard_image));
    force_write (scoreboard_fd, (char*)scoreboard_image,
		 sizeof(scoreboard_image));
}

void reopen_scoreboard (pool *p)
{
    if (scoreboard_fd != -1) pclosef (p, scoreboard_fd);
    
    scoreboard_fd = popenf(p, scoreboard_fname, O_CREAT|O_RDWR, 0666);
    if (scoreboard_fd == -1)
    {
	fprintf (stderr, "Cannot open scoreboard file:\n");
	perror (scoreboard_fname);
	exit (1);
    }
}

void cleanup_scoreboard ()
{
    unlink (scoreboard_fname);
}

/* Routines called to deal with the scoreboard image
 * --- note that we do *not* need write locks, since update_child_status
 * only updates a *single* record in place, and only one process writes to
 * a given scoreboard slot at a time (either the child process owning that
 * slot, or the parent, noting that the child has died).
 *
 * As a final note --- setting the score entry to getpid() is always safe,
 * since when the parent is writing an entry, it's only noting SERVER_DEAD
 * anyway.
 */

void sync_scoreboard_image ()
{
    lseek (scoreboard_fd, 0L, 0);
    force_read (scoreboard_fd, (char*)scoreboard_image,
		sizeof(scoreboard_image));
}

void update_child_status (int child_num, int status)
{
    short_score new_score_rec;
    new_score_rec.pid = getpid();
    new_score_rec.status = status;

    lseek (scoreboard_fd, (long)child_num * sizeof(short_score), 0);
    force_write (scoreboard_fd, (char*)&new_score_rec, sizeof(short_score));
}

int count_idle_servers ()
{
    int i;
    int res = 0;

    for (i = 0; i < HARD_SERVER_MAX; ++i)
	if (scoreboard_image[i].status == SERVER_READY)
	    ++res;

    return res;
}

int find_free_child_num ()
{
    int i;

    for (i = 0; i < HARD_SERVER_MAX; ++i)
	if (scoreboard_image[i].status == SERVER_DEAD)
	    return i;

    return -1;
}

int find_child_by_pid (int pid)
{
    int i;

    for (i = 0; i < HARD_SERVER_MAX; ++i)
	if (scoreboard_image[i].pid == pid)
	    return i;

    return -1;
}

void reclaim_child_processes ()
{
    int i, status;
    int my_pid = getpid();

    sync_scoreboard_image();
    for (i = 0; i < HARD_SERVER_MAX; ++i) {
	int pid = scoreboard_image[i].pid;

	if (pid != my_pid && pid != 0)
	    waitpid (scoreboard_image[i].pid, &status, 0);
    }
}

/* Finally, this routine is used by the caretaker process to wait for
 * a while...
 */

static jmp_buf wait_timeout_buf;
static int wait_or_timeout_retval = -1;

static void longjmp_out_of_alarm (int sig) {
    longjmp (wait_timeout_buf, 1);
}

int wait_or_timeout (int *status)
{
    wait_or_timeout_retval = -1;
    
    if (setjmp(wait_timeout_buf) != 0) {
	errno = ETIMEDOUT;
	alarm(0);
	return wait_or_timeout_retval;
    }
    
    signal (SIGALRM, longjmp_out_of_alarm);
    alarm(1);
#if defined(NEXT)
    wait_or_timeout_retval = wait((union wait *)status);
#else
    wait_or_timeout_retval = wait(status);
#endif
    alarm(0);
    return wait_or_timeout_retval;
}


/*****************************************************************
 * Here follows a long bunch of generic server bookkeeping stuff...
 */

void detach()
{
    int x;

    chdir("/");
    if((x = fork()) > 0)
        exit(0);
    else if(x == -1) {
        fprintf(stderr,"httpd: unable to fork new process\n");
        perror("fork");
        exit(1);
    }
#ifndef NO_SETSID
    if((pgrp=setsid()) == -1) {
        fprintf(stderr,"httpd: setsid failed\n");
        perror("setsid");
        exit(1);
    }
#else
#if defined(NEXT)
    if(setpgrp(0,getpid()) == -1 || (pgrp = getpgrp(0)) == -1) {
        fprintf(stderr,"httpd: setpgrp or getpgrp failed\n");
        perror("setpgrp");
        exit(1);
    }
#else
    if((pgrp=setpgrp(getpid(),0)) == -1) {
        fprintf(stderr,"httpd: setpgrp failed\n");
        perror("setpgrp");
        exit(1);
    }
#endif    
#endif
}

void sig_term() {
    log_error("httpd: caught SIGTERM, shutting down", server_conf);
    cleanup_scoreboard();
#ifndef NO_KILLPG
    killpg(pgrp,SIGKILL);
#else
    kill(-pgrp,SIGKILL);
#endif
    shutdown(sd,2);
    close(sd);
    exit(1);
}

void bus_error() {
    log_error("httpd: caught SIGBUS, dumping core", server_conf);
    chdir(server_root);
    abort();         
    exit(1);
}

void seg_fault() {
    log_error("httpd: caught SIGSEGV, dumping core", server_conf);
    chdir(server_root);
    abort();
    exit(1);
}

void just_die()			/* SIGHUP to child process??? */
{
    exit (0);
}

/* Reset group privileges, after rereading the config files
 * (our uid may have changed, and if so, we want the new perms).
 *
 * Don't reset the uid yet --- we do that only in the child process,
 * so as not to lose any root privs.  But we can set the group stuff
 * now, once, as opposed to once per each new child.
 *
 * Note that we use the username as set in the config files, rather than
 * the lookup of to uid --- the same uid may have multiple passwd entries,
 * with different sets of groups for each.
 */
  
static void set_group_privs()
{
  if(!geteuid()) {
    char *name;
  
    /* Get username if passed as a uid */
    
    if (user_name[0] == '#') {
      struct passwd* ent;
      uid_t uid=atoi(&user_name[1]);

      if ((ent = getpwuid(uid)) == NULL) {
	 log_error("couldn't determine user name from uid", server_conf);
	 exit(1);
      }
      
      name = ent->pw_name;
    } else name = user_name;

    /* Reset `groups' attributes. */
    
    if (initgroups(name, group_id) == -1) {
        log_error ("unable to set groups", server_conf);
	exit (1);
    }

    if (setgid(group_id) == -1) {
        log_error ("unable to set group id", server_conf);
	exit (1);
    }
  }
}

void restart() {
    signal (SIGALRM, SIG_IGN);
    alarm (0);
#ifdef NEXT
    longjmp(restart_buffer,1);
#else
    siglongjmp(restart_buffer,1);
#endif
}

void set_signals() {
	if(!one_process)
	{
	    signal(SIGSEGV,(void (*)())seg_fault);
    	signal(SIGBUS,(void (*)())bus_error);
	}
    signal(SIGTERM,(void (*)())sig_term);
    signal(SIGHUP,(void (*)())restart);
}

/*****************************************************************
 * Connection structures and accounting...
 * Should these be global?  Only to this file, at least...
 */

pool *pconf;			/* Pool for config stuff */
pool *ptrans;			/* Pool for per-transaction stuff */

server_rec *find_virtual_server (struct in_addr server_ip, server_rec *server)
{
    server_rec *virt;

    for (virt = server->next; virt; virt = virt->next)
	if (virt->host_addr.s_addr == server_ip.s_addr)
	    return virt;

    return server;
}

void default_server_hostnames(server_rec *s)
{
    /* Main host first */
    
    if (!s->server_hostname)
	s->server_hostname = get_local_host(pconf);

    /* Then virtual hosts */
    
    for (s = s->next; s; s = s->next)
	if (!s->server_hostname) {
	    struct hostent *h = gethostbyaddr ((char *)&(s->host_addr),
					       sizeof (struct in_addr),
					       AF_INET);
	    if (h != NULL) {
		s->server_hostname = pstrdup (pconf, (char *)h->h_name);
	    }
	}
}
	
void abort_connection (conn_rec *c)
{
    /* Make sure further I/O DOES NOT HAPPEN */
    shutdown (fileno (c->client), 2);
    signal (SIGPIPE, SIG_IGN);	/* Ignore further complaints */
    c->aborted = 1;
}

conn_rec *new_connection (pool *p, server_rec *server, FILE *in, FILE *out,
			  const struct sockaddr_in *saddr)
{
    conn_rec *conn = (conn_rec *)pcalloc (p, sizeof(conn_rec));
    
    /* Get a connection structure, and initialize what fields we can
     * (the rest are zeroed out by pcalloc).
     */
    
    conn = (conn_rec *)pcalloc(p, sizeof(conn_rec));
    
    conn->pool = p;
    conn->server = find_virtual_server (saddr->sin_addr, server);
    conn->client = out;
    conn->request_in = in;
    
    get_remote_host(conn);
    
    return conn;
}

/*****************************************************************
 * Child process main loop.
 * The following vars are static to avoid getting clobbered by longjmp();
 * they are really private to child_main.
 */

static int csd;
static int dupped_csd;
static int requests_this_child;
static int child_num;

void child_main(int child_num_arg)
{
    int clen;
    struct sockaddr sa_server;
    struct sockaddr sa_client;

#ifdef ULTRIX_BRAIN_DEATH
    extern char *rfc931();
#else
    extern char *rfc931 (struct sockaddr_in *, struct sockaddr_in *);
#endif

    csd = -1;
    dupped_csd = -1;
    child_num = child_num_arg;
    requests_this_child = 0;
    reopen_scoreboard (pconf);
    update_child_status (child_num, SERVER_READY);

    /* Only try to switch if we're running as root */
    if(!geteuid() && setuid(user_id) == -1) {
        log_error ("unable to change uid", server_conf);
	exit (1);
    }

#ifdef NEXT
    setjmp(jmpbuffer);
#else
    sigsetjmp(jmpbuffer,1);
#endif
    signal(SIGURG, timeout);

    while (1) {
	FILE *conn_in, *conn_out;
	request_rec *r;
      
        alarm(0);		/* Cancel any outstanding alarms. */
        timeout_req = NULL;	/* No request in progress */
	current_conn = NULL;
        signal(SIGPIPE, timeout);  
    
	clear_pool (ptrans);
	
	sync_scoreboard_image();
	
	if ((count_idle_servers() >= daemons_max_free)
	    || (max_requests_per_child > 0
	        && ++requests_this_child >= max_requests_per_child))
	{
	    exit(0);
	}

	clen=sizeof(sa_client);
	update_child_status (child_num, SERVER_READY);
	
	accept_mutex_on();  /* Lock around "accept", if necessary */
	
	while ((csd=accept(sd, &sa_client, &clen)) == -1) 
           if (errno != EINTR) 
		log_error("socket error: accept failed", server_conf);

	accept_mutex_off(); /* unlock after "accept" */

	clen = sizeof(sa_server);
	if(getsockname(csd, &sa_server, &clen) < 0) {
	    log_error("getsockname: failed", server_conf);
	    continue;
	}
	
	dupped_csd = csd;
#if defined(AUX) || defined(SCO)
	if ((dupped_csd = dup(csd)) < 0) {
	    log_error("couldn't duplicate csd", server_conf);
	    dupped_csd = csd;	/* Oh well... */
	}
#endif
	update_child_status (child_num, SERVER_BUSY);
	conn_in = pfdopen (ptrans, csd, "r");
	conn_out = pfdopen (ptrans, dupped_csd, "w");

	current_conn = new_connection (ptrans, server_conf, conn_in, conn_out,
				       (struct sockaddr_in *)&sa_server);

	if (current_conn->server->do_rfc931)
	    current_conn->remote_logname = 
		rfc931((struct sockaddr_in *)&sa_client,
		       (struct sockaddr_in *)&sa_server);
	
	r = read_request (current_conn);
	if (r) process_request (r); /* else premature EOF --- ignore */
		
	if (bytes_in_pool (ptrans) > 80000) {
	    char errstr[MAX_STRING_LEN];
	    sprintf (errstr, "Memory hog alert: allocated %ld bytes for %s",
	             bytes_in_pool (ptrans), r->the_request);
            log_error (errstr, r->server);
        }
		
	fflush (conn_out);
	pfclose (ptrans,conn_in);
	pfclose (ptrans,conn_out);
    }    
}

void make_child(server_rec *server_conf, int child_num)
{
    int pid;

    if (one_process) {
	signal (SIGHUP, (void (*)())just_die);
	signal (SIGTERM, (void (*)())just_die);
	child_main (child_num);
    }

    if ((pid = fork()) == -1) {
	log_error("Unable to fork new process", server_conf);
	return;
    } 
    
    if (!pid) {
	signal (SIGHUP, (void (*)())just_die);
	signal (SIGTERM, (void (*)())just_die);
	child_main (child_num);
    }
}

/*****************************************************************
 * Executive routines.
 */

static int keepalive_value = 1;  
static int one = 1;
static int num_children = 0;

void standalone_main(int argc, char **argv)
{
    struct sockaddr_in sa_server;

    standalone = 1;
    sd = -1;
    
    if (!one_process) detach(); 
    
#ifdef NEXT
    setjmp(restart_buffer);
#else
    sigsetjmp(restart_buffer,1);
#endif

    signal (SIGHUP, SIG_IGN);	/* Until we're done (re)reading config */
    
    if(!one_process)
#ifndef NO_KILLPG
      killpg(pgrp,SIGHUP);	/* Kill 'em off */
#else
      kill(-pgrp,SIGHUP);
#endif
    
    if (sd != -1) {
	reclaim_child_processes(); /* Not when just starting up */
	log_error ("SIGHUP received.  Attempting to restart", server_conf);
    }
    
    clear_pool (pconf);
    ptrans = make_sub_pool (pconf);
    
    server_conf = read_config(pconf, ptrans, server_confname); 
    open_logs(server_conf, pconf);
    set_group_privs();
    accept_mutex_init(pconf);
    reinit_scoreboard(pconf);
    
    default_server_hostnames (server_conf);

    if ((sd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) == -1) {
        fprintf(stderr,"httpd: could not get socket\n");
        perror("socket");
        exit(1);
    }

    note_cleanups_for_fd (pconf, sd); /* arrange to close on exec or restart */
    
    if((setsockopt(sd,SOL_SOCKET,SO_REUSEADDR,(const char *)&one,sizeof(one)))
       == -1) {
        fprintf(stderr,"httpd: could not set socket option\n");
        perror("setsockopt");
        exit(1);
    }
    if((setsockopt(sd,SOL_SOCKET,SO_KEEPALIVE,(const void *)&keepalive_value,
        sizeof(keepalive_value))) == -1) {
        fprintf(stderr,"httpd: could not set socket option SO_KEEPALIVE\n"); 
        perror("setsockopt"); 
        exit(1); 
    }

    memset((char *) &sa_server, 0, sizeof(sa_server));
    sa_server.sin_family=AF_INET;
    sa_server.sin_addr=bind_address;
    sa_server.sin_port=htons(server_conf->port);
    if(bind(sd,(struct sockaddr *) &sa_server,sizeof(sa_server)) == -1) {
	if (bind_address.s_addr != htonl(INADDR_ANY))
	    fprintf(stderr,"httpd: could not bind to address %s port %d\n",
		    inet_ntoa(bind_address), server_conf->port);
	else
	    fprintf(stderr,"httpd: could not bind to port %d\n",
		    server_conf->port);
        perror("bind");
        exit(1);
    }
    listen(sd, 512);

    set_signals();
    log_pid(pconf, pid_fname);

    num_children = 0;
    
    if (daemons_max_free < daemons_min_free + 1) /* Don't thrash... */
	daemons_max_free = daemons_min_free + 1;

    while (num_children < daemons_to_start) {
	make_child(server_conf, num_children++);
    }

    log_error ("Server configured -- resuming normal operations", server_conf);
    
    while (1) {
	int status, child_slot;
	int pid = wait_or_timeout(&status);
	
	if (pid >= 0) {
	    /* Child died... note that it's gone in the scoreboard. */
	    sync_scoreboard_image();
	    child_slot = find_child_by_pid (pid);
	    if (child_slot >= 0) update_child_status (child_slot, SERVER_DEAD);
        }

	sync_scoreboard_image();
	if ((count_idle_servers() < daemons_min_free)
	    && (child_slot = find_free_child_num()) >= 0
	    && child_slot <= daemons_limit)
	    make_child(server_conf, child_slot);
    }

} /* standalone_main */

extern char *optarg;
extern int optind;

int
main(int argc, char *argv[])
{
    int c;

    init_alloc();
    pconf = permanent_pool;
    ptrans = make_sub_pool(pconf);
    
    server_argv0 = argv[0];
    strcpy (server_root, HTTPD_ROOT);
    strcpy (server_confname, SERVER_CONFIG_FILE);

    while((c = getopt(argc,argv,"Xd:f:v")) != -1) {
        switch(c) {
          case 'd':
            strcpy (server_root, optarg);
            break;
          case 'f':
            strcpy (server_confname, optarg);
            break;
          case 'v':
            printf("Server version %s.\n",SERVER_VERSION);
            exit(1);
	  case 'X':
	    ++one_process;	/* Weird debugging mode. */
	    break;
          case '?':
            usage(argv[0]);
        }
    }

    setup_prelinked_modules();
    
    server_conf = read_config (pconf, ptrans, server_confname);
    
    if(standalone) {
        clear_pool (pconf);	/* standalone_main rereads... */
        standalone_main(argc, argv);
    }
    else {
        conn_rec *conn;
	request_rec *r;
	struct sockaddr sa_server;
      
	open_logs(server_conf, pconf);
	set_group_privs();
	default_server_hostnames (server_conf);

        user_id = getuid();
        group_id = getgid();

	c = sizeof(sa_server);
	if(getsockname(csd, &sa_server, &c) < 0) {
	    perror("getsockname");
	    fprintf(stderr, "Error getting local address\n");
	    exit(1);
	}
	server_conf->port =ntohs(((struct sockaddr_in *)&sa_server)->sin_port);
	conn = new_connection (ptrans, server_conf, stdin, stdout,
			       (struct sockaddr_in *)&sa_server);
	r = read_request (conn);
	if (r) process_request (r); /* else premature EOF (ignore) */
    }
    exit (0);
}


