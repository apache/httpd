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

#include "apr_strings.h"
#include "apr_portable.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "http_config.h"
#include "unixd.h"
#include "http_conf_globals.h"
#include "mpm.h"
#include "scoreboard.h"
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

AP_DECLARE_DATA scoreboard *ap_scoreboard_image = NULL;
AP_DECLARE_DATA const char *ap_scoreboard_fname=NULL;
AP_DECLARE_DATA int ap_extended_status = 0;
AP_DECLARE_DATA apr_time_t ap_restart_time = 0;

#if APR_HAS_SHARED_MEMORY
#include "apr_shmem.h"

static apr_shmem_t *scoreboard_shm = NULL;

apr_status_t ap_cleanup_shared_mem(void *d)
{
    apr_shm_free(scoreboard_shm, ap_scoreboard_image);
    ap_scoreboard_image = NULL;
    apr_shm_destroy(scoreboard_shm);

    return APR_SUCCESS;
}

static void setup_shared_mem(apr_pool_t *p)
{
    char buf[512];
    char errmsg[120];
    const char *fname;
    apr_status_t rv;

    fname = ap_server_root_relative(p, ap_scoreboard_fname);
    rv = apr_shm_init(&scoreboard_shm, SCOREBOARD_SIZE, fname, p);
    if (rv != APR_SUCCESS) {
        apr_snprintf(buf, sizeof(buf), "%s: could not open(create) scoreboard: %s",
                    ap_server_argv0, apr_strerror(rv, errmsg, sizeof errmsg));
        fprintf(stderr, "%s\n", buf);
        exit(APEXIT_INIT);
    }
    ap_scoreboard_image = apr_shm_malloc(scoreboard_shm, SCOREBOARD_SIZE);
    if (ap_scoreboard_image == NULL) {
        apr_snprintf(buf, sizeof(buf), "%s: cannot allocate scoreboard",
                    ap_server_argv0);
        perror(buf); /* o.k. since MM sets errno */
        apr_shm_destroy(scoreboard_shm);
        exit(APEXIT_INIT);
    }
    apr_register_cleanup(p, NULL, ap_cleanup_shared_mem, apr_null_cleanup);
    ap_scoreboard_image->global.running_generation = 0;
}

void reopen_scoreboard(apr_pool_t *p)
{
}
#endif   /* APR_SHARED_MEM */

/* Called by parent process */
void reinit_scoreboard(apr_pool_t *p)
{
    int running_gen = 0;
    if (ap_scoreboard_image)
	running_gen = ap_scoreboard_image->global.running_generation;
    if (ap_scoreboard_image == NULL) {
        setup_shared_mem(p);
    }
    memset(ap_scoreboard_image, 0, SCOREBOARD_SIZE);
    ap_scoreboard_image->global.running_generation = running_gen;
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

apr_inline void ap_sync_scoreboard_image(void)
{
}

AP_DECLARE(int) ap_exists_scoreboard_image(void)
{
    return (ap_scoreboard_image ? 1 : 0);
}

static apr_inline void put_scoreboard_info(int child_num, int thread_num, 
				       short_score *new_score_rec)
{
    /* XXX - needs to be fixed to account for threads */
#ifdef SCOREBOARD_FILE
    lseek(scoreboard_fd, (long) child_num * sizeof(short_score), 0);
    force_write(scoreboard_fd, new_score_rec, sizeof(short_score));
#endif
}

void update_scoreboard_global(void)
{
#ifdef SCOREBOARD_FILE
    lseek(scoreboard_fd,
	  (char *) &ap_scoreboard_image->global -(char *) ap_scoreboard_image, 0);
    force_write(scoreboard_fd, &ap_scoreboard_image->global,
		sizeof ap_scoreboard_image->global);
#endif
}

void increment_counts(int child_num, int thread_num, request_rec *r)
{
    short_score *ss;

    ss = &ap_scoreboard_image->servers[child_num][thread_num];

#ifdef HAVE_TIMES
    times(&ss->times);
#endif
    ss->access_count++;
    ss->my_access_count++;
    ss->conn_count++;
    ss->bytes_served += r->bytes_sent;
    ss->my_bytes_served += r->bytes_sent;
    ss->conn_bytes += r->bytes_sent;

    put_scoreboard_info(child_num, thread_num, ss);
}

AP_DECLARE(int) find_child_by_pid(apr_proc_t *pid)
{
    int i;
    int max_daemons_limit = ap_get_max_daemons();

    for (i = 0; i < max_daemons_limit; ++i)
	if (ap_scoreboard_image->parent[i].pid == pid->pid)
	    return i;

    return -1;
}

int ap_update_child_status(int child_num, int thread_num, int status, request_rec *r)
{
    int old_status;
    short_score *ss;
    parent_score *ps;

    if (child_num < 0)
	return -1;

    ss = &ap_scoreboard_image->servers[child_num][thread_num];
    old_status = ss->status;
    ss->status = status;

    ps = &ap_scoreboard_image->parent[child_num];
    
    if ((status == SERVER_READY  || status == SERVER_ACCEPTING)
	&& old_status == SERVER_STARTING) {
        ss->thread_num = child_num * HARD_SERVER_LIMIT + thread_num;
	ps->worker_threads = ap_threads_per_child;
    }

    if (ap_extended_status) {
	if (status == SERVER_READY || status == SERVER_DEAD) {
	    /*
	     * Reset individual counters
	     */
	    if (status == SERVER_DEAD) {
		ss->my_access_count = 0L;
		ss->my_bytes_served = 0L;
	    }
	    ss->conn_count = (unsigned short) 0;
	    ss->conn_bytes = (unsigned long) 0;
	}
	if (r) {
	    conn_rec *c = r->connection;
	    apr_cpystrn(ss->client, ap_get_remote_host(c, r->per_dir_config,
				  REMOTE_NOLOOKUP), sizeof(ss->client));
	    if (r->the_request == NULL) {
		    apr_cpystrn(ss->request, "NULL", sizeof(ss->request));
	    } else if (r->parsed_uri.password == NULL) {
		    apr_cpystrn(ss->request, r->the_request, sizeof(ss->request));
	    } else {
		/* Don't reveal the password in the server-status view */
		    apr_cpystrn(ss->request, apr_pstrcat(r->pool, r->method, " ",
					       ap_unparse_uri_components(r->pool, &r->parsed_uri, UNP_OMITPASSWORD),
					       r->assbackwards ? NULL : " ", r->protocol, NULL),
				       sizeof(ss->request));
	    }
	    ss->vhostrec =  r->server;
	}
    }
    
    put_scoreboard_info(child_num, thread_num, ss);
    return old_status;
}

void ap_time_process_request(int child_num, int thread_num, int status)
{
    short_score *ss;

    if (child_num < 0)
	return;

    ss = &ap_scoreboard_image->servers[child_num][thread_num];

    if (status == START_PREQUEST) {
        ss->start_time = apr_now(); 
    }
    else if (status == STOP_PREQUEST) {
        ss->stop_time = apr_now(); 
    }
    put_scoreboard_info(child_num, thread_num, ss);
}

