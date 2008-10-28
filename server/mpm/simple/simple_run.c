/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define APR_RING_DEBUG 1

#include "httpd.h"
#include "http_log.h"
#include "simple_types.h"
#include "simple_event.h"
#include "simple_children.h"
#include "simple_run.h"
#include "simple_io.h"
#include "ap_mpm.h"
#include "scoreboard.h"

#include "ap_listen.h"

/**
 * Create Timers.
 */
static apr_status_t
simple_main_setup_timers(simple_core_t *sc)
{
  simple_register_timer(sc,
                        simple_check_children_size,
                        NULL,
                        0);

  return APR_SUCCESS;
}

/**
 * Create worker thread pool.
 */
static apr_status_t
simple_setup_workers(simple_core_t *sc)
{
  apr_status_t rv;

  ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL,
               "simple_setup_workers: spawning %d threads", sc->procmgr.thread_count);

  rv = apr_thread_pool_create(&sc->workers,
                              sc->procmgr.thread_count,
                              sc->procmgr.thread_count,
                              sc->pool);

  if (rv) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                 "simple_setup_workers: apr_thread_pool_create with %d threads failed", sc->procmgr.thread_count);
    return rv;
  }

  return APR_SUCCESS;
}

static apr_status_t
simple_setup_listeners(simple_core_t *sc)
{
  ap_listen_rec *lr;
  apr_status_t rv;

  for (lr = ap_listeners; lr != NULL; lr = lr->next) {
    apr_pollfd_t *pfd = apr_palloc(sc->pool, sizeof(apr_pollfd_t));
    simple_sb_t *sb = apr_pcalloc(sc->pool, sizeof(simple_sb_t));

    pfd->p = sc->pool;
    pfd->desc_type = APR_POLL_SOCKET;
    pfd->desc.s = lr->sd;
    pfd->reqevents = APR_POLLIN;
    
    sb->type = SIMPLE_PT_CORE_ACCEPT;
    sb->baton = lr;

    pfd->client_data = sb;

    rv = apr_socket_opt_set(pfd->desc.s, APR_SO_NONBLOCK, 1);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                   "simple_setup_workers: apr_socket_opt_set(APR_SO_NONBLOCK = 1) failed on %pI", lr->bind_addr);
      return rv;
    }
    
    rv = apr_pollcb_add(sc->pollcb, pfd);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                   "simple_setup_workers: apr_pollcb_add failed on %pI", lr->bind_addr);
      return rv;
    }
  }

  return APR_SUCCESS;
}



static apr_status_t
simple_io_callback(void *baton, apr_pollfd_t *pfd)
{
  apr_status_t rv = APR_SUCCESS;
  simple_core_t *sc = (simple_core_t *)baton;
  simple_sb_t *sb = pfd->client_data;

  
  if (sb->type == SIMPLE_PT_CORE_ACCEPT) {
    rv = simple_io_accept(sc, sb);
  }
  else if (sb->type == SIMPLE_PT_CORE_IO) {
    rv = simple_io_event_process(sc, sb);
  }
  else if (sb->type == SIMPLE_PT_USER) {
    /* TODO: */
    abort();
  }
  else {
    abort();
  }

  return rv;
}

static void *
simple_timer_invoke(apr_thread_t* thread, void *baton)
{
  simple_timer_t *ep = (simple_timer_t *)baton;
  simple_core_t *sc = simple_core_get();

  ep->cb(sc, ep->baton);
 
  apr_thread_mutex_lock(sc->mtx);
  APR_RING_INSERT_TAIL(&sc->dead_timer_ring, ep, simple_timer_t, link);
  apr_thread_mutex_unlock(sc->mtx);

  return NULL;
}

#ifndef apr_time_from_msec
#define apr_time_from_msec(msec) ((apr_time_t)(msec) * 1000)
#endif

static int
simple_run_loop(simple_core_t *sc)
{
  apr_status_t rv;
  simple_timer_t *ep = NULL;
  
  while (sc->mpm_state == AP_MPMQ_RUNNING) {
    apr_time_t now = apr_time_now();
    apr_interval_time_t timeout = apr_time_from_msec(500);
    
    apr_thread_mutex_lock(sc->mtx);
    simple_timer_t *head = APR_RING_FIRST(&sc->timer_ring);
    
    if (head != APR_RING_SENTINEL(&sc->timer_ring, simple_timer_t, link)) {
      if (now < head->expires) {
        timeout = (head->expires - now);
        if (timeout > apr_time_from_msec(500)) {
          /* pqXXXXX: I'm 95% sure that the Linux Powertop guys will slap me for this. */
          timeout = apr_time_from_msec(500);
        }
      }
    }
    apr_thread_mutex_unlock(sc->mtx);

    rv = apr_pollcb_poll(sc->pollcb,
                         timeout,
                         simple_io_callback,
                         sc);

    now = apr_time_now();

    if (rv) {
      if (!APR_STATUS_IS_EINTR(rv) && !APR_STATUS_IS_TIMEUP(rv)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "simple_main_loop: apr_pollcb_poll failed");
        return !OK;
      }
    }
    
    APR_RING_HEAD(simple_temp_timer_ring_t, simple_timer_t) tmp_ring;
    APR_RING_INIT(&tmp_ring, simple_timer_t, link);

    apr_thread_mutex_lock(sc->mtx);

    APR_RING_CHECK_CONSISTENCY(&sc->timer_ring, simple_timer_t, link);
    
    /* now iterate any timers */
    if (!APR_RING_EMPTY(&sc->timer_ring, simple_timer_t, link)) {
      for (ep = APR_RING_FIRST(&sc->timer_ring);
           ep != APR_RING_SENTINEL(&sc->timer_ring,
                                   simple_timer_t, link);
           ep = APR_RING_NEXT(ep, link))
      {
        if (ep->expires < now) {
          simple_timer_t *next = APR_RING_PREV(ep, link);
          /* push this task */
          APR_RING_REMOVE(ep, link);
          APR_RING_CHECK_CONSISTENCY(&sc->timer_ring, simple_timer_t, link);
          APR_RING_INSERT_TAIL(&tmp_ring, ep, simple_timer_t, link);
          ep = next;
        }
        else {
          break;
        }
      }
    }

    APR_RING_CHECK_CONSISTENCY(&sc->timer_ring, simple_timer_t, link);
    
    apr_thread_mutex_unlock(sc->mtx);

    if (!APR_RING_EMPTY(&tmp_ring, simple_timer_t, link)) {
      for (ep = APR_RING_FIRST(&tmp_ring);
           ep != APR_RING_SENTINEL(&tmp_ring,
                                   simple_timer_t, link);
           ep = APR_RING_NEXT(ep, link))
      {
        apr_thread_pool_push(sc->workers,
                             simple_timer_invoke,
                             ep,
                             APR_THREAD_TASK_PRIORITY_NORMAL,
                             NULL);
      }
    }
  }
  
  return 0;
}

void
simple_single_process_hack(simple_core_t *sc)
{
  apr_status_t rv;
  /* Normally this is only ran in the child processes, but we want to do it here too...*/
  rv = simple_setup_listeners(sc);
  if (rv) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                 "simple_single_child_hack: simple_setup_listeners failed");
  }
}

static int
simple_setup_privs(simple_core_t *sc)
{
  /* TODO: These should be a series of hooks, chroot, drop user, SELinux support, etc. */
  /* TODO: chroot support */
  /* TODO: drop to configured user */
  return 0;
}

int
simple_child_loop(simple_core_t *sc)
{
  apr_status_t rv;

  rv = simple_setup_workers(sc);
  if (rv) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                 "simple_child_loop: simple_setup_workers failed");
    return !OK;
  }

  rv = simple_setup_listeners(sc);
  if (rv) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                 "simple_child_loop: simple_setup_sockets failed");
    return !OK;
  }

  rv = simple_setup_privs(sc);
  if (rv) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                 "simple_child_loop: simple_drop_privs failed");
    return !OK;
  }

  return simple_run_loop(sc);
}

int
simple_main_loop(simple_core_t *sc)
{
  apr_status_t rv;

  rv = simple_setup_workers(sc);
  if (rv) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                 "simple_main_loop: simple_setup_workers failed");
    return !OK;
  }

  rv = simple_main_setup_timers(sc);
  if (rv) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                 "simple_main_loop: simple_setup_timers failed");
    return !OK;
  }

  return simple_run_loop(sc);
}

