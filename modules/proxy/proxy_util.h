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

#ifndef PROXY_UTIL_H_
#define PROXY_UTIL_H_

/**
 * @file  proxy_util.h
 * @brief Internal interfaces private to mod_proxy.
 *
 * @defgroup MOD_PROXY_PRIVATE Private
 * @ingroup MOD_PROXY
 * @{
 */

PROXY_DECLARE(int) ap_proxy_is_ipaddr(struct dirconn_entry *This, apr_pool_t *p);
PROXY_DECLARE(int) ap_proxy_is_domainname(struct dirconn_entry *This, apr_pool_t *p);
PROXY_DECLARE(int) ap_proxy_is_hostname(struct dirconn_entry *This, apr_pool_t *p);
PROXY_DECLARE(int) ap_proxy_is_word(struct dirconn_entry *This, apr_pool_t *p);

extern PROXY_DECLARE_DATA int proxy_lb_workers;
extern PROXY_DECLARE_DATA const apr_strmatch_pattern *ap_proxy_strmatch_path;
extern PROXY_DECLARE_DATA const apr_strmatch_pattern *ap_proxy_strmatch_domain;

/**
 * Register optional functions declared within proxy_util.c.
 */
void proxy_util_register_hooks(apr_pool_t *p);

/*
 * Get the busy counter from the shared worker memory
 *
 * @param worker Pointer to the worker structure.
 * @return      apr_size_t value atomically read for the worker.
 */
PROXY_DECLARE(apr_size_t) ap_proxy_get_busy_count(proxy_worker *worker);

/*
 * Set the busy counter from the shared worker memory
 *
 * @param worker Pointer to the worker structure.
 * @param to value to set the busy counter.
 * @return      void
 */
PROXY_DECLARE(void) ap_proxy_set_busy_count(proxy_worker *worker, apr_size_t to);

/*
 * decrement the busy counter from the shared worker memory
 * note it is called by apr_pool_cleanup_register()
 * therfore the void * and apr_status_t.
 *
 * @param worker_ Pointer to the worker structure.
 * @return      apr_status_t returns APR_SUCCESS.
 */
PROXY_DECLARE(apr_status_t) ap_proxy_decrement_busy_count(void *worker_);

/*
 * increment the busy counter from the shared worker memory
 *
 * @param worker Pointer to the worker structure.
 * @return      void
 */
PROXY_DECLARE(void) ap_proxy_increment_busy_count(proxy_worker *worker);

/*
 * Create (or, on a restart within the same process lifetime, reuse) the
 * shared admission table that ap_proxy_try_reserve_worker() and friends
 * use to enforce worker->s->maxbusy across all children AND across a
 * graceful restart. Must be called once from the (long-lived) parent
 * process, after all proxy_server_conf's are built, before any child is
 * forked; mod_proxy.c's post_config hook is the right place. Harmless,
 * and a correctly recognised no-op, if called again on every subsequent
 * restart of the same process.
 *
 * @param main_s The main server_rec, to walk every virtual host's workers.
 * @return      void. Logs and leaves maxbusy unenforced on allocation
 *              failure, rather than failing the whole server.
 */
PROXY_DECLARE(void) ap_proxy_admission_table_init(server_rec *main_s);

/*
 * Fail-closed check for ap_proxy_admission_table_init(): if any
 * configured worker has a non-zero maxbusy but the admission table
 * could not be created, that limit cannot be enforced at all, so this
 * logs and returns an error instead of letting the server start up
 * silently violating a configured hard limit. Call once from
 * post_config, after every worker's maxbusy is known, i.e. after
 * ap_proxy_admission_table_init() and after all section/per-dir proxy
 * configuration has been processed.
 *
 * @param main_s The main server_rec, to walk every virtual host's workers.
 * @return      APR_SUCCESS, or an error if startup must be refused.
 */
PROXY_DECLARE(apr_status_t) ap_proxy_admission_table_check(server_rec *main_s);

/*
 * Return the number of worker->s->maxbusy admission slots this worker
 * currently has reserved, across all children and generations. For
 * reporting only (e.g. the balancer-manager page); 0 if the admission
 * table is unavailable.
 *
 * @param worker Pointer to the worker structure.
 * @return      apr_size_t Number of slots currently reserved.
 */
PROXY_DECLARE(apr_size_t) ap_proxy_get_reserved_count(proxy_worker *worker);

/*
 * Return non-zero if worker has a free maxbusy admission slot, i.e. it is
 * not currently at its configured worker->s->maxbusy limit (0 means no
 * limit, always has capacity). This is a point-in-time snapshot only: it
 * is meant for use as a selection-time filter (skip saturated workers in
 * favour of others), not as the actual admission decision. The admission
 * decision itself must go through ap_proxy_try_reserve_worker(), which is
 * atomic and race-free; this function alone is NOT sufficient to enforce
 * the hard limit, since two processes could both see capacity and then
 * both reserve the last slot.
 *
 * @param worker Pointer to the worker structure.
 * @return      non-zero if the worker currently has a free maxbusy slot.
 */
PROXY_DECLARE(int) ap_proxy_worker_has_capacity(proxy_worker *worker);

/*
 * Atomically reserve one worker->s->maxbusy admission slot, unless the
 * worker is already at that limit, in which case no reservation is made.
 * The check and the reservation are a single atomic operation across all
 * children, so this is safe to use as a hard concurrency admission gate.
 * This is independent of worker->s->busy (a load-balancing metric only):
 * the reservation counter is never reset by any lbmethod's reset(), and
 * releasing it (see ap_proxy_release_worker_reservation() below) has no
 * effect on worker->s->busy.
 *
 * If worker->s->maxbusy is 0 (the default, no limit), this always
 * succeeds without touching any shared counter.
 *
 * @param worker Pointer to the worker structure.
 * @return      1 if a slot was reserved (the caller holds the reservation
 *              and must eventually call, exactly once,
 *              ap_proxy_release_worker_reservation()), 0 if
 *              worker->s->maxbusy was already reached (no reservation was
 *              made; nothing to release).
 */
PROXY_DECLARE(int) ap_proxy_try_reserve_worker(proxy_worker *worker);

/*
 * Release one worker->s->maxbusy admission slot previously obtained via a
 * successful ap_proxy_try_reserve_worker(worker) call. Safe to register
 * directly with apr_pool_cleanup_register() or run early with
 * apr_pool_cleanup_run() (void * / apr_status_t signature).
 *
 * The contract is strict, not merely "safe by construction": a call here
 * must correspond to exactly one prior successful reservation on this
 * worker. The internal CAS loop floors at 0 only to avoid undefined
 * underflow of the shared counter if that contract is ever violated by a
 * caller bug -- flooring does NOT make a stray or duplicate call harmless:
 * while the real count is still above 0, an extra release silently steals
 * another, unrelated request's reservation.
 *
 * Looks the worker's admission slot up by its stable identity (the same
 * one ap_proxy_try_reserve_worker() used), never by worker->s->maxbusy,
 * so it stays correct even if that configured value changes between the
 * reservation and this release (e.g. a graceful restart reconfigures the
 * worker while an old-generation request is still outstanding on it).
 * Admission slots are preregistered in post_config for every configured
 * maxbusy != 0 BalancerMember and are never reclaimed for the life of the
 * parent process, so "no slot" is not a normal case to release against:
 * callers must call this function if and only if the matching
 * ap_proxy_try_reserve_worker() call returned 1, exactly once per such
 * call. It is not a safe default to call "just in case".
 *
 * @param worker_ Pointer to the worker structure.
 * @return      apr_status_t returns APR_SUCCESS.
 */
PROXY_DECLARE(apr_status_t) ap_proxy_release_worker_reservation(void *worker_);


/*
 * interpolate an env str in a configuration string
 *
 * @param r    current request
 * @param str  the string to interpolcate
 * @return     the interpolated string
 */
PROXY_DECLARE(const char *) ap_proxy_interpolate(request_rec *r,
                                                 const char *str);

/*
 * Canonicalize the URL in r->filename
 * @param r           current request
 * @return            OK or an HTTP_XXX error
 */
PROXY_DECLARE(int) ap_proxy_canon_url(request_rec *r);

/** @} */

#endif /* PROXY_UTIL_H_ */
