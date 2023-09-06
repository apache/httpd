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
PROXY_DECLARE(apr_size_t) getbusy_count(proxy_worker *worker);

/*
 * Set the busy counter from the shared worker memory
 *
 * @param worker Pointer to the worker structure.
 * @param to value to set the busy counter.
 * @return      void
 */
PROXY_DECLARE(void) setbusy_count(proxy_worker *worker, apr_size_t to);

/*
 * decrement the busy counter from the shared worker memory
 * note it is called by apr_pool_cleanup_register()
 * therfore the void * and apr_status_t.
 *
 * @param worker_ Pointer to the worker structure.
 * @return      apr_status_t returns APR_SUCCESS.
 */
PROXY_DECLARE(apr_status_t) decrement_busy_count(void *worker_);

/*
 * increment the busy counter from the shared worker memory
 *
 * @param worker Pointer to the worker structure.
 * @return      void
 */
PROXY_DECLARE(void) increment_busy_count(proxy_worker *worker);

/** @} */

#endif /* PROXY_UTIL_H_ */
