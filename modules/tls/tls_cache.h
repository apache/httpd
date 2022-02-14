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
#ifndef tls_cache_h
#define tls_cache_h

/* name of the global session cache mutex, should we need it */
#define TLS_SESSION_CACHE_MUTEX_TYPE    "tls-session-cache"


/**
 * Set the specification of the session cache to use. The syntax is
 *   "default|none|<provider_name>(:<arguments>)?"
 *
 * @param spec the cache specification
 * @param gconf the modules global configuration
 * @param p pool for permanent allocations
 * @param ptemp  pool for temporary allocations
 * @return NULL on success or an error message
 */
const char *tls_cache_set_specification(
    const char *spec, tls_conf_global_t *gconf, apr_pool_t *p, apr_pool_t *ptemp);

/**
 * Setup before configuration runs, announces our potential global mutex.
 */
void tls_cache_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp);

/**
 * Verify the cache settings at the end of the configuration and
 * create the default session cache, if not already done.
 */
apr_status_t tls_cache_post_config(apr_pool_t *p, apr_pool_t *ptemp, server_rec *s);

/**
 * Started a new child, make sure that global mutex we might use is set up.
 */
void tls_cache_init_child(apr_pool_t *p, server_rec *s);

/**
 * Free all cache related resources.
 */
void tls_cache_free(server_rec *s);

/**
 * Initialize the session store for the server's config builder.
 */
apr_status_t tls_cache_init_server(
    rustls_server_config_builder *builder, server_rec *s);

#endif /* tls_cache_h */