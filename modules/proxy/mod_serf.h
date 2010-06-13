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


/**
 * @file mod_serf.h
 * @brief Serf Interfaces
 *
 */

#include "httpd.h"
#include "http_config.h"
#if !defined(WIN32) && !defined(NETWARE)
#include "ap_config_auto.h"
#endif
#ifdef HAVE_SERF
#include "serf.h"
#endif

#include "ap_provider.h"

#ifndef _MOD_SERF_H_
#define _MOD_SERF_H_
/**
 * @addtogroup Serf_cluster_provider
 * @{
 */
#define AP_SERF_CLUSTER_PROVIDER "serf_cluster"
typedef struct ap_serf_server_t ap_serf_server_t;
struct ap_serf_server_t {
    /* TOOD: consider using apr_sockaddr_t, except they suck. */
    const char *ip;
    apr_port_t port;
};

typedef struct ap_serf_cluster_provider_t ap_serf_cluster_provider_t;
struct ap_serf_cluster_provider_t {
    /**
     * Human readable name of this provider, used in configuration.
     */
    const char *name;
    /**
     * Baton passed to all methods in this provider.
     *
     * This field may be NULL.
     */
    void *baton;
    /**
     * Check that the key/value pairs used to configure the 
     * cluster are valid.
     *
     * Return non-NULL on failure with an error message, like standard httpd
     * configuration directives.
     *
     * This field must be set.
     */
    const char* (*check_config)(void *baton,
                                cmd_parms *cmd,
                                apr_table_t *params);
    /**
     * Provide an ordered array of ap_serf_server_t in the order that
     * mod_serf should attempt to use them.  If a server on the list
     * is known to be not responding, it may be skipped.  If mod_serf is 
     * unable to contact any of the servers, a 502 will be returned to the 
     * client.
     *
     * Returns OK on sucess, all other return codes will result in a 500.
     *
     * This field must be set.
     */
    int (*list_servers)(void *baton,
                        request_rec *r,
                        apr_table_t *params,
                        apr_array_header_t **servers);
    /**
     * If a request was successfully fulfilled by this address, feedback will
     * be given to the provider, so it may make better recommendations.
     *
     * This field may be NULL.
     */
    void (*server_success)(void *baton, request_rec *r, apr_table_t *params,
                           ap_serf_server_t* server);
    /**
     * If a request failed to be fulfilled by this address, feedback will
     * be given to the provider, so it may make better recommendations.
     *
     * This field may be NULL.
     */
    void (*server_failure)(void *baton, request_rec *r, apr_table_t *params,
                           ap_serf_server_t* server);

};
/** @} */

#endif /* _MOD_SERF_H_ */

