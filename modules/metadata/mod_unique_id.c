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

/*
 * mod_unique_id.c: generate a unique identifier for each request
 *
 * Original author: Dean Gaudet <dgaudet@arctic.org>
 * UUencoding modified by: Alvaro Martinez Echevarria <alvaro@lander.es>
 * Complete rewrite by: Atle Solbakken <atle@goliathdns.no>, April 2021
 */

#ifdef _WIN32
#include <process.h>
#define getpid _getpid
#else
#include <unistd.h>
#endif

/* Enable when ready to use new library encoder
 * #define WITH_APR_ENCODE
 */
#define THREADED_COUNTER "unique_id_counter"

#include "apr.h"
#ifdef WITH_APR_ENCODE    
#    include "apr_encode.h"
#endif
#include "apr_thread_proc.h"
#include "apr_cstr.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"

typedef apr_uint16_t unique_counter;

/* Unique ID structure members must be aligned on 1-byte boundaries */

#pragma pack(push)
#pragma pack(1)

typedef struct unique_id_rec {
    apr_uint32_t process_id;
    apr_uint32_t thread_id;
    apr_uint64_t timestamp;
    apr_uint16_t server_id;
    unique_counter counter;
} unique_id_rec;

#ifndef WITH_APR_ENCODE
typedef struct unique_id_rec_padded {
    struct unique_id_rec unique_id;
    apr_uint16_t pad;
} unique_id_rec_padded;
#endif

#pragma pack(pop)

typedef struct unique_id_server_config_rec { 
    /* A value of -1 means not initialized, and 0 will be used. Max value is 65535. */
    int server_id;
} unique_id_server_config_rec;

#if APR_HAS_THREADS
struct unique_thread_data {
    unique_counter counter;
};
#else
static unique_counter global_counter = 0;
#endif

module AP_MODULE_DECLARE_DATA unique_id_module;

/*
 * This module generates (almost) unique IDs for each request to a particular server.
 *
 * IDs /might/ be unique across servers if and only if two requests happen simultaneously
 * and the servers clocks are synchronized.
 *
 * A combination of different parameters however ensure a low chance for ID collisions:
 *
 * - Process ID of the running process
 * - Thread ID of the running thread
 * - Timestamp in microseconds
 * - 16 bit incrementing counter for each unique Thread ID
 * - 16 bit server ID manually set (defaults to 0)
 *
 * The resulting ID string will be a base64 encoded string (RFC4648) 27 characaters long. The
 * length may change, applications storing the value should fit longer strings and not depend
 * on the size.
 *
 * For non-threaded servers, the Thread ID will always be 0 and the counter is incremented
 * for each process and wraps around after some time.
 *
 */

/* TODO : Endian conversion could be provided for tidyness but having this left out
 *        probably won't cause collisions. */

static void populate_unique_id (unique_id_rec *unique_id, apr_uintptr_t thread_id, apr_uint32_t counter, apr_uint16_t server_id)
{
    unique_id->process_id = ((apr_uint64_t) getpid()) & 0x00000000ffffffff;
    unique_id->thread_id = ((apr_uint64_t) thread_id) & 0x00000000ffffffff;
    unique_id->timestamp = apr_time_now();
    unique_id->server_id = server_id;
    unique_id->counter = counter;
}

static int get_server_id(apr_uint16_t *server_id, const request_rec *r)
{
    const unique_id_server_config_rec *conf;

    /* Note : Cast away const */
    if ((conf = ap_get_module_config((void *) r->server->module_config, &unique_id_module)) == NULL ||
         conf->server_id < -1 ||
	 conf->server_id > 65535
    ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, HTTP_INTERNAL_SERVER_ERROR, r->server, "Server ID of Unique ID module not initialized correctly");
    	return HTTP_INTERNAL_SERVER_ERROR;
    }

    *server_id = conf->server_id < 0 ? 0 : conf->server_id;

    return OK;
}

static const char *create_unique_id_string(const request_rec *r)
{
    char *ret = NULL;
    unique_id_rec unique_id;
    const apr_size_t ret_size = sizeof(unique_id) * 2;
    apr_uint16_t server_id;

    if (get_server_id(&server_id, r) != OK) {
        goto out;
    }

#if APR_HAS_THREADS
    {
        struct unique_thread_data *thread_data = NULL;
        apr_thread_t *thread = r->connection->current_thread;

        if (apr_thread_data_get((void **) &thread_data, THREADED_COUNTER, thread) != APR_SUCCESS || thread_data == NULL) {
            thread_data = apr_pcalloc(apr_thread_pool_get(thread), sizeof(*thread_data));
            if (thread_data == NULL) {
                goto out;
            }
            thread_data->counter = 0;
            if (apr_thread_data_set(thread_data, THREADED_COUNTER, NULL, thread) != APR_SUCCESS) {
                goto out;
            }
        }

        populate_unique_id(&unique_id, (apr_uintptr_t) thread, ++(thread_data->counter), server_id);
    }
#else
    populate_unique_id(&unique_id, 0, ++global_counter, server_id);
#endif

    if ((ret = (char *)apr_pcalloc(r->pool, ret_size)) == NULL) {
        goto out;
    }

#ifdef WITH_APR_ENCODE    
    /* Use Base64 without the / per RFC 4648 */
    if (apr_encode_base64(ret, (const char *) &unique_id, sizeof(unique_id), APR_ENCODE_URL|APR_ENCODE_NOPADDING, &ret_size) != APR_SUCCESS) {
        ret = NULL;
        goto out;
    }
#else
    {
        /* Use the base64url encoding per RFC 4648, avoiding characters which
         * are not safe in URLs. */
        static const char uuencoder[64] = {
           'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
           'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
           'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
           'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
           '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_',
        };

        unique_id_rec_padded unique_id_padded = {
            unique_id, 0
        };

        const unsigned char *src = (const unsigned char *) &unique_id_padded;
        const unsigned char *max = src + sizeof(unique_id);
        int wpos = 0;
        const unsigned char *pos;

        for (pos = src; pos < max; pos += 3) {    
            ret[wpos++] = uuencoder[pos[0] >> 2];
            ret[wpos++] = uuencoder[((pos[0] & 0x03) << 4) | ((pos[1] & 0xf0) >> 4)];
            if (pos + 1 == max) break;
            ret[wpos++] = uuencoder[((pos[1] & 0x0f) << 2) | ((pos[2] & 0xc0) >> 6)];
            if (pos + 2 == max) break;
            ret[wpos++] = uuencoder[pos[2] & 0x3f];
        }

        ret[wpos++] = '\0';
    }
#endif

////    /* Debug
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
            "Unique ID generated: %s pid %" APR_UINT64_T_FMT " tid %" APR_UINT64_T_FMT " time %" APR_UINT64_T_FMT " server %" APR_UINT64_T_FMT " count %" APR_UINT64_T_FMT "",
            ret,
            (apr_uint64_t) unique_id.process_id,
            (apr_uint64_t) unique_id.thread_id,
            (apr_uint64_t) unique_id.timestamp,
            (apr_uint64_t) unique_id.server_id,
            (apr_uint64_t) unique_id.counter
    );
//    */

    out:
    return ret;
}

/*
 * There are two ways the generation of a unique id can be triggered:
 *
 * - from the post_read_request hook which calls set_unique_id()
 * - from error logging via the generate_log_id hook which calls
 *   generate_log_id(). This may happen before or after set_unique_id()
 *   has been called, or not at all.
 */

static int get_request_unique_id(const char **result_id, const request_rec *r)
{
    const char *id = NULL;

    /* Return any previously set ID or make a new one */
    if ( (id = apr_table_get(r->subprocess_env, "UNIQUE_ID")) == NULL &&
         (id = r->log_id) == NULL &&
         (id = create_unique_id_string(r)) == NULL
    ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, HTTP_INTERNAL_SERVER_ERROR, r->server, "Unique ID generation failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    *result_id = id;

    return OK;
}

static int generate_log_id_hook(const conn_rec *c, const request_rec *r, const char **id)
{
    (void)(c);

    /* we do not care about connection ids */
    if (r == NULL)
        return DECLINED;

    return get_request_unique_id(id, r);
}

static int post_read_request_hook(request_rec *r)
{
    const char *id = NULL;

    int ret = get_request_unique_id(&id, r);

    if (id != NULL) {
        apr_table_setn(r->subprocess_env, "UNIQUE_ID", id);
    }

    return (ret == OK ? DECLINED : ret);
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_generate_log_id(generate_log_id_hook, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(post_read_request_hook, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *create_unique_id_server_config (apr_pool_t *p, server_rec *d)
{
    unique_id_server_config_rec *ret;
    if ((ret = apr_pcalloc(p, sizeof(unique_id_server_config_rec))) != NULL) {
        ret->server_id = -1;
    }
    return ret;
}

static void *merge_unique_id_server_config(apr_pool_t *p, void *basev, void *addv)
{
    unique_id_server_config_rec *base = (unique_id_server_config_rec *) basev;
    unique_id_server_config_rec *add = (unique_id_server_config_rec *) addv;
    unique_id_server_config_rec *new;

    if ((new = apr_pcalloc (p, sizeof(*new))) != NULL) {
        /* Default value is -1 which means not initialized */
        new->server_id = add->server_id >= 0 ? add->server_id : base->server_id;
    }

    return new;
}

static const char *set_server_id (cmd_parms *cmd, void *dummy, const char *arg)
{
    int tmp = -1;
    const char *err;
    unique_id_server_config_rec *conf;

    if ((err = ap_check_cmd_context (cmd, GLOBAL_ONLY)) != NULL) {
    	return err;
    }

    conf = (unique_id_server_config_rec *) ap_get_module_config (
            cmd->server->module_config,
	    &unique_id_module
    );

    if (conf == NULL) {
    	return "Unique ID: data not previously allocated";
    }

    if (apr_cstr_atoi(&tmp, arg) != APR_SUCCESS || tmp < 0 || tmp > 65535) {
    	return "Unique ID: Invalid syntax in UniqueIdServerId parameter. Must be a number between 0 and 65535 inclusive.";
    }

    conf->server_id = tmp;

    return NULL;
}

static const command_rec unique_id_cmds[] =
{
    AP_INIT_TAKE1("UniqueIdServerId", set_server_id, NULL, RSRC_CONF, "Set a unique ID of server in the range 0 to 65535"),
    {NULL}
};

AP_DECLARE_MODULE(unique_id) = {
    STANDARD20_MODULE_STUFF,
    NULL,                           /* dir config creater */
    NULL,                           /* dir merger --- default is to override */
    create_unique_id_server_config, /* server config */
    merge_unique_id_server_config,  /* merge server configs */
    unique_id_cmds,                 /* command apr_table_t */
    register_hooks                  /* register hooks */
};
