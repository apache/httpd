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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"

typedef apr_uint16_t unique_counter;

struct unique_id_rec {
    apr_uint32_t process_id;
    apr_uint32_t thread_id;
    apr_uint64_t timestamp;
    apr_uint16_t random;
    unique_counter counter;
} __attribute__ ((packed));
typedef struct unique_id_rec unique_id_rec;

#ifndef WITH_APR_ENCODE
struct unique_id_rec_padded {
    struct unique_id_rec unique_id;
    apr_uint16_t pad;
} __attribute__ ((packed));
typedef struct unique_id_rec_padded unique_id_rec_padded;
#endif

#if APR_HAS_THREADS
struct unique_thread_data {
    unique_counter counter;
};
#else
static unique_counter global_counter = 0;
#endif

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
 * - 16 pseudo-random bits
 *
 * The resulting ID string will be a base64 encoded string (RFC4648) 27 characaters long. The
 * length may change, applications storing the value should fit longer strings and not depend
 * on the size.
 *
 * For non-threaded servers, the Thread ID will always be 0 and the counter is incremented
 * for each process and wraps around after some time.
 *
 */

/* TODO : Provide a configuration parameter to set a server ID to ensure complete
 *        uniqueness across servers */

/* TODO : Endian conversion could be provided for tidyness but having this left out
 *        probably won't cause collisions. */

static void populate_unique_id (unique_id_rec *unique_id, apr_uintptr_t thread_id, apr_uint32_t counter)
{
    unique_id->process_id = ((apr_uint64_t) getpid()) & 0x00000000ffffffff;
    unique_id->thread_id = ((apr_uint64_t) thread_id) & 0x00000000ffffffff;
    unique_id->timestamp = apr_time_now();
    ap_random_insecure_bytes(&unique_id->random, sizeof(unique_id->random));
    unique_id->counter = counter;
}

static const char *create_unique_id_string(const request_rec *r)
{
    char *ret = NULL;
    unique_id_rec unique_id;
    const apr_size_t ret_size = sizeof(unique_id) * 2;

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

        populate_unique_id(&unique_id, (apr_uintptr_t) thread, ++(thread_data->counter));
    }
#else
    populate_unique_id(&unique_id, 0, ++global_counter);
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

    /* Debug
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
            "Unique ID generated: %s pid %" APR_UINT64_T_FMT " tid %" APR_UINT64_T_FMT " time %" APR_UINT64_T_FMT " rand %" APR_UINT64_T_FMT " count %" APR_UINT64_T_FMT "",
            ret,
            (apr_uint64_t) unique_id.process_id,
            (apr_uint64_t) unique_id.thread_id,
            (apr_uint64_t) unique_id.timestamp,
            (apr_uint64_t) unique_id.random,
            (apr_uint64_t) unique_id.counter
    );
    */

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

AP_DECLARE_MODULE(unique_id) = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};
