/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>

#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_connection.h>
#include <http_request.h>

#include "h2_private.h"
#include "h2_bucket_beam.h"
#include "h2_h2.h"
#include "h2_io.h"
#include "h2_mplx.h"
#include "h2_response.h"
#include "h2_request.h"
#include "h2_task.h"
#include "h2_util.h"

h2_io *h2_io_create(int id, apr_pool_t *pool, const h2_request *request)
{
    h2_io *io = apr_pcalloc(pool, sizeof(*io));
    if (io) {
        io->id = id;
        io->pool = pool;
        io->request = request;
        if (request->body) {
            h2_beam_create(&io->beam_in, pool, id, "input", 0);
        }
    }
    return io;
}

void h2_io_redo(h2_io *io)
{
    io->worker_started = 0;
    io->response = NULL;
    io->rst_error = 0;
    io->started_at = io->done_at = 0;
}

int h2_io_can_redo(h2_io *io) {
    if (io->submitted
        || (io->beam_in && h2_beam_was_received(io->beam_in)) 
        || !io->request) {
        /* cannot repeat that. */
        return 0;
    }
    return (!strcmp("GET", io->request->method)
            || !strcmp("HEAD", io->request->method)
            || !strcmp("OPTIONS", io->request->method));
}

void h2_io_set_response(h2_io *io, h2_response *response, 
                        h2_bucket_beam *output) 
{
    AP_DEBUG_ASSERT(response);
    AP_DEBUG_ASSERT(!io->response);
    /* we used to clone the response into out own pool. But
     * we have much tighter control over the EOR bucket nowadays,
     * so just use the instance given */
    io->response = response;
    if (output) {
        io->beam_out = output;
    }
    if (response->rst_error) {
        h2_io_rst(io, response->rst_error);
    }
}

void h2_io_rst(h2_io *io, int error)
{
    io->rst_error = error;
    if (io->beam_in) {
        h2_beam_abort(io->beam_in);
    }
    if (io->beam_out) {
        h2_beam_abort(io->beam_out);
    }
}

void h2_io_shutdown(h2_io *io)
{
    if (io->beam_in) {
        h2_beam_shutdown(io->beam_in);
    }
    if (io->beam_out) {
        h2_beam_shutdown(io->beam_out);
    }
}
