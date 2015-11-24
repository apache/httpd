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

#ifndef __mod_h2__h2_io_set__
#define __mod_h2__h2_io_set__

struct h2_io;

/**
 * A set of h2_io instances. Allows lookup by stream id
 * and other criteria.
 */
typedef struct h2_io_set h2_io_set;

h2_io_set *h2_io_set_create(apr_pool_t *pool);

void h2_io_set_destroy(h2_io_set *set);

apr_status_t h2_io_set_add(h2_io_set *set, struct h2_io *io);
h2_io *h2_io_set_get(h2_io_set *set, int stream_id);
h2_io *h2_io_set_remove(h2_io_set *set, struct h2_io *io);

int h2_io_set_is_empty(h2_io_set *set);
apr_size_t h2_io_set_size(h2_io_set *set);


typedef int h2_io_set_iter_fn(void *ctx, struct h2_io *io);

/**
 * Iterator over all h2_io* in the set or until a
 * callback returns 0. It is not safe to add or remove
 * set members during iteration.
 *
 * @param set the set of h2_io to iterate over
 * @param iter the function to call for each io
 * @param ctx user data for the callback
 * @return 1 iff iteration completed for all members
 */
int h2_io_set_iter(h2_io_set *set,
                   h2_io_set_iter_fn *iter, void *ctx);

h2_io *h2_io_set_pop_highest_prio(h2_io_set *set);

#endif /* defined(__mod_h2__h2_io_set__) */
