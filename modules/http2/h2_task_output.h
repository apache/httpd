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

#ifndef __mod_h2__h2_task_output__
#define __mod_h2__h2_task_output__

/* h2_task_output reads a HTTP/1 response from the brigade and applies
 * them to a h2_output_converter. The brigade is setup as the output brigade
 * for our pseudo httpd conn_rec that is handling a specific h2_task.
 * 
 */
struct apr_thread_cond_t;
struct h2_mplx;
struct h2_task;
struct h2_from_h1;

typedef struct h2_task_output h2_task_output;

struct h2_task_output {
    struct h2_task *task;
    struct h2_from_h1 *from_h1;
    
    unsigned int response_open : 1;

    apr_off_t written;
    apr_bucket_brigade *bb;
};

h2_task_output *h2_task_output_create(struct h2_task *task, conn_rec *c);

apr_status_t h2_task_output_write(h2_task_output *output,
                                  ap_filter_t* filter,
                                  apr_bucket_brigade* brigade);

apr_status_t h2_task_output_freeze(h2_task_output *output);
apr_status_t h2_task_output_thaw(h2_task_output *output);

#endif /* defined(__mod_h2__h2_task_output__) */
