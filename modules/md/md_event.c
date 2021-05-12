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

#include <assert.h>
#include <apr_optional.h>
#include <apr_strings.h>

#include "md.h"
#include "md_event.h"


typedef struct md_subscription {
    struct md_subscription *next;
    md_event_cb *cb;
    void *baton;
} md_subscription;

static struct {
    apr_pool_t *p;
    md_subscription *subs;
} EVNT;

static apr_status_t cleanup_setup(void *dummy)
{
    (void)dummy;
    memset(&EVNT, 0, sizeof(EVNT));
    return APR_SUCCESS;
}

void md_event_init(apr_pool_t *p)
{
    memset(&EVNT, 0, sizeof(EVNT));
    EVNT.p = p;
    apr_pool_cleanup_register(p, NULL, cleanup_setup, apr_pool_cleanup_null);
}

void md_event_subscribe(md_event_cb *cb, void *baton)
{
    md_subscription *sub;
    
    sub = apr_pcalloc(EVNT.p, sizeof(*sub));
    sub->cb = cb;
    sub->baton = baton;
    sub->next = EVNT.subs;
    EVNT.subs = sub;
} 

apr_status_t md_event_raise(const char *event, 
                            const char *mdomain, 
                            struct md_job_t *job, 
                            struct md_result_t *result, 
                            apr_pool_t *p)
{
    md_subscription *sub = EVNT.subs;
    apr_status_t rv;

    while (sub) {
        rv = sub->cb(event, mdomain, sub->baton, job, result, p);
        if (APR_SUCCESS != rv) return rv;
        sub = sub->next;
    }
    return APR_SUCCESS;
}

void md_event_holler(const char *event, 
                     const char *mdomain, 
                     struct md_job_t *job, 
                     struct md_result_t *result, 
                     apr_pool_t *p)
{
    md_subscription *sub = EVNT.subs;
    while (sub) {
        sub->cb(event, mdomain, sub->baton, job, result, p);
        sub = sub->next;
    }
}
