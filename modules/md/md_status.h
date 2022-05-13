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

#ifndef md_status_h
#define md_status_h

struct md_json_t;
struct md_reg_t;
struct md_result_t;
struct md_ocsp_reg_t;

#include "md_store.h"

/** 
 * Get a JSON summary of the MD and its status (certificates, jobs, etc.).
 */
apr_status_t md_status_get_md_json(struct md_json_t **pjson, const md_t *md, 
                                   struct md_reg_t *reg, struct md_ocsp_reg_t *ocsp,
                                   apr_pool_t *p);

/** 
 * Get a JSON summary of all MDs and their status.
 */
apr_status_t md_status_get_json(struct md_json_t **pjson, apr_array_header_t *mds, 
                                struct md_reg_t *reg, struct md_ocsp_reg_t *ocsp,
                                apr_pool_t *p);

/**
 * Take stock of all MDs given for a short overview. The JSON returned
 * will carry integers for MD_KEY_COMPLETE, MD_KEY_RENEWING, 
 * MD_KEY_ERRORED, MD_KEY_READY and MD_KEY_TOTAL.
 */
void  md_status_take_stock(struct md_json_t **pjson, apr_array_header_t *mds, 
                           struct md_reg_t *reg, apr_pool_t *p);


typedef struct md_job_t md_job_t;

struct md_job_t {
    md_store_group_t group;/* group where job is persisted */
    const char *mdomain;   /* Name of the MD this job is about */
    md_store_t *store;     /* store where it is persisted */
    apr_pool_t *p;     
    apr_time_t next_run;   /* Time this job wants to be processed next */
    apr_time_t last_run;   /* Time this job ran last (or 0) */
    struct md_result_t *last_result; /* Result from last run */
    int finished;          /* true iff the job finished successfully */
    int notified;          /* true iff notifications were handled successfully */
    int notified_renewed;  /* true iff a 'renewed' notification was handled successfully */
    apr_time_t valid_from; /* at which time the finished job results become valid, 0 if immediate */
    int error_runs;        /* Number of errored runs of an unfinished job */
    int fatal_error;       /* a fatal error is remedied by retrying */
    md_json_t *log;        /* array of log objects with minimum fields
                              MD_KEY_WHEN (timestamp) and MD_KEY_TYPE (string) */
    apr_size_t max_log;    /* max number of log entries, new ones replace oldest */
    int dirty;
    struct md_result_t *observing;
    apr_time_t min_delay;  /* smallest delay a repeated attempt should have */
};

/**
 * Create a new job instance for the given MD name. 
 * Job load/save will work using the name.
 */
md_job_t *md_job_make(apr_pool_t *p, md_store_t *store, 
                      md_store_group_t group, const char *name,
                      apr_time_t min_delay);

void md_job_set_group(md_job_t *job, md_store_group_t group);

/**
 * Update the job from storage in <group>/job->mdomain.
 */
apr_status_t md_job_load(md_job_t *job);

/**
 * Update storage from job in <group>/job->mdomain.
 */
apr_status_t md_job_save(md_job_t *job, struct md_result_t *result, apr_pool_t *p);

/**
 * Append to the job's log. Timestamp is automatically added.
 * @param type          type of log entry
 * @param status        status of entry (maybe NULL)
 * @param detail        description of what happened
 */
void md_job_log_append(md_job_t *job, const char *type, 
                       const char *status, const char *detail);

/**
 * Retrieve the latest log entry of a certain type.
 */
md_json_t *md_job_log_get_latest(md_job_t *job, const char *type);

/**
 * Get the time the latest log entry of the given type happened, or 0 if
 * none is found.
 */
apr_time_t md_job_log_get_time_of_latest(md_job_t *job, const char *type);

void md_job_start_run(md_job_t *job, struct md_result_t *result, md_store_t *store);
void md_job_end_run(md_job_t *job, struct md_result_t *result);
void md_job_retry_at(md_job_t *job, apr_time_t later);

/**
 * Given the number of errors and the last problem encountered,
 * recommend a delay for the next attempt of job
 */
apr_time_t md_job_delay_on_errors(md_job_t *job, int err_count, const char *last_problem);

apr_status_t md_job_notify(md_job_t *job, const char *reason, struct md_result_t *result);

#endif /* md_status_h */
