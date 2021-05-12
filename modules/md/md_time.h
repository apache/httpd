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

#ifndef mod_md_md_time_h
#define mod_md_md_time_h

#include <stdio.h>

#define MD_SECS_PER_HOUR      (60*60)
#define MD_SECS_PER_DAY       (24*MD_SECS_PER_HOUR)

typedef struct md_timeperiod_t md_timeperiod_t;

struct md_timeperiod_t {
    apr_time_t start;
    apr_time_t end;
};

apr_time_t md_timeperiod_length(const md_timeperiod_t *period);

int md_timeperiod_contains(const md_timeperiod_t *period, apr_time_t time);
int md_timeperiod_has_started(const md_timeperiod_t *period, apr_time_t time);
int md_timeperiod_has_ended(const md_timeperiod_t *period, apr_time_t time);
apr_interval_time_t md_timeperiod_remaining(const md_timeperiod_t *period, apr_time_t time);

/**
 * Return the timeperiod common between a and b. If both do not overlap, return {0,0}.
 */
md_timeperiod_t md_timeperiod_common(const md_timeperiod_t *a, const md_timeperiod_t *b);

char *md_timeperiod_print(apr_pool_t *p, const md_timeperiod_t *period);

/**
 * Print a human readable form of the give duration in days/hours/min/sec 
 */
const char *md_duration_print(apr_pool_t *p, apr_interval_time_t duration);
const char *md_duration_roughly(apr_pool_t *p, apr_interval_time_t duration);

/**
 * Parse a machine readable string duration in the form of NN[unit], where
 * unit is d/h/mi/s/ms with the default given should the unit not be specified.
 */
apr_status_t md_duration_parse(apr_interval_time_t *ptimeout, const char *value, 
                               const char *def_unit);
const char *md_duration_format(apr_pool_t *p, apr_interval_time_t duration);

typedef struct {
    apr_interval_time_t norm; /* if > 0, normalized base length */
    apr_interval_time_t len;  /* length of the timespan */
} md_timeslice_t;

apr_status_t md_timeslice_create(md_timeslice_t **pts, apr_pool_t *p,
                                 apr_interval_time_t norm, apr_interval_time_t len); 

int md_timeslice_eq(const md_timeslice_t *ts1, const md_timeslice_t *ts2);

const char *md_timeslice_parse(md_timeslice_t **pts, apr_pool_t *p, 
                              const char *val, apr_interval_time_t defnorm);
const char *md_timeslice_format(const md_timeslice_t *ts, apr_pool_t *p);

md_timeperiod_t md_timeperiod_slice_before_end(const md_timeperiod_t *period, 
                                               const md_timeslice_t *ts);

#endif /* md_util_h */
