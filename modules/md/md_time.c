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
 
#include <stdio.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_time.h>

#include "md.h"
#include "md_time.h"

apr_time_t md_timeperiod_length(const md_timeperiod_t *period)
{
    return (period->start < period->end)? (period->end - period->start) : 0;
}

int md_timeperiod_contains(const md_timeperiod_t *period, apr_time_t time)
{
    return md_timeperiod_has_started(period, time) 
        && !md_timeperiod_has_ended(period, time);
}

int md_timeperiod_has_started(const md_timeperiod_t *period, apr_time_t time)
{
    return (time >= period->start);
}

int md_timeperiod_has_ended(const md_timeperiod_t *period, apr_time_t time)
{
    return (time >= period->start) && (time <= period->end);
}

apr_interval_time_t md_timeperiod_remaining(const md_timeperiod_t *period, apr_time_t time)
{
    if (time < period->start) return md_timeperiod_length(period);
    if (time < period->end) return period->end - time;
    return 0;
}

char *md_timeperiod_print(apr_pool_t *p, const md_timeperiod_t *period)
{
    char tstart[APR_RFC822_DATE_LEN];
    char tend[APR_RFC822_DATE_LEN];

    apr_rfc822_date(tstart, period->start);
    apr_rfc822_date(tend, period->end);
    return apr_pstrcat(p, tstart, " - ", tend, NULL);
}

static const char *duration_print(apr_pool_t *p, int roughly, apr_interval_time_t duration)
{
    const char *s = "", *sep = "";
    long days = (long)(apr_time_sec(duration) / MD_SECS_PER_DAY);
    int rem = (int)(apr_time_sec(duration) % MD_SECS_PER_DAY);
    
    s = roughly? "~" : "";
    if (days > 0) {
        s = apr_psprintf(p, "%s%ld days", s, days);
        if (roughly) return s;
        sep = " ";
    }
    if (rem > 0) {
        int hours = (rem / MD_SECS_PER_HOUR);
        rem = (rem % MD_SECS_PER_HOUR);
        if (hours > 0) {
            s = apr_psprintf(p, "%s%s%d hours", s, sep, hours); 
        if (roughly) return s;
            sep = " "; 
        }
        if (rem > 0) {
            int minutes = (rem / 60);
            rem = (rem % 60);
            if (minutes > 0) {
                s = apr_psprintf(p, "%s%s%d minutes", s, sep, minutes); 
                if (roughly) return s;
                sep = " "; 
            }
            if (rem > 0) {
                s = apr_psprintf(p, "%s%s%d seconds", s, sep, rem); 
                if (roughly) return s;
                sep = " "; 
            }
        }
    }
    else if (days == 0) {
        s = "0 seconds";
        if (duration != 0) {
            s = apr_psprintf(p, "%d ms", (int)apr_time_msec(duration));
        }
    }
    return s;
}

const char *md_duration_print(apr_pool_t *p, apr_interval_time_t duration)
{
    return duration_print(p, 0, duration);
}

const char *md_duration_roughly(apr_pool_t *p, apr_interval_time_t duration)
{
    return duration_print(p, 1, duration);
}

static const char *duration_format(apr_pool_t *p, apr_interval_time_t duration)
{
    const char *s = "0";
    int units = (int)(apr_time_sec(duration) / MD_SECS_PER_DAY);
    int rem = (int)(apr_time_sec(duration) % MD_SECS_PER_DAY);
    
    if (rem == 0) {
        s = apr_psprintf(p, "%dd", units); 
    }
    else {
        units = (int)(apr_time_sec(duration) / MD_SECS_PER_HOUR);
        rem = (int)(apr_time_sec(duration) % MD_SECS_PER_HOUR);
        if (rem == 0) {
            s = apr_psprintf(p, "%dh", units); 
        }
        else {
            units = (int)(apr_time_sec(duration) / 60);
            rem = (int)(apr_time_sec(duration) % 60);
            if (rem == 0) {
                s = apr_psprintf(p, "%dmi", units); 
            }
            else {
                units = (int)(apr_time_sec(duration));
                rem = (int)(apr_time_msec(duration) % 1000);
                if (rem == 0) {
                    s = apr_psprintf(p, "%ds", units); 
                }
                else {
                    s = apr_psprintf(p, "%dms", (int)(apr_time_msec(duration))); 
                }
            }
        }
    }
    return s;
}

const char *md_duration_format(apr_pool_t *p, apr_interval_time_t duration)
{
    return duration_format(p, duration);
}

apr_status_t md_duration_parse(apr_interval_time_t *ptimeout, const char *value, 
                               const char *def_unit)
{
    char *endp;
    apr_int64_t n;
    
    n = apr_strtoi64(value, &endp, 10);
    if (errno) {
        return errno;
    }
    if (!endp || !*endp) {
        if (!def_unit) def_unit = "s";
    }
    else if (endp == value) {
        return APR_EINVAL;
    }
    else {
        def_unit = endp;
    }
    
    switch (*def_unit) {
    case 'D':
    case 'd':
        *ptimeout = apr_time_from_sec(n * MD_SECS_PER_DAY);
        break;
    case 's':
    case 'S':
        *ptimeout = (apr_interval_time_t) apr_time_from_sec(n);
        break;
    case 'h':
    case 'H':
        /* Time is in hours */
        *ptimeout = (apr_interval_time_t) apr_time_from_sec(n * MD_SECS_PER_HOUR);
        break;
    case 'm':
    case 'M':
        switch (*(++def_unit)) {
        /* Time is in milliseconds */
        case 's':
        case 'S':
            *ptimeout = (apr_interval_time_t) n * 1000;
            break;
        /* Time is in minutes */
        case 'i':
        case 'I':
            *ptimeout = (apr_interval_time_t) apr_time_from_sec(n * 60);
            break;
        default:
            return APR_EGENERAL;
        }
        break;
    default:
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

static apr_status_t percentage_parse(const char *value, int *ppercent)
{
    char *endp;
    apr_int64_t n;
    
    n = apr_strtoi64(value, &endp, 10);
    if (errno) {
        return errno;
    }
    if (*endp == '%') {
        if (n < 0) {
            return APR_BADARG;
        }
        *ppercent = (int)n;
        return APR_SUCCESS;
    }
    return APR_EINVAL;
}

apr_status_t md_timeslice_create(md_timeslice_t **pts, apr_pool_t *p,
                                 apr_interval_time_t norm, apr_interval_time_t len)
{
    md_timeslice_t *ts;

    ts = apr_pcalloc(p, sizeof(*ts));
    ts->norm = norm;
    ts->len = len;
    *pts = ts;
    return APR_SUCCESS;
}

const char *md_timeslice_parse(md_timeslice_t **pts, apr_pool_t *p, 
                               const char *val, apr_interval_time_t norm)
{
    md_timeslice_t *ts;
    int percent = 0;

    *pts = NULL;
    if (!val) {
        return "cannot parse NULL value";
    }

    ts = apr_pcalloc(p, sizeof(*ts));
    if (md_duration_parse(&ts->len, val, "d") == APR_SUCCESS) {
        *pts = ts;
        return NULL;
    }
    else {
        switch (percentage_parse(val, &percent)) {
            case APR_SUCCESS:
                ts->norm = norm;
                ts->len = apr_time_from_sec((apr_time_sec(norm) * percent / 100L));
                *pts = ts;
                return NULL;
            case APR_BADARG:
                return "percent must be less than 100";
        }
    }
    return "has unrecognized format";
}

const char *md_timeslice_format(const md_timeslice_t *ts, apr_pool_t *p) {
    if (ts->norm > 0) {
        int percent = (int)(((long)apr_time_sec(ts->len)) * 100L 
                            / ((long)apr_time_sec(ts->norm))); 
        return apr_psprintf(p, "%d%%", percent);
    }
    return duration_format(p, ts->len);
}

md_timeperiod_t md_timeperiod_slice_before_end(const md_timeperiod_t *period, 
                                               const md_timeslice_t *ts)
{
    md_timeperiod_t r;
    apr_time_t duration = ts->len;
    
    if (ts->norm > 0) {
        int percent = (int)(((long)apr_time_sec(ts->len)) * 100L 
                            / ((long)apr_time_sec(ts->norm))); 
        apr_time_t plen = md_timeperiod_length(period);
        if (apr_time_sec(plen) > 100) {
            duration = apr_time_from_sec(apr_time_sec(plen) * percent / 100);
        }
        else {
            duration = plen * percent / 100;
        }
    }
    r.start = period->end - duration;
    r.end = period->end;
    return r;
}

int md_timeslice_eq(const md_timeslice_t *ts1, const md_timeslice_t *ts2)
{
    if (ts1 == ts2) return 1;
    if (!ts1 || !ts2) return 0;
    return (ts1->norm == ts2->norm) && (ts1->len == ts2->len);
}

md_timeperiod_t md_timeperiod_common(const md_timeperiod_t *a, const md_timeperiod_t *b)
{
    md_timeperiod_t c;
    
    c.start = (a->start > b->start)? a->start : b->start;
    c.end = (a->end < b->end)? a->end : b->end;
    if (c.start > c.end) {
        c.start = c.end = 0;
    }
    return c;
}
