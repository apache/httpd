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
 
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include "md_log.h"

#define LOG_BUFFER_LEN  1024

static const char *level_names[] = {
    "emergency",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug",
    "trace1",
    "trace2",
    "trace3",
    "trace4",
    "trace5",
    "trace6",
    "trace7",
    "trace8",
};

const char *md_log_level_name(md_log_level_t level)
{
    return level_names[level];
}

static md_log_print_cb *log_printv;
static md_log_level_cb *log_level;
static void *log_baton;

void md_log_set(md_log_level_cb *level_cb, md_log_print_cb *print_cb, void *baton)
{
    log_printv = print_cb;
    log_level = level_cb;
    log_baton = baton;
}

int md_log_is_level(apr_pool_t *p, md_log_level_t level)
{
    if (!log_level) {
        return 0;
    }
    return log_level(log_baton, p, level);
}

void md_log_perror(const char *file, int line, md_log_level_t level, 
                   apr_status_t rv, apr_pool_t *p, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (log_printv) {
        log_printv(file, line, level, rv, log_baton, p, fmt, ap);
    }
    va_end(ap);
}
