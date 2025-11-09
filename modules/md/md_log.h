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

#ifndef mod_md_md_log_h
#define mod_md_md_log_h

typedef enum {
    MD_LOG_EMERG,
    MD_LOG_ALERT,
    MD_LOG_CRIT,
    MD_LOG_ERR, 
    MD_LOG_WARNING, 
    MD_LOG_NOTICE, 
    MD_LOG_INFO, 
    MD_LOG_DEBUG, 
    MD_LOG_TRACE1, 
    MD_LOG_TRACE2, 
    MD_LOG_TRACE3, 
    MD_LOG_TRACE4, 
    MD_LOG_TRACE5, 
    MD_LOG_TRACE6, 
    MD_LOG_TRACE7, 
    MD_LOG_TRACE8, 
} md_log_level_t;

#define MD_LOG_MARK     __FILE__,__LINE__

#ifndef APLOGNO
#define APLOGNO(n)              "AH" #n ": "
#endif

const char *md_log_level_name(md_log_level_t level);

int md_log_is_level(apr_pool_t *p, md_log_level_t level);

void md_log_perror(const char *file, int line, md_log_level_t level, 
                   apr_status_t rv, apr_pool_t *p, const char *fmt, ...)
                                __attribute__((format(printf,6,7)));

typedef int md_log_level_cb(void *baton, apr_pool_t *p, md_log_level_t level);

typedef void md_log_print_cb(const char *file, int line, md_log_level_t level, 
                apr_status_t rv, void *baton, apr_pool_t *p, const char *fmt, va_list ap);

void md_log_set(md_log_level_cb *level_cb, md_log_print_cb *print_cb, void *baton);

#endif /* md_log_h */
