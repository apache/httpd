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

#ifndef SSL_CT_UTIL_H
#define SSL_CT_UTIL_H

#include "httpd.h"

apr_status_t ctutil_path_join(char **out, const char *dirname, const char *basename,
                              apr_pool_t *p, server_rec *s);

int ctutil_dir_exists(apr_pool_t *p, const char *dirname);

int ctutil_file_exists(apr_pool_t *p, const char *filename);

void ctutil_buffer_to_array(apr_pool_t *p, const char *b,
                            apr_size_t b_size, apr_array_header_t **out);

apr_status_t ctutil_fopen(const char *fn, const char *mode, FILE **f);

apr_status_t ctutil_read_dir(apr_pool_t *p,
                             server_rec *s,
                             const char *dirname,
                             const char *pattern,
                             apr_array_header_t **outarr);

apr_status_t ctutil_read_file(apr_pool_t *p,
                              server_rec *s,
                              const char *fn,
                              apr_off_t limit,
                              char **contents,
                              apr_size_t *contents_size);

apr_status_t ctutil_run_to_log(apr_pool_t *p,
                               server_rec *s,
                               const char *args[8],
                               const char *desc_for_log);

void ctutil_thread_mutex_lock(apr_thread_mutex_t *m);
void ctutil_thread_mutex_unlock(apr_thread_mutex_t *m);

apr_status_t ctutil_file_write_uint16(server_rec *s,
                                      apr_file_t *f,
                                      apr_uint16_t val);

apr_status_t ctutil_file_write_uint24(server_rec *s,
                                      apr_file_t *f,
                                      apr_uint32_t val);

void ctutil_log_array(const char *file, int line, int module_index,
                      int level, server_rec *s, const char *desc,
                      apr_array_header_t *arr);

apr_status_t ctutil_read_var_bytes(const unsigned char **mem,
                                   apr_size_t *avail,
                                   const unsigned char **start,
                                   apr_size_t *len);

apr_status_t ctutil_deserialize_uint64(const unsigned char **mem,
                                       apr_size_t *avail, apr_uint64_t *pval);
apr_status_t ctutil_deserialize_uint16(const unsigned char **mem,
                                       apr_size_t *avail,
                                       apr_uint16_t *pval);

apr_status_t ctutil_serialize_uint64(unsigned char **mem, apr_size_t *avail,
                                     apr_uint64_t val);

apr_status_t ctutil_serialize_uint24(unsigned char **mem, apr_size_t *avail,
                                     apr_uint32_t val);

apr_status_t ctutil_serialize_uint16(unsigned char **mem, apr_size_t *avail,
                                     apr_uint16_t val);

apr_status_t ctutil_serialize_uint8(unsigned char **mem, apr_size_t *avail,
                                    unsigned char val);

apr_status_t ctutil_write_var16_bytes(unsigned char **mem, apr_size_t *avail,
                                      const unsigned char *val,
                                      apr_uint16_t len);

apr_status_t ctutil_write_var24_bytes(unsigned char **mem, apr_size_t *avail,
                                      const unsigned char *val,
                                      apr_uint32_t len);

void ctutil_run_internal_tests(apr_pool_t *p);

#endif /* SSL_CT_UTIL_H */
