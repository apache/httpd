/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef APACHE_UTIL_SCRIPT_H
#define APACHE_UTIL_SCRIPT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APACHE_ARG_MAX
#ifdef _POSIX_ARG_MAX
#define APACHE_ARG_MAX _POSIX_ARG_MAX
#else
#define APACHE_ARG_MAX 512
#endif
#endif

API_EXPORT(char **) ap_create_environment(pool *p, table *t);
API_EXPORT(int) ap_find_path_info(const char *uri, const char *path_info);
API_EXPORT(void) ap_add_cgi_vars(request_rec *r);
API_EXPORT(void) ap_add_common_vars(request_rec *r);
API_EXPORT(int) ap_scan_script_header_err(request_rec *r, FILE *f, char *buffer);
API_EXPORT(int) ap_scan_script_header_err_buff(request_rec *r, BUFF *f,
                                               char *buffer);
API_EXPORT(int) ap_scan_script_header_err_core(request_rec *r, char *buffer,
				       int (*getsfunc) (char *, int, void *),
				       void *getsfunc_data);
API_EXPORT_NONSTD(int) ap_scan_script_header_err_strs(request_rec *r, 
                                                      char *buffer, 
                                                      const char **termch,
                                                      int *termarg, ...);
API_EXPORT(void) ap_send_size(size_t size, request_rec *r);
API_EXPORT(int) ap_call_exec(request_rec *r, child_info *pinfo, char *argv0, char **env,
                          int shellcmd);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_UTIL_SCRIPT_H */
