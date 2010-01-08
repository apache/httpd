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

#ifndef SERVICE_H
#define SERVICE_H

#ifdef WIN32

/* BIG RED WARNING: exit() is mapped to allow us to capture the exit
 * status.  This header must only be included from modules linked into
 * the ApacheCore.dll - since it's a horrible behavior to exit() from
 * any module outside the main() block, and we -will- assume it's a
 * fatal error.  No dynamically linked module will ever be able to find
 * the real_exit_code, and _will_ GP fault if it tries this macro.
 */

#define exit(status) ((exit)((real_exit_code==2) ? (real_exit_code = (status)) \
                                                 : ((real_exit_code = 0), (status))))
extern int real_exit_code;
void hold_console_open_on_error(void);

int service_main(int (*main_fn)(int, char **), int argc, char **argv);
int service95_main(int (*main_fn)(int, char **), int argc, char **argv,
		   char *display_name);
void service_set_status(int status);
void service_cd();
char *get_service_name(char *display_name);
char *get_display_name(char *service_name);
BOOL isProcessService();
BOOL isValidService(char *display_name);
void InstallService(pool *p, char *display_name, int argc, char **argv, int reconfig);
void RemoveService(char *display_name);
int send_signal_to_service(char *display_name, char *sig, 
                           int argc, char **argv);
BOOL isWindowsNT(void);
void ap_start_console_monitor(void);
void ap_start_child_console(int is_child_of_service);

#endif /* WIN32 */

#endif /* SERVICE_H */
