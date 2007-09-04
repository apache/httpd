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

#ifndef APACHE_REGISTRY_H
#define APACHE_REGISTRY_H

#ifdef WIN32

/*
 * Declarations for users of the functions defined in registry.c
 */

API_EXPORT(int) ap_registry_get_server_root(pool *p, char *dir, int size);
extern int ap_registry_set_server_root(char *dir);
extern int ap_registry_get_service_args(pool *p, int *argc, char ***argv, char *display_name);
extern int ap_registry_set_service_args(pool *p, int argc, char **argv, char *display_name);

#endif WIN32

#endif APACHE_REGISTRY_H
