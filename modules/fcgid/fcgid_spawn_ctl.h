/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

#ifndef FCGID_SPAWN_CONTROL_H
#define FCGID_SPAWN_CONTROL_H
#include "fcgid_proctbl.h"
#include "fcgid_pm.h"

void spawn_control_init(server_rec * main_server, apr_pool_t * configpool);
void register_termination(server_rec * main_server,
                          fcgid_procnode * procnode);
void register_spawn(server_rec * main_server, fcgid_procnode * procnode);
int is_spawn_allowed(server_rec * main_server, fcgid_command * command);
int is_kill_allowed(server_rec * main_server, fcgid_procnode * procnode);

#endif
