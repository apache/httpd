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

#include "httpd.h"

#ifndef APACHE_MPM_SIMPLE_H
#define APACHE_MPM_SIMPLE_H

#define MPM_NAME "Simple"

/* pqXXXXXX: shouldn't need this really. */
#define AP_MPM_WANT_SIGNAL_SERVER

/* pqXXXXXX: signal server has a hidden dependency */
#define AP_MPM_WANT_SET_PIDFILE

extern server_rec *ap_server_conf;

#endif /* APACHE_MPM_SIMPLE_H */
