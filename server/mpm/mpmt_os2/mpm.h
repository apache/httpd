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

/**
 * @file  mpmt_os2/mpm.h
 * @brief MPM for os2
 *
 * @defgroup APACHE_MPM_OS2 os2 MPM
 * @ingroup  APACHE_OS_OS2 APACHE_MPM
 */
 
#ifndef APACHE_MPM_MPMT_OS2_H
#define APACHE_MPM_MPMT_OS2_H

#define MPMT_OS2_MPM

#include "httpd.h"
#include "mpm_default.h"
#include "scoreboard.h"

#define MPM_NAME "MPMT_OS2"

extern server_rec *ap_server_conf;
#define AP_MPM_WANT_SET_PIDFILE
#define AP_MPM_WANT_SET_MAX_REQUESTS
#define AP_MPM_DISABLE_NAGLE_ACCEPTED_SOCK
#define AP_MPM_WANT_SET_MAX_MEM_FREE

#endif /* APACHE_MPM_MPMT_OS2_H */
/** @} */
