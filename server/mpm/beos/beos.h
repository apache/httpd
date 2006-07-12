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
 * @file  beos/beos.h
 * @brief Extern functions/values for BEOS MPM
 *
 * @addtogroup APACHE_MPM_BEOS
 * @{
 */
#ifndef APACHE_MPM_BEOS_H
#define APACHE_MPM_BEOS_H

extern int ap_threads_per_child;
extern int ap_pipe_of_death[2];
extern int ap_extended_status;
extern void clean_child_exit(int);
extern int max_daemons_limit;

#endif /* APACHE_MPM_BEOS_H */
/** @} */
