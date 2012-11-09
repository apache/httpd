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

#ifndef _eventopt_mpm_equeue_h_
#define _eventopt_mpm_equeue_h_

#include "httpd.h"

typedef struct ap_equeue_t ap_equeue_t;

apr_status_t
ap_equeue_create(apr_pool_t *p,
                 unsigned int nelem,
                 apr_size_t elem_size,
                 ap_equeue_t **eqout);


/**
 * Current value of the reader, returns NULL if the reader is caught up
 * with the writer
 */
void* ap_equeue_reader_next(ap_equeue_t *eq);

/**
 * Returns pointer to next available write slot.  May block
 * in a spin lock if none are available.
 */
void* ap_equeue_writer_value(ap_equeue_t *eq);

/**
 * Move the write position up one, making the previously 
 * editted value available to the reader.
 */
void ap_equeue_writer_onward(ap_equeue_t *eq);


#endif
