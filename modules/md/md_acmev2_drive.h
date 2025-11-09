/* Copyright 2019 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef md_acmev2_drive_h
#define md_acmev2_drive_h

struct md_json_t;
struct md_proto_driver_t;
struct md_result_t;

apr_status_t md_acmev2_drive_renew(struct md_acme_driver_t *ad, 
                                   struct md_proto_driver_t *d,
                                   struct md_result_t *result);

#endif /* md_acmev2_drive_h */
