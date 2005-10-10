/* Copyright 2001-2005 The Apache Software Foundation or its licensors, as
 * applicable.
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

#ifndef AP_RELEASE_H
#define AP_RELEASE_H

/*
 * The below defines the base string of the Server: header. Additional
 * tokens can be added via the ap_add_version_component() API call.
 *
 * The tokens are listed in order of their significance for identifying the
 * application.
 *
 * "Product tokens should be short and to the point -- use of them for 
 * advertizing or other non-essential information is explicitly forbidden."
 *
 * Example: "Apache/1.1.0 MrWidget/0.1-alpha" 
 */
#define AP_SERVER_BASEVENDOR "Apache Software Foundation"
#define AP_SERVER_BASEPRODUCT "Apache"
#define AP_SERVER_MAJORVERSION "2"
#define AP_SERVER_MINORVERSION "0"
#define AP_SERVER_PATCHLEVEL "55"
#define AP_SERVER_MINORREVISION AP_SERVER_MAJORVERSION "." AP_SERVER_MINORVERSION
#define AP_SERVER_BASEREVISION  AP_SERVER_MINORREVISION "." AP_SERVER_PATCHLEVEL
#define AP_SERVER_BASEVERSION AP_SERVER_BASEPRODUCT "/" AP_SERVER_BASEREVISION
#define AP_SERVER_VERSION  AP_SERVER_BASEVERSION

#endif
