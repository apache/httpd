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

#ifndef APACHE_RFC1413_H
#define APACHE_RFC1413_H

#ifdef __cplusplus
extern "C" {
#endif

API_EXPORT(extern char *) ap_rfc1413(conn_rec *conn, server_rec *srv);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_RFC1413_H */
