/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
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

#ifndef mod_h2_mod_h2_h
#define mod_h2_mod_h2_h

const char *h2_get_protocol(conn_rec *c);


/** 
 * An optional function which returns the h2 protocol used on the given
 * connection and NULL if no h2* protocol is active on it.
 */
APR_DECLARE_OPTIONAL_FN(const char *, h2_get_protocol, (conn_rec*));

#endif
