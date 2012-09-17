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

#include "ap_config.h"

#if APR_CHARSET_EBCDIC

#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "util_charset.h"

/* ap_hdrs_to_ascii, ap_hdrs_from_ascii
 *
 * These are the translation handles used to translate between the network
 * format of protocol headers and the local machine format.
 *
 * For an EBCDIC machine, these are valid handles which are set up at
 * initialization to translate between ISO-8859-1 and the code page of
 * the source code.
 *
 * For an ASCII machine, these remain NULL so that when they are stored
 * in the BUFF via ap_bsetop(BO_RXLATE) it ensures that no translation is
 * performed.
 */

apr_xlate_t *ap_hdrs_to_ascii, *ap_hdrs_from_ascii;

#endif /*APR_CHARSET_EBCDIC */
