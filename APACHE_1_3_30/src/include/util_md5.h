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

#ifndef APACHE_UTIL_MD5_H
#define APACHE_UTIL_MD5_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ap_md5.h"

API_EXPORT(char *) ap_md5(pool *a, const unsigned char *string);
API_EXPORT(char *) ap_md5_binary(pool *a, const unsigned char *buf, int len);
API_EXPORT(char *) ap_md5contextTo64(pool *p, AP_MD5_CTX * context);
#ifdef CHARSET_EBCDIC
API_EXPORT(char *) ap_md5digest(pool *p, FILE *infile, int convert);
#else
API_EXPORT(char *) ap_md5digest(pool *p, FILE *infile);
#endif /* CHARSET_EBCDIC */

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_UTIL_MD5_H */
