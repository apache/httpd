/* Copyright 2001-2004 The Apache Software Foundation
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

#ifndef AP_EBCDIC_H
#define AP_EBCDIC_H  "$Id: ap_ebcdic.h,v 1.5 2004/02/16 22:25:08 nd Exp $"

#include <sys/types.h>

extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
API_EXPORT(void *) ebcdic2ascii(void *dest, const void *srce, size_t count);
API_EXPORT(void *) ascii2ebcdic(void *dest, const void *srce, size_t count);

#endif /*AP_EBCDIC_H*/
