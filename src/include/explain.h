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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef EXPLAIN
#define DEF_Explain
#define Explain0(f)
#define Explain1(f,a1)
#define Explain2(f,a1,a2)
#define Explain3(f,a1,a2,a3)
#define Explain4(f,a1,a2,a3,a4)
#define Explain5(f,a1,a2,a3,a4,a5)
#define Explain6(f,a1,a2,a3,a4,a5,a6)
#else
#include "http_log.h"
#define DEF_Explain
#define Explain0(f) \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f)
#define Explain1(f,a1) \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1)
#define Explain2(f,a1,a2) \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1,a2)
#define Explain3(f,a1,a2,a3) \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1,a2,a3)
#define Explain4(f,a1,a2,a3,a4) \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1,a2,a3,a4)
#define Explain5(f,a1,a2,a3,a4,a5)  \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1,a2,a3,a4,a5)
#define Explain6(f,a1,a2,a3,a4,a5,a6)   \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1,a2,a3,a4,a5,a6)

#endif

#ifdef __cplusplus
}
#endif
