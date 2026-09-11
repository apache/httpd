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
 * @file ap_bounds_safety.h
 * @brief Portability macros for optional Clang -fbounds-safety
 *
 * When AP_SUPPORT_FBOUNDS_SAFETY is defined (typically via
 * -DAP_SUPPORT_FBOUNDS_SAFETY and a Clang toolchain that implements
 * -fbounds-safety), these macros expand to Clang bounds annotations.
 * Otherwise they expand to nothing so default builds are unchanged.
 *
 * Pattern matches libwebp / libpng / giflib / lz4 / zstd / libzip
 * inert-macro -fbounds-safety adoption: annotations are inert unless
 * explicitly enabled.
 */

#ifndef AP_BOUNDS_SAFETY_H
#define AP_BOUNDS_SAFETY_H

#ifdef AP_SUPPORT_FBOUNDS_SAFETY

#  include <ptrcheck.h>
/* Non-ABI-breaking sized-by annotations for byte buffers whose companion
 * field / argument is a capacity in bytes (e.g. ap_varbuf.avail + 1).
 * Prefer AP_SIZED_BY for buffers that are non-NULL when live; use
 * *_OR_NULL when the pointer may be NULL (e.g. after ap_varbuf_free()).
 */
#  define AP_SIZED_BY(n) __sized_by(n)
#  define AP_SIZED_BY_OR_NULL(n) __sized_by_or_null(n)
#  define AP_COUNTED_BY(n) __counted_by(n)
#  define AP_COUNTED_BY_OR_NULL(n) __counted_by_or_null(n)

#else /* !AP_SUPPORT_FBOUNDS_SAFETY */

#  define AP_SIZED_BY(n)
#  define AP_SIZED_BY_OR_NULL(n)
#  define AP_COUNTED_BY(n)
#  define AP_COUNTED_BY_OR_NULL(n)

#endif /* AP_SUPPORT_FBOUNDS_SAFETY */

#endif /* AP_BOUNDS_SAFETY_H */
