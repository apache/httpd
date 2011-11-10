/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

#ifndef APREQ_VERSION_H
#define APREQ_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "apr_version.h"
#include "apreq.h"

/**
 * @file apreq_version.h
 * @brief Versioning API for libapreq
 * @ingroup libapreq2
 *
 * There are several different mechanisms for accessing the version. There
 * is a string form, and a set of numbers; in addition, there are constants
 * which can be compiled into your application, and you can query the library
 * being used for its actual version.
 *
 * Note that it is possible for an application to detect that it has been
 * compiled against a different version of libapreq by use of the compile-time
 * constants and the use of the run-time query function.
 *
 * libapreq version numbering follows the guidelines specified in:
 *
 *     http://apr.apache.org/versioning.html
 */

/* The numeric compile-time version constants. These constants are the
 * authoritative version numbers for libapreq.
 */

/** major version
 * Major API changes that could cause compatibility problems for older
 * programs such as structure size changes.  No binary compatibility is
 * possible across a change in the major version.
 */
#define APREQ_MAJOR_VERSION       2

/**
 * Minor API changes that do not cause binary compatibility problems.
 * Should be reset to 0 when upgrading APREQ_MAJOR_VERSION
 */
#define APREQ_MINOR_VERSION       8

/** patch level */
#define APREQ_PATCH_VERSION       0

/**
 *  This symbol is defined for internal, "development" copies of libapreq.
 *  This symbol will be \#undef'd for releases.
 */
#define APREQ_IS_DEV_VERSION


/** The formatted string of libapreq's version */
#define APREQ_VERSION_STRING \
     APR_STRINGIFY(APREQ_MAJOR_VERSION) "." \
     APR_STRINGIFY(APREQ_MINOR_VERSION) "." \
     APR_STRINGIFY(APREQ_PATCH_VERSION) \
     APREQ_IS_DEV_STRING

/**
 * Return libapreq's version information information in a numeric form.
 *
 *  @param pvsn Pointer to a version structure for returning the version
 *              information.
 */
APREQ_DECLARE(void) apreq_version(apr_version_t *pvsn);

/** Return libapreq's version information as a string. */
APREQ_DECLARE(const char *) apreq_version_string(void);


/** Internal: string form of the "is dev" flag */
#ifdef APREQ_IS_DEV_VERSION
#define APREQ_IS_DEV_STRING "-dev"
#else
#define APREQ_IS_DEV_STRING ""
#endif


#ifdef __cplusplus
}
#endif

#endif /* APREQ_VERSION_H */
