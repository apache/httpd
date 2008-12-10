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

#ifndef APREQ_ERROR_H
#define APREQ_ERROR_H

#include "apr_errno.h"
#include "apreq.h"

#ifdef  __cplusplus
 extern "C" {
#endif

/**
 * apreq's wrapper around apr_strerror();
 * recognizes APREQ_ERROR_* status codes.
 */
APREQ_DECLARE(char *)
apreq_strerror(apr_status_t s, char *buf, apr_size_t bufsize);

/**
 * @file apreq_error.h
 * @brief Error status codes.
 * @ingroup libapreq2
 *
 * Define the APREQ_ error codes.
 */

#ifndef APR_EBADARG
/**
 * Bad Arguments return value
 * @see APR_BADARG
 */
#define APR_EBADARG                APR_BADARG   /* XXX: don't use APR_BADARG */
#endif

/** Internal apreq error. */
#define APREQ_ERROR_GENERAL        APR_OS_START_USERERR
/** Attempted to perform unsafe action with tainted data. */
#define APREQ_ERROR_TAINTED        (APREQ_ERROR_GENERAL + 1)
/** Parsing interrupted. */
#define APREQ_ERROR_INTERRUPT      (APREQ_ERROR_GENERAL + 2)

/** Invalid input data. */
#define APREQ_ERROR_BADDATA        (APREQ_ERROR_GENERAL  + 10)
/** Invalid character. */
#define APREQ_ERROR_BADCHAR        (APREQ_ERROR_BADDATA  +  1)
/** Invalid byte sequence. */
#define APREQ_ERROR_BADSEQ         (APREQ_ERROR_BADDATA  +  2)
/** Invalid attribute. */
#define APREQ_ERROR_BADATTR        (APREQ_ERROR_BADDATA  +  3)
/** Invalid header. */
#define APREQ_ERROR_BADHEADER      (APREQ_ERROR_BADDATA  +  4)
/** Invalid utf8 encoding. */
#define APREQ_ERROR_BADUTF8        (APREQ_ERROR_BADDATA  +  5)

/** Missing input data. */
#define APREQ_ERROR_NODATA         (APREQ_ERROR_GENERAL  + 20)
/** Missing required token. */
#define APREQ_ERROR_NOTOKEN        (APREQ_ERROR_NODATA   +  1)
/** Missing attribute. */
#define APREQ_ERROR_NOATTR         (APREQ_ERROR_NODATA   +  2)
/** Missing header. */
#define APREQ_ERROR_NOHEADER       (APREQ_ERROR_NODATA   +  3)
/** Missing parser. */
#define APREQ_ERROR_NOPARSER       (APREQ_ERROR_NODATA   +  4)


/** Conflicting information. */
#define APREQ_ERROR_MISMATCH       (APREQ_ERROR_GENERAL  + 30)
/** Exceeds configured maximum limit. */
#define APREQ_ERROR_OVERLIMIT      (APREQ_ERROR_MISMATCH +  1)
/** Below configured minimum limit. */
#define APREQ_ERROR_UNDERLIMIT     (APREQ_ERROR_MISMATCH +  2)
/** Setting already configured. */
#define APREQ_ERROR_NOTEMPTY       (APREQ_ERROR_MISMATCH +  3)


#ifdef __cplusplus
 }
#endif

#endif /* APREQ_ERROR_H */
