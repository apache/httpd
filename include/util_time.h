/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2001-2004 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

#ifndef APACHE_UTIL_TIME_H
#define APACHE_UTIL_TIME_H

#include "apr.h"
#include "apr_time.h"
#include "httpd.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @package Apache date-time handling functions
 */

/* Maximum delta from the current time, in seconds, for a past time
 * to qualify as "recent" for use in the ap_explode_recent_*() functions:
 * (Must be a power of two minus one!)
 */
#define AP_TIME_RECENT_THRESHOLD 15

/**
 * convert a recent time to its human readable components in local timezone
 * @param tm the exploded time
 * @param t the time to explode: MUST be within the last
 *          AP_TIME_RECENT_THRESHOLD seconds
 * @note This is a faster alternative to apr_explode_localtime that uses
 *       a cache of pre-exploded time structures.  It is useful for things
 *       that need to explode the current time multiple times per second,
 *       like loggers.
 * @return APR_SUCCESS iff successful
 */
AP_DECLARE(apr_status_t) ap_explode_recent_localtime(apr_time_exp_t *tm,
                                                     apr_time_t t);

/**
 * convert a recent time to its human readable components in GMT timezone
 * @param tm the exploded time
 * @param t the time to explode: MUST be within the last
 *          AP_TIME_RECENT_THRESHOLD seconds
 * @note This is a faster alternative to apr_time_exp_gmt that uses
 *       a cache of pre-exploded time structures.  It is useful for things
 *       that need to explode the current time multiple times per second,
 *       like loggers.
 * @return APR_SUCCESS iff successful
 */
AP_DECLARE(apr_status_t) ap_explode_recent_gmt(apr_time_exp_t *tm,
                                               apr_time_t t);


/**
 * format a recent timestamp in the ctime() format.
 * @param date_str String to write to.
 * @param t the time to convert 
 */
AP_DECLARE(apr_status_t) ap_recent_ctime(char *date_str, apr_time_t t);

/**
 * format a recent timestamp in the RFC822 format
 * @param date_str String to write to (must have length >= APR_RFC822_DATE_LEN)
 * @param t the time to convert 
 */
AP_DECLARE(apr_status_t) ap_recent_rfc822_date(char *date_str, apr_time_t t);

#ifdef __cplusplus
}
#endif

#endif  /* !APACHE_UTIL_TIME_H */
