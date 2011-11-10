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

#ifndef APREQ_UTIL_H
#define APREQ_UTIL_H

#include "apr_file_io.h"
#include "apr_buckets.h"
#include "apreq.h"

#ifdef  __cplusplus
 extern "C" {
#endif

/**
 * This header contains useful functions for creating new
 * parsers, hooks or modules.  It includes
 *
 *    - string <-> array converters
 *    - substring search functions
 *    - simple encoders & decoders for urlencoded strings
 *    - simple time, date, & file-size converters
 * @file apreq_util.h
 * @brief Utility functions for apreq.
 * @ingroup libapreq2
 */

/**
 * Join an array of values. The result is an empty string if there are
 * no values.
 *
 * @param p    Pool to allocate return value.
 * @param sep  String that is inserted between the joined values.
 * @param arr  Array of apreq_value_t entries.
 * @param mode Join type- see apreq_join_t.
 *
 * @return Joined string, or NULL on error
 */
APREQ_DECLARE(char *) apreq_join(apr_pool_t *p,
                                 const char *sep,
                                 const apr_array_header_t *arr,
                                 apreq_join_t mode);

/**
 * Returns offset of match string's location, or -1 if no match is found.
 *
 * @param hay  Location of bytes to scan.
 * @param hlen Number of bytes available for scanning.
 * @param ndl  Search string
 * @param nlen Length of search string.
 * @param type Match type.
 *
 * @return Offset of match string, or -1 if no match is found.
 *
 */
APREQ_DECLARE(apr_ssize_t) apreq_index(const char* hay, apr_size_t hlen,
                                       const char* ndl, apr_size_t nlen,
                                       const apreq_match_t type);

/**
 * Places a quoted copy of src into dest.  Embedded quotes are escaped with a
 * backslash ('\').
 *
 * @param dest Location of quoted copy.  Must be large enough to hold the copy
 *             and trailing null byte.
 * @param src  Original string.
 * @param slen Length of original string.
 * @param dest Destination string.
 *
 * @return length of quoted copy in dest.
 */
APREQ_DECLARE(apr_size_t) apreq_quote(char *dest, const char *src,
                                      const apr_size_t slen);

/**
 *
 * Same as apreq_quote() except when src begins and ends in quote marks. In
 * that case it assumes src is quoted correctly, and just copies src to dest.
 *
 * @param dest Location of quoted copy.  Must be large enough to hold the copy
 *             and trailing null byte.
 * @param src  Original string.
 * @param slen Length of original string.
 * @param dest Destination string.
 *
 * @return length of quoted copy in dest.
 */
APREQ_DECLARE(apr_size_t) apreq_quote_once(char *dest, const char *src,
                                           const apr_size_t slen);

/**
 * Url-encodes a string.
 *
 * @param dest Location of url-encoded result string. Caller must ensure it
 *             is large enough to hold the encoded string and trailing '\\0'.
 * @param src  Original string.
 * @param slen Length of original string.
 *
 * @return length of url-encoded string in dest; does not exceed 3 * slen.
 */
APREQ_DECLARE(apr_size_t) apreq_encode(char *dest, const char *src,
                                       const apr_size_t slen);

/**
 * Convert a string from cp1252 to utf8.  Caller must ensure it is large enough
 * to hold the encoded string and trailing '\\0'.
 *
 * @param dest Location of utf8-encoded result string. Caller must ensure it
 *             is large enough to hold the encoded string and trailing '\\0'.
 * @param src  Original string.
 * @param slen Length of original string.
 *
 * @return length of utf8-encoded string in dest; does not exceed 3 * slen.
 */
APREQ_DECLARE(apr_size_t) apreq_cp1252_to_utf8(char *dest,
                                               const char *src, apr_size_t slen);

/**
 * Heuristically determine the charset of a string.
 *
 * @param src  String to scan.
 * @param slen Length of string.
 *
 * @return APREQ_CHARSET_ASCII  if the string contains only 7-bit chars;
 * @return APREQ_CHARSET_UTF8   if the string is a valid utf8 byte sequence;
 * @return APREQ_CHARSET_LATIN1 if the string has no control chars;
 * @return APREQ_CHARSET_CP1252 if the string has control chars.
 */
APREQ_DECLARE(apreq_charset_t) apreq_charset_divine(const char *src,
                                                    apr_size_t slen);

/**
 * Url-decodes a string.
 *
 * @param dest Location of url-encoded result string. Caller must ensure dest is
 *             large enough to hold the encoded string and trailing null character.
 * @param dlen points to resultant length of url-decoded string in dest
 * @param src  Original string.
 * @param slen Length of original string.
 *
 * @return APR_SUCCESS.
 * @return APR_INCOMPLETE if the string
 *                        ends in the middle of an escape sequence.
 * @return ::APREQ_ERROR_BADSEQ or ::APREQ_ERROR_BADCHAR on malformed input.
 *
 * @remarks In the non-success case, dlen will be set to include
 *          the last succesfully decoded value.  This function decodes
 *          \%uXXXX into a utf8 (wide) character, following ECMA-262
 *          (the Javascript spec) Section B.2.1.
 */

APREQ_DECLARE(apr_status_t) apreq_decode(char *dest, apr_size_t *dlen,
                                         const char *src, apr_size_t slen);

/**
 * Url-decodes an iovec array.
 *
 * @param dest  Location of url-encoded result string. Caller must ensure dest is
 *              large enough to hold the encoded string and trailing null character.
 * @param dlen  Resultant length of dest.
 * @param v     Array of iovecs that represent the source string
 * @param nelts Number of iovecs in the array.
 *
 * @return APR_SUCCESS.
 * @return APR_INCOMPLETE if the iovec
 *                        ends in the middle of an escape sequence.
 * @return ::APREQ_ERROR_BADSEQ or ::APREQ_ERROR_BADCHAR on malformed input.
 *
 * @remarks In the non-APR_SUCCESS case, dlen will be set to include
 *          the last succesfully decoded value.  This function decodes
 *          \%uXXXX into a utf8 (wide) character, following ECMA-262
 *          (the Javascript spec) Section B.2.1.
 */

APREQ_DECLARE(apr_status_t) apreq_decodev(char *dest, apr_size_t *dlen,
                                          struct iovec *v, int nelts);

/**
 * Returns an url-encoded copy of a string.
 *
 * @param p    Pool used to allocate the return value.
 * @param src  Original string.
 * @param slen Length of original string.
 *
 * @return The url-encoded string.
 *
 * @remarks Use this function insead of apreq_encode if its
 *          caller might otherwise overflow dest.
 */
static APR_INLINE
char *apreq_escape(apr_pool_t *p, const char *src, const apr_size_t slen)
{
    char *rv;

    if (src == NULL)
        return NULL;

    rv = (char *)apr_palloc(p, 3 * slen + 1);
    apreq_encode(rv, src, slen);
    return rv;
}

/**
 * An \e in-situ url-decoder.
 *
 * @param str  The string to decode
 *
 * @return  Length of decoded string, or < 0 on error.
 */
static APR_INLINE apr_ssize_t apreq_unescape(char *str)
{
    apr_size_t len;
    apr_status_t rv = apreq_decode(str, &len, str, strlen(str));
    if (rv == APR_SUCCESS)
        return (apr_ssize_t)len;
    else
        return -1;
}

/**
 * Converts file sizes (KMG) to bytes
 *
 * @param s  file size matching m/^\\d+[KMG]b?$/i
 *
 * @return 64-bit integer representation of s.
 *
 * @todo What happens when s is malformed?  Should this return
 *       an unsigned value instead?
 */

APREQ_DECLARE(apr_int64_t) apreq_atoi64f(const char *s);

/**
 * Converts time strings (YMDhms) to seconds
 *
 * @param s time string matching m/^\\+?\\d+[YMDhms]$/
 *
 * @return 64-bit integer representation of s as seconds.
 *
 * @todo What happens when s is malformed?  Should this return
 *       an unsigned value instead?
 */

APREQ_DECLARE(apr_int64_t) apreq_atoi64t(const char *s);

/**
 * Writes brigade to a file.
 *
 * @param f       File that gets the brigade.
 * @param wlen    On a successful return, wlen holds the length of
 *                the brigade, which is the amount of data written to
 *                the file.
 * @param bb      Bucket brigade.
 *
 * @return APR_SUCCESS.
 * @return Error status code from either an unsuccessful apr_bucket_read(),
 *         or a failed apr_file_writev().
 *
 * @remarks       This function leaks a bucket brigade into bb->p whenever
 *                the final bucket in bb is a spool bucket.
 */

APREQ_DECLARE(apr_status_t) apreq_brigade_fwrite(apr_file_t *f,
                                                 apr_off_t *wlen,
                                                 apr_bucket_brigade *bb);
/**
 * Makes a temporary file.
 *
 * @param fp    Points to the temporary apr_file_t on success.
 * @param pool  Pool to associate with the temp file.  When the
 *              pool is destroyed, the temp file will be closed
 *              and deleted.
 * @param path  The base directory which will contain the temp file.
 *              If param == NULL, the directory will be selected via
 *              tempnam().  See the tempnam manpage for details.
 *
 * @return APR_SUCCESS.
 * @return Error status code from unsuccessful apr_filepath_merge(),
 *         or a failed apr_file_mktemp().
 */

APREQ_DECLARE(apr_status_t) apreq_file_mktemp(apr_file_t **fp,
                                              apr_pool_t *pool,
                                              const char *path);

/**
 * Set aside all buckets in the brigade.
 *
 * @param bb Brigade.
 * @param p  Setaside buckets into this pool.
 * @return APR_SUCCESS.
 * @return Error status code from an unsuccessful apr_bucket_setaside().
 */

static APR_INLINE
apr_status_t apreq_brigade_setaside(apr_bucket_brigade *bb, apr_pool_t *p)
{
    apr_bucket *e;
    for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        apr_status_t rv = apr_bucket_setaside(e, p);
        if (rv != APR_SUCCESS)
            return rv;
    }
    return APR_SUCCESS;
}


/**
 * Copy a brigade.
 *
 * @param d (destination) Copied buckets are appended to this brigade.
 * @param s (source) Brigade to copy from.
 *
 * @return APR_SUCCESS.
 * @return Error status code from an unsuccessful apr_bucket_copy().
 *
 * @remarks s == d produces Undefined Behavior.
 */

static APR_INLINE
apr_status_t apreq_brigade_copy(apr_bucket_brigade *d, apr_bucket_brigade *s) {
    apr_bucket *e;
    for (e = APR_BRIGADE_FIRST(s); e != APR_BRIGADE_SENTINEL(s);
         e = APR_BUCKET_NEXT(e))
    {
        apr_bucket *c;
        apr_status_t rv = apr_bucket_copy(e, &c);
        if (rv != APR_SUCCESS)
            return rv;

        APR_BRIGADE_INSERT_TAIL(d, c);
    }
    return APR_SUCCESS;
}

/**
 * Move the front of a brigade.
 *
 * @param d (destination) Append buckets to this brigade.
 * @param s (source) Brigade to take buckets from.
 * @param e First bucket of s after the move.  All buckets
 *          before e are appended to d.
 *
 * @remarks This moves all buckets when e == APR_BRIGADE_SENTINEL(s).
 */

static APR_INLINE
void apreq_brigade_move(apr_bucket_brigade *d, apr_bucket_brigade *s,
                        apr_bucket *e)
{
    apr_bucket *f;

    if (e != APR_BRIGADE_SENTINEL(s)) {
        f = APR_RING_FIRST(&s->list);
        if (f == e) /* zero buckets to be moved */
            return;

        /* obtain the last bucket to be moved */
        e = APR_RING_PREV(e, link);

        APR_RING_UNSPLICE(f, e, link);
        APR_RING_SPLICE_HEAD(&d->list, f, e, apr_bucket, link);
    }
    else {
        APR_BRIGADE_CONCAT(d, s);
    }
}


/**
 * Search a header string for the value of a particular named attribute.
 *
 * @param hdr Header string to scan.
 * @param name Name of attribute to search for.
 * @param nlen Length of name.
 * @param val Location of (first) matching value.
 * @param vlen Length of matching value.
 *
 * @return APR_SUCCESS.
 * @return ::APREQ_ERROR_NOATTR if the attribute is not found.
 * @return ::APREQ_ERROR_BADSEQ if an unpaired quote mark was detected.
 */
APREQ_DECLARE(apr_status_t) apreq_header_attribute(const char *hdr,
                                                   const char *name,
                                                   const apr_size_t nlen,
                                                   const char **val,
                                                   apr_size_t *vlen);


/**
 * Concatenates the brigades, spooling large brigades into
 * a tempfile (APREQ_SPOOL) bucket.
 *
 * @param pool           Pool for creating a tempfile bucket.
 * @param temp_dir       Directory for tempfile creation.
 * @param brigade_limit  If out's length would exceed this value,
 *                       the appended buckets get written to a tempfile.
 * @param out            Resulting brigade.
 * @param in             Brigade to append.
 *
 * @return APR_SUCCESS.
 * @return Error status code resulting from either apr_brigade_length(),
 *         apreq_file_mktemp(), apreq_brigade_fwrite(), or apr_file_seek().
 *
 * @todo Flesh out these error codes, making them as explicit as possible.
 */
APREQ_DECLARE(apr_status_t) apreq_brigade_concat(apr_pool_t *pool,
                                                 const char *temp_dir,
                                                 apr_size_t brigade_limit,
                                                 apr_bucket_brigade *out,
                                                 apr_bucket_brigade *in);

/**
 * Determines the spool file used by the brigade. Returns NULL if the
 * brigade is not spooled in a file (does not use an APREQ_SPOOL
 * bucket).
 *
 * @param bb the bucket brigade
 * @return the spool file, or NULL.
 */
APREQ_DECLARE(apr_file_t *)apreq_brigade_spoolfile(apr_bucket_brigade *bb);

#ifdef __cplusplus
 }
#endif

#endif /* APREQ_UTIL_H */
