/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#ifndef APACHE_UTIL_CHARSET_H
#define APACHE_UTIL_CHARSET_H

#ifdef APACHE_XLATE

#ifdef __cplusplus
extern "C" {
#endif

#include "apr_xlate.h"

extern apr_xlate_t *ap_hdrs_to_ascii, *ap_hdrs_from_ascii;
extern apr_xlate_t *ap_locale_to_ascii, *ap_locale_from_ascii;

/* Save & Restore the current conversion settings
 *
 * On an EBCDIC machine:
 *
 * "input"  means: ASCII -> EBCDIC (when reading MIME Headers and
 *                                  PUT/POST data)
 * "output" means: EBCDIC -> ASCII (when sending MIME Headers and Chunks)
 *
 * On an ASCII machine:
 *
 *   no conversion of headers, so we need to set the translation handle
 *   to NULL
 */

#define AP_PUSH_INPUTCONVERSION_STATE(_buff, _newx) \
        apr_xlate_t *saved_input_xlate; \
        ap_bgetopt(_buff, BO_RXLATE, &saved_input_xlate); \
        ap_bsetopt(_buff, BO_RXLATE, &(_newx))

#define AP_POP_INPUTCONVERSION_STATE(_buff) \
        ap_bsetopt(_buff, BO_RXLATE, &saved_input_xlate)

#define AP_PUSH_OUTPUTCONVERSION_STATE(_buff, _newx) \
        apr_xlate_t *saved_output_xlate; \
        ap_bgetopt(_buff, BO_WXLATE, &saved_output_xlate); \
        ap_bsetopt(_buff, BO_WXLATE, &(_newx))

#define AP_POP_OUTPUTCONVERSION_STATE(_buff) \
        ap_bsetopt(_buff, BO_WXLATE, &saved_output_xlate)

/* ap_set_content_xlate() is called by Apache core or a module to set
 * up character set translation (a.k.a. recoding) for content.
 */
API_EXPORT(apr_status_t) ap_set_content_xlate(request_rec *r, int output,
                                             apr_xlate_t *xlate);

#ifdef __cplusplus
}
#endif

#endif  /* APACHE_XLATE */
    
#endif  /* !APACHE_UTIL_CHARSET_H */
