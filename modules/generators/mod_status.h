/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2003-2004 The Apache Software Foundation.  All rights
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
 */

#ifndef MOD_STATUS_H
#define MOD_STATUS_H

#include "ap_config.h"
#include "httpd.h"

#define AP_STATUS_SHORT    (0x1)  /* short, non-HTML report requested */
#define AP_STATUS_NOTABLE  (0x2)  /* HTML report without tables */
#define AP_STATUS_EXTENDED (0x4)  /* detailed report */

#if !defined(WIN32)
#define STATUS_DECLARE(type)            type
#define STATUS_DECLARE_NONSTD(type)     type
#define STATUS_DECLARE_DATA
#elif defined(STATUS_DECLARE_STATIC)
#define STATUS_DECLARE(type)            type __stdcall
#define STATUS_DECLARE_NONSTD(type)     type
#define STATUS_DECLARE_DATA
#elif defined(STATUS_DECLARE_EXPORT)
#define STATUS_DECLARE(type)            __declspec(dllexport) type __stdcall
#define STATUS_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define STATUS_DECLARE_DATA             __declspec(dllexport)
#else
#define STATUS_DECLARE(type)            __declspec(dllimport) type __stdcall
#define STATUS_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define STATUS_DECLARE_DATA             __declspec(dllimport)
#endif

/* Optional hooks which can insert extra content into the mod_status
 * output.  FLAGS will be set to the bitwise OR of any of the
 * AP_STATUS_* flags.
 *
 * Implementations of this hook should generate content using
 * functions in the ap_rputs/ap_rprintf family; each hook should
 * return OK or DECLINED. */
APR_DECLARE_EXTERNAL_HOOK(ap, STATUS, int, status_hook,
                          (request_rec *r, int flags))
#endif
