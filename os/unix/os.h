/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

#ifndef APACHE_OS_H
#define APACHE_OS_H

#include "apr.h"
#include "ap_config.h"

#ifndef PLATFORM
#define PLATFORM "Unix"
#endif

/**
 * @package OS Specific Functions
 */

/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */


#if APR_HAS_INLINE
/* Compiler supports inline, so include the inlineable functions as
 * part of the header
 */

#include "os-inline.c"

#else

/* Compiler does not support inline, so prototype the inlineable functions
 * as normal
 */

/**
 * Is the path an absolute or relative path
 * @param file The path to the file
 * @return 1 if absolute, 0 otherwise
 * @deffunc int ap_os_is_path_absolute(const char *file)
 */
extern int ap_os_is_path_absolute(const char *file);

#endif

/* Other ap_os_ routines not used by this platform */

/**
 * Perform canonicalization on a given filename.  This means that files on
 * all platforms have the same format
 * @param p The pool to allocate the canonical filename out of
 * @param f The filename to canonicalize
 * @return The new filename
 * @deffunc char *ap_os_canonical_filename(apr_pool_t *p, const char *f)
 */
#define ap_os_canonical_filename(p,f)  (f)

/**
 * Perform canonicalization on a given filename, except that the input case
 * is preserved.
 * @param p The pool to allocate the canonical filename out of
 * @param f The filename to canonicalize
 * @return The new filename
 * @deffunc char *ap_os_case_canonical_filename(apr_pool_t *p, const char *f)
 */
#define ap_os_case_canonical_filename(p,f)  (f)

/**
 * Tries to match a filename to the existing patch, and returns the pathname
 * in the case that is present on the existing path.  This routine also
 * converts alias names to long names.
 * @param p The pool to allocate out of
 * @param f The file to match
 * @return The matched file name with the correct case
 * @deffunc char *ap_os_systemcase_filename(apr_pool_t *p, const char *f)
 */
#define ap_os_systemcase_filename(p,f)  (f)

#endif	/* !APACHE_OS_H */
