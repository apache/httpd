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
 */

#ifndef APACHE_AP_MMN_H
#define APACHE_AP_MMN_H

/**
 * @package Module Magic Number
 */

/*
 * MODULE_MAGIC_NUMBER_MAJOR
 * Major API changes that could cause compatibility problems for older modules
 * such as structure size changes.  No binary compatibility is possible across
 * a change in the major version.
 *
 * MODULE_MAGIC_NUMBER_MINOR
 * Minor API changes that do not cause binary compatibility problems.
 * Should be reset to 0 when upgrading MODULE_MAGIC_NUMBER_MAJOR.
 *
 * See the MODULE_MAGIC_AT_LEAST macro below for an example.
 */

/*
 * 20010224 (2.0.13-dev) MODULE_MAGIC_COOKIE reset to "AP20"
 * 20010523 (2.0.19-dev) bump for scoreboard structure reordering
 * 20010627 (2.0.19-dev) more API changes than I can count
 * 20010726 (2.0.22-dev) more big API changes
 * 20010808 (2.0.23-dev) dir d_is_absolute bit introduced, bucket changes, etc
 * 20010825 (2.0.25-dev) removed d_is_absolute, introduced map_to_storage hook
 * 20011002 (2.0.26-dev) removed 1.3-depreciated request_rec.content_language
 */

#define MODULE_MAGIC_COOKIE 0x41503230UL /* "AP20" */

#ifndef MODULE_MAGIC_NUMBER_MAJOR
#define MODULE_MAGIC_NUMBER_MAJOR 20011002
#endif
#define MODULE_MAGIC_NUMBER_MINOR 0                     /* 0...n */
#define MODULE_MAGIC_NUMBER MODULE_MAGIC_NUMBER_MAJOR	/* backward compat */

/**
 * Determine if the server's current MODULE_MAGIC_NUMBER is at least a
 * specified value.
 * <pre>
 * Useful for testing for features.
 * For example, suppose you wish to use the apr_table_overlap
 *    function.  You can do this:
 * 
 * #if MODULE_MAGIC_AT_LEAST(19980812,2)
 *     ... use apr_table_overlap()
 * #else
 *     ... alternative code which doesn't use apr_table_overlap()
 * #endif
 * </pre>
 * @param major The major module magic number
 * @param minor The minor module magic number
 * @deffunc MODULE_MAGIC_AT_LEAST(int major, int minor)
 */
#define MODULE_MAGIC_AT_LEAST(major,minor)		\
    ((major) > MODULE_MAGIC_NUMBER_MAJOR 		\
	|| ((major) == MODULE_MAGIC_NUMBER_MAJOR 	\
	    && (minor) >= MODULE_MAGIC_NUMBER_MINOR))

#endif /* !APACHE_AP_MMN_H */
