/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

/*
 * suexec.h -- user-definable variables for the suexec wrapper code.
 *             (See README.configure on how to customize these variables.)
 */


#ifndef _SUEXEC_H
#define _SUEXEC_H

/*
 * HTTPD_USER -- Define as the username under which Apache normally
 *               runs.  This is the only user allowed to execute
 *               this program.
 */
#ifndef HTTPD_USER
#define HTTPD_USER "www"
#endif

/*
 * UID_MIN -- Define this as the lowest UID allowed to be a target user
 *            for suEXEC.  For most systems, 500 or 100 is common.
 */
#ifndef UID_MIN
#define UID_MIN 100
#endif

/*
 * GID_MIN -- Define this as the lowest GID allowed to be a target group
 *            for suEXEC.  For most systems, 100 is common.
 */
#ifndef GID_MIN
#define GID_MIN 100
#endif

/*
 * USERDIR_SUFFIX -- Define to be the subdirectory under users' 
 *                   home directories where suEXEC access should
 *                   be allowed.  All executables under this directory
 *                   will be executable by suEXEC as the user so 
 *                   they should be "safe" programs.  If you are 
 *                   using a "simple" UserDir directive (ie. one 
 *                   without a "*" in it) this should be set to 
 *                   the same value.  suEXEC will not work properly
 *                   in cases where the UserDir directive points to 
 *                   a location that is not the same as the user's
 *                   home directory as referenced in the passwd file.
 *
 *                   If you have VirtualHosts with a different
 *                   UserDir for each, you will need to define them to
 *                   all reside in one parent directory; then name that
 *                   parent directory here.  IF THIS IS NOT DEFINED
 *                   PROPERLY, ~USERDIR CGI REQUESTS WILL NOT WORK!
 *                   See the suEXEC documentation for more detailed
 *                   information.
 */
#ifndef USERDIR_SUFFIX
#define USERDIR_SUFFIX "public_html"
#endif

/*
 * LOG_EXEC -- Define this as a filename if you want all suEXEC
 *             transactions and errors logged for auditing and
 *             debugging purposes.
 */
#ifndef LOG_EXEC
#define LOG_EXEC "/usr/local/apache/logs/cgi.log"	/* Need me? */
#endif

/*
 * DOC_ROOT -- Define as the DocumentRoot set for Apache.  This
 *             will be the only hierarchy (aside from UserDirs)
 *             that can be used for suEXEC behavior.
 */
#ifndef DOC_ROOT
#define DOC_ROOT "/usr/local/apache/htdocs"
#endif

/*
 * SAFE_PATH -- Define a safe PATH environment to pass to CGI executables.
 *
 */
#ifndef SAFE_PATH
#define SAFE_PATH "/usr/local/bin:/usr/bin:/bin"
#endif

#endif /* _SUEXEC_H */
