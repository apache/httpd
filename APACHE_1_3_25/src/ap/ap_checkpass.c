/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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
 * Simple password verify, which 'know's about various password
 * types, such as the simple base64 encoded crypt()s, MD5 $ marked
 * FreeBSD style and netscape SHA1's.
 */
#include <string.h>

#include "ap_config.h"
#include "ap_md5.h"
#include "ap_sha1.h"
#include "ap.h"
#if HAVE_CRYPT_H
#include <crypt.h>
#endif

/*
 * Validate a plaintext password against a smashed one.  Use either
 * crypt() (if available), ap_MD5Encode() or ap_SHA1Encode depending 
 * upon the format of the smashed input password.  
 *
 * Return NULL if they match, or an explanatory text string if they don't.
 */

API_EXPORT(char *) ap_validate_password(const char *passwd, const char *hash)
{
    char sample[120];


    /* FreeBSD style MD5 string 
     */
    if (strncmp(hash, AP_MD5PW_ID, AP_MD5PW_IDLEN) == 0) {

	ap_MD5Encode((const unsigned char *)passwd,
		     (const unsigned char *)hash, sample, sizeof(sample));
    }
    /* Netscape / SHA1 ldap style strng  
     */
    else if (strncmp(hash, AP_SHA1PW_ID, AP_SHA1PW_IDLEN) == 0) {

 	ap_sha1_base64(passwd, strlen(passwd), sample);
    }
    else {
	/*
	 * It's not our algorithm, so feed it to crypt() if possible.
	 */
#if defined(WIN32) || defined(NETWARE)
	/*
	 * On Windows, the only alternative to our MD5 algorithm is plain
	 * text.
	 */
	ap_cpystrn(sample, passwd, sizeof(sample) - 1);
#else
	ap_cpystrn(sample, (char *)crypt(passwd, hash), sizeof(sample) - 1);
#endif
    }
    return (strcmp(sample, hash) == 0) ? NULL : "password mismatch";
}
