/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
