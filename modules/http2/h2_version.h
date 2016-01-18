/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef mod_h2_h2_version_h
#define mod_h2_h2_version_h

#undef PACKAGE_VERSION
#undef PACKAGE_TARNAME
#undef PACKAGE_STRING
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT

/**
 * @macro
 * Version number of the http2 module as c string
 */
#define MOD_HTTP2_VERSION "1.2.2"

/**
 * @macro
 * Numerical representation of the version number of the http2 module
 * release. This is a 24 bit number with 8 bits for major number, 8 bits
 * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
 */
#define MOD_HTTP2_VERSION_NUM 0x010202


#endif /* mod_h2_h2_version_h */
