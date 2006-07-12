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

/**
 * @file ajp_header.h
 * @brief AJP defines
 *
 * @addtogroup AJP_defines
 * @{
 */

#ifndef AJP_HEADER_H
#define AJP_HEADER_H

/*
 * Conditional request attributes
 * 
 */
#define SC_A_CONTEXT            (unsigned char)1
#define SC_A_SERVLET_PATH       (unsigned char)2
#define SC_A_REMOTE_USER        (unsigned char)3
#define SC_A_AUTH_TYPE          (unsigned char)4
#define SC_A_QUERY_STRING       (unsigned char)5
#define SC_A_JVM_ROUTE          (unsigned char)6
#define SC_A_SSL_CERT           (unsigned char)7
#define SC_A_SSL_CIPHER         (unsigned char)8
#define SC_A_SSL_SESSION        (unsigned char)9
#define SC_A_REQ_ATTRIBUTE      (unsigned char)10
#define SC_A_SSL_KEY_SIZE       (unsigned char)11       /* only in if JkOptions +ForwardKeySize */
#define SC_A_SECRET             (unsigned char)12
#define SC_A_ARE_DONE           (unsigned char)0xFF

/*
 * Request methods, coded as numbers instead of strings.
 * The list of methods was taken from Section 5.1.1 of RFC 2616,
 * RFC 2518, the ACL IETF draft, and the DeltaV IESG Proposed Standard.
 *          Method        = "OPTIONS"
 *                        | "GET"    
 *                        | "HEAD"   
 *                        | "POST"   
 *                        | "PUT"    
 *                        | "DELETE" 
 *                        | "TRACE"  
 *                        | "PROPFIND"
 *                        | "PROPPATCH"
 *                        | "MKCOL"
 *                        | "COPY"
 *                        | "MOVE"
 *                        | "LOCK"
 *                        | "UNLOCK"
 *                        | "ACL"
 *                        | "REPORT"
 *                        | "VERSION-CONTROL"
 *                        | "CHECKIN"
 *                        | "CHECKOUT"
 *                        | "UNCHECKOUT"
 *                        | "SEARCH"
 *                        | "MKWORKSPACE"
 *                        | "UPDATE"
 *                        | "LABEL"
 *                        | "MERGE"
 *                        | "BASELINE-CONTROL"
 *                        | "MKACTIVITY"
 * 
 */
#define SC_M_OPTIONS            (unsigned char)1
#define SC_M_GET                (unsigned char)2
#define SC_M_HEAD               (unsigned char)3
#define SC_M_POST               (unsigned char)4
#define SC_M_PUT                (unsigned char)5
#define SC_M_DELETE             (unsigned char)6
#define SC_M_TRACE              (unsigned char)7
#define SC_M_PROPFIND           (unsigned char)8
#define SC_M_PROPPATCH          (unsigned char)9
#define SC_M_MKCOL              (unsigned char)10
#define SC_M_COPY               (unsigned char)11
#define SC_M_MOVE               (unsigned char)12
#define SC_M_LOCK               (unsigned char)13
#define SC_M_UNLOCK             (unsigned char)14
#define SC_M_ACL                (unsigned char)15
#define SC_M_REPORT             (unsigned char)16
#define SC_M_VERSION_CONTROL    (unsigned char)17
#define SC_M_CHECKIN            (unsigned char)18
#define SC_M_CHECKOUT           (unsigned char)19
#define SC_M_UNCHECKOUT         (unsigned char)20
#define SC_M_SEARCH             (unsigned char)21
#define SC_M_MKWORKSPACE        (unsigned char)22
#define SC_M_UPDATE             (unsigned char)23
#define SC_M_LABEL              (unsigned char)24
#define SC_M_MERGE              (unsigned char)25
#define SC_M_BASELINE_CONTROL   (unsigned char)26
#define SC_M_MKACTIVITY         (unsigned char)27


/*
 * Frequent request headers, these headers are coded as numbers
 * instead of strings.
 * 
 * Accept
 * Accept-Charset
 * Accept-Encoding
 * Accept-Language
 * Authorization
 * Connection
 * Content-Type
 * Content-Length
 * Cookie
 * Cookie2
 * Host
 * Pragma
 * Referer
 * User-Agent
 * 
 */

#define SC_ACCEPT               (unsigned short)0xA001
#define SC_ACCEPT_CHARSET       (unsigned short)0xA002
#define SC_ACCEPT_ENCODING      (unsigned short)0xA003
#define SC_ACCEPT_LANGUAGE      (unsigned short)0xA004
#define SC_AUTHORIZATION        (unsigned short)0xA005
#define SC_CONNECTION           (unsigned short)0xA006
#define SC_CONTENT_TYPE         (unsigned short)0xA007
#define SC_CONTENT_LENGTH       (unsigned short)0xA008
#define SC_COOKIE               (unsigned short)0xA009    
#define SC_COOKIE2              (unsigned short)0xA00A
#define SC_HOST                 (unsigned short)0xA00B
#define SC_PRAGMA               (unsigned short)0xA00C
#define SC_REFERER              (unsigned short)0xA00D
#define SC_USER_AGENT           (unsigned short)0xA00E

/*
 * Frequent response headers, these headers are coded as numbers
 * instead of strings.
 * 
 * Content-Type
 * Content-Language
 * Content-Length
 * Date
 * Last-Modified
 * Location
 * Set-Cookie
 * Servlet-Engine
 * Status
 * WWW-Authenticate
 * 
 */

#define SC_RESP_CONTENT_TYPE        (unsigned short)0xA001
#define SC_RESP_CONTENT_LANGUAGE    (unsigned short)0xA002
#define SC_RESP_CONTENT_LENGTH      (unsigned short)0xA003
#define SC_RESP_DATE                (unsigned short)0xA004
#define SC_RESP_LAST_MODIFIED       (unsigned short)0xA005
#define SC_RESP_LOCATION            (unsigned short)0xA006
#define SC_RESP_SET_COOKIE          (unsigned short)0xA007
#define SC_RESP_SET_COOKIE2         (unsigned short)0xA008
#define SC_RESP_SERVLET_ENGINE      (unsigned short)0xA009
#define SC_RESP_STATUS              (unsigned short)0xA00A
#define SC_RESP_WWW_AUTHENTICATE    (unsigned short)0xA00B
#define SC_RES_HEADERS_NUM          11

#endif /* AJP_HEADER_H */
/** @} */
