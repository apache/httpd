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
 * @file fcgi_protocol.h
 * @brief FastCGI protocol defines
 *
 * @defgroup FCGI_defines FastCGI protocol definition
 * @ingroup APACHE_INTERNAL
 * @{
 */

#ifndef FCGI_PROTOCOL_H
#define FCGI_PROTOCOL_H


#define FCGI_VERSION 1

#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)

typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} fcgi_header;

#define FCGI_HDR_VERSION_OFFSET         0
#define FCGI_HDR_TYPE_OFFSET            1
#define FCGI_HDR_REQUEST_ID_B1_OFFSET   2
#define FCGI_HDR_REQUEST_ID_B0_OFFSET   3
#define FCGI_HDR_CONTENT_LEN_B1_OFFSET  4
#define FCGI_HDR_CONTENT_LEN_B0_OFFSET  5
#define FCGI_HDR_PADDING_LEN_OFFSET     6
#define FCGI_HDR_RESERVED_OFFSET        7

#define FCGI_BRB_ROLEB1_OFFSET       0
#define FCGI_BRB_ROLEB0_OFFSET       1
#define FCGI_BRB_FLAGS_OFFSET        2
#define FCGI_BRB_RESERVED0_OFFSET    3
#define FCGI_BRB_RESERVED1_OFFSET    4
#define FCGI_BRB_RESERVED2_OFFSET    5
#define FCGI_BRB_RESERVED3_OFFSET    6
#define FCGI_BRB_RESERVED4_OFFSET    7

/*
 * Number of bytes in a fcgi_header.  Future versions of the protocol
 * will not reduce this number.
 */
#define FCGI_HEADER_LEN  8

/*
 * Mask for flags component of FCGI_BeginRequestBody
 */
#define FCGI_KEEP_CONN  1

/*
 * Values for role component of FCGI_BeginRequestBody
 */
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3

typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} fcgi_begin_request_body;

/*
 * Maximum size of the allowed environment.
 */
#define FCGI_MAX_ENV_SIZE  65535

/* #define FCGI_DUMP_ENV_VARS */


#endif /* FCGI_PROTOCOL_H */
/** @} */
