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
 */

/*
 * TODO: Possible additions to this API include getting a list of connection
 * IDs and a list of keys in a particular row.
 */

#ifndef APACHE_MPM_STATUS_H
#define APACHE_MPM_STATUS_H

#include "apr_lib.h"

/**
 * @package MPM Status API
 */

typedef struct ap_status_table_row_t ap_status_table_row_t;
/** 
 * The MPM status table row structure.  MPMs should use this structure in
 * a table to store the status for the requests.  This structure stores the
 * status for one connection 
 */ 
struct ap_status_table_row_t {
    /** The connection id.  This is used as a key for the status table */
    long conn_id;
    /** The actual status.  This is a table of key-value pairs */
    apr_table_t *data;
};

/**
 * Get a cell from the status table. Don't mess with the string you get.
 * @param conn_id Connection ID of the current connection
 * @param key The key to determine which status value should be retrieved
 *            for the connection.
 * @deffunc const char *ap_get_connection_status(long conn_id, const char *key)
 */
AP_DECLARE(const char *) ap_get_connection_status(long conn_id, const char *key);

/**
 * Get an array of current connection IDs.
 * @param p The pool to allocate the array out of
 * @return An array of all the current connection IDs
 * @deffunc apr_array_header_t *ap_get_connections(apr_pool_t *p)
 */
AP_DECLARE(apr_array_header_t *) ap_get_connections(apr_pool_t *p);

/**
 * Get an array of keys from a given connection.
 * @param p Pool to allocate out of
 * @param conn_id Connection ID to get the keys for
 * @return an array of keys from a given connection
 * @deffunc apr_array_header_t *ap_get_connection_keys(apr_pool_t *p, long conn_id)
 */
AP_DECLARE(apr_array_header_t *) ap_get_connection_keys(apr_pool_t *p,
                                                       long conn_id);

/**
 * Set a cell in the status table. No guarantees are made that long strings
 * won't be truncated.
 * @param conn_id Connection ID to update
 * @param key key to update
 * @param value value to set for the key
 * @deffunc void ap_update_connection_status(long conn_id, const char *key, const char *value)
 */
AP_DECLARE(void) ap_update_connection_status(long conn_id, const char *key, const char *value);

/**
 * Clear out this connection's status values. Normally called when a
 * connection is closed
 * @param conn_id The connection ID to clear
 * @deffunc void ap_reset_connection_status(long conn_id)
 */
AP_DECLARE(void) ap_reset_connection_status(long conn_id);

/**
 * Returns the most up-to-date status table available, in the form of an array
 * of ap_status_row_t's.
 * @param p pool to allocate the array out of, generally from the request_rec
 * @return The table of statuses for all connections
 * @deffunc apr_array_header_t *ap_get_status_table(apr_pool_t *p)
 */
AP_DECLARE(apr_array_header_t *) ap_get_status_table(apr_pool_t *p);

#endif /* APACHE_SERVER_STATS_H */

