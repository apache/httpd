/* ====================================================================
 * Copyright (c) 1995-2000 The Apache Software Foundation.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Software Foundation
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Software Foundation" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Software Foundation.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Software Foundation
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE Apache Software Foundation ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE Apache Software Foundation OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Software Foundation and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/*
 * TODO: Possible additions to this API include getting a list of connection
 * IDs and a list of keys in a particular row.
 */

#ifndef APACHE_MPM_STATUS_H
#define APACHE_MPM_STATUS_H

#include "apr_lib.h"

typedef struct {
    long conn_id;
    ap_table_t *data;
} ap_status_table_row_t;

/**
 *
 * Get a cell from the status table. Don't mess with the string you get.
 *
 * conn_id = Connection ID
 * key = key
 *
 */
API_EXPORT(const char *) ap_get_connection_status(long conn_id, const char *key);

/**
 * Get an array of current connection IDs.
 *
 */
API_EXPORT(ap_array_header_t *) ap_get_connections(ap_context_t *p);

/**
 * Get an array of keys from a given connection.
 *
 * conn_id = Connection ID
 *
 */
API_EXPORT(ap_array_header_t *) ap_get_connection_keys(ap_context_t *p,
                                                       long conn_id);

/**
 *
 * Set a cell in the status table. No guarantees are made that long strings
 * won't be truncated.
 *
 * conn_id = Connection ID
 * key = key
 * value = value
 *
 */
API_EXPORT(void) ap_update_connection_status(long conn_id, const char *key, const char *value);

/**
 *
 * Clear out this connection's status values. Normally called when a
 * connection is closed
 *
 * conn_id = Connection ID
 *
 */
API_EXPORT(void) ap_reset_connection_status(long conn_id);

/**
 *
 * Returns the most up-to-date status table available, in the form of an array
 * of ap_status_row_t's.
 *
 * p = context, generally of the request
 *
 */
API_EXPORT(ap_array_header_t *) ap_get_status_table(ap_context_t *p);

#endif /* APACHE_SERVER_STATS_H */

