/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <httpd.h>

#include <http_log.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "h3_ssl.h"
#include "h3_util.h"

void make_nv(nghttp3_nv* nv, const char* name, const char* value)
{
    nv->name = (uint8_t*)name;
    nv->value = (uint8_t*)value;
    nv->namelen = strlen(name);
    nv->valuelen = strlen(value);
    nv->flags = NGHTTP3_NV_FLAG_NONE;
}

char* get_openssl_error_string(apr_pool_t* p)
{
    char* buf;
    long len;
    char* ret = NULL;

    // 1. Create a Memory BIO
    // BIO_s_mem() is the memory BIO method
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        return strdup("Failed to create memory BIO.");
    }

    // 2. Print Errors to the BIO (This clears the error queue)
    ERR_print_errors(bio);

    // 3. Extract the Data
    // BIO_get_mem_data returns the internal pointer and its length.
    // NOTE: This pointer is managed by the BIO and should NOT be freed separately.
    len = BIO_get_mem_data(bio, &buf);

    if (len > 0)
    {
        // Allocate a new buffer (+1 for the null terminator)
        ret = (char*)apr_palloc(p, (size_t)(len + 1));
        if (ret != NULL)
        {
            // Copy the data and null-terminate the string
            memcpy(ret, buf, (size_t)len);
            ret[len] = '\0';
        }
    }

    // Clean up the BIO object
    BIO_free(bio);

    // Return the dynamically allocated error string
    return ret;
}

void ERR_print_errors_log(struct h3ssl* h3ssl)
{
    char* err = NULL;
    char* str;
    // if (h3ssl->r != NULL)
    //     err = get_openssl_error_string(h3ssl->r->pool);
    if (h3ssl->c != NULL)
        err = get_openssl_error_string(h3ssl->c->pool);
    if (h3ssl->p != NULL)
        err = get_openssl_error_string(h3ssl->p);
    if (err == NULL)
    {
        abort(); // JFC error in the logic...
        return;
    }
    /* There might several error print them one by one */
    str = err;
    for (size_t i = 0; i < strlen(err); i++)
    {
        if (err[i] == '\n')
        {
            err[i] = '\0';
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "OPENSSL error %s", str);
            str = err + i + 1;
        }
    }
}
