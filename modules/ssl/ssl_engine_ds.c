/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_ds.c
**  Additional Data Structures
*/

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
 */

                             /* ``If you can't do it in
                                  C or assembly language,
                                  it isn't worth doing.''
                                         -- Unknown         */
#include "mod_ssl.h"

/*  _________________________________________________________________
**
**  Data Structures which store _arbitrary_ data
**  _________________________________________________________________
*/

ssl_ds_array *ssl_ds_array_make(apr_pool_t *p, int size)
{
    ssl_ds_array *a;

    if ((a = (ssl_ds_array *)apr_palloc(p, sizeof(ssl_ds_array))) == NULL)
        return NULL;
    a->pPool = p;
    apr_pool_sub_make(&a->pSubPool, p, NULL);
    if (a->pSubPool == NULL)
        return NULL;
    a->aData = apr_array_make(a->pSubPool, 2, size);
    return a;
}

BOOL ssl_ds_array_isempty(ssl_ds_array *a)
{
    if (a == NULL || a->aData == NULL || a->aData->nelts == 0)
        return TRUE;
    else
        return FALSE;
}

void *ssl_ds_array_push(ssl_ds_array *a)
{
    void *d;

    d = (void *)apr_array_push(a->aData);
    return d;
}

void *ssl_ds_array_get(ssl_ds_array *a, int n)
{
    void *d;

    if (n < 0 || n >= a->aData->nelts)
        return NULL;
    d = (void *)(a->aData->elts+(a->aData->elt_size*n));
    return d;
}

void ssl_ds_array_wipeout(ssl_ds_array *a)
{
    if (a->aData->nelts > 0)
        memset(a->aData->elts, 0, a->aData->elt_size*a->aData->nelts);
    return;
}

void ssl_ds_array_kill(ssl_ds_array *a)
{
    apr_pool_destroy(a->pSubPool);
    a->pSubPool = NULL;
    a->aData    = NULL;
    return;
}

ssl_ds_table *ssl_ds_table_make(apr_pool_t *p, int size)
{
    ssl_ds_table *t;

    if ((t = (ssl_ds_table *)apr_palloc(p, sizeof(ssl_ds_table))) == NULL)
        return NULL;
    t->pPool = p;
    apr_pool_sub_make(&t->pSubPool, p, NULL);
    if (t->pSubPool == NULL)
        return NULL;
    t->aKey  = apr_array_make(t->pSubPool, 2, MAX_STRING_LEN);
    t->aData = apr_array_make(t->pSubPool, 2, size);
    return t;
}

BOOL ssl_ds_table_isempty(ssl_ds_table *t)
{
    if (t == NULL || t->aKey == NULL || t->aKey->nelts == 0)
        return TRUE;
    else
        return FALSE;
}

void *ssl_ds_table_push(ssl_ds_table *t, char *key)
{
    char *k;
    void *d;

    k = (char *)apr_array_push(t->aKey);
    d = (void *)apr_array_push(t->aData);
    apr_cpystrn(k, key, t->aKey->elt_size);
    return d;
}

void *ssl_ds_table_get(ssl_ds_table *t, char *key)
{
    char *k;
    void *d;
    int i;

    d = NULL;
    for (i = 0; i < t->aKey->nelts; i++) {
        k = (t->aKey->elts+(t->aKey->elt_size*i));
        if (strEQ(k, key)) {
            d = (void *)(t->aData->elts+(t->aData->elt_size*i));
            break;
        }
    }
    return d;
}

void ssl_ds_table_wipeout(ssl_ds_table *t)
{
    if (t->aKey->nelts > 0) {
        memset(t->aKey->elts, 0, t->aKey->elt_size*t->aKey->nelts);
        memset(t->aData->elts, 0, t->aData->elt_size*t->aData->nelts);
    }
    return;
}

void ssl_ds_table_kill(ssl_ds_table *t)
{
    apr_pool_destroy(t->pSubPool);
    t->pSubPool = NULL;
    t->aKey     = NULL;
    t->aData    = NULL;
    return;
}

/*
 * certain key and cert data needs to survive restarts,
 * which are stored in the user data table of s->process->pool.
 * to prevent "leaking" of this data, we use malloc/free
 * rather than apr_palloc and these wrappers to help make sure
 * we do not leak the malloc-ed data.
 */
unsigned char *ssl_asn1_table_set(apr_hash_t *table,
                                  const void *key,
                                  long int length)
{
    apr_ssize_t klen = strlen(key);
    ssl_asn1_t *asn1 = apr_hash_get(table, key, klen);

    /*
     * if a value for this key already exists,
     * reuse as much of the already malloc-ed data
     * as possible.
     */
    if (asn1 && (asn1->nData != length)) {
        free(asn1->cpData); /* XXX: realloc? */
        asn1->cpData = NULL;
    }
    else {
        asn1 = malloc(sizeof(*asn1));
        asn1->mtime = 0; /* used as a note for encrypted private keys */
        asn1->cpData = NULL;
    }

    asn1->nData = length;
    if (!asn1->cpData) {
        asn1->cpData = malloc(length);
    }

    apr_hash_set(table, key, klen, asn1);

    return asn1->cpData; /* caller will assign a value to this */
}

ssl_asn1_t *ssl_asn1_table_get(apr_hash_t *table,
                               const void *key)
{
    return (ssl_asn1_t *)apr_hash_get(table, key, APR_HASH_KEY_STRING);
}

void ssl_asn1_table_unset(apr_hash_t *table,
                          const void *key)
{
    apr_ssize_t klen = strlen(key);
    ssl_asn1_t *asn1 = apr_hash_get(table, key, klen);

    if (!asn1) {
        return;
    }

    if (asn1->cpData) {
        free(asn1->cpData);
    }
    free(asn1);

    apr_hash_set(table, key, klen, NULL);
}
