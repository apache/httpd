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
 * Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * 4. The names "mod_ssl" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    rse@engelschall.com.
 *
 * 5. Products derived from this software may not be called "mod_ssl"
 *    nor may "mod_ssl" appear in their names without prior
 *    written permission of Ralf S. Engelschall.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
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

ssl_ds_array *ssl_ds_array_make(pool *p, int size)
{
    ssl_ds_array *a;

    if ((a = (ssl_ds_array *)ap_palloc(p, sizeof(ssl_ds_array))) == NULL)
        return NULL;
    a->pPool = p;
    if ((a->pSubPool = ap_make_sub_pool(p)) == NULL)
        return NULL;
    a->aData   = ap_make_array(a->pSubPool, 2, size);
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

    d = (void *)ap_push_array(a->aData);
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
    ap_destroy_pool(a->pSubPool);
    a->pSubPool = NULL;
    a->aData    = NULL;
    return;
}

ssl_ds_table *ssl_ds_table_make(pool *p, int size)
{
    ssl_ds_table *t;

    if ((t = (ssl_ds_table *)ap_palloc(p, sizeof(ssl_ds_table))) == NULL)
        return NULL;
    t->pPool = p;
    if ((t->pSubPool = ap_make_sub_pool(p)) == NULL)
        return NULL;
    t->aKey  = ap_make_array(t->pSubPool, 2, MAX_STRING_LEN);
    t->aData = ap_make_array(t->pSubPool, 2, size);
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

    k = (char *)ap_push_array(t->aKey);
    d = (void *)ap_push_array(t->aData);
    ap_cpystrn(k, key, t->aKey->elt_size);
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
    ap_destroy_pool(t->pSubPool);
    t->pSubPool = NULL;
    t->aKey     = NULL;
    t->aData    = NULL;
    return;
}

