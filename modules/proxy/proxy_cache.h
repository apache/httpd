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

#ifndef __AP_CACHE_H__
#define __AP_CACHE_H__

#include <stdarg.h>
#include "httpd.h"
#include "apr_file_io.h"
#include "apr_network_io.h"
#include "apr_pools.h"
#include "apr_hooks.h"
#include "httpd.h"

/**
 * @package Apache Caching Module API
 */

/* Interface to caching modules
 * This interface will allow access to special modules that will
 * do actual caching calls and maintain elements appropriatly.
 *
 * To date there is only a file version and a shared memory of these caching
 * backends. Clients of thie API need not know where their data will go, in
 * general there are several calls (marked A) that will work on the database
 * as a whole. From those points you will go onto (B) where you can seek, create
 * and remove records. 
 * Upon seeking or creating records you will have an active ap_cache_el. You may
 * continue down into (C) section. 
 *
 * A cache element has two distinct parts, the header (D) and the data (E).
 * One of the uses of the header section will, in fact, be internal to the
 * cache backends to manage expiration. For example, ap_cache modules may
 * use the "Cache-Control" header entry for ap_cache_garbage_collect().
 * All data portions or headers may be used for any purpose, and are not
 * actually used by the API, though some headers may have special meanings
 * to certain backends.
 */

/* *********************
 *  Example client usage:
 *
 *  ap_cache_handle_t *my_cache;
 *  ap_cache_el *element;
 *  apr_file_t *element_buff;
 *
 *  ap_cache_create(&my_cache, "Cache of Farm Animals");
 *
 *  ap_cache_push(my_cache, "Pig", &element);
 *  ap_cache_el_header_add(element, "Sound", "Oink");
 *  ap_cache_el_data(element, &element_buff);
 *  ap_bputs("I smell bacon!\n", element_buff);
 *  ap_cache_el_finalize(element);
 *
 *  ap_cache_seek(my_cache", "Cow", &element);
 *  ap_cache_el_header_walk(my_cache, some_func, NULL, "Sound", NULL);
 *  ....
 *  
 *  ap_cache_close(my_cache);
 *
 *  A client can do anything it wants to an "active" cache_el however it
 *  must guarantee that when it is done with the cache element it will
 *  be finalized. In this way an element in a cache can only be active one
 *  time (and any cache_seek for this element will fail), for this reason
 *  one shouldn't stay open for long ammounts of time. The client is also
 *  responsible for calling garbage_collect periodically to give the cache a
 *  chance to clean up for itself if this is the behaviour it wants.
 */

/* Types used by clients of this interface */
typedef struct ap_cache_handle_t ap_cache_handle_t;
typedef struct ap_cache_el 
{
    ap_cache_handle_t *cache;
    const char *name;
} ap_cache_el;

/* A) Works on the cache database as a whole */
/**
 * This will initialize a cache_handle. This is the main entry point into the 
 * caching API, from this point active caching modules will be asked to fill 
 * in the cache_handle.
 * @param  Where to put the handle
 * @param  A descriptive unique string for your client, this description could
 *         used by caching modules to determine if the their backend is suitable
 *         for this client.
 * @param  Current server_rec, this will be used for retreiving configuration, 
 *         and various other necesar server pieces.
 * @deffunc apr_status_t ap_cache_init(ap_cache_handle_t **h, const char *desc, server_rec *r)
 */
apr_status_t ap_cache_init(ap_cache_handle_t **h, const char *desc, server_rec *r);

/**
 * This function will finalize a cache_handle, after this call the handle will
 * no longer be usable.
 * @param  The handle to close
 * @deffunc apr_status_t ap_cache_close(ap_cache_handle_t *)
 */
apr_status_t ap_cache_close(ap_cache_handle_t *);

/**
 * Force a garbage collection of the cache_handle, the client should call this periodically,
 * the caching module will not do this on its own, however it isn't required to actually 
 * garbage collect anything, and may defer the call until later.
 * @param  The handle to force a garbage collection.
 * @deffunc apr_status_t ap_cache_garbage_collect(ap_cache_handle_t *h)
 */
apr_status_t ap_cache_garbage_collect(ap_cache_handle_t *h);

/* B) insertion and query into database */
/**
 * Seek for a given element in an open cache. This call will fail if the requested element
 * is already "in use" by previous call to ap_cache_seek or ap_cache_create.
 * When finished with the element you must call ap_cache_el_finalize immediatly so the 
 * element is no longer locked.
 * @param  The cache to search in.
 * @param  The name of the record you are looking for
 * @param  Where to put the cache element if a seek succeeds.
 * @deffunc apr_status_t ap_cache_seek(ap_cache_handle_t *h, const char *name, ap_cache_el **)
 */
apr_status_t ap_cache_seek(ap_cache_handle_t *h, const char *name, ap_cache_el **);

/**
 * Create a new element inside of a cache, you must call this first function to put 
 * something new into a cache; after calling you may use the cache_el passed in as
 * you would use one retrieved from an ap_cache_seek. The element will be locked after
 * this call.
 * When finished with the element you must call ap_cache_el_finalize immediatly so the 
 * element is no longer locked.
 * @param  The cache to create this element in.
 * @param  The name to give this new record
 * @param  Where to put this new element. 
 * @deffunc apr_status_t ap_cache_create(ap_cache_handle_t *h, const char *name, ap_cache_el **)
 */
apr_status_t ap_cache_create(ap_cache_handle_t *h, const char *name, ap_cache_el **);

/**
 * Remove a record from a cache. This call will fail if the requested element
 * is already "in use" by previous call to ap_cache_seek or ap_cache_create.
 * When finished with the element you must call ap_cache_el_finalize immediatly so the 
 * element is no longer locked.
 * @param  The cache to remove this record from.
 * @param  The name of the record to remove from the cache.
 * @deffunc apr_status_t ap_cache_remove(ap_cache_handle_t *h, const char *name)
 */
apr_status_t ap_cache_remove(ap_cache_handle_t *h, const char *name);

/* (C) Works on an actual element */

/* (D) Works on the header section */
/**
 * This will retrieve a header value from the element.
 * @param  A previously ap-cache_seek()'d or ap_cache_create()'d element.
 * @param  Header name looking to retrieve, must be null terminated.
 * @param  Where to put the value
 * @deffunc apr_status_t ap_cache_el_header(ap_cache_el *el, const char *hdr, char **val)
 */
apr_status_t ap_cache_el_header(ap_cache_el *el, const char *hdr, char **val);

/**
 * Walk through all the headers for given values. This function is synonymous with 
 * ap_table_walk.
 * @param  The element to walk through.
 * @param  The callback function to use for each element. The paramaters for this function:
 *         1) Client defined data, as passed in by the next paramater to ap-cache_el_header_walk
 *         2) The name of current header that forced this callback.
 *         3) The value of the current header.
 * @param  User defined data passed back to the callback as argument 1.
 * @param  NULL terminated list of headers to walk through. If the first value 
 *         of this list is NULL then ALL element will be walked over.
 * @deffunc apr_status_t ap_cache_el_header_walk(ap_cache_el *el, 
 *                                 int (*comp)(void *, const char *, const char *), void *rec, ...);
 */
apr_status_t ap_cache_el_header_walk(ap_cache_el *el, 
                                    int (*comp)(void *, const char *, const char *), void *rec, ...);

/**
 * This will merge an existing apr_table_t into a cache_el's header section.
 * @param  The cache element to merge onto.
 * @param  The filled in apr_table_t to merge in.
 * @deffunc apr_status_t ap_cache_el_header_merge(ap_cache_el *el, apr_table_t *tbl)
 */
apr_status_t ap_cache_el_header_merge(ap_cache_el *el, apr_table_t *tbl);

/**
 * This will set the current value of a header name to a given value. Using this function
 * the same as first ap_cache_el_header_remove, and then ap-cache_el_header_add.
 * @param  The cache element to modify
 * @param  The name of the header to change
 * @param  The value to assign to the given name.
 * @deffunc apr_status_t ap_cache_el_header_set(ap_cache_el *el, const char *hdrname, const char *hdrval)
 */
apr_status_t ap_cache_el_header_set(ap_cache_el *el, const char *hdrname, const char *hdrval);

/**
 * Each header may have more than one value, you may call this function repeatedly and it will
 * continue adding values onto a header element. If you want to assign a single value to a
 * header you must use ap_cache_el_header_set instead.
 * @param  The cache element to add to
 * @param  The name of the header to append values to.
 * @param  The value to append to the given header name.
 * @deffunc apr_status_t ap_cache_el_header_add(ap_cache_el *el, const char *hdrname, const char *hdrval)
 */
apr_status_t ap_cache_el_header_add(ap_cache_el *el, const char *hdrname, const char *hdrval);

/**
 * This will remove all headers of a given name.
 * @param  The cache element to remove headers from
 * @param  The name of the header to remove. This will remove ALL values assigned to this
 *         header (via the ap_cache_el_header_add call).
 * @deffunc apr_status_t ap_cache_el_header_remove(ap_cache_el *el, const char *hdr)
 */
apr_status_t ap_cache_el_header_remove(ap_cache_el *el, const char *hdr);

/**
 * This will clear out an entire header section. You may use this if you are intending
 * to change the entire value of the header section of a cache element.
 * @param  The element to clear 
 * @deffunc apr_status_t ap_cache_el_header_clear(ap_cache_el *el)
 */
apr_status_t ap_cache_el_header_clear(ap_cache_el *el);

/* (E) Works on the data section */
/**
 * Retrieve a apr_file_t for a given cache element, where this data goes is opaque to all
 * clients of this API. You can do all operations on the apr_file_t and trust the underlying
 * caching module will accept the data and put it in the appropriate place.
 * @param  The element to retrieve data
 * @param  Where to put the apr_file_t structure when it comes back. In some cases this
 *         will be a normal buff that will either write to a network, or disk - but
 *         you should not rely on it going anywhere in a caching module as the destination
 *         for all data is opaque.
 * @deffunc apr_status_t ap_cache_el_data(ap_cache_el *el, apr_file_t **)
 */
apr_status_t ap_cache_el_data(ap_cache_el *el, apr_file_t **);

/**
 * Convenience function to put an existing apr_file_t into a cache_el's data section. This
 * function will probably not be fully optimal - and will actually just pipe one apr_file_t
 * to another.
 * @param  The element to append to
 * @param  An existing apr_file_t to append onto the ap_cache_el's stream of data.
 * @deffunc apr_status_t ap_cache_el_data_append(ap_cache_el *el, apr_file_t *data)
 */
apr_status_t ap_cache_el_data_append(ap_cache_el *el, apr_file_t *data);

/**
 * Clear the data section of an existing cache_el. You may use this if you are 
 * intending to change the entire value of the data section of a cache element.
 * @param  The element to clear
 * @deffunc apr_status_t ap_cache_el_data_clear(ap_cache_el *el)
 */
apr_status_t ap_cache_el_data_clear(ap_cache_el *el);

/**
 * This will complete an open element. When you are done working on a caching
 * element you must call this so the object will be unlocked and all data will
 * be finalized, in some cases that means certain data won't make it into the
 * destination backend until this call is made. Each module may decide how much
 * this function actually does but you MUST call this function immediatly after
 * completing a cache record.
 * @param  The element to finalize, after calling this function the caching
 *         element is no longer valid and you must ap_cache_seek for it again if
 *         you want to make any further changes to it.
 * @deffunc apr_status_t ap_cache_el_finalize(ap_cache_el *el)
 */
apr_status_t ap_cache_el_finalize(ap_cache_el *el);

/* ****************************************************************************/
/* ****************************************************************************/
/* This section is internal entirely, but it is exposed because
 * implementors of caching modules will need to use some of this. Clients
 * of the library are NEVER to use this interface however, and should use
 * the above accessors to the cache.
 */ 

/* This is how a cache module can grab control. This will be fired once the 
 * ap_cache_init call is made, each paramater will coorespond to the paramaters
 * passed into ap_cache_init. If your cache wants to reject a hook call return 
 * APR_ENOTIMPL from your hook and the next caching module will be tried.
 */
AP_DECLARE_HOOK(apr_status_t, cache_init, (ap_cache_handle_t **, const char *desc, server_rec *t))

/* These are various enum's passed into call back functions (as defined below) */
typedef enum { AP_CACHE_SEEK, AP_CACHE_CREATE, AP_CACHE_CHANGE, AP_CACHE_REMOVE } ap_cache_query;
typedef enum { AP_CACHE_DATA, AP_CACHE_HEADER } ap_cache_part;

/* These are the callback functions filled in by handler of the cache_init hook. 
 * function may be NULL and will in turn return APR_ENOTIMPL by any of the various 
 * calls in the API.
 */
typedef struct ap_cache_methods 
{
    apr_status_t (*cache_close)(ap_cache_handle_t *h);
    apr_status_t (*cache_garbage_coll)(ap_cache_handle_t *h);
    apr_status_t (*cache_element)(ap_cache_handle_t *h, const char *name, ap_cache_el **,
                                 ap_cache_query flag);
    apr_status_t (*cache_el_header_walk)(ap_cache_el *el, 
                                     int (*comp)(void *, const char *, const char *), void *rec, va_list);
    apr_status_t (*cache_el_hdr)(ap_cache_el *el, const char *name, const char *val, ap_cache_query flag);
    apr_status_t (*cache_el_data)(ap_cache_el *el, apr_file_t **);
    apr_status_t (*cache_el_reset)(ap_cache_el *, ap_cache_part flag);
    apr_status_t (*cache_el_final)(ap_cache_el *el);
} ap_cache_methods;
/* This is declared here because modules need to fill this in, however
 *  clients of the library should NEVER use this 
 */
struct ap_cache_handle_t
{
    apr_pool_t *pool;    /* pool for alloc's */
    server_rec *server; /* access to configurations, used on init */
    ap_cache_methods meth;
};

#endif /* __AP_CACHE_H__ */
