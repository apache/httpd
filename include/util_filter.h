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

#ifndef AP_FILTER_H
#define AP_FILTER_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef APR_HAVE_STDARG_H
#include <stdarg.h>
#endif

#include "httpd.h"
#include "apr.h"
#include "ap_buckets.h"

/**
 * @package Apache filter library
 */

#define AP_NOBODY_WROTE         -1;

/*
 * FILTER CHAIN
 *
 * Filters operate using a "chaining" mechanism. The filters are chained
 * together into a sequence. When output is generated, it is passed through
 * each of the filters on this chain, until it reaches the end (or "bottom")
 * and is placed onto the network.
 *
 * The top of the chain, the code generating the output, is typically called
 * a "content generator." The content generator's output is fed into the
 * filter chain using the standard Apache output mechanisms: ap_rputs(),
 * ap_rprintf(), ap_rwrite(), etc.
 *
 * Each filter is defined by a callback. This callback takes the output from
 * the previous filter (or the content generator if there is no previous
 * filter), operates on it, and passes the result to the next filter in the
 * chain. This pass-off is performed using the ap_fc_* functions, such as
 * ap_fc_puts(), ap_fc_printf(), ap_fc_write(), etc.
 *
 * When content generation is complete, the system will pass an "end of
 * stream" marker into the filter chain. The filters will use this to flush
 * out any internal state and to detect incomplete syntax (for example, an
 * unterminated SSI directive).
 */

/* forward declare the filter type */
typedef struct ap_filter_t ap_filter_t;

/*
 * ap_filter_func:
 *
 * This function type is used for filter callbacks. It will be passed a
 * pointer to "this" filter, and a "bucket" containing the content to be
 * filtered.
 *
 * In filter->ctx, the callback will find its context. This context is
 * provided here, so that a filter may be installed multiple times, each
 * receiving its own per-install context pointer.
 *
 * Callbacks are associated with a filter definition, which is specified
 * by name. See ap_register_filter() for setting the association between
 * a name for a filter and its associated callback (and other information).
 *
 * The *bucket structure (and all those referenced by ->next and ->prev)
 * should be considered "const". The filter is allowed to modify the
 * next/prev to insert/remove/replace elements in the bucket list, but
 * the types and values of the individual buckets should not be altered.
 *
 * The return value of a filter should be an APR status value.
 */
typedef apr_status_t (*ap_filter_func)(ap_filter_t *f, ap_bucket_brigade *b);

/*
 * ap_filter_type:
 *
 * Filters have different types/classifications. These are used to group
 * and sort the filters to properly sequence their operation.
 *
 * AP_FTYPE_CONTENT:
 *     These filters are used to alter the content that is passed through
 *     them. Examples are SSI or PHP.
 *
 * AP_FTYPE_CONNECTION:
 *     These filters will alter the content, but in ways that are more
 *     strongly associated with the output connection. Examples are
 *     compression, character recoding, or chunked transfer coding.
 *
 *     It is important to note that these types of filters are not allowed
 *     in a sub-request. A sub-requests output can certainly be filtered
 *     by AP_FTYPE_CONTENT filters, but all of the "final processing" is
 *     determined by the main request.
 *
 * The types have a particular sort order, which allows us to insert them
 * into the filter chain in a determistic order. Within a particular grouping,
 * the ordering is equivalent to the order of calls to ap_add_filter().
 */
typedef enum {
    AP_FTYPE_CONTENT,
    AP_FTYPE_CONNECTION
} ap_filter_type;

/*
 * ap_filter_t:
 *
 * This is the request-time context structure for an installed filter (in
 * the output filter chain). It provides the callback to use for filtering,
 * the request this filter is associated with (which is important when
 * an output chain also includes sub-request filters), the context for this
 * installed filter, and the filter ordering/chaining fields.
 *
 * Filter callbacks are free to use ->ctx as they please, to store context
 * during the filter process. Generally, this is superior over associating
 * the state directly with the request. A callback should not change any of
 * the other fields.
 */

typedef struct ap_filter_rec_t ap_filter_rec_t;

/**
 * This structure is used for recording information about the
 * registered filters. It associates a name with the filter's callback
 * and filter type.
 *
 * At the moment, these are simply linked in a chain, so a ->next pointer
 * is available.
 */
struct ap_filter_rec_t {
    /** The registered name for this filter */
    const char *name;
    /** The function to call when this filter is invoked. */
    ap_filter_func filter_func;
    /** The type of filter, either AP_FTYPE_CONTENT or AP_FTYPE_CONNECTION.  
     * An AP_FTYPE_CONTENT filter modifies the data based on information 
     * found in the content.  An AP_FTYPE_CONNECTION filter modifies the 
     * data based on the type of connection.
     */
    ap_filter_type ftype;

    /** The next filter_rec in the list */
    struct ap_filter_rec_t *next;
};

/**
 * The representation of a filter chain.  Each request has a list
 * of these structures which are called in turn to filter the data.  Sub
 * requests get an exact copy of the main requests filter chain.
 */
struct ap_filter_t {
     /** The internal representation of this filter.  This includes
      *  the filter's name, type, and the actual function pointer.
     */
    ap_filter_rec_t *frec;

    /** A place to store any data associated with the current filter */
    void *ctx;

    /** The next filter in the chain */
    ap_filter_t *next;

    /** The request_rec associated with the current filter.  If a sub-request
     *  adds filters, then the sub-request is the request associated with the
     * filter.
     */
    request_rec *r;
};

/* This function just passes the current bucket brigade down to the next
 * filter on the filter stack.  When a filter actually writes to the network
 * (usually either core or SSL), that filter should return the number of bytes
 * actually written and it will get propogated back up to the handler.  If
 * nobody writes the data to the network, then this function will most likely
 * seg fault.  I haven't come up with a good way to detect that case yet, and
 * it should never happen.  Regardless, it's an unrecoverable error for the
 * current request.  I would just rather it didn't take out the whole child
 * process.  
 */
/**
 * Pass the current bucket brigade down to the next filter on the filter
 * stack.  The filter should return an apr_status_t value.  If the bottom-most 
 * filter doesn't write to the network, then AP_NOBODY_WROTE is returned.
 * @param filter The next filter in the chain
 * @param bucket The current bucket brigade
 * @return apr_status_t value
 * @deffunc apr_status_t ap_pass_brigade(ap_filter_t *filter, ap_bucket_brigade *bucket)
 */
API_EXPORT(apr_status_t) ap_pass_brigade(ap_filter_t *filter, ap_bucket_brigade *bucket);

/*
 * ap_register_filter():
 *
 * This function is used to register a filter with the system. After this
 * registration is performed, then a filter may be added into the filter
 * chain by using ap_add_filter() and simply specifying the name.
 *
 * The filter's callback and type should be passed.
 */
/**
 * Register a filter for later use.  This allows modules to name their filter
 * functions for later addition to a specific request
 * @param name The name to attach to the filter function
 * @param filter_func The filter function to name
 * @param The type of filter function, either AP_FTYPE_CONTENT or AP_FTYPE_CONNECTION
 * @deffunc void ap_register_filter(const char *name, ap_filter_func filter_func, ap_filter_type ftype)
 */
API_EXPORT(void) ap_register_filter(const char *name,
                                    ap_filter_func filter_func,
                                    ap_filter_type ftype);

/*
 * ap_add_filter():
 *
 * Adds a named filter into the filter chain on the specified request record.
 * The filter will be installed with the specified context pointer.
 *
 * Filters added in this way will always be placed at the end of the filters
 * that have the same type (thus, the filters have the same order as the
 * calls to ap_add_filter). If the current filter chain contains filters
 * from another request, then this filter will be added before those other
 * filters.
 * 
 * To re-iterate that last comment.  This function is building a FIFO
 * list of filters.  Take note of that when adding your filter to the chain.
 */
/**
 * Add a filter to the current request.  Filters are added in a FIFO manner.
 * The first filter added will be the first filter called.
 * @param name The name of the filter to add
 * @param r The request to add this filter for.
 * @deffunc void ap_add_filter(const char *name, request_rec *r)
 */
API_EXPORT(void) ap_add_filter(const char *name, request_rec *r);

/* The next two filters are for abstraction purposes only.  They could be
 * done away with, but that would require that we break modules if we ever
 * want to change our filter registration method.  The basic idea, is that
 * all filters have a place to store data, the ctx pointer.  These functions
 * fill out that pointer with a bucket brigade, and retrieve that data on
 * the next call.  The nice thing about these functions, is that they
 * automatically concatenate the bucket brigades together for you.  This means
 * that if you have already stored a brigade in the filters ctx pointer, then
 * when you add more it will be tacked onto the end of that brigade.  When
 * you retrieve data, if you pass in a bucket brigade to the get function,
 * it will append the current brigade onto the one that you are retrieving.
 */
/**
 * Get data that was saved aside for the current filter from an earlier call
 * @param f The current filter
 * @param b The bucket brigade to append to the data that was saved earlier.
 *          This should be the brigade that was most recently passed to the
 *          filter
 * @return A single bucket brigade containing all of the data that was set 
 *         aside from a previous call to ap_save_data_to_filter and the data
 *         that was most recently passed to this filter.
 * @deffunc ap_bucket_brigade *ap_get_saved_data(ap_filter_t *f, ap_bucket_brigade **b)
 */
API_EXPORT(ap_bucket_brigade *) ap_get_saved_data(ap_filter_t *f, 
                                                  ap_bucket_brigade **b);

/**
 * Save a bucket brigade to a filter.  This is used to save portions of the
 * data off to the side for consumption later
 * @param f The current filter
 * @param b The bucket brigade to save aside
 * @deffunc void ap_save_data_to_filter(ap_filter_t *f, ap_bucket_brigade **b)
 */
API_EXPORT(void) ap_save_data_to_filter(ap_filter_t *f, ap_bucket_brigade **b);    

#ifdef __cplusplus
}
#endif

#endif	/* !AP_FILTER_H */
