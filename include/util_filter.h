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
typedef struct apr_filter_t apr_filter_t;

/*
 * apr_filter_func:
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
 */
typedef apr_status_t (*apr_filter_func)();

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
 * apr_filter_t:
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
struct apr_filter_t {
    apr_filter_func filter_func;

    void *ctx;

    ap_filter_type ftype;
    apr_filter_t *next;
};

/*
 * ap_register_filter():
 *
 * This function is used to register a filter with the system. After this
 * registration is performed, then a filter may be added into the filter
 * chain by using ap_add_filter() and simply specifying the name.
 *
 * The filter's callback and type should be passed.
 */
API_EXPORT(void) ap_register_filter(const char *name,
                                    apr_filter_func filter_func,
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
 */
API_EXPORT(void) ap_add_filter(const char *name, void *ctx, request_rec *r);


/*
 * Things to do later:
 * Add parameters to apr_filter_func type.  Those parameters will be something
 *     like:
 *         (request_rec *r, apr_filter_t *filter, ap_data_list *the_data)
 *      obviously, the request_rec is the current request, and the filter
 *      is the current filter stack.  The data_list is a bucket list or
 *      bucket_brigade, but I am trying to keep this patch neutral.  (If this
 *      comment breaks that, well sorry, but the information must be there
 *      somewhere.  :-)
 *
 * Add a function like ap_pass_data.  This function will basically just
 * call the next filter in the chain, until the current filter is NULL.  If the
 * current filter is NULL, that means that nobody wrote to the network, and
 * we have a HUGE bug, so we need to return an error and log it to the 
 * log file.
 */
#ifdef __cplusplus
}
#endif

#endif	/* !AP_FILTER_H */
