/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

#ifndef APREQ_APACHE2_H
#define APREQ_APACHE2_H

#include "apreq_module.h"
#include "apr_optional.h"
#include <httpd.h>

#ifdef  __cplusplus
 extern "C" {
#endif


/**
 * @defgroup mod_apreq2 Apache 2.X Filter Module
 * @ingroup APACHE_MODS
 * @brief mod_apreq2 - DSO that ties libapreq2 to Apache HTTPD 2.X.
 *
 * mod_apreq2 provides the "APREQ2" input filter for using libapreq2
 * (and allow its parsed data structures to be shared) within
 * the Apache 2.X webserver.  Using it, libapreq2 works properly
 * in every phase of the HTTP request, from translation handlers
 * to output filters, and even for subrequests / internal redirects.
 *
 * <hr>
 *
 * <h2>Activating mod_apreq2 in Apache 2.X</h2>
 *
 * The installation process triggered by
 * <code>% make install</code>
 * <em>will not modify your webserver's config file</em>. Hence,
 * be sure you activate it on startup by adding a LoadModule directive
 * to your webserver config; e.g.
 *
 * @code
 *
 *     LoadModule apreq_module    modules/mod_apreq2.so
 *
 * @endcode
 *
 * The mod_apreq2 filter is named "apreq2", and may be used in Apache's
 * input filter directives, e.g.
 * @code
 *
 *     AddInputFilter apreq2         # or
 *     SetInputFilter apreq2
 *
 * @endcode
 *
 * However, this is not required because libapreq2 will add the filter (only)
 * if it's necessary.  You just need to ensure that your module invokes
 * apreq_handle_apache2() <em>before the content handler ultimately reads
 * from the input filter chain</em>.  It is important to realize that no
 * matter how the input filters are initially arranged, the APREQ2 filter
 * will attempt to reposition itself to be the last input filter to read the
 * data.
 *
 * If you want to use other input filters to transform the incoming HTTP
 * request data, is important to register those filters with Apache
 * as having type AP_FTYPE_CONTENT_SET or AP_FTYPE_RESOURCE.  Due to the
 * limitations of Apache's current input filter design, types higher than
 * AP_FTYPE_CONTENT_SET may not work properly whenever the apreq filter is
 * active.
 *
 * This is especially true when a content handler uses libapreq2 to parse
 * some of the post data before doing an internal redirect.  Any input
 * filter subsequently added to the redirected request will bypass the
 * original apreq filter (and therefore lose access to some of the original
 * post data), unless its type is less than the type of the apreq filter
 * (currently AP_FTYPE_PROTOCOL-1).
 *
 *
 * <H2>Server Configuration Directives</H2>
 *
 * <TABLE class="qref">
 *   <CAPTION>Per-directory commands for mod_apreq2</CAPTION>
 *   <TR>
 *     <TH>Directive</TH>
 *     <TH>Context</TH>
 *     <TH>Default</TH><TH>Description</TH>
 *   </TR>
 *   <TR class="odd">
 *     <TD>APREQ2_ReadLimit</TD>
 *     <TD>directory</TD>
 *     <TD> #APREQ_DEFAULT_READ_LIMIT </TD>
 *     <TD> Maximum number of bytes mod_apreq2 will send off to libapreq2
 *          for parsing. mod_apreq2 will log this event and subsequently
 *          remove itself from the filter chain.
 *     </TD>
 *   </TR>
 *   <TR>
 *     <TD>APREQ2_BrigadeLimit</TD>
 *     <TD>directory</TD>
 *     <TD>#APREQ_DEFAULT_BRIGADE_LIMIT</TD>
 *     <TD> Maximum number of bytes mod_apreq2 will let accumulate
 *          within the heap-buckets in a brigade.  Excess data will be
 *          spooled to an appended file bucket.
 *     </TD>
 *   </TR>
 *   <TR class="odd">
 *     <TD>APREQ2_TempDir</TD>
 *     <TD>directory</TD>
 *     <TD>NULL</TD>
 *     <TD> Sets the location of the temporary directory apreq will use to spool
 *          overflow brigade data (based on the APREQ2_BrigadeLimit setting).
 *          If left unset, libapreq2 will select a platform-specific location
 *          via apr_temp_dir_get().
 *     </TD>
 *  </TR>
 * </TABLE>
 *
 * <H2>Implementation Details</H2>
 * <PRE>
 *   XXX apreq as a normal input filter
 *   XXX apreq as a "virtual" content handler.
 *   XXX apreq as a transparent "tee".
 *   XXX apreq parser registration in post_config
 * </PRE>
 *
 * @{
 */
/**
 * Create an apreq handle which communicates with an Apache 2.X
 * request_rec.
 */
APREQ_DECLARE(apreq_handle_t *) apreq_handle_apache2(request_rec *r);

/**
 *
 *      
 */
#ifdef WIN32
typedef __declspec(dllexport) apreq_handle_t *
(__stdcall apr_OFN_apreq_handle_apache2_t) (request_rec *r);
#else
APR_DECLARE_OPTIONAL_FN(APREQ_DECLARE(apreq_handle_t *),
                        apreq_handle_apache2, (request_rec *r));
#endif

/**
 * The mod_apreq2 filter is named "apreq2", and may be used in Apache's
 * input filter directives, e.g.
 * @code
 *
 *     AddInputFilter apreq2         # or
 *     SetInputFilter apreq2
 * @endcode
 * See above
 */
#define APREQ_FILTER_NAME "apreq2"

/**
 * The Apache2 Module Magic Number for use in the Apache 2.x module structures
 * This gets bumped if changes in th4e API will break third party applications
 * using this apache2 module
 * @see APREQ_MODULE
 */
#define APREQ_APACHE2_MMN 20101207

/** @} */

#ifdef __cplusplus
 }
#endif

#endif
