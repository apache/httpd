/* ====================================================================
 * Copyright (c) 1998 The Apache Group.  All rights reserved.
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
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
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
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#ifndef APACHE_AP_MMN_H
#define APACHE_AP_MMN_H

/*
 * MODULE_MAGIC_NUMBER_MAJOR
 * Major API changes that could cause compatibility problems for older modules
 * such as structure size changes.  No binary compatibility is possible across
 * a change in the major version.
 *
 * MODULE_MAGIC_NUMBER_MINOR
 * Minor API changes that do not cause binary compatibility problems.
 * Should be reset to 0 when upgrading MODULE_MAGIC_NUMBER_MAJOR.
 *
 * See the MODULE_MAGIC_AT_LEAST macro below for an example.
 */

/*
 * 19950525		- original value
 * 19960512 (1.1b2)	- updated, 1.1, version.
 * 19960526 (1.1b3)	- get_token(), table_unset(), pstrndup()
 *			  functions added
 * 19960725 (1.2-dev)	- HTTP/1.1 compliance
 *			  (new version of read_client_block)
 * 19960806 (1.2-dev)	- scan_script_header_err() added
 * 19961007 (1.2-dev)	- replace read_client_block() with get_client_block()
 * 19961125 (1.2b1)	- change setup_client_block() to Roy's version
 * 19961211 (1.2b3)	- rwrite() added
 * 19970103 (1.2b5-dev)	- header parse API
 * 19970427 (1.2b9-dev)	- port references made unsigned
 * 19970526 (1.2)	- correct vhost walk for multiple requests on a single
 *			  connect
 * 19970623 (1.3-dev)	- NT changes
 * 19970628 (1.3-dev)	- ap_slack (fd fixes) added
 * 19970717 (1.3-dev)	- child_init API hook added
 * 19970719 (1.3-dev)	- discard_request_body() added (to clear the decks
 *			  as needed)
 * 19970728 (1.3a2-dev)	- child_exit API hook added
 * 19970818 (1.3a2-dev)	- post read-request phase added
 * 19970825 (1.3a2-dev)	- r->mtime cell added
 * 19970831 (1.3a2-dev)	- error logging changed to use aplog_error()
 * 19970902 (1.3a2-dev)	- MD5 routines and structures renamed to ap_*
 * 19970912 (1.3b1-dev)	- set_last_modified split into set_last_modified,
 * 			  set_etag and meets_conditions
 *			  register_other_child API
 *			  piped_log API
 *			  short_score split into parent and child pieces
 *			  os_is_absolute_path
 * 19971026 (1.3b3-dev)	- custom config hooks in place
 * 19980126 (1.3b4-dev)	- ap_cpystrn(), table_addn(), table_setn(),
 *			  table_mergen()
 * 19980201 (1.3b4-dev)	- construct_url()
 *			  prototype server_rec * -> request_rec *
 *			  add get_server_name() and get_server_port()
 * 19980207 (1.3b4-dev)	- add dynamic_load_handle to module structure as part
 *			  of the STANDARD_MODULE_STUFF header
 * 19980304 (1.3b6-dev)	- abstraction of SERVER_BUILT and SERVER_VERSION
 * 19980305 (1.3b6-dev)	- ap_config.h added for use by external modules
 * 19980312 (1.3b6-dev)	- parse_uri_components() and its ilk
 *			  remove r->hostlen, add r->unparsed_uri
 *			  set_string_slot_lower()
 *			  clarification: non-RAW_ARGS cmd handlers do not
 *			  need to pstrdup() their arguments
 *			  clarification: request_rec members content_type,
 *			  handler, content_encoding, content_language,
 *			  content_languages MUST all be lowercase strings,
 *			  and MAY NOT be modified in place -- modifications
 *			  require pstrdup().
 * 19980317 (1.3b6-dev)	- CORE_EXPORTs for win32 and <Perl>
 *			  API export basic_http_header, send_header_field,
 *			  set_keepalive, srm_command_loop, check_cmd_context,
 *			  tm2sec
 *			  spacetoplus(), plustospace(), client_to_stdout()
 *			  removed
 * 19980324 (1.3b6-dev)	- API_EXPORT(index_of_response)
 * 19980413 (1.3b6-dev)	- The BIG SYMBOL RENAMING: general ap_ prefix
 *			  (see src/include/compat.h for more details)
 *			  ap_vformatter() API, see src/include/ap.h
 * 19980507 (1.3b7-dev)	- addition of ap_add_version_component() and
 *			  discontinuation of -DSERVER_SUBVERSION support
 * 19980519 (1.3b7-dev)	- add child_info * to spawn function (as passed to
 *			  ap_spawn_child_err_buff) and to ap_call_exec to make
 *			  children work correctly on Win32.
 * 19980527 (1.3b8-dev)	- renamed some more functions to ap_ prefix which were
 *			  missed at the big renaming (they are defines):
 *			  is_default_port, default_port and http_method.
 *			  A new communication method for modules was added:
 *			  they can create customized error messages under the
 *			  "error-notes" key in the request_rec->notes table.
 *			  This string will be printed in place of the canned
 *			  error responses, and will be propagated to
 *			  ErrorDocuments or cgi scripts in the
 *			  (REDIRECT_)ERROR_NOTES variable.
 * 19980627 (1.3.1-dev)	- More renaming that we forgot/bypassed. In particular:
 *			  table_elts --> ap_table_elts
 *			  is_table_empty --> ap_is_table_empty
 * 19980708 (1.3.1-dev)	- ap_isalnum(), ap_isalpha(), ... "8-bit safe" ctype
 *			  macros and apctype.h added
 * 19980713 (1.3.1-dev)	- renaming of C header files:
 *			  1. conf.h      -> ap_config.h
 *			  2. conf_auto.h -> ap_config_auto.h - now merged
 *			  3. ap_config.h -> ap_config_auto.h - now merged
 *			  4. compat.h    -> ap_compat.h
 *			  5. apctype.h   -> ap_ctype.h
 * 19980806 (1.3.2-dev) - add ap_log_rerror()
 *                      - add ap_scan_script_header_err_core()
 *                      - add ap_uuencode()
 *                      - add ap_custom_response()
 * 19980811 (1.3.2-dev)	- added limit_req_line, limit_req_fieldsize, and
 *			  limit_req_fields to server_rec.
 *			  added limit_req_body to core_dir_config and
 *			  ap_get_limit_req_body() to get its value.
 * 19980812 (1.3.2-dev)	- split off MODULE_MAGIC_NUMBER
 * 19980812.2           - add ap_overlap_tables()
 * 19980816 (1.3.2-dev)	- change proxy to use tables for headers, change
 *                        struct cache_req to typedef cache_req.
 *                        Delete ap_proxy_get_header(), ap_proxy_add_header(),
 *                        ap_proxy_del_header(). Change interface of 
 *                        ap_proxy_send_fb() and ap_proxy_cache_error(). 
 *                        Add ap_proxy_send_hdr_line() and ap_proxy_bputs2().
 * 19980825 (1.3.2-dev) - renamed is_HTTP_xxx() macros to ap_is_HTTP_xxx()
 * 19980825.1           - mod_proxy only (minor change): modified interface of
 *                        ap_proxy_read_headers() and rdcache() to use a
 *                        request_rec* instead of pool*
 *                        (for implementing better error reporting).
 * 19980906 (1.3.2-dev) - added ap_md5_binary()
 * 19980917 (1.3.2-dev) - bs2000: changed os_set_authfile() to os_set_account()
 */

#ifndef MODULE_MAGIC_NUMBER_MAJOR
#define MODULE_MAGIC_NUMBER_MAJOR 19980917
#endif
#define MODULE_MAGIC_NUMBER_MINOR 0                     /* 0...n */
#define MODULE_MAGIC_NUMBER MODULE_MAGIC_NUMBER_MAJOR	/* backward compat */

/* Useful for testing for features. */
#define MODULE_MAGIC_AT_LEAST(major,minor)		\
    ((major) > MODULE_MAGIC_NUMBER_MAJOR 		\
	|| ((major) == MODULE_MAGIC_NUMBER_MAJOR 	\
	    && (minor) >= MODULE_MAGIC_NUMBER_MINOR))

/* For example, suppose you wish to use the ap_overlap_tables
   function.  You can do this:

#if MODULE_MAGIC_AT_LEAST(19980812,2)
    ... use ap_overlap_tables()
#else
    ... alternative code which doesn't use ap_overlap_tables()
#endif

*/

#endif /* !APACHE_AP_MMN_H */
