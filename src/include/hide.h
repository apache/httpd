/* ====================================================================
 * Copyright (c) 1995-1998 The Apache Group.  All rights reserved.
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
 * 5. Redistributions of any form whatsoever must retain the following
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

#ifndef APACHE_HTTP_HIDE_H
#define APACHE_HTTP_HIDE_H

/*
 *  The definition of HIDE has no run-time penalty, but helps
 *  keep the Apache namespace from colliding with that used by
 *  other libraries pulled in by modules. 
 */

/* 
 *  DO NOT EDIT ANYTHING BELOW THIS LINE - Any changes made here will be lost!
 *  The section below is updated by running the script hide.pl 
 *  __________________________________________________________________________
 */
#ifdef HIDE

/*
 *  BSS segment symbols
 */
#define bind_address                   AP_bind_address
#define coredump_dir                   AP_coredump_dir
#define daemons_limit                  AP_daemons_limit
#define daemons_max_free               AP_daemons_max_free
#define daemons_min_free               AP_daemons_min_free
#define daemons_to_start               AP_daemons_to_start
#define excess_requests_per_child      AP_excess_requests_per_child
#define group_id                       AP_group_id
#define jmpbuffer                      AP_jmpbuffer
#define listenbacklog                  AP_listenbacklog
#define listeners                      AP_listeners
#define lock_fname                     AP_lock_fname
#define max_requests_per_child         AP_max_requests_per_child
#define my_pid                         AP_my_pid
#define permanent_pool                 AP_permanent_pool
#define pgrp                           AP_pgrp
#define pid_fname                      AP_pid_fname
#define restart_time                   AP_restart_time
#define scoreboard_fname               AP_scoreboard_fname
#define sd                             AP_sd
#define server_argv0                   AP_server_argv0
#define server_conf                    AP_server_conf
#define server_confname                AP_server_confname
#define server_post_read_config        AP_server_post_read_config
#define server_pre_read_config         AP_server_pre_read_config
#define server_root                    AP_server_root
#define standalone                     AP_standalone
#define threads_per_child              AP_threads_per_child
#define timebuf                        AP_timebuf
#define user_id                        AP_user_id
#define user_name                      AP_user_name

/*
 *  Data segment symbols
 */
#define access_module                  AP_access_module
#define action_module                  AP_action_module
#define agent_log_module               AP_agent_log_module
#define alias_module                   AP_alias_module
#define alloc_mutex                    AP_alloc_mutex
#define anon_auth_module               AP_anon_auth_module
#define asis_module                    AP_asis_module
#define auth_module                    AP_auth_module
#define autoindex_module               AP_autoindex_module
#define block_freelist                 AP_block_freelist
#define cern_meta_module               AP_cern_meta_module
#define cgi_module                     AP_cgi_module
#define config_log_module              AP_config_log_module
#define core_cmds                      AP_core_cmds
#define core_handlers                  AP_core_handlers
#define core_module                    AP_core_module
#define day_snames                     AP_day_snames
#define db_auth_module                 AP_db_auth_module
#define dbm_auth_module                AP_dbm_auth_module
#define default_parms                  AP_default_parms
#define digest_module                  AP_digest_module
#define dir_module                     AP_dir_module
#define dummy_mutex                    AP_dummy_mutex
#define env_module                     AP_env_module
#define example_cmds                   AP_example_cmds
#define example_handlers               AP_example_handlers
#define example_module                 AP_example_module
#define expires_module                 AP_expires_module
#define headers_module                 AP_headers_module
#define imap_module                    AP_imap_module
#define includes_module                AP_includes_module
#define info_module                    AP_info_module
#define mime_magic_module              AP_mime_magic_module
#define mime_module                    AP_mime_module
#define month_snames                   AP_month_snames
#define negotiation_module             AP_negotiation_module
#define one_process                    AP_one_process
#define prelinked_modules              AP_prelinked_modules
#define preloaded_modules              AP_preloaded_modules
#define proxy_module                   AP_proxy_module
#define referer_log_module             AP_referer_log_module
#define rewrite_module                 AP_rewrite_module
#define rfc1413_timeout                AP_rfc1413_timeout
#define scoreboard_image               AP_scoreboard_image
#define setenvif_module                AP_setenvif_module
#define so_cmds                        AP_so_cmds
#define so_module                      AP_so_module
#define spawn_mutex                    AP_spawn_mutex
#define speling_module                 AP_speling_module
#define status_module                  AP_status_module
#define suexec_enabled                 AP_suexec_enabled
#define top_module                     AP_top_module
#define unique_id_module               AP_unique_id_module
#define userdir_module                 AP_userdir_module
#define usertrack_module               AP_usertrack_module

/*
 *  Text segment symbols
 */
#define AMCSocketCleanup               AP_AMCSocketCleanup
#define AMCSocketInitialize            AP_AMCSocketInitialize
#define MD5Final                       AP_MD5Final
#define MD5Init                        AP_MD5Init
#define MD5Update                      AP_MD5Update
#define add_cgi_vars                   AP_add_cgi_vars
#define add_common_vars                AP_add_common_vars
#define add_file_conf                  AP_add_file_conf
#define add_module                     AP_add_module
#define add_module_command             AP_add_module_command
#define add_named_module               AP_add_named_module
#define add_per_dir_conf               AP_add_per_dir_conf
#define add_per_url_conf               AP_add_per_url_conf
#define allow_options                  AP_allow_options
#define allow_overrides                AP_allow_overrides
#define ap__new_connection             AP_ap__new_connection
#define ap_cpystrn                     AP_ap_cpystrn
#define ap_escape_quotes               AP_ap_escape_quotes
#define ap_md5                         AP_ap_md5
#define ap_md5contextTo64              AP_ap_md5contextTo64
#define ap_md5digest                   AP_ap_md5digest
#define ap_signal                      AP_ap_signal
#define ap_slack                       AP_ap_slack
#define ap_snprintf                    AP_ap_snprintf
#define ap_vsnprintf                   AP_ap_vsnprintf
#define apapi_get_server_built         AP_apapi_get_server_built
#define apapi_get_server_version       AP_apapi_get_server_version
#define aplog_error                    AP_aplog_error
#define append_arrays                  AP_append_arrays
#define array_cat                      AP_array_cat
#define auth_name                      AP_auth_name
#define auth_type                      AP_auth_type
#define basic_http_header              AP_basic_http_header
#define bclose                         AP_bclose
#define bcreate                        AP_bcreate
#define bfilbuf                        AP_bfilbuf
#define bfileno                        AP_bfileno
#define bflsbuf                        AP_bflsbuf
#define bflush                         AP_bflush
#define bgetopt                        AP_bgetopt
#define bgets                          AP_bgets
#define bhalfduplex                    AP_bhalfduplex
#define block_alarms                   AP_block_alarms
#define blookc                         AP_blookc
#define bnonblock                      AP_bnonblock
#define bonerror                       AP_bonerror
#define bpushfd                        AP_bpushfd
#define bputs                          AP_bputs
#define bread                          AP_bread
#define bsetflag                       AP_bsetflag
#define bsetopt                        AP_bsetopt
#define bskiplf                        AP_bskiplf
#define bvputs                         AP_bvputs
#define bwrite                         AP_bwrite
#define bytes_in_block_list            AP_bytes_in_block_list
#define bytes_in_free_blocks           AP_bytes_in_free_blocks
#define bytes_in_pool                  AP_bytes_in_pool
#define call_exec                      AP_call_exec
#define can_exec                       AP_can_exec
#define cfg_closefile                  AP_cfg_closefile
#define cfg_getc                       AP_cfg_getc
#define cfg_getline                    AP_cfg_getline
#define chdir_file                     AP_chdir_file
#define check_access                   AP_check_access
#define check_alarm                    AP_check_alarm
#define check_auth                     AP_check_auth
#define check_cmd_context              AP_check_cmd_context
#define check_serverpath               AP_check_serverpath
#define check_symlinks                 AP_check_symlinks
#define check_user_id                  AP_check_user_id
#define checkmask                      AP_checkmask
#define child_exit_modules             AP_child_exit_modules
#define child_init_modules             AP_child_init_modules
#define child_main                     AP_child_main
#define child_terminate                AP_child_terminate
#define cleanup_for_exec               AP_cleanup_for_exec
#define clear_module_list              AP_clear_module_list
#define clear_module_list_command      AP_clear_module_list_command
#define clear_pool                     AP_clear_pool
#define clear_table                    AP_clear_table
#define client_to_stdout               AP_client_to_stdout
#define close_piped_log                AP_close_piped_log
#define construct_server               AP_construct_server
#define construct_url                  AP_construct_url
#define copy_array                     AP_copy_array
#define copy_array_hdr                 AP_copy_array_hdr
#define copy_table                     AP_copy_table
#define core_reorder_directories       AP_core_reorder_directories
#define core_translate                 AP_core_translate
#define count_dirs                     AP_count_dirs
#define create_connection_config       AP_create_connection_config
#define create_core_dir_config         AP_create_core_dir_config
#define create_core_server_config      AP_create_core_server_config
#define create_default_per_dir_config  AP_create_default_per_dir_config
#define create_empty_config            AP_create_empty_config
#define create_environment             AP_create_environment
#define create_per_dir_config          AP_create_per_dir_config
#define create_request_config          AP_create_request_config
#define create_server_config           AP_create_server_config
#define default_handler                AP_default_handler
#define default_port_for_request       AP_default_port_for_request
#define default_port_for_scheme        AP_default_port_for_scheme
#define default_type                   AP_default_type
#define destroy_pool                   AP_destroy_pool
#define destroy_sub_req                AP_destroy_sub_req
#define detach                         AP_detach
#define die                            AP_die
#define directory_walk                 AP_directory_walk
#define dirsection                     AP_dirsection
#define discard_request_body           AP_discard_request_body
#define do_nothing                     AP_do_nothing
#define document_root                  AP_document_root
#define each_byterange                 AP_each_byterange
#define end_ifmod                      AP_end_ifmod
#define endlimit_section               AP_endlimit_section
#define error_log2stderr               AP_error_log2stderr
#define escape_html                    AP_escape_html
#define escape_path_segment            AP_escape_path_segment
#define escape_shell_cmd               AP_escape_shell_cmd
#define exists_scoreboard_image        AP_exists_scoreboard_image
#define file_walk                      AP_file_walk
#define filesection                    AP_filesection
#define finalize_request_protocol      AP_finalize_request_protocol
#define finalize_sub_req_protocol      AP_finalize_sub_req_protocol
#define find_command                   AP_find_command
#define find_command_in_modules        AP_find_command_in_modules
#define find_last_token                AP_find_last_token
#define find_linked_module             AP_find_linked_module
#define find_module_name               AP_find_module_name
#define find_path_info                 AP_find_path_info
#define find_pool                      AP_find_pool
#define find_token                     AP_find_token
#define find_types                     AP_find_types
#define fini_vhost_config              AP_fini_vhost_config
#define fixup_virtual_hosts            AP_fixup_virtual_hosts
#define fnmatch                        AP_fnmatch
#define force_library_loading          AP_force_library_loading
#define free_blocks                    AP_free_blocks
#define get_basic_auth_pw              AP_get_basic_auth_pw
#define get_client_block               AP_get_client_block
#define get_gmtoff                     AP_get_gmtoff
#define get_local_host                 AP_get_local_host
#define get_mime_headers               AP_get_mime_headers
#define get_module_config              AP_get_module_config
#define get_path_info                  AP_get_path_info
#define get_remote_host                AP_get_remote_host
#define get_remote_logname             AP_get_remote_logname
#define get_server_name                AP_get_server_name
#define get_server_port                AP_get_server_port
#define get_time                       AP_get_time
#define get_token                      AP_get_token
#define get_virthost_addr              AP_get_virthost_addr
#define getparents                     AP_getparents
#define getword                        AP_getword
#define getword_conf                   AP_getword_conf
#define getword_conf_nc                AP_getword_conf_nc
#define getword_nc                     AP_getword_nc
#define getword_nulls                  AP_getword_nulls
#define getword_nulls_nc               AP_getword_nulls_nc
#define getword_white                  AP_getword_white
#define getword_white_nc               AP_getword_white_nc
#define gm_timestr_822                 AP_gm_timestr_822
#define gname2id                       AP_gname2id
#define handle_command                 AP_handle_command
#define hard_timeout                   AP_hard_timeout
#define header_parse                   AP_header_parse
#define ht_time                        AP_ht_time
#define include_config                 AP_include_config
#define ind                            AP_ind
#define index_of_response              AP_index_of_response
#define init_alloc                     AP_init_alloc
#define init_config_globals            AP_init_config_globals
#define init_modules                   AP_init_modules
#define init_server_config             AP_init_server_config
#define init_suexec                    AP_init_suexec
#define init_vhost_config              AP_init_vhost_config
#define init_virtual_host              AP_init_virtual_host
#define internal_internal_redirect     AP_internal_internal_redirect
#define internal_redirect              AP_internal_redirect
#define internal_redirect_handler      AP_internal_redirect_handler
#define invoke_cmd                     AP_invoke_cmd
#define invoke_handler                 AP_invoke_handler
#define is_directory                   AP_is_directory
#define is_fnmatch                     AP_is_fnmatch
#define is_initial_req                 AP_is_initial_req
#define is_matchexp                    AP_is_matchexp
#define is_url                         AP_is_url
#define just_die                       AP_just_die
#define keepalive_timeout              AP_keepalive_timeout
#define kill_cleanup                   AP_kill_cleanup
#define kill_cleanups_for_fd           AP_kill_cleanups_for_fd
#define kill_cleanups_for_socket       AP_kill_cleanups_for_socket
#define kill_timeout                   AP_kill_timeout
#define limit_section                  AP_limit_section
#define location_walk                  AP_location_walk
#define log_assert                     AP_log_assert
#define log_error                      AP_log_error
#define log_pid                        AP_log_pid
#define log_printf                     AP_log_printf
#define log_reason                     AP_log_reason
#define log_transaction                AP_log_transaction
#define log_unixerr                    AP_log_unixerr
#define make_array                     AP_make_array
#define make_dirstr                    AP_make_dirstr
#define make_dirstr_parent             AP_make_dirstr_parent
#define make_dirstr_prefix             AP_make_dirstr_prefix
#define make_full_path                 AP_make_full_path
#define make_sub_pool                  AP_make_sub_pool
#define make_sub_request               AP_make_sub_request
#define make_table                     AP_make_table
#define malloc_block                   AP_malloc_block
#define matches_request_vhost          AP_matches_request_vhost
#define meets_conditions               AP_meets_conditions
#define merge_core_dir_configs         AP_merge_core_dir_configs
#define merge_core_server_configs      AP_merge_core_server_configs
#define merge_per_dir_configs          AP_merge_per_dir_configs
#define merge_server_configs           AP_merge_server_configs
#define mime_find_ct                   AP_mime_find_ct
#define new_block                      AP_new_block
#define no2slash                       AP_no2slash
#define note_auth_failure              AP_note_auth_failure
#define note_basic_auth_failure        AP_note_basic_auth_failure
#define note_cleanups_for_fd           AP_note_cleanups_for_fd
#define note_cleanups_for_file         AP_note_cleanups_for_file
#define note_cleanups_for_socket       AP_note_cleanups_for_socket
#define note_digest_auth_failure       AP_note_digest_auth_failure
#define note_subprocess                AP_note_subprocess
#define null_cleanup                   AP_null_cleanup
#define open_error_log                 AP_open_error_log
#define open_logs                      AP_open_logs
#define open_piped_log                 AP_open_piped_log
#define os_escape_path                 AP_os_escape_path
#define os_is_path_absolute            AP_os_is_path_absolute
#define overlay_tables                 AP_overlay_tables
#define palloc                         AP_palloc
#define parseHTTPdate                  AP_parseHTTPdate
#define parse_htaccess                 AP_parse_htaccess
#define parse_uri                      AP_parse_uri
#define parse_uri_components           AP_parse_uri_components
#define parse_vhost_addrs              AP_parse_vhost_addrs
#define pcalloc                        AP_pcalloc
#define pcfg_open_custom               AP_pcfg_open_custom
#define pcfg_openfile                  AP_pcfg_openfile
#define pclosedir                      AP_pclosedir
#define pclosef                        AP_pclosef
#define pclosesocket                   AP_pclosesocket
#define pduphostent                    AP_pduphostent
#define pfclose                        AP_pfclose
#define pfdopen                        AP_pfdopen
#define pfopen                         AP_pfopen
#define pgethostbyname                 AP_pgethostbyname
#define plustospace                    AP_plustospace
#define pool_is_ancestor               AP_pool_is_ancestor
#define pool_join                      AP_pool_join
#define popendir                       AP_popendir
#define popenf                         AP_popenf
#define pregcomp                       AP_pregcomp
#define pregfree                       AP_pregfree
#define pregsub                        AP_pregsub
#define process_command_config         AP_process_command_config
#define process_request                AP_process_request
#define process_request_internal       AP_process_request_internal
#define process_resource_config        AP_process_resource_config
#define proxy_add_header               AP_proxy_add_header
#define proxy_c2hex                    AP_proxy_c2hex
#define proxy_cache_check              AP_proxy_cache_check
#define proxy_cache_error              AP_proxy_cache_error
#define proxy_cache_tidy               AP_proxy_cache_tidy
#define proxy_cache_update             AP_proxy_cache_update
#define proxy_canon_netloc             AP_proxy_canon_netloc
#define proxy_canonenc                 AP_proxy_canonenc
#define proxy_connect_handler          AP_proxy_connect_handler
#define proxy_date_canon               AP_proxy_date_canon
#define proxy_del_header               AP_proxy_del_header
#define proxy_doconnect                AP_proxy_doconnect
#define proxy_ftp_canon                AP_proxy_ftp_canon
#define proxy_ftp_handler              AP_proxy_ftp_handler
#define proxy_garbage_coll             AP_proxy_garbage_coll
#define proxy_garbage_init             AP_proxy_garbage_init
#define proxy_get_header               AP_proxy_get_header
#define proxy_hash                     AP_proxy_hash
#define proxy_hex2c                    AP_proxy_hex2c
#define proxy_hex2sec                  AP_proxy_hex2sec
#define proxy_host2addr                AP_proxy_host2addr
#define proxy_http_canon               AP_proxy_http_canon
#define proxy_http_handler             AP_proxy_http_handler
#define proxy_is_domainname            AP_proxy_is_domainname
#define proxy_is_hostname              AP_proxy_is_hostname
#define proxy_is_ipaddr                AP_proxy_is_ipaddr
#define proxy_is_word                  AP_proxy_is_word
#define proxy_liststr                  AP_proxy_liststr
#define proxy_log_uerror               AP_proxy_log_uerror
#define proxy_read_headers             AP_proxy_read_headers
#define proxy_sec2hex                  AP_proxy_sec2hex
#define proxy_send_fb                  AP_proxy_send_fb
#define proxy_send_headers             AP_proxy_send_headers
#define proxyerror                     AP_proxyerror
#define psignature                     AP_psignature
#define psocket                        AP_psocket
#define pstrcat                        AP_pstrcat
#define pstrdup                        AP_pstrdup
#define pstrndup                       AP_pstrndup
#define push_array                     AP_push_array
#define rationalize_mtime              AP_rationalize_mtime
#define read_config                    AP_read_config
#define read_request                   AP_read_request
#define read_request_line              AP_read_request_line
#define register_cleanup               AP_register_cleanup
#define register_other_child           AP_register_other_child
#define reinit_scoreboard              AP_reinit_scoreboard
#define remove_module                  AP_remove_module
#define rename_original_env            AP_rename_original_env
#define reopen_scoreboard              AP_reopen_scoreboard
#define require                        AP_require
#define requires                       AP_requires
#define reset_timeout                  AP_reset_timeout
#define response_code_string           AP_response_code_string
#define rfc1413                        AP_rfc1413
#define rflush                         AP_rflush
#define rind                           AP_rind
#define rprintf                        AP_rprintf
#define rputc                          AP_rputc
#define rputs                          AP_rputs
#define run_cleanup                    AP_run_cleanup
#define run_fixups                     AP_run_fixups
#define run_post_read_request          AP_run_post_read_request
#define run_sub_req                    AP_run_sub_req
#define rvputs                         AP_rvputs
#define rwrite                         AP_rwrite
#define satisfies                      AP_satisfies
#define satisfy                        AP_satisfy
#define scan_script_header_err         AP_scan_script_header_err
#define scan_script_header_err_buff    AP_scan_script_header_err_buff
#define send_error_response            AP_send_error_response
#define send_fb                        AP_send_fb
#define send_fb_length                 AP_send_fb_length
#define send_fd                        AP_send_fd
#define send_fd_length                 AP_send_fd_length
#define send_header_field              AP_send_header_field
#define send_http_header               AP_send_http_header
#define send_http_options              AP_send_http_options
#define send_http_trace                AP_send_http_trace
#define send_mmap                      AP_send_mmap
#define send_size                      AP_send_size
#define server_port                    AP_server_port
#define server_root_relative           AP_server_root_relative
#define server_type                    AP_server_type
#define set_access_name                AP_set_access_name
#define set_bind_address               AP_set_bind_address
#define set_byterange                  AP_set_byterange
#define set_callback_and_alarm         AP_set_callback_and_alarm
#define set_content_length             AP_set_content_length
#define set_content_md5                AP_set_content_md5
#define set_coredumpdir                AP_set_coredumpdir
#define set_daemons_to_start           AP_set_daemons_to_start
#define set_document_root              AP_set_document_root
#define set_error_document             AP_set_error_document
#define set_etag                       AP_set_etag
#define set_excess_requests            AP_set_excess_requests
#define set_file_slot                  AP_set_file_slot
#define set_flag_slot                  AP_set_flag_slot
#define set_group                      AP_set_group
#define set_hostname_lookups           AP_set_hostname_lookups
#define set_idcheck                    AP_set_idcheck
#define set_keep_alive                 AP_set_keep_alive
#define set_keep_alive_max             AP_set_keep_alive_max
#define set_keep_alive_timeout         AP_set_keep_alive_timeout
#define set_keepalive                  AP_set_keepalive
#define set_last_modified              AP_set_last_modified
#define set_limit_cpu                  AP_set_limit_cpu
#define set_limit_mem                  AP_set_limit_mem
#define set_limit_nproc                AP_set_limit_nproc
#define set_listenbacklog              AP_set_listenbacklog
#define set_listener                   AP_set_listener
#define set_lockfile                   AP_set_lockfile
#define set_loglevel                   AP_set_loglevel
#define set_max_free_servers           AP_set_max_free_servers
#define set_max_requests               AP_set_max_requests
#define set_min_free_servers           AP_set_min_free_servers
#define set_module_config              AP_set_module_config
#define set_name_virtual_host          AP_set_name_virtual_host
#define set_options                    AP_set_options
#define set_override                   AP_set_override
#define set_pidfile                    AP_set_pidfile
#define set_scoreboard                 AP_set_scoreboard
#define set_send_buffer_size           AP_set_send_buffer_size
#define set_server_alias               AP_set_server_alias
#define set_server_limit               AP_set_server_limit
#define set_server_root                AP_set_server_root
#define set_server_string_slot         AP_set_server_string_slot
#define set_serverpath                 AP_set_serverpath
#define set_signals                    AP_set_signals
#define set_signature_flag             AP_set_signature_flag
#define set_string_slot                AP_set_string_slot
#define set_sub_req_protocol           AP_set_sub_req_protocol
#define set_threads                    AP_set_threads
#define set_timeout                    AP_set_timeout
#define set_use_canonical_name         AP_set_use_canonical_name
#define set_user                       AP_set_user
#define setup_client_block             AP_setup_client_block
#define setup_prelinked_modules        AP_setup_prelinked_modules
#define should_client_block            AP_should_client_block
#define show_directives                AP_show_directives
#define show_modules                   AP_show_modules
#define show_overrides                 AP_show_overrides
#define sig_coredump                   AP_sig_coredump
#define soft_timeout                   AP_soft_timeout
#define some_auth_required             AP_some_auth_required
#define spacetoplus                    AP_spacetoplus
#define spawn_child_err                AP_spawn_child_err
#define spawn_child_err_buff           AP_spawn_child_err_buff
#define srm_command_loop               AP_srm_command_loop
#define standalone_main                AP_standalone_main
#define start_ifmod                    AP_start_ifmod
#define start_restart                  AP_start_restart
#define start_shutdown                 AP_start_shutdown
#define str_tolower                    AP_str_tolower
#define strcasecmp_match               AP_strcasecmp_match
#define strcmp_match                   AP_strcmp_match
#define sub_req_lookup_file            AP_sub_req_lookup_file
#define sub_req_lookup_uri             AP_sub_req_lookup_uri
#define sync_scoreboard_image          AP_sync_scoreboard_image
#define table_add                      AP_table_add
#define table_addn                     AP_table_addn
#define table_do                       AP_table_do
#define table_get                      AP_table_get
#define table_merge                    AP_table_merge
#define table_mergen                   AP_table_mergen
#define table_set                      AP_table_set
#define table_setn                     AP_table_setn
#define table_unset                    AP_table_unset
#define time_process_request           AP_time_process_request
#define timeout                        AP_timeout
#define tm2sec                         AP_tm2sec
#define translate_name                 AP_translate_name
#define uname2id                       AP_uname2id
#define unblock_alarms                 AP_unblock_alarms
#define unescape_url                   AP_unescape_url
#define unload_file                    AP_unload_file
#define unload_module                  AP_unload_module
#define unparse_uri_components         AP_unparse_uri_components
#define unregister_other_child         AP_unregister_other_child
#define update_child_status            AP_update_child_status
#define update_mtime                   AP_update_mtime
#define update_vhost_from_headers      AP_update_vhost_from_headers
#define update_vhost_given_ip          AP_update_vhost_given_ip
#define urlsection                     AP_urlsection
#define usage                          AP_usage
#define util_uri_init                  AP_util_uri_init
#define uudecode                       AP_uudecode
#define vbprintf                       AP_vbprintf
#define virtualhost_section            AP_virtualhost_section

#endif
/*  __________________________________________________________________________
 *
 *  DO NOT EDIT ANYTHING ABOVE THIS LINE - Any changes made here will be lost!
 *  The section below is updated by running the script hide.pl 
 */

#endif  /* !APACHE_HTTP_HIDE_H */
