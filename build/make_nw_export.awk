# Based on apr's make_export.awk, which is
# based on Ryan Bloom's make_export.pl

# List of functions that we don't support, yet??
/apr_##name##_set_inherit/{next}
/apr_##name##_unset_inherit/{next}
/apr_compare_groups/{next}
/apr_compare_users/{next}
/apr_find_pool/{next}
/apr_generate_random_bytes/{next}
/apr_lock_create_np/{next}
/apr_md5_set_xlate/{next}
/apr_mmap_create/{next}
/apr_mmap_delete/{next}
/apr_mmap_offset/{next}
/apr_os_thread_get/{next}
/apr_os_thread_put/{next}
/apr_pool_free_blocks_num_bytes/{next}
/apr_pool_join/{next}
/apr_pool_num_bytes/{next}
/apr_proc_mutex_child_init/{next}
/apr_proc_mutex_create/{next}
/apr_proc_mutex_create_np/{next}
/apr_proc_mutex_destroy/{next}
/apr_proc_mutex_lock/{next}
/apr_proc_mutex_trylock/{next}
/apr_proc_mutex_unlock/{next}
/apr_proc_other_child_check/{next}
/apr_proc_other_child_read/{next}
/apr_proc_other_child_register/{next}
/apr_proc_other_child_unregister/{next}
/apr_sendfile/{next}
/apr_shm_avail/{next}
/apr_shm_calloc/{next}
/apr_shm_destroy/{next}
/apr_shm_free/{next}
/apr_shm_init/{next}
/apr_shm_malloc/{next}
/apr_shm_name_get/{next}
/apr_shm_name_set/{next}
/apr_shm_open/{next}
/apr_signal/{next}
/apr_signal_thread/{next}
/apr_socket_from_file/{next}
/apr_thread_once/{next}
/apr_thread_once_init/{next}
/apr_xlate_close/{next}
/apr_xlate_conv_buffer/{next}
/apr_xlate_conv_byte/{next}
/apr_xlate_conv_char/{next}
/apr_xlate_get_sb/{next}
/apr_xlate_open/{next}
/apr_brigade_consume/{next}
/apr_bucket_mmap_create/{next}
/apr_bucket_mmap_make/{next}
/apr_bucket_type_mmap/{next}
/apr_md4_set_xlate/{next}
#/XML_ParserFree/{next}
#/XML_ParserCreate/{next}
#/XML_SetUserData/{next}
#/XML_SetElementHandler/{next}
#/XML_SetCharacterDataHandler/{next}
#/XML_Parse/{next}
#/XML_GetErrorCode/{next}
#/XML_ErrorString/{next}


function add_symbol (sym_name) {
	if (count) {
		found++
	}
#	for (i = 0; i < count; i++) {
#		line = line "\t"
#	}
	line = line sym_name ",\n"

	if (count == 0) {
		printf(" %s", line)
		line = ""
	}
}

/^[ \t]*AP[RU]?_DECLARE[^(]*[(][^)]*[)]([^ ]* )*[^(]+[(]/ {
    sub("[ \t]*AP[RU]?_DECLARE[^(]*[(][^)]*[)][ \t]*", "")
    sub("[(].*", "")
    sub("([^ ]* (^([ \t]*[(])))+", "")

    add_symbol($0)
    next
}

/^[ \t]*AP_DECLARE_HOOK[^(]*[(][^)]*[)]/ {
    split($0, args, ",")
    symbol = args[2]
    sub("^[ \t]+", "", symbol)
    sub("[ \t]+$", "", symbol)

    add_symbol("ap_hook_" symbol)
    add_symbol("ap_hook_get_" symbol)
    add_symbol("ap_run_" symbol)
    next
}

/^[ \t]*AP[RU]?_DECLARE_DATA .*;$/ {
       varname = $NF;
       gsub( /[*;]/, "", varname);
       gsub( /\[.*\]/, "", varname);
       add_symbol(varname);
}

#END {
#	printf(" %s", line)
#}
