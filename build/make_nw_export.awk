# Based on apr's make_export.awk, which is
# based on Ryan Bloom's make_export.pl

# List of functions that we don't support, yet??
/ap_get_module_config/{next}
/ap_gname2id/{next}
/ap_mpm_pod_check/{next}
/ap_mpm_pod_close/{next}
/ap_mpm_pod_killpg/{next}
/ap_mpm_pod_open/{next}
/ap_mpm_pod_signal/{next}
/ap_os_create_privileged_process/{next}
/ap_send_mmap/{next}
/ap_set_module_config/{next}
/ap_uname2id/{next}



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

/^[ \t]*AP([RU]|_CORE)?_DECLARE[^(]*[(][^)]*[)]([^ ]* )*[^(]+[(]/ {
    sub("[ \t]*AP([RU]|_CORE)?_DECLARE[^(]*[(][^)]*[)][ \t]*", "")
    sub("[(].*", "")
    sub("([^ ]* (^([ \t]*[(])))+", "")

    add_symbol($0)
    next
}

/^[ \t]*AP_DECLARE_HOOK[^(]*[(][^)]*/ {
    split($0, args, ",")
    symbol = args[2]
    sub("^[ \t]+", "", symbol)
    sub("[ \t]+$", "", symbol)

    add_symbol("ap_hook_" symbol)
    add_symbol("ap_hook_get_" symbol)
    add_symbol("ap_run_" symbol)
    next
}

/^[ \t]*APR_POOL_DECLARE_ACCESSOR[^(]*[(][^)]*[)]/ {
    sub("[ \t]*APR_POOL_DECLARE_ACCESSOR[^(]*[(]", "", $0)
    sub("[)].*$", "", $0)
    add_symbol("apr_" $0 "_pool_get")
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
