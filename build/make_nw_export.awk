# Based on apr's make_export.awk, which is
# based on Ryan Bloom's make_export.pl

BEGIN {
    printf(" (APACHE2)\n")
}

# List of functions that we don't support, yet??
#/ap_some_name/{next}

# The following APIs are actually defined as macros and
# should not be included in the export list. If util_debug.c
# is included or AP_DEBUG is defined, these macros turn
# into functions and should be included in the export list.
/ap_get_module_config/{next}
/ap_set_module_config/{next}
/ap_strchr/{next}
/ap_strchr_c/{next}
/ap_strrchr/{next}
/ap_strrchr_c/{next}
/ap_strstr/{next}
/ap_strstr_c/{next}


function add_symbol (sym_name) {
	if (count) {
		found++
	}
    gsub (/ /, "", sym_name)
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

/^[ \t]*APR_DECLARE_INHERIT_SET[^(]*[(][^)]*[)]/ {
    sub("[ \t]*APR_DECLARE_INHERIT_SET[^(]*[(]", "", $0)
    sub("[)].*$", "", $0)
    add_symbol("apr_" $0 "_inherit_set")
    next
}

/^[ \t]*APR_DECLARE_INHERIT_UNSET[^(]*[(][^)]*[)]/ {
    sub("[ \t]*APR_DECLARE_INHERIT_UNSET[^(]*[(]", "", $0)
    sub("[)].*$", "", $0)
    add_symbol("apr_" $0 "_inherit_unset")
    next
}

/^[ \t]*(extern[ \t]+)?AP[RU]?_DECLARE_DATA .*;$/ {
       varname = $NF;
       gsub( /[*;]/, "", varname);
       gsub( /\[.*\]/, "", varname);
       add_symbol(varname);
}

#END {
#	printf(" %s", line)
#}
