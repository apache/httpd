# Based on apr's make_export.awk, which is
# based on Ryan Bloom's make_export.pl

BEGIN {
    printf(" (APACHE2)\n")
}

# List of functions that we don't support, yet??
#/ap_some_name/{next}


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

/^[ \t]*AP[RU]?_DECLARE_DATA .*;$/ {
       varname = $NF;
       gsub( /[*;]/, "", varname);
       gsub( /\[.*\]/, "", varname);
       add_symbol(varname);
}

#END {
#	printf(" %s", line)
#}
