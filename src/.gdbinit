# gdb macros which may be useful for folks using gdb to debug
# apache.  Delete it if it bothers you.

define dump_table
    set $t = (table_entry *)((array_header *)$arg0)->elts
    set $n = ((array_header *)$arg0)->nelts
    set $i = 0
    while $i < $n
	printf "[%u] '%s'='%s'\n", $i, $t[$i].key, $t[$i].val
	set $i = $i + 1
    end
end
document dump_table
    Print the key/value pairs in a table.
end

define dump_string_array
    set $a = (char **)((array_header *)$arg0)->elts
    set $n = (int)((array_header *)$arg0)->nelts
    set $i = 0
    while $i < $n
	printf "[%u] '%s'\n", $i, $a[$i]
	set $i = $i + 1
    end
end
document dump_string_array
    Print all of the elements in an array of strings.
end
