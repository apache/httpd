# gdb macros which may be useful for folks using gdb to debug
# apache.  Delete it if it bothers you.

define dump_table
    set $t = (apr_table_entry_t *)((apr_array_header_t *)$arg0)->elts
    set $n = ((apr_array_header_t *)$arg0)->nelts
    set $i = 0
    while $i < $n
	printf "[%u] '%s'='%s'\n", $i, $t[$i].key, $t[$i].val
	set $i = $i + 1
    end
end
document dump_table
    Print the key/value pairs in a table.
end


define rh
	run -f /home/dgaudet/ap2/conf/mpm.conf
end

define ro
	run -DONE_PROCESS
end

define dump_string_array
    set $a = (char **)((apr_array_header_t *)$arg0)->elts
    set $n = (int)((apr_array_header_t *)$arg0)->nelts
    set $i = 0
    while $i < $n
	printf "[%u] '%s'\n", $i, $a[$i]
	set $i = $i + 1
    end
end
document dump_string_array
    Print all of the elements in an array of strings.
end

define dump_bucket
    set $bucket = $arg0
    printf "bucket=%s(0x%lx), length=%ld, data=0x%lx\n", \
            $bucket->type->name, \
            (unsigned long)$bucket, (long)$bucket->length, \
            (unsigned long)$bucket->data
end
document dump_bucket
    Print bucket info
end

define dump_brigade
    set $bb = $arg0
    set $bucket = ((&((apr_bucket_brigade *)$bb)->list))->next
    set $sentinel = ((char *)((&(((apr_bucket_brigade *)$bb)->list)) \
                               - ((size_t) &((struct apr_bucket *)0)->link)))
    set $i = 0

    printf "dump of brigade 0x%lx\n", (unsigned long)$bb
    if $bucket == $sentinel
        printf "brigade is empty\n"
    end

    while $bucket != $sentinel
        printf "   %d: bucket=%s(0x%lx), length=%ld, data=0x%lx\n", \
                $i, $bucket->type->name, \
                (unsigned long)$bucket, (long)$bucket->length, \
                (unsigned long)$bucket->data
        set $i = $i + 1
        set $bucket = $bucket->link.next
    end
end
document dump_brigade
    Print bucket brigade info
end

define dump_filters
    set $f = $arg0
    while $f
        printf "%s(0x%lx): ctx=0x%lx, r=0x%lx, c=0x%lx\n", \
        $f->frec->name, (unsigned long)$f, (unsigned long)$f->ctx, \
        $f->r, $f->c
        set $f = $f->next
    end
end
document dump_filters
    Print filter chain info
end
