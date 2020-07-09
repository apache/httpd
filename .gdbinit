# gdb macros which may be useful for folks using gdb to debug
# apache.  Delete it if it bothers you.

define dump_table
    set $t = (apr_table_entry_t *)((apr_array_header_t *)$arg0)->elts
    set $n = ((apr_array_header_t *)$arg0)->nelts
    set $i = 0
    while $i < $n
	if $t[$i].val == (void *)0L
	   printf "[%u] '%s'=>NULL\n", $i, $t[$i].key
	else
	   printf "[%u] '%s'='%s' [%p]\n", $i, $t[$i].key, $t[$i].val, $t[$i].val
	end
	set $i = $i + 1
    end
end
document dump_table
    Print the key/value pairs in a table.
end

define dump_skiplist
    set $sl = (apr_skiplist *)$arg0
    set $m = $sl->bottom
    printf "skiplist@%p: size=%lu: height=%d\n", $sl, $sl->size, $sl->height
    while ($m)
        printf "(%p,%.12lx)", $m, $m->data
        set $u = $m->up
        while ($u)
            printf " (%p,%.12lx)", $u, $u->data
            set $u = $u->up
        end
        printf "\n"
        set $m = $m->next
    end
end
document dump_skiplist
    Print the nodes/values in a skiplist
end

define dump_string_hash
    set $h = $arg0->array
    set $n = $arg0->max
    set $i = 0
    while $i < $n
        set $ent = $h[$i]       
        while $ent != (void *)0L
            printf "'%s' => '%p'\n", $ent->key, $ent->val
            set $ent = $ent->next
        end
	set $i = $i + 1
    end
end
document dump_string_hash
    Print the entries in a hash table indexed by strings
end

define dump_string_shash
    set $h = $arg0->array
    set $n = $arg0->max
    set $i = 0
    while $i < $n
        set $ent = $h[$i]       
        while $ent != (void *)0L
            printf "'%s' => '%s'\n", $ent->key, $ent->val
            set $ent = $ent->next
        end
	set $i = $i + 1
    end
end
document dump_string_shash
    Print the entries in a hash table indexed by strings with string values
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

define printmemn
    set $i = 0
    while $i < $arg1
        if $arg0[$i] < 0x20 || $arg0[$i] > 0x7e
            printf "~"
        else
            printf "%c", $arg0[$i]
        end
        set $i = $i + 1
    end
end

define print_bkt_datacol
    # arg0 == column name
    # arg1 == format
    # arg2 == value
    # arg3 == suppress header?
    set $suppressheader = $arg3

    if !$suppressheader
        printf " "
        printf $arg0
        printf "="
    else
        printf " | "
    end
    printf $arg1, $arg2
end

define dump_bucket_ex
    # arg0 == bucket
    # arg1 == suppress header?
    set $bucket = (struct apr_bucket *)$arg0
    set $sh = $arg1
    set $refcount = -1

    print_bkt_datacol "bucket" "%-9s" $bucket->type->name $sh
    printf "(%12lx)", (unsigned long)$bucket
    print_bkt_datacol "length" "%-6ld" (long)($bucket->length) $sh
    print_bkt_datacol "data" "%12lx" $bucket->data $sh

    if !$sh
        printf "\n    "
    end

    if (($bucket->type == &apr_bucket_type_eos)   || \
        ($bucket->type == &apr_bucket_type_flush))

        # metadata buckets, no content
        print_bkt_datacol "contents" "%c" ' ' $sh
        printf "                     "
        print_bkt_datacol "rc" "n/%c" 'a' $sh

    else
    if ($bucket->type == &ap_bucket_type_error)

        # metadata bucket, no content but it does have an error code in it
        print_bkt_datacol "contents" "%c" ' ' $sh
        set $status = ((ap_bucket_error *)$bucket->data)->status
        printf " (status=%3d)        ", $status
        print_bkt_datacol "rc" "n/%c" 'a' $sh

    else
    if ($bucket->type == &apr_bucket_type_file)

        # file bucket, can show fd and refcount
        set $fd = ((apr_bucket_file*)$bucket->data)->fd->filedes
        print_bkt_datacol "contents" "[***file***] fd=%-6ld" (long)$fd $sh
        set $refcount = ((apr_bucket_refcount *)$bucket->data)->refcount
        print_bkt_datacol "rc" "%d" $refcount $sh

    else
    if (($bucket->type == &apr_bucket_type_heap)      || \
        ($bucket->type == &apr_bucket_type_pool)      || \
        ($bucket->type == &apr_bucket_type_mmap)      || \
        ($bucket->type == &apr_bucket_type_transient) || \
        ($bucket->type == &apr_bucket_type_immortal))

        # in-memory buckets

        if $bucket->type == &apr_bucket_type_heap
            set $refcount = ((apr_bucket_refcount *)$bucket->data)->refcount
            set $p = (apr_bucket_heap *)$bucket->data
            set $data = $p->base+$bucket->start

        else
        if $bucket->type == &apr_bucket_type_pool
            set $refcount = ((apr_bucket_refcount *)$bucket->data)->refcount
            set $p = (apr_bucket_pool *)$bucket->data
            if !$p->pool
                set $p = (apr_bucket_heap *)$bucket->data
            end
            set $data = $p->base+$bucket->start

        else
        if $bucket->type == &apr_bucket_type_mmap
            # is this safe if not APR_HAS_MMAP?
            set $refcount = ((apr_bucket_refcount *)$bucket->data)->refcount
            set $p = (apr_bucket_mmap *)$bucket->data
            set $data = ((char *)$p->mmap->mm)+$bucket->start

        else
        if (($bucket->type == &apr_bucket_type_transient) || \
            ($bucket->type == &apr_bucket_type_immortal))
            set $data = ((char *)$bucket->data)+$bucket->start

        end
        end
        end
        end

        if $sh
            printf " | ["
        else
            printf " contents=["
        end
        set $datalen = $bucket->length
        if $isValidAddress($data) == 1
            if $datalen > 17
                printmem $data 17
                printf "..."
                set $datalen = 20
            else
                printmemn $data $datalen
            end
            printf "]"
            while $datalen < 20
                printf " "
                set $datalen = $datalen + 1
            end
        else
            printf "Iv addr %12lx]", $data
        end

        if $refcount != -1
            print_bkt_datacol "rc" "%d" $refcount $sh
        else
            print_bkt_datacol "rc" "n/%c" 'a' $sh
        end

    else
        if ($bucket->type == &apr_bucket_type_pipe)

            # pipe bucket, can show fd
            set $fd = ((apr_file_t*)$bucket->data)->filedes;
            print_bkt_datacol "contents" "[***pipe***] fd=%-6ld" (long)$fd $sh

        else
        if ($bucket->type == &apr_bucket_type_socket)

            # file bucket, can show fd
            set $fd = ((apr_socket_t*)$bucket->data)->socketdes;
            print_bkt_datacol "contents" "[**socket**] fd=%-6ld" (long)$fd $sh

        else

            # 3rd-party bucket type
            print_bkt_datacol "contents" "[**opaque**]%-10c" ' ' $sh
        end
        end

        # no refcount
        printf "         "
        print_bkt_datacol "rc" "n/%c" 'a' $sh
    end
    end
    end
    end

    printf "\n"

end

define dump_bucket
    dump_bucket_ex $arg0 0
end
document dump_bucket
    Print bucket info
end

define dump_brigade
    set $bb = (apr_bucket_brigade *)$arg0
    set $bucket = $bb->list.next
    set $sentinel = ((char *)((&($bb->list)) \
                               - ((size_t) &((struct apr_bucket *)0)->link)))
    printf "dump of brigade 0x%lx\n", (unsigned long)$bb

    printf "   | type     (address)      | length | "
    printf "data address | contents               | rc\n"
    printf "------------------------------------------"
    printf "----------------------------------------\n"

    if $bucket == $sentinel
        printf "brigade is empty\n"
    end

    set $j = 0
    set $brigade_length = 0
    while $bucket != $sentinel
        printf "%2d", $j
        dump_bucket_ex $bucket 1
        set $j = $j + 1
        if $bucket->length > 0
            set $brigade_length = $brigade_length + $bucket->length
        end
        set $bucket = $bucket->link.next
    end
    printf "end of brigade\n"
    printf "Length of brigade (excluding buckets of unknown length): %u\n", $brigade_length
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

define dump_filter_chain
    set $r = $arg0
    set $f = $r->output_filters
    while $f
        if $f == $r->output_filters
            printf "r->output_filters =>\n"
        end
        if $f == $r->proto_output_filters
            printf "r->proto_output_filters =>\n"
        end
        if $f == $r->connection->output_filters
            printf "r->connection->output_filters =>\n"
        end
        
        printf "  %s(0x%lx): type=%d, ctx=0x%lx, r=%s(0x%lx), c=0x%lx\n", \
          $f->frec->name, (unsigned long)$f, $f->frec->ftype, (unsigned long)$f->ctx, \
          $f->r == $r ? "r" : ($f->r == 0L ? "null" : \
          ($f->r == $r->main ? "r->main" :  \
          ($r->main && $f->r == $r->main->main ? "r->main->main" : "????"))), \
          $f->r, $f->c

        set $f = $f->next
    end
end
document dump_filter_chain
    Print filter chain info given a request_rec pointer
end

define dump_process_rec
    set $p = $arg0
    printf "process_rec=0x%lx:\n", (unsigned long)$p
    printf "   pool=0x%lx, pconf=0x%lx\n", \
           (unsigned long)$p->pool, (unsigned long)$p->pconf
end
document dump_process_rec
    Print process_rec info
end

define dump_server_addr_recs
    set $sa_ = $arg0
    set $san_ = 0
    while $sa_
      ### need to call apr_sockaddr_info_getbuf to print ->host_addr properly
      ### which is a PITA since we need a buffer :(
      printf " addr#%d: vhost=%s -> :%d\n", $san_++, $sa_->virthost, $sa_->host_port
      set $sa_ = $sa_->next
    end
end
document dump_server_addr_recs
    Print server_addr_rec info
end


define dump_server_rec
    set $s = $arg0
    printf "name=%s:%d (0x%lx)\n", \
            $s->server_hostname, $s->port, $s
    dump_server_addr_recs $s->addrs
    dump_process_rec($s->process)
end
document dump_server_rec
    Print server_rec info
end

define dump_servers
    set $s = $arg0
    while $s
        dump_server_rec($s)
        printf "\n"
        set $s = $s->next
    end
end
document dump_servers
    Print server_rec list info
end

define dump_request_tree
    set $r = $arg0
    set $i
    while $r
        printf "r=(0x%lx): uri=%s, handler=%s, r->main=0x%lx\n", \
          $r, $r->unparsed_uri, $r->handler ? $r->handler : "(none)", $r->main
        set $r = $r->main
    end
end        

define dump_scoreboard
    # Need to reserve size of array first before string literals could be
    # put in
    set $status = {0, 1, 2, 3, 4 ,5 ,6 ,7 ,8 ,9 ,10}
    set $status = {"DEAD", "STARTING", "READY", "BUSY_READ", "BUSY_WRITE", "BUSY_KEEPALIVE", "BUSY_LOG", "BUSY_DNS", "CLOSING", "GRACEFUL", "IDLE_KILL"}
    set $i = 0
    while ($i < server_limit)
        if ap_scoreboard_image->servers[$i][0].pid != 0
            set $j = 0
            while ($j < threads_per_child)
                set $ws = ap_scoreboard_image->servers[$i][$j]
                printf "pid: %d, tid: 0x%lx, status: %s\n", $ws.pid, $ws.tid, $status[$ws.status]
                set $j = $j +1
            end
        end
        set $i = $i +1
    end
end
document dump_scoreboard
    Dump the scoreboard
end

define dump_allocator
    printf "Allocator current_free_index = %d, max_free_index = %d\n", \
            ($arg0)->current_free_index, ($arg0)->max_free_index
    printf "Allocator free list:\n"
    set $i = 0
    set $max =(sizeof $arg0->free)/(sizeof $arg0->free[0])
    set $kb = 0
    while $i < $max
        set $node = $arg0->free[$i]
        if $node != 0
            printf " #%2d: ", $i
            while $node != 0
                printf "%d, ", ($node->index + 1) << 12
                set $kb = $kb + (($node->index + 1) << 2)
                set $node = $node->next
            end
            printf "ends.\n"
        end
        set $i = $i + 1
    end
    printf "Sum of free blocks: %dkiB\n", $kb
end
document dump_allocator
    Print status of an allocator and its freelists.
end

define dump_one_pool
    set $p = $arg0
    set $size = 0
    set $free = 0
    set $nodes = 0
    set $node = $arg0->active
    set $done = 0
    while $done == 0
        set $size = $size + (($node->index + 1) << 12)
        set $free = $free + ($node->endp - $node->first_avail)
        set $nodes = $nodes + 1
        set $node = $node->next
        if $node == $arg0->active
            set $done = 1
        end
    end
    printf "Pool '"
    if $p->tag
        printf "%s", $p->tag
    else
        printf "no tag"
    end
    printf "' [%p]: %d/%d free (%d blocks)\n", $p, $free, $size, $nodes
end

define dump_all_pools
    if $argc > 0
        set $root = $arg0
    else
        set $root = ap_pglobal
    end
    while $root->parent
        set $root = $root->parent
    end
    dump_pool_and_children $root
end
document dump_all_pools
    Dump the whole pool hierarchy starting from apr_global_pool. Optionally takes an arbitrary pool as starting parameter.
end

python

from __future__ import print_function

class DumpPoolAndChilds (gdb.Command):
  """Dump the whole pool hierarchy starting from the given pool."""

  def __init__ (self):
    super (DumpPoolAndChilds, self).__init__ ("dump_pool_and_children", gdb.COMMAND_USER)

  def _allocator_free_blocks(self, alloc):
    salloc = "%s" % (alloc)
    if self.total_free_blocks.get(salloc) != None:
      return self.total_free_blocks[salloc]
    i = 0
    dalloc = alloc.dereference()
    max =(dalloc['free'].type.sizeof)/(dalloc['free'][0].type.sizeof)
    kb = 0
    while i < max:
      node = dalloc['free'][i]
      if node != 0:
        while node != 0:
          noded = node.dereference()
          kb = kb + ((int(noded['index']) + 1) << 2)
          node = noded['next']
      i = i + 1
    self.total_free_blocks[salloc] = kb
    return kb


  def _dump_one_pool(self, arg):
    size = 0
    free = 0
    nodes = 0
    darg = arg.dereference()
    active = darg['active']
    node = active
    done = 0
    while done == 0:
      noded = node.dereference()
      size = size + ((int(noded['index']) + 1) << 12)
      free = free + (noded['endp'] - noded['first_avail'])
      nodes = nodes + 1
      node = noded['next']
      if node == active:
        done = 1
    if darg['tag'] != 0:
      tag = darg['tag'].string()
    else:
      tag = "No tag"
    print("Pool '%s' [%s]: %d/%d free (%d blocks) allocator: %s free blocks in allocator: %i kiB" % (tag, arg, free, size, nodes, darg['allocator'], self._allocator_free_blocks(darg['allocator'])))
    self.free = self.free + free
    self.size = self.size + size
    self.nodes = self.nodes + nodes

  def _dump(self, arg, depth):
    pool = arg
    while pool:
        print("%*c" % (depth * 4 + 1, " "), end="")
        self._dump_one_pool(pool)
        if pool['child'] != 0:
            self._dump(pool['child'], depth + 1)
        pool = pool['sibling']

  def invoke (self, arg, from_tty):
    pool = gdb.parse_and_eval(arg)
    self.free = 0
    self.size = 0
    self.nodes = 0
    self.total_free_blocks = {}
    self._dump(pool, 0)
    print("Total %d/%d free (%d blocks)" % (self.free, self.size, self.nodes))
    sum = 0
    for key in self.total_free_blocks:
      sum = sum + self.total_free_blocks[key]
    print("Total free allocator blocks: %i kiB" % (sum))

DumpPoolAndChilds ()
end
document dump_pool_and_children
    Dump the whole pool hierarchy starting from the given pool.
end

python

class isValidAddress (gdb.Function):
    """Determines if the argument is a valid address."""

    def __init__(self):
        super(isValidAddress, self).__init__("isValidAddress")

    def invoke(self, address):
        inf = gdb.inferiors()[0]
        result = 1
        try:
            inf.read_memory(address, 8)
        except:
            result = 0
        return result

isValidAddress()

end

# Set sane defaults for common signals:
handle SIGPIPE noprint pass nostop
handle SIGUSR1 print pass nostop
