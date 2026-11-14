/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef __linux__

    #include <errno.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <sys/syscall.h>
    #include <unistd.h>

    #include "h3_socket.h"

/* Kernel ABI numbers, defined here so that old headers (EL7) still build. */
    #define BPF_MAP_CREATE 0
    #define BPF_MAP_UPDATE_ELEM 2
    #define BPF_PROG_LOAD 5
    #define MAP_REUSEPORT_SOCKARRAY 20
    #define PROG_SK_REUSEPORT 21
    #define FN_SKB_LOAD_BYTES 26
    #define FN_SK_SELECT_REUSEPORT 82
    #define SK_PASS 1
    #ifndef SO_ATTACH_REUSEPORT_EBPF
        #define SO_ATTACH_REUSEPORT_EBPF 52
    #endif

struct insn
{
    uint8_t code;
    uint8_t dst : 4;
    uint8_t src : 4;
    int16_t off;
    int32_t imm;
};

union attr
{
    struct
    {
        uint32_t type, key_size, value_size, max_entries, flags;
    } map;
    struct
    {
        uint32_t fd, pad;
        uint64_t key, value, flags;
    } elem;
    struct
    {
        uint32_t type, insn_cnt;
        uint64_t insns, license;
    } prog;
    uint8_t raw[120];
};

    #define MOV_X(d, s) {0xbf, d, s, 0, 0}
    #define MOV_K(d, k) {0xb7, d, 0, 0, k}
    #define ADD_K(d, k) {0x07, d, 0, 0, k}
    #define LDX_B(d, s, o) {0x71, d, s, o, 0}
    #define STX_W(d, s, o) {0x63, d, s, o, 0}
    #define JEQ_K(d, k, o) {0x15, d, 0, o, k}
    #define JNE_K(d, k, o) {0x55, d, 0, o, k}
    #define JSET_K(d, k, o) {0x45, d, 0, o, k}
    #define JA(o) {0x05, 0, 0, o, 0}
    #define CALL(f) {0x85, 0, 0, 0, f}
    #define EXIT {0x95, 0, 0, 0, 0}
    #define MAP_INSN 16

/* Select the socket from byte 0 of the destination connection ID.
 * No selection (short packet, empty or unknown index): the kernel hash applies. */
static struct insn prog[] = {
    MOV_X(6, 1),           /*  0 r6 = ctx */
    MOV_K(2, 8),           /*  1 after the UDP header */
    MOV_X(3, 10),          /*  2 */
    ADD_K(3, -8),          /*  3 to fp-8 */
    MOV_K(4, 7),           /*  4 flags .. long header DCID byte 0 */
    CALL(FN_SKB_LOAD_BYTES), /* 5 */
    JNE_K(0, 0, 15),       /*  6 too short: pass */
    LDX_B(2, 10, -8),      /*  7 r2 = flags */
    LDX_B(3, 10, -7),      /*  8 r3 = short header DCID byte 0 */
    JSET_K(2, 0x80, 1),    /*  9 long header */
    JA(3),                 /* 10 */
    LDX_B(4, 10, -3),      /* 11 r4 = DCID length */
    JEQ_K(4, 0, 9),        /* 12 empty DCID: pass */
    LDX_B(3, 10, -2),      /* 13 r3 = long header DCID byte 0 */
    STX_W(10, 3, -16),     /* 14 key */
    MOV_X(1, 6),           /* 15 */
    {0x18, 2, 1, 0, 0},    /* 16 r2 = map fd (patched) */
    {0, 0, 0, 0, 0},       /* 17 */
    MOV_X(3, 10),          /* 18 */
    ADD_K(3, -16),         /* 19 &key */
    MOV_K(4, 0),           /* 20 */
    CALL(FN_SK_SELECT_REUSEPORT), /* 21 */
    MOV_K(0, SK_PASS),     /* 22 pass */
    EXIT,                  /* 23 */
};

static int sys_bpf(int cmd, union attr* a)
{
    return (int)syscall(__NR_bpf, cmd, a, sizeof(*a));
}

int h3_socket_route_by_cid(const int* fds, int n, char* err, size_t errlen)
{
    const char* step = "map";
    int map = -1, fd = -1, ok = 0;
    union attr a;
    if (n < 2 || n > 256)
    {
        snprintf(err, errlen, "%d sockets: a one-byte index needs 2 to 256", n);
        return 0;
    }
    memset(&a, 0, sizeof(a));
    a.map.type = MAP_REUSEPORT_SOCKARRAY;
    a.map.key_size = 4;
    a.map.value_size = 4;
    a.map.max_entries = (uint32_t)n;
    map = sys_bpf(BPF_MAP_CREATE, &a);
    for (int i = 0; map >= 0 && i < n; i++)
    {
        uint32_t key = (uint32_t)i, value = (uint32_t)fds[i];
        step = "map update";
        memset(&a, 0, sizeof(a));
        a.elem.fd = (uint32_t)map;
        a.elem.key = (uint64_t)(uintptr_t)&key;
        a.elem.value = (uint64_t)(uintptr_t)&value;
        if (sys_bpf(BPF_MAP_UPDATE_ELEM, &a) != 0)
        {
            goto done;
        }
    }
    if (map >= 0)
    {
        step = "program load";
        prog[MAP_INSN].imm = map;
        memset(&a, 0, sizeof(a));
        a.prog.type = PROG_SK_REUSEPORT;
        a.prog.insn_cnt = sizeof(prog) / sizeof(prog[0]);
        a.prog.insns = (uint64_t)(uintptr_t)prog;
        a.prog.license = (uint64_t)(uintptr_t) "Apache-2.0";
        fd = sys_bpf(BPF_PROG_LOAD, &a);
    }
    if (fd >= 0)
    {
        step = "attach";
        ok = setsockopt(fds[0], SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &fd, sizeof(fd)) == 0; /* one attach covers the group */
    }
done:
    if (!ok)
    {
        snprintf(err, errlen, "%s: %s", step, strerror(errno));
    }
    /* The group holds the program, the program holds the map. */
    if (fd >= 0)
    {
        close(fd);
    }
    if (map >= 0)
    {
        close(map);
    }
    return ok;
}

#endif
