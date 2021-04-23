/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_fnmatch.h"
#include "apr_lib.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_log.h"

#include "ssl_ct_util.h"

APLOG_USE_MODULE(ssl_ct);

apr_status_t ctutil_path_join(char **out, const char *dirname, const char *basename,
                              apr_pool_t *p, server_rec *s)
{
    apr_status_t rv;

    rv = apr_filepath_merge(out, dirname, basename, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02776) "can't build filename from %s and %s",
                     dirname, basename);
    }

    return rv;
}

int ctutil_dir_exists(apr_pool_t *p, const char *dirname)
{
    apr_finfo_t finfo;
    apr_status_t rv = apr_stat(&finfo, dirname, APR_FINFO_TYPE, p);

    return rv == APR_SUCCESS && finfo.filetype == APR_DIR;
}

int ctutil_file_exists(apr_pool_t *p, const char *filename)
{
    apr_finfo_t finfo;
    apr_status_t rv = apr_stat(&finfo, filename, APR_FINFO_TYPE, p);

    return rv == APR_SUCCESS && finfo.filetype == APR_REG;
}

void ctutil_buffer_to_array(apr_pool_t *p, const char *b,
                            apr_size_t b_size, apr_array_header_t **out)
{
    apr_array_header_t *arr = apr_array_make(p, 10, sizeof(char *));
    const char *ch, *last;

    ch = b;
    last = b + b_size - 1;
    while (ch < last) {
        const char *end = memchr(ch, '\n', last - ch);
        const char *line;

        if (!end) {
            end = last + 1;
        }
        while (apr_isspace(*ch) && ch < end) {
            ch++;
        }
        if (ch < end) {
            const char *tmpend = end - 1;

            while (tmpend > ch
                   && isspace(*tmpend)) {
                --tmpend;
            }
            
            line = apr_pstrndup(p, ch, 1 + tmpend - ch);
            *(const char **)apr_array_push(arr) = line;
        }
        ch = end + 1;
    }

    *out = arr;
}

apr_status_t ctutil_fopen(const char *fn, const char *mode, FILE **f)
{
    apr_status_t rv;

    *f = fopen(fn, mode);
    if (*f == NULL) {
        rv = errno; /* XXX Windows equivalent -- CreateFile + fdopen? */
    }
    else {
        rv = APR_SUCCESS;
    }

    return rv;
}

/* read_dir() is remarkably like apr_match_glob(), which could
 * probably use some processing flags to indicate variations on
 * the basic behavior (and implement better error checking).
 */
apr_status_t ctutil_read_dir(apr_pool_t *p,
                             server_rec *s,
                             const char *dirname,
                             const char *pattern,
                             apr_array_header_t **outarr)
{
    apr_array_header_t *arr;
    apr_dir_t *d;
    apr_finfo_t finfo;
    apr_status_t rv;
    int reported = 0;

    /* add to existing array if it already exists */
    arr = *outarr;
    if (arr == NULL) {
        arr = apr_array_make(p, 4, sizeof(char *));
    }

    rv = apr_dir_open(&d, dirname, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02777) "couldn't read dir %s",
                     dirname);
        return rv;
    }

    while ((rv = apr_dir_read(&finfo, APR_FINFO_NAME, d)) == APR_SUCCESS) {
        const char *fn;

        if (APR_SUCCESS == apr_fnmatch(pattern, finfo.name, APR_FNM_CASE_BLIND)) {
            rv = ctutil_path_join((char **)&fn, dirname, finfo.name, p, s);
            if (rv != APR_SUCCESS) {
                reported = 1;
                break;
            }

            *(char **)apr_array_push(arr) = apr_pstrdup(p, fn);
        }
    }

    if (APR_STATUS_IS_ENOENT(rv)) {
        rv = APR_SUCCESS;
    }
    else if (rv != APR_SUCCESS && !reported) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02778) "couldn't read entry from dir %s", dirname);
    }

    apr_dir_close(d);

    if (rv == APR_SUCCESS) {
        *outarr = arr;
    }

    return rv;
}

apr_status_t ctutil_read_file(apr_pool_t *p,
                              server_rec *s,
                              const char *fn,
                              apr_off_t limit,
                              char **contents,
                              apr_size_t *contents_size)
{
    apr_file_t *f;
    apr_finfo_t finfo;
    apr_status_t rv;
    apr_size_t nbytes;

    *contents = NULL;
    *contents_size = 0;

    rv = apr_file_open(&f, fn, APR_READ | APR_BINARY, APR_FPROT_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02779) "couldn't read %s", fn);
        return rv;
    }
    
    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, f);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02780) "couldn't retrieve size of %s", fn);
        apr_file_close(f);
        return rv;
    }

    if (finfo.size > limit) {
        rv = APR_ENOSPC;
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02781) "size %" APR_OFF_T_FMT " of %s exceeds "
                     "limit (%" APR_OFF_T_FMT ")", finfo.size, fn, limit);
        apr_file_close(f);
        return rv;
    }

    nbytes = (apr_size_t)finfo.size;
    *contents = apr_palloc(p, nbytes);
    rv = apr_file_read_full(f, *contents, nbytes, contents_size);
    if (rv != APR_SUCCESS) { /* shouldn't get APR_EOF since we know
                              * how big the file is
                              */
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02782) "apr_file_read_full");
    }
    apr_file_close(f);

    return rv;
}

#if APR_FILES_AS_SOCKETS
static void io_loop(apr_pool_t *p, server_rec *s, apr_proc_t *proc,
                    const char *desc_for_log)
{
    apr_status_t rv;
    apr_pollfd_t pfd = {0};
    apr_pollset_t *pollset;
    int fds_waiting;

    rv = apr_pollset_create(&pollset, 2, p, 0);
    ap_assert(rv == APR_SUCCESS);

    fds_waiting = 0;

    pfd.p = p;
    pfd.desc_type = APR_POLL_FILE;
    pfd.reqevents = APR_POLLIN;
    pfd.desc.f = proc->err;
    rv = apr_pollset_add(pollset, &pfd);
    ap_assert(rv == APR_SUCCESS);
    ++fds_waiting;

    pfd.desc.f = proc->out;
    rv = apr_pollset_add(pollset, &pfd);
    ap_assert(rv == APR_SUCCESS);
    ++fds_waiting;

    while (fds_waiting) {
        int i, num_events;
        const apr_pollfd_t *pdesc;
        char buf[4096];
        apr_size_t len;

        rv = apr_pollset_poll(pollset, apr_time_from_sec(10),
                              &num_events, &pdesc);
        if (rv != APR_SUCCESS && !APR_STATUS_IS_EINTR(rv)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         APLOGNO(02783) "apr_pollset_poll");
            break;
        }

        for (i = 0; i < num_events; i++) {
            len = sizeof buf;
            rv = apr_file_read(pdesc[i].desc.f, buf, &len);
            if (APR_STATUS_IS_EOF(rv)) {
                apr_file_close(pdesc[i].desc.f);
                apr_pollset_remove(pollset, &pdesc[i]);
                --fds_waiting;
            }
            else if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             APLOGNO(02784) "apr_file_read");
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, s,
                             "%s: %.*s", desc_for_log, (int)len, buf);
            }
        }
    }
}
#else /* APR_FILES_AS_SOCKETS */
static void io_loop(apr_pool_t *p, server_rec *s, apr_proc_t *proc,
                    const char *desc_for_log)
{
    apr_status_t rv;
    apr_file_t *fds[2] = {proc->out, proc->err};
    apr_size_t len;
    char buf[4096];
    int fds_waiting = 2;

    while (fds_waiting) {
        int i;
        int read = 0;

        for (i = 0; i < sizeof fds / sizeof fds[0]; i++) {
            if (!fds[i]) {
                continue;
            }
            len = sizeof buf;
            rv = apr_file_read(fds[i], buf, &len);
            if (APR_STATUS_IS_EOF(rv)) {
                apr_file_close(fds[i]);
                fds[i] = NULL;
                --fds_waiting;
            }
            else if (APR_STATUS_IS_EAGAIN(rv)) {
                /* we don't actually know if data is ready before reading, so
                 * this isn't an error
                 */
            }
            else if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             APLOGNO(02785) "apr_file_read");
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, s,
                             "%s: %.*s", desc_for_log, (int)len, buf);
                ++read;
            }
        }
        if (fds_waiting && !read) {
            /* no tight loop */
            apr_sleep(apr_time_from_msec(100));
        }
    }
}
#endif /* APR_FILES_AS_SOCKETS */

apr_status_t ctutil_run_to_log(apr_pool_t *p,
                               server_rec *s,
                               const char *args[8],
                               const char *desc_for_log)
{
    apr_exit_why_e exitwhy;
    apr_proc_t proc = {0};
    apr_procattr_t *attr;
    apr_status_t rv;
    int exitcode;

    rv = apr_procattr_create(&attr, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02786) "apr_procattr_create failed");
        return rv;
    }

    rv = apr_procattr_io_set(attr,
                             APR_NO_PIPE,
                             APR_CHILD_BLOCK,
                             APR_CHILD_BLOCK);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02787) "apr_procattr_io_set failed");
        return rv;
    }

    if (APLOGtrace1(s)) {
        const char *cmdline = "";
        const char **curarg = args;

        while (*curarg) {
            cmdline = apr_pstrcat(p, cmdline, *curarg, " ", NULL);
            curarg++;
        }
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                     "Running \"%s\"", cmdline);
    }

    rv = apr_proc_create(&proc, args[0], args, NULL, attr, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02788) "apr_proc_create failed");
        return rv;
    }

    io_loop(p, s, &proc, desc_for_log);

    rv = apr_proc_wait(&proc, &exitcode, &exitwhy, APR_WAIT);
    rv = rv == APR_CHILD_DONE ? APR_SUCCESS : rv;

    ap_log_error(APLOG_MARK,
                 rv != APR_SUCCESS || exitcode ? APLOG_ERR : APLOG_DEBUG,
                 rv, s,
                 APLOGNO(02789) "exit code from %s: %d (%s)", 
                 desc_for_log, exitcode,
                 exitwhy == APR_PROC_EXIT ? "exited normally" : "exited due to a signal");

    if (rv == APR_SUCCESS && exitcode) {
        rv = APR_EGENERAL;
    }

    return rv;
}

void ctutil_thread_mutex_lock(apr_thread_mutex_t *m)
{
    apr_status_t rv = apr_thread_mutex_lock(m);
    ap_assert(rv == APR_SUCCESS);
}

void ctutil_thread_mutex_unlock(apr_thread_mutex_t *m)
{
    apr_status_t rv = apr_thread_mutex_unlock(m);
    ap_assert(rv == APR_SUCCESS);
}

apr_status_t ctutil_file_write_uint16(server_rec *s,
                                      apr_file_t *f,
                                      apr_uint16_t in_val)
{
    apr_size_t nbytes;
    apr_status_t rv;
    char vals[2];

    vals[0] = (in_val & 0xFF00) >> 8;
    vals[1] = (in_val & 0x00FF);
    nbytes = sizeof(vals);
    rv = apr_file_write(f, vals, &nbytes);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02790) "can't write 2-byte length to file");
    }
    return rv;
}

apr_status_t ctutil_file_write_uint24(server_rec *s,
                                      apr_file_t *f,
                                      apr_uint32_t in_val)
{
    apr_size_t nbytes;
    apr_status_t rv;
    char vals[3];

    vals[0] = (in_val & 0xFF0000) >> 16;
    vals[1] = (in_val & 0x00FF00) >> 8;
    vals[2] = (in_val & 0x0000FF) >> 0;
    nbytes = sizeof(vals);
    rv = apr_file_write(f, vals, &nbytes);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(02791) "can't write 3-byte length to file");
    }
    return rv;
}

void ctutil_log_array(const char *file, int line, int module_index,
                      int level, server_rec *s, const char *desc,
                      apr_array_header_t *arr)
{
    const char **elts = (const char **)arr->elts;
    int i;

    /* Intentional no APLOGNO */
    ap_log_error(file, line, module_index, level,
                 0, s, "%s", desc);
    for (i = 0; i < arr->nelts; i++) {
        /* Intentional no APLOGNO */
        ap_log_error(file, line, module_index, level,
                     0, s, ">>%s", elts[i]);
    }
}

static apr_status_t deserialize_uint(const unsigned char **mem,
                                     apr_size_t *avail,
                                     apr_byte_t num_bits, apr_uint64_t *pval)
{
    apr_byte_t num_bytes = num_bits / 8;
    apr_uint64_t val = 0;
    int i;

    if (*avail < num_bytes || num_bits > 64) {
        return APR_EINVAL;
    }

    for (i = 0; i < num_bytes; i++) {
        val = (val << 8) | **mem;
        *mem += 1;
        *avail -= 1;
    }

    *pval = val;
    return APR_SUCCESS;
}

apr_status_t ctutil_deserialize_uint64(const unsigned char **mem,
                                       apr_size_t *avail,
                                       apr_uint64_t *pval)
{
    return deserialize_uint(mem, avail, 64, pval);
}

apr_status_t ctutil_deserialize_uint16(const unsigned char **mem,
                                       apr_size_t *avail,
                                       apr_uint16_t *pval)
{
    apr_status_t rv;
    apr_uint64_t val64 = 0;

    rv = deserialize_uint(mem, avail, 16, &val64);
    *pval = (apr_uint16_t)val64;
    return rv;
}

static apr_status_t serialize_uint(unsigned char **mem, apr_size_t *avail,
                                   apr_byte_t num_bits, apr_uint64_t val)
{
    apr_byte_t num_bytes = num_bits / 8;
    int i;
    apr_uint64_t mask;
    apr_byte_t shift;

    if (*avail < num_bytes || num_bits > 64) {
        return APR_EINVAL;
    }

    mask = (apr_uint64_t)0xFF << (num_bits - 8);
    shift = num_bits - 8;
    for (i = 0; i < num_bytes; i++) {
        **mem = (unsigned char)((val & mask) >> shift);
        *mem += 1;
        *avail -= 1;
        mask = mask >> 8;
        shift -= 8;
    }

    return APR_SUCCESS;
}

apr_status_t ctutil_serialize_uint64(unsigned char **mem, apr_size_t *avail,
                                     apr_uint64_t val)
{
    return serialize_uint(mem, avail, 64, val);
}

apr_status_t ctutil_serialize_uint24(unsigned char **mem, apr_size_t *avail,
                                     apr_uint32_t val)
{
    return serialize_uint(mem, avail, 24, val);
}

apr_status_t ctutil_serialize_uint16(unsigned char **mem, apr_size_t *avail,
                                     apr_uint16_t val)
{
    return serialize_uint(mem, avail, 16, val);
}

apr_status_t ctutil_serialize_uint8(unsigned char **mem, apr_size_t *avail,
                                    unsigned char val)
{
    return serialize_uint(mem, avail, 8, val);
}

apr_status_t ctutil_write_var16_bytes(unsigned char **mem, apr_size_t *avail,
                                      const unsigned char *val,
                                      apr_uint16_t len)
{
    apr_status_t rv;

    if (*avail < (sizeof(apr_uint16_t) + len)) {
        return APR_EINVAL;
    }

    rv = ctutil_serialize_uint16(mem, avail, len);
    if (rv != APR_SUCCESS) { /* should not occur */
        return rv;
    }

    memcpy(*mem, val, len);
    *mem += len;
    *avail -= len;
    return APR_SUCCESS;
}

apr_status_t ctutil_write_var24_bytes(unsigned char **mem, apr_size_t *avail,
                                      const unsigned char *val,
                                      apr_uint32_t len)
{
    apr_status_t rv;

    if (*avail < (3 + len)) {
        return APR_EINVAL;
    }

    rv = ctutil_serialize_uint24(mem, avail, len);
    if (rv != APR_SUCCESS) { /* should not occur */
        return rv;
    }

    memcpy(*mem, val, len);
    *mem += len;
    *avail -= len;
    return APR_SUCCESS;
}

/* all this deserialization crap is of course from
 * c-t/src/proto/serializer.cc
 */
static apr_status_t read_length_prefix(const unsigned char **mem, apr_size_t *avail,
                                       apr_size_t *result)
{
    apr_status_t rv;
    apr_uint16_t val;

    rv = ctutil_deserialize_uint16(mem, avail, &val);
    if (rv == APR_SUCCESS) {
        *result = val;
    }

    return rv;
}

static apr_status_t read_fixed_bytes(const unsigned char **mem, apr_size_t *avail,
                                     apr_size_t len,
                                     const unsigned char **start)
{
    if (*avail < len) {
        return APR_EINVAL;
    }

    *start = *mem;
    *avail -= len;
    *mem += len;

    return APR_SUCCESS;
}

apr_status_t ctutil_read_var_bytes(const unsigned char **mem, apr_size_t *avail,
                                   const unsigned char **start, apr_size_t *len)
{
    apr_status_t rv;

    rv = read_length_prefix(mem, avail, len);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = read_fixed_bytes(mem, avail, *len, start);
    return rv;
}

#define TESTURL1 "https://127.0.0.1:8888"
#define TESTURL2 "https://127.0.0.1:9999"
#define TESTURL3 "https://127.0.0.1:10000"

void ctutil_run_internal_tests(apr_pool_t *p)
{
    apr_array_header_t *arr;
    const char *filecontents =
      " " TESTURL1 " \r\n" TESTURL2 "\n"
      TESTURL3 /* no "\n" */ ;
    unsigned char buf[8], *ch;
    const unsigned char *const_ch;
    apr_size_t avail;
    apr_status_t rv;
    apr_uint16_t val16;
    apr_uint64_t val64;

    ctutil_buffer_to_array(p, filecontents, strlen(filecontents), &arr);
    
    ap_assert(ap_array_str_contains(arr, TESTURL1));
    ap_assert(ap_array_str_contains(arr, TESTURL2));
    ap_assert(ap_array_str_contains(arr, TESTURL3));
    ap_assert(!ap_array_str_contains(arr, TESTURL1 "x"));

    ch = buf;
    avail = 8;
    rv = ctutil_serialize_uint64(&ch, &avail, 0xDEADBEEFCAFEBABE);
    ap_assert(rv == APR_SUCCESS);
    ap_assert(avail == 0);
    ap_assert(ch == buf + 8);
    ap_assert(buf[0] == 0xDE);
    ap_assert(buf[1] == 0xAD);
    ap_assert(buf[2] == 0xBE);
    ap_assert(buf[3] == 0xEF);
    ap_assert(buf[4] == 0xCA);
    ap_assert(buf[5] == 0xFE);
    ap_assert(buf[6] == 0xBA);
    ap_assert(buf[7] == 0xBE);

    const_ch = buf;
    avail = 8;
    rv = ctutil_deserialize_uint64(&const_ch, &avail, &val64);
    ap_assert(rv == APR_SUCCESS);
    ap_assert(avail == 0);
    ap_assert(const_ch == buf + 8);
    ap_assert(val64 == 0xDEADBEEFCAFEBABE);

    ch = buf;
    avail = 7;
    ap_assert(ctutil_serialize_uint64(&ch, &avail, 0xDEADBEEFCAFEBABE)
              == APR_EINVAL);

    ch = buf;
    avail = 3;
    rv = ctutil_serialize_uint24(&ch, &avail, 0xDEADBE);
    ap_assert(rv == APR_SUCCESS);
    ap_assert(avail == 0);
    ap_assert(ch == buf + 3);
    ap_assert(buf[0] == 0xDE);
    ap_assert(buf[1] == 0xAD);
    ap_assert(buf[2] == 0xBE);

    ch = buf;
    avail = 1;
    ap_assert(ctutil_serialize_uint16(&ch, &avail, 0xDEAD)
              == APR_EINVAL);

    ch = buf;
    avail = 2;
    rv = ctutil_serialize_uint16(&ch, &avail, 0xDEAD);
    ap_assert(rv == APR_SUCCESS);
    ap_assert(avail == 0);
    ap_assert(ch == buf + 2);
    ap_assert(buf[0] == 0xDE);
    ap_assert(buf[1] == 0xAD);

    const_ch = buf;
    avail = 2;
    rv = ctutil_deserialize_uint16(&const_ch, &avail, &val16);
    ap_assert(rv == APR_SUCCESS);
    ap_assert(avail == 0);
    ap_assert(val16 == 0xDEAD);

    ch = buf;
    avail = 1;
    ap_assert(ctutil_serialize_uint16(&ch, &avail, 0xDEAD)
              == APR_EINVAL);

    ch = buf;
    avail = 1;
    rv = ctutil_serialize_uint8(&ch, &avail, 0xDE);
    ap_assert(rv == APR_SUCCESS);
    ap_assert(avail == 0);
    ap_assert(ch == buf + 1);
    ap_assert(buf[0] == 0xDE);

    ch = buf;
    avail = 0;
    ap_assert(ctutil_serialize_uint8(&ch, &avail, 0xDE)
              == APR_EINVAL);

    ch = buf;
    avail = 8;
    rv = ctutil_write_var16_bytes(&ch, &avail, 
                                  (unsigned char *)"\x01""\x02""\x03""\x04", 4);
    ap_assert(rv == APR_SUCCESS);
    ap_assert(avail == 2);
    ap_assert(ch == buf + 6);
    ap_assert(buf[0] == 0);
    ap_assert(buf[1] == 4);
    ap_assert(buf[2] == 0x01);
    ap_assert(buf[3] == 0x02);
    ap_assert(buf[4] == 0x03);
    ap_assert(buf[5] == 0x04);

    ch = buf;
    avail = 3;
    rv = ctutil_write_var16_bytes(&ch, &avail, 
                                  (unsigned char *)"\x01""\x02""\x03""\x04", 4);
    ap_assert(rv == APR_EINVAL);

    ch = buf;
    avail = 8;
    rv = ctutil_write_var24_bytes(&ch, &avail, 
                                  (unsigned char *)"\x01""\x02""\x03""\x04", 4);
    ap_assert(rv == APR_SUCCESS);
    ap_assert(avail == 1);
    ap_assert(ch == buf + 7);
    ap_assert(buf[0] == 0);
    ap_assert(buf[1] == 0);
    ap_assert(buf[2] == 4);
    ap_assert(buf[3] == 0x01);
    ap_assert(buf[4] == 0x02);
    ap_assert(buf[5] == 0x03);
    ap_assert(buf[6] == 0x04);

    ch = buf;
    avail = 4;
    rv = ctutil_write_var24_bytes(&ch, &avail, 
                                  (unsigned char *)"\x01""\x02""\x03""\x04", 4);
    ap_assert(rv == APR_EINVAL);
}
