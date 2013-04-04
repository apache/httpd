/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * Originally written @ BBC by Graham Leggett
 * Copyright 2009-2011 British Broadcasting Corporation
 *
 */

#include "apr.h"
#include "apr_lib.h"
#include "apr_buckets.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_hash.h"
#include "apr_poll.h"
#include "apr_portable.h"
#include "apr_getopt.h"
#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_uuid.h"
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STRING_H
#include <string.h>
#endif

#include "ap_release.h"

#define DEFAULT_MAXLINES 0
#define DEFAULT_MAXSIZE 0
#define DEFAULT_AGE 0 * 1000 * 1000
#define DEFAULT_PREFIX 0
#define DEFAULT_NONBLOCK 0

typedef struct file_rec
{
    apr_pool_t *pool;
    apr_file_t *file_err;
    apr_file_t *file_in;
    apr_file_t *file_out;
    const char *directory;
    apr_bucket_alloc_t *alloc;
    apr_bucket_brigade *bb;
    apr_hash_t *request_uuids;
    apr_hash_t *response_uuids;
    apr_hash_t *filters;
    int limit;
    apr_size_t skipped_bytes;
    apr_size_t dropped_fragments;
    apr_time_t start;
    apr_time_t end;
} file_rec;

typedef struct uuid_rec
{
    apr_pool_t *pool;
    const char *uuid;
    file_rec *file;
    apr_uint64_t count;
    apr_time_t last;
    apr_size_t offset;
    int direction;
} uuid_rec;

typedef struct filter_rec
{
    apr_pool_t *pool;
    const char *prefix;
    apr_size_t len;
} filter_rec;

typedef struct header_rec
{
    apr_size_t len;
    apr_time_t timestamp;
    int direction;
    char uuid[APR_UUID_FORMATTED_LENGTH + 1];
    apr_uint64_t count;
    uuid_rec *rec;
} header_rec;

static const apr_getopt_option_t
        cmdline_opts[] =
        {
                /* commands */
                {
                        "file",
                        'f',
                        1,
                        "   --file, -f <name>\t\t\tFile to read the firehose from.\n\t\t\t\t\tDefaults to stdin." },
                {
                        "output-directory",
                        'd',
                        1,
                        "   --output-directory, -o <name>\tDirectory to write demuxed connections\n\t\t\t\t\tto." },
                {
                        "uuid",
                        'u',
                        1,
                        "   --uuid, -u <uuid>\t\t\tThe UUID of the connection to\n\t\t\t\t\tdemultiplex. Can be specified more\n\t\t\t\t\tthan once." },
                /*				{ "output-host", 'h', 1,
                 "   --output-host, -h <hostname>\tHostname to write demuxed connections to." },*/
                /*				{
                 "speed",
                 's',
                 1,
                 "   --speed, -s <factor>\tSpeed up or slow down demuxing\n\t\t\t\tby the given factor." },*/
                { "help", 258, 0, "   --help, -h\t\t\t\tThis help text." },
                { "version", 257, 0,
                        "   --version\t\t\t\tDisplay the version of the program." },
                { NULL } };

#define HELP_HEADER "Usage : %s [options] [prefix1 [prefix2 ...]]\n\n" \
                    "Firehose demultiplexes the given stream of multiplexed connections, and\n" \
                    "writes each connection to a file, or to a socket as appropriate.\n" \
                    "\n" \
                    "When writing to files, each connection is placed into a dedicated file\n" \
                    "named after the UUID of the connection within the stream. Separate files\n" \
                    "will be created if requests and responses are found in the stream.\n" \
                    "\n" \
                    "If an optional prefix is specified as a parameter, connections that start\n" \
                    "with the given prefix will be included. The prefix needs to fit completely\n" \
                    "within the first fragment for a successful match to occur.\n" \
                    "\n"
/*                    "When writing to a socket, new connections\n"
 *                    "are opened for each connection in the stream, allowing it to be possible to\n"
 *                    "'replay' traffic recorded by one server to other server.\n"
 *                    "\n\n"
 */
#define HELP_FOOTER ""

/**
 * Who are we again?
 */
static void version(const char * const progname)
{
    printf("%s (%s)\n", progname, AP_SERVER_VERSION);
}

/**
 * Help the long suffering end user.
 */
static void help(const char *argv, const char * header, const char *footer,
        const apr_getopt_option_t opts[])
{
    int i = 0;

    if (header) {
        printf(header, argv);
    }

    while (opts[i].name) {
        printf("%s\n", opts[i].description);
        i++;
    }

    if (footer) {
        printf("%s\n", footer);
    }
}

/**
 * Cleanup a uuid record. Removes the record from the uuid hashtable in files.
 */
static apr_status_t cleanup_uuid_rec(void *dummy)
{
    uuid_rec *rec = (uuid_rec *) dummy;

    if (rec->direction == '>') {
        apr_hash_set(rec->file->response_uuids, rec->uuid, APR_HASH_KEY_STRING,
                NULL);
    }
    if (rec->direction == '<') {
        apr_hash_set(rec->file->request_uuids, rec->uuid, APR_HASH_KEY_STRING,
                NULL);
    }

    return APR_SUCCESS;
}

/**
 * Create a uuid record, register a cleanup for it's destruction.
 */
static apr_status_t make_uuid_rec(file_rec *file, header_rec *header,
        uuid_rec **ptr)
{
    apr_pool_t *pool;
    uuid_rec *rec;
    apr_pool_create(&pool, file->pool);

    rec = apr_pcalloc(pool, sizeof(uuid_rec));
    rec->pool = pool;
    rec->file = file;
    rec->uuid = apr_pstrdup(pool, header->uuid);
    rec->count = 0;
    rec->last = header->timestamp;
    rec->direction = header->direction;

    if (header->direction == '>') {
        apr_hash_set(file->response_uuids, rec->uuid, APR_HASH_KEY_STRING, rec);
    }
    if (header->direction == '<') {
        apr_hash_set(file->request_uuids, rec->uuid, APR_HASH_KEY_STRING, rec);
    }

    apr_pool_cleanup_register(pool, rec, cleanup_uuid_rec, cleanup_uuid_rec);

    *ptr = rec;
    return APR_SUCCESS;
}

/**
 * Process the end of the fragment body.
 *
 * This function renames the completed stream to it's final name.
 */
static apr_status_t finalise_body(file_rec *file, header_rec *header)
{
    apr_status_t status;
    char *nfrom, *nto, *from, *to;
    apr_pool_t *pool;

    apr_pool_create(&pool, file->pool);

    to = apr_pstrcat(pool, header->uuid, header->direction == '>' ? ".response"
            : ".request", NULL);
    from = apr_pstrcat(pool, to, ".part", NULL);

    status = apr_filepath_merge(&nfrom, file->directory, from,
            APR_FILEPATH_SECUREROOT, pool);
    if (APR_SUCCESS == status) {
        status = apr_filepath_merge(&nto, file->directory, to,
                APR_FILEPATH_SECUREROOT, pool);
        if (APR_SUCCESS == status) {
            if (APR_SUCCESS == (status = apr_file_mtime_set(nfrom, file->end, pool))) {
                if (APR_SUCCESS != (status = apr_file_rename(nfrom, nto, pool))) {
                    apr_file_printf(
                            file->file_err,
                            "Could not rename file '%s' to '%s' for fragment write: %pm\n",
                            nfrom, nto, &status);
                }
            }
            else {
                apr_file_printf(
                        file->file_err,
                        "Could not set mtime on file '%s' to '%" APR_TIME_T_FMT "' for fragment write: %pm\n",
                        nfrom, file->end, &status);
            }
        }
        else {
            apr_file_printf(file->file_err,
                    "Could not merge directory '%s' with file '%s': %pm\n",
                    file->directory, to, &status);
        }
    }
    else {
        apr_file_printf(file->file_err,
                "Could not merge directory '%s' with file '%s': %pm\n",
                file->directory, from, &status);
    }

    apr_pool_destroy(pool);

    return status;
}

/**
 * Check if the fragment matches on of the prefixes.
 */
static int check_prefix(file_rec *file, header_rec *header, const char *str,
        apr_size_t len)
{
    apr_hash_index_t *hi;
    void *val;
    apr_pool_t *pool;
    int match = -1;

    apr_pool_create(&pool, file->pool);

    for (hi = apr_hash_first(pool, file->filters); hi; hi = apr_hash_next(hi)) {
        filter_rec *filter;
        apr_hash_this(hi, NULL, NULL, &val);
        filter = (filter_rec *) val;

        if (len > filter->len && !strncmp(filter->prefix, str, filter->len)) {
            match = 1;
            break;
        }
        match = 0;
    }

    apr_pool_destroy(pool);

    return match;
}

/**
 * Process part of the fragment body, given the header parameters.
 *
 * Currently, we append it to a file named after the UUID of the connection.
 *
 * The file is opened on demand and closed when done, so that we are
 * guaranteed never to hit a file handle limit (within reason).
 */
static apr_status_t process_body(file_rec *file, header_rec *header,
        const char *str, apr_size_t len)
{
    apr_status_t status;
    char *native, *name;
    apr_pool_t *pool;
    apr_file_t *handle;

    if (!file->start) {
        file->start = header->timestamp;
    }
    file->end = header->timestamp;

    apr_pool_create(&pool, file->pool);

    name
            = apr_pstrcat(pool, header->uuid,
                    header->direction == '>' ? ".response.part"
                            : ".request.part", NULL);

    status = apr_filepath_merge(&native, file->directory, name,
            APR_FILEPATH_SECUREROOT, pool);
    if (APR_SUCCESS == status) {
        if (APR_SUCCESS == (status = apr_file_open(&handle, native, APR_WRITE
                | APR_CREATE | APR_APPEND, APR_OS_DEFAULT, pool))) {
            if (APR_SUCCESS != (status = apr_file_write_full(handle, str, len,
                    &len))) {
                apr_file_printf(file->file_err,
                        "Could not write fragment body to file '%s': %pm\n",
                        native, &status);
            }
        }
        else {
            apr_file_printf(file->file_err,
                    "Could not open file '%s' for fragment write: %pm\n",
                    native, &status);
        }
    }
    else {
        apr_file_printf(file->file_err,
                "Could not merge directory '%s' with file '%s': %pm\n",
                file->directory, name, &status);
    }

    apr_pool_destroy(pool);

    return status;
}

/**
 * Parse a chunk extension, detect overflow.
 * There are two error cases:
 *  1) If the conversion would require too many bits, a -1 is returned.
 *  2) If the conversion used the correct number of bits, but an overflow
 *     caused only the sign bit to flip, then that negative number is
 *     returned.
 * In general, any negative number can be considered an overflow error.
 */
static apr_status_t read_hex(const char **buf, apr_uint64_t *val)
{
    const char *b = *buf;
    apr_uint64_t chunksize = 0;
    apr_size_t chunkbits = sizeof(apr_uint64_t) * 8;

    if (!apr_isxdigit(*b)) {
        return APR_EGENERAL;
    }
    /* Skip leading zeros */
    while (*b == '0') {
        ++b;
    }

    while (apr_isxdigit(*b) && (chunkbits > 0)) {
        int xvalue = 0;

        if (*b >= '0' && *b <= '9') {
            xvalue = *b - '0';
        }
        else if (*b >= 'A' && *b <= 'F') {
            xvalue = *b - 'A' + 0xa;
        }
        else if (*b >= 'a' && *b <= 'f') {
            xvalue = *b - 'a' + 0xa;
        }

        chunksize = (chunksize << 4) | xvalue;
        chunkbits -= 4;
        ++b;
    }
    *buf = b;
    if (apr_isxdigit(*b) && (chunkbits <= 0)) {
        /* overflow */
        return APR_EGENERAL;
    }

    *val = chunksize;

    return APR_SUCCESS;
}

/**
 * Parse what might be a fragment header line.
 *
 * If the parse doesn't match for any reason, an error is returned, otherwise
 * APR_SUCCESS.
 *
 * The header structure will be filled with the header values as parsed.
 */
static apr_status_t process_header(file_rec *file, header_rec *header,
        const char *str, apr_size_t len)
{
    apr_uint64_t val;
    apr_status_t status;
    int i;
    apr_uuid_t raw;
    const char *end = str + len;

    if (APR_SUCCESS != (status = read_hex(&str, &val))) {
        return status;
    }
    header->len = val;

    if (!apr_isspace(*(str++))) {
        return APR_EGENERAL;
    }

    if (APR_SUCCESS != (status = read_hex(&str, &val))) {
        return status;
    }
    header->timestamp = val;

    if (!apr_isspace(*(str++))) {
        return APR_EGENERAL;
    }

    if (*str != '<' && *str != '>') {
        return APR_EGENERAL;
    }
    header->direction = *str;
    str++;

    if (!apr_isspace(*(str++))) {
        return APR_EGENERAL;
    }

    for (i = 0; str[i] && i < APR_UUID_FORMATTED_LENGTH; i++) {
        header->uuid[i] = str[i];
    }
    header->uuid[i] = 0;
    if (apr_uuid_parse(&raw, header->uuid)) {
        return APR_EGENERAL;
    }
    str += i;

    if (!apr_isspace(*(str++))) {
        return APR_EGENERAL;
    }

    if (APR_SUCCESS != (status = read_hex(&str, &val))) {
        return status;
    }
    header->count = val;

    if ((*(str++) != '\r')) {
        return APR_EGENERAL;
    }
    if ((*(str++) != '\n')) {
        return APR_EGENERAL;
    }
    if (str != end) {
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

/**
 * Suck on the file/pipe, and demux any fragments on the incoming stream.
 *
 * If EOF is detected, this function returns.
 */
static apr_status_t demux(file_rec *file)
{
    apr_size_t len = 0;
    apr_status_t status = APR_SUCCESS;
    apr_bucket *b, *e;
    apr_bucket_brigade *bb, *obb;
    int footer = 0;
    const char *buf;

    bb = apr_brigade_create(file->pool, file->alloc);
    obb = apr_brigade_create(file->pool, file->alloc);
    b = apr_bucket_pipe_create(file->file_in, file->alloc);

    APR_BRIGADE_INSERT_HEAD(bb, b);

    do {

        /* when the pipe is closed, the pipe disappears from the brigade */
        if (APR_BRIGADE_EMPTY(bb)) {
            break;
        }

        status = apr_brigade_split_line(obb, bb, APR_BLOCK_READ,
                HUGE_STRING_LEN);

        if (APR_SUCCESS == status || APR_EOF == status) {
            char str[HUGE_STRING_LEN];
            len = HUGE_STRING_LEN;

            apr_brigade_flatten(obb, str, &len);

            apr_brigade_cleanup(obb);

            if (len == HUGE_STRING_LEN) {
                file->skipped_bytes += len;
                continue;
            }
            else if (footer) {
                if (len == 2 && str[0] == '\r' && str[1] == '\n') {
                    footer = 0;
                    continue;
                }
                file->skipped_bytes += len;
            }
            else if (len > 0) {
                header_rec header;
                status = process_header(file, &header, str, len);
                if (APR_SUCCESS != status) {
                    file->skipped_bytes += len;
                    continue;
                }
                else {
                    int ignore = 0;

                    header.rec = NULL;
                    if (header.direction == '>') {
                        header.rec = apr_hash_get(file->response_uuids,
                                header.uuid, APR_HASH_KEY_STRING);
                    }
                    if (header.direction == '<') {
                        header.rec = apr_hash_get(file->request_uuids,
                                header.uuid, APR_HASH_KEY_STRING);
                    }
                    if (header.rec) {
                        /* does the count match what is expected? */
                        if (header.count != header.rec->count) {
                            file->dropped_fragments++;
                            ignore = 1;
                        }
                    }
                    else {
                        /* must we ignore unknown uuids? */
                        if (file->limit) {
                            ignore = 1;
                        }

                        /* is the counter not what we expect? */
                        else if (header.count != 0) {
                            file->skipped_bytes += len;
                            ignore = 1;
                        }

                        /* otherwise, make a new uuid */
                        else {
                            make_uuid_rec(file, &header, &header.rec);
                        }
                    }

                    if (header.len) {
                        if (APR_SUCCESS != (status = apr_brigade_partition(bb,
                                header.len, &e))) {
                            apr_file_printf(
                                    file->file_err,
                                    "Could not read fragment body from input file: %pm\n", &status);
                            break;
                        }
                        while ((b = APR_BRIGADE_FIRST(bb)) && e != b) {
                            apr_bucket_read(b, &buf, &len, APR_READ_BLOCK);
                            if (!ignore && !header.count && !check_prefix(file,
                                    &header, buf, len)) {
                                ignore = 1;
                            }
                            if (!ignore) {
                                status = process_body(file, &header, buf, len);
                                header.rec->offset += len;
                            }
                            if (ignore || APR_SUCCESS != status) {
                                apr_bucket_delete(b);
                                file->skipped_bytes += len;
                                continue;
                            }
                            apr_bucket_delete(b);
                        }
                        if (!ignore) {
                            header.rec->count++;
                        }
                        footer = 1;
                        continue;
                    }
                    else {
                        /* an empty header means end-of-connection */
                        if (header.rec) {
                            if (!ignore) {
                                if (!header.count) {
                                    status = process_body(file, &header, "", 0);
                                }
                                status = finalise_body(file, &header);
                            }
                            apr_pool_destroy(header.rec->pool);
                        }
                    }

                }
            }

        }
        else {
            apr_file_printf(file->file_err,
                    "Could not read fragment header from input file: %pm\n", &status);
            break;
        }

    } while (1);

    return status;
}

/**
 * Start the application.
 */
int main(int argc, const char * const argv[])
{
    apr_status_t status;
    apr_pool_t *pool;
    char errmsg[1024];
    apr_getopt_t *opt;
    int optch;
    const char *optarg;

    file_rec *file;

    /* lets get APR off the ground, and make sure it terminates cleanly */
    if (APR_SUCCESS != (status = apr_app_initialize(&argc, &argv, NULL))) {
        return 1;
    }
    atexit(apr_terminate);

    if (APR_SUCCESS != (status = apr_pool_create(&pool, NULL))) {
        return 1;
    }

#ifdef SIGPIPE
    apr_signal_block(SIGPIPE);
#endif

    file = apr_pcalloc(pool, sizeof(file_rec));
    apr_file_open_stderr(&file->file_err, pool);
    apr_file_open_stdin(&file->file_in, pool);
    apr_file_open_stdout(&file->file_out, pool);

    file->pool = pool;
    file->alloc = apr_bucket_alloc_create(pool);
    file->bb = apr_brigade_create(pool, file->alloc);
    file->request_uuids = apr_hash_make(pool);
    file->response_uuids = apr_hash_make(pool);
    file->filters = apr_hash_make(pool);

    apr_getopt_init(&opt, pool, argc, argv);
    while ((status = apr_getopt_long(opt, cmdline_opts, &optch, &optarg))
            == APR_SUCCESS) {

        switch (optch) {
        case 'f': {
            status = apr_file_open(&file->file_in, optarg, APR_FOPEN_READ,
                    APR_OS_DEFAULT, pool);
            if (status != APR_SUCCESS) {
                apr_file_printf(file->file_err,
                        "Could not open file '%s' for read: %pm\n", optarg, &status);
                return 1;
            }
            break;
        }
        case 'd': {
            apr_finfo_t finfo;
            status = apr_stat(&finfo, optarg, APR_FINFO_TYPE, pool);
            if (status != APR_SUCCESS) {
                apr_file_printf(file->file_err,
                        "Directory '%s' could not be found: %pm\n", optarg, &status);
                return 1;
            }
            if (finfo.filetype != APR_DIR) {
                apr_file_printf(file->file_err,
                        "Path '%s' isn't a directory\n", optarg);
                return 1;
            }
            file->directory = optarg;
            break;
        }
        case 'u': {
            apr_pool_t *pchild;
            uuid_rec *rec;
            apr_pool_create(&pchild, pool);
            rec = apr_pcalloc(pchild, sizeof(uuid_rec));
            rec->pool = pchild;
            rec->uuid = optarg;
            apr_hash_set(file->request_uuids, optarg, APR_HASH_KEY_STRING, rec);
            apr_hash_set(file->response_uuids, optarg, APR_HASH_KEY_STRING, rec);
            file->limit++;
            break;
        }
        case 257: {
            version(argv[0]);
            return 0;
        }
        case 258: {
            help(argv[0], HELP_HEADER, HELP_FOOTER, cmdline_opts);
            return 0;

        }
        }

    }
    if (APR_SUCCESS != status && APR_EOF != status) {
        return 1;
    }

    /* read filters from the command line */
    while (opt->ind < argc) {
        apr_pool_t *pchild;
        filter_rec *filter;
        apr_pool_create(&pchild, pool);
        filter = apr_pcalloc(pchild, sizeof(filter_rec));
        filter->pool = pchild;
        filter->prefix = opt->argv[opt->ind];
        filter->len = strlen(opt->argv[opt->ind]);
        apr_hash_set(file->filters, opt->argv[opt->ind], APR_HASH_KEY_STRING,
                filter);
        opt->ind++;
    }

    status = demux(file);

    /* warn people if any non blocking writes failed */
    if (file->skipped_bytes || file->dropped_fragments) {
        apr_file_printf(
                file->file_err,
                "Warning: %" APR_SIZE_T_FMT " bytes skipped, %" APR_SIZE_T_FMT " fragments dropped.\n",
                file->skipped_bytes, file->dropped_fragments);
    }

    if (APR_SUCCESS != status) {
        return 1;
    }

    return 0;
}
