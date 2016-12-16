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

#ifndef MOD_CACHE_DISK_H
#define MOD_CACHE_DISK_H

#include "apr_file_io.h"

#include "cache_disk_common.h"

/*
 * include for mod_cache_disk: Disk Based HTTP 1.1 Cache.
 */

typedef struct {
    apr_pool_t *pool;
    const char *file;
    apr_file_t *fd;
    char *tempfile;
    apr_file_t *tempfd;
} disk_cache_file_t;

/*
 * disk_cache_object_t
 * Pointed to by cache_object_t::vobj
 */
typedef struct disk_cache_object {
    const char *root;            /* the location of the cache directory */
    apr_size_t root_len;
    const char *prefix;
    disk_cache_file_t data;      /* data file structure */
    disk_cache_file_t hdrs;      /* headers file structure */
    disk_cache_file_t vary;      /* vary file structure */
    const char *hashfile;        /* Computed hash key for this URI */
    const char *name;            /* Requested URI without vary bits - suitable for mortals. */
    const char *key;             /* On-disk prefix; URI with Vary bits (if present) */
    apr_off_t file_size;         /*  File size of the cached data file  */
    disk_cache_info_t disk_info; /* Header information. */
    apr_table_t *headers_in;     /* Input headers to save */
    apr_table_t *headers_out;    /* Output headers to save */
    apr_off_t offset;            /* Max size to set aside */
    apr_time_t timeout;          /* Max time to set aside */
    unsigned int done:1;         /* Is the attempt to cache complete? */
} disk_cache_object_t;


/*
 * mod_cache_disk configuration
 */
/* TODO: Make defaults OS specific */
#define CACHEFILE_LEN 20        /* must be less than HASH_LEN/2 */
#define DEFAULT_DIRLEVELS 2
#define DEFAULT_DIRLENGTH 2
#define DEFAULT_MIN_FILE_SIZE 1
#define DEFAULT_MAX_FILE_SIZE 1000000
#define DEFAULT_READSIZE 0
#define DEFAULT_READTIME 0

typedef struct {
    const char* cache_root;
    apr_size_t cache_root_len;
    int dirlevels;               /* Number of levels of subdirectories */
    int dirlength;               /* Length of subdirectory names */
} disk_cache_conf;

typedef struct {
    apr_off_t minfs;             /* minimum file size for cached files */
    apr_off_t maxfs;             /* maximum file size for cached files */
    apr_off_t readsize;          /* maximum data to attempt to cache in one go */
    apr_time_t readtime;         /* maximum time taken to cache in one go */
    unsigned int minfs_set:1;
    unsigned int maxfs_set:1;
    unsigned int readsize_set:1;
    unsigned int readtime_set:1;
} disk_cache_dir_conf;

#endif /*MOD_CACHE_DISK_H*/

