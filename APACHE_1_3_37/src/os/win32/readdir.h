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

/*
 * Structures and types used to implement opendir/readdir/closedir
 * on Windows 95/NT.
 */

#ifndef APACHE_READDIR_H
#define APACHE_READDIR_H

#ifdef WIN32

#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#ifndef API_EXPORT
# define API_EXPORT(type)    __declspec(dllexport) type __stdcall
#endif

/* struct dirent - same as Unix */
struct dirent {
    long d_ino;                    /* inode (always 1 in WIN32) */
    off_t d_off;                /* offset to this dirent */
    unsigned short d_reclen;    /* length of d_name */
    char d_name[_MAX_FNAME+1];    /* filename (null terminated) */
};

/* typedef DIR - not the same as Unix */
typedef struct {
    long handle;                /* _findfirst/_findnext handle */
    short offset;                /* offset into directory */
    short finished;             /* 1 if there are not more files */
    struct _finddata_t fileinfo;  /* from _findfirst/_findnext */
    char *dir;                  /* the dir we are reading */
    struct dirent dent;         /* the dirent to return */
} DIR;

/* Function prototypes */
API_EXPORT(DIR *) opendir(const char *);
API_EXPORT(struct dirent *) readdir(DIR *);
API_EXPORT(int) closedir(DIR *);

#endif /* WIN32 */

#endif /* ndef APACHE_READDIR_H */
