/*
 * Copyright (c) 2005, 2008 Sun Microsystems, Inc. All Rights Reserved.
 * Use is subject to license terms.
 *
 *      Copyright (c) 1984 AT&T
 *        All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBSED_H
#define LIBSED_H

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>

#include "apr_file_io.h"

#define SED_NLINES 256
#define SED_DEPTH 20
#define SED_LABSIZE 50
#define SED_ABUFSIZE 20

typedef struct sed_reptr_s sed_reptr_t;

struct sed_reptr_s {
    sed_reptr_t *next;
    char        *ad1;
    char        *ad2;
    char        *re1;
    sed_reptr_t *lb1;
    char        *rhs;
    int         findex;
    char        command;
    int         gfl;
    char        pfl;
    char        negfl;
    int         nrep;
};

typedef struct sed_label_s sed_label_t;

struct sed_label_s {
    char        asc[9];
    sed_reptr_t *chain;
    sed_reptr_t *address;
};

typedef apr_status_t (sed_err_fn_t)(void *data, const char *error);
typedef apr_status_t (sed_write_fn_t)(void *ctx, char *buf, int sz);

typedef struct sed_commands_s sed_commands_t;
#define NWFILES 11 /* 10 plus one for standard output */

struct sed_commands_s {
    sed_err_fn_t *errfn;
    void         *data;

    unsigned     lsize;
    char         *linebuf;
    char         *lbend;
    const char   *saveq;

    char         *cp;
    char         *lastre;
    char         *respace;
    char         sseof;
    char         *reend;
    const char   *earg;
    int          eflag;
    int          gflag;
    int          nflag;
    apr_int64_t  tlno[SED_NLINES];
    int          nlno;
    int          depth;

    char         *fname[NWFILES];
    int          nfiles;

    sed_label_t  ltab[SED_LABSIZE];
    sed_label_t  *labtab;
    sed_label_t  *lab;
    sed_label_t  *labend;

    sed_reptr_t  **cmpend[SED_DEPTH];
    sed_reptr_t  *ptrspace;
    sed_reptr_t  *ptrend;
    sed_reptr_t  *rep;
    int          nrep;
    apr_pool_t   *pool;
    int          canbefinal;
};

typedef struct sed_eval_s sed_eval_t;

struct sed_eval_s {
    sed_err_fn_t   *errfn;
    sed_write_fn_t *writefn;
    void           *data;

    sed_commands_t *commands;

    apr_int64_t    lnum;
    void           *fout;

    unsigned       lsize;
    char           *linebuf;
    char           *lspend;

    unsigned       hsize;
    char           *holdbuf;
    char           *hspend;

    unsigned       gsize;
    char           *genbuf;
    char           *lcomend;

    apr_file_t    *fcode[NWFILES];
    sed_reptr_t    *abuf[SED_ABUFSIZE];
    sed_reptr_t    **aptr;
    sed_reptr_t    *pending;
    unsigned char  *inar;
    int            nrep;

    int            dolflag;
    int            sflag;
    int            jflag;
    int            delflag;
    int            lreadyflag;
    int            quitflag;
    int            finalflag;
    int            numpass;
    int            nullmatch;
    int            col;
    apr_pool_t     *pool;
};

apr_status_t sed_init_commands(sed_commands_t *commands, sed_err_fn_t *errfn, void *data,
                               apr_pool_t *p);
apr_status_t sed_compile_string(sed_commands_t *commands, const char *s);
apr_status_t sed_compile_file(sed_commands_t *commands, apr_file_t *fin);
char* sed_get_finalize_error(const sed_commands_t *commands, apr_pool_t* pool);
int sed_canbe_finalized(const sed_commands_t *commands);
void sed_destroy_commands(sed_commands_t *commands);

apr_status_t sed_init_eval(sed_eval_t *eval, sed_commands_t *commands,
                           sed_err_fn_t *errfn, void *data,
                           sed_write_fn_t *writefn, apr_pool_t *p);
apr_status_t sed_reset_eval(sed_eval_t *eval, sed_commands_t *commands, sed_err_fn_t *errfn, void *data);
apr_status_t sed_eval_buffer(sed_eval_t *eval, const char *buf, int bufsz, void *fout);
apr_status_t sed_eval_file(sed_eval_t *eval, apr_file_t *fin, void *fout);
apr_status_t sed_finalize_eval(sed_eval_t *eval, void *f);
void sed_destroy_eval(sed_eval_t *eval);

#ifdef __cplusplus
}
#endif

#endif /* LIBSED_H */
