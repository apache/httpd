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

#include "apr.h"
#include "apr_lib.h"
#include "libsed.h"
#include "sed.h"
#include "apr_strings.h"
#include "regexp.h"

static const char *const trans[040]  = {
    "\\01",
    "\\02",
    "\\03",
    "\\04",
    "\\05",
    "\\06",
    "\\07",
    "\\10",
    "\\11",
    "\n",
    "\\13",
    "\\14",
    "\\15",
    "\\16",
    "\\17",
    "\\20",
    "\\21",
    "\\22",
    "\\23",
    "\\24",
    "\\25",
    "\\26",
    "\\27",
    "\\30",
    "\\31",
    "\\32",
    "\\33",
    "\\34",
    "\\35",
    "\\36",
    "\\37"
};
static const char rub[] = {"\\177"};

extern int sed_step(char *p1, char *p2, int circf, step_vars_storage *vars);
static int substitute(sed_eval_t *eval, sed_reptr_t *ipc,
                      step_vars_storage *step_vars);
static apr_status_t execute(sed_eval_t *eval);
static int match(sed_eval_t *eval, char *expbuf, int gf,
                 step_vars_storage *step_vars);
static apr_status_t dosub(sed_eval_t *eval, char *rhsbuf, int n,
                          step_vars_storage *step_vars);
static char *place(sed_eval_t *eval, char *asp, char *al1, char *al2);
static apr_status_t command(sed_eval_t *eval, sed_reptr_t *ipc,
                            step_vars_storage *step_vars);
static apr_status_t wline(sed_eval_t *eval, char *buf, int sz);
static apr_status_t arout(sed_eval_t *eval);

static void eval_errf(sed_eval_t *eval, const char *fmt, ...)
{
    if (eval->errfn && eval->pool) {
        va_list args;
        const char* error;
        va_start(args, fmt);
        error = apr_pvsprintf(eval->pool, fmt, args);
        eval->errfn(eval->data, error);
        va_end(args);
    }
}

#define INIT_BUF_SIZE 1024

/*
 * grow_buffer
 */
static void grow_buffer(apr_pool_t *pool, char **buffer,
                        char **spend, unsigned int *cursize,
                        unsigned int newsize)
{
    char* newbuffer = NULL;
    int spendsize = 0;
    if (*cursize >= newsize)
        return;
    /* Avoid number of times realloc is called. It could cause huge memory
     * requirement if line size is huge e.g 2 MB */
    if (newsize < *cursize * 2) {
        newsize = *cursize * 2;
    }

    /* Align it to 4 KB boundary */
    newsize = (newsize  + ((1 << 12) - 1)) & ~((1 << 12) -1);
    newbuffer = apr_pcalloc(pool, newsize);
    if (*spend && *buffer && (*cursize > 0)) {
        spendsize = *spend - *buffer;
    }
    if ((*cursize > 0) && *buffer) {
        memcpy(newbuffer, *buffer, *cursize);
    }
    *buffer = newbuffer;
    *cursize = newsize;
    if (spend != buffer) {
        *spend = *buffer + spendsize;
    }
}

/*
 * grow_line_buffer
 */
static void grow_line_buffer(sed_eval_t *eval, int newsize)
{
    grow_buffer(eval->pool, &eval->linebuf, &eval->lspend,
                &eval->lsize, newsize);
}

/*
 * grow_hold_buffer
 */
static void grow_hold_buffer(sed_eval_t *eval, int newsize)
{
    grow_buffer(eval->pool, &eval->holdbuf, &eval->hspend,
                &eval->hsize, newsize);
}

/*
 * grow_gen_buffer
 */
static void grow_gen_buffer(sed_eval_t *eval, int newsize,
                            char **gspend)
{
    if (gspend == NULL) {
        gspend = &eval->genbuf;
    }
    grow_buffer(eval->pool, &eval->genbuf, gspend,
                &eval->gsize, newsize);
    eval->lcomend = &eval->genbuf[71];
}

/*
 * appendmem_to_linebuf
 */
static void appendmem_to_linebuf(sed_eval_t *eval, const char* sz, int len)
{
    unsigned int reqsize = (eval->lspend - eval->linebuf) + len;
    if (eval->lsize < reqsize) {
        grow_line_buffer(eval, reqsize);
    }
    memcpy(eval->lspend, sz, len);
    eval->lspend += len;
}

/*
 * append_to_linebuf
 */
static void append_to_linebuf(sed_eval_t *eval, const char* sz)
{
    int len = strlen(sz);
    /* Copy string including null character */
    appendmem_to_linebuf(eval, sz, len + 1);
    --eval->lspend; /* lspend will now point to NULL character */
}

/*
 * copy_to_linebuf
 */
static void copy_to_linebuf(sed_eval_t *eval, const char* sz)
{
    eval->lspend = eval->linebuf;
    append_to_linebuf(eval, sz);
}

/*
 * append_to_holdbuf
 */
static void append_to_holdbuf(sed_eval_t *eval, const char* sz)
{
    int len = strlen(sz);
    unsigned int reqsize = (eval->hspend - eval->holdbuf) + len + 1;
    if (eval->hsize <= reqsize) {
        grow_hold_buffer(eval, reqsize);
    }
    strcpy(eval->hspend, sz);
    /* hspend will now point to NULL character */
    eval->hspend += len;
}

/*
 * copy_to_holdbuf
 */
static void copy_to_holdbuf(sed_eval_t *eval, const char* sz)
{
    eval->hspend = eval->holdbuf;
    append_to_holdbuf(eval, sz);
}

/*
 * append_to_genbuf
 */
static void append_to_genbuf(sed_eval_t *eval, const char* sz, char **gspend)
{
    int len = strlen(sz);
    unsigned int reqsize = (*gspend - eval->genbuf) + len + 1;
    if (eval->gsize < reqsize) {
        grow_gen_buffer(eval, reqsize, gspend);
    }
    strcpy(*gspend, sz);
    /* *gspend will now point to NULL character */
    *gspend += len;
}

/*
 * copy_to_genbuf
 */
static void copy_to_genbuf(sed_eval_t *eval, const char* sz)
{
    int len = strlen(sz);
    unsigned int reqsize = len + 1;
    if (eval->gsize < reqsize) {
        grow_gen_buffer(eval, reqsize, NULL);
    }
}

/*
 * sed_init_eval
 */
apr_status_t sed_init_eval(sed_eval_t *eval, sed_commands_t *commands, sed_err_fn_t *errfn, void *data, sed_write_fn_t *writefn, apr_pool_t* p)
{
    memset(eval, 0, sizeof(*eval));
    eval->pool = p;
    eval->writefn = writefn;
    return sed_reset_eval(eval, commands, errfn, data);
}

/*
 * sed_reset_eval
 */
apr_status_t sed_reset_eval(sed_eval_t *eval, sed_commands_t *commands, sed_err_fn_t *errfn, void *data)
{
    int i;

    eval->errfn = errfn;
    eval->data = data;

    eval->commands = commands;

    eval->lnum = 0;
    eval->fout = NULL;

    if (eval->linebuf == NULL) {
        eval->lsize = INIT_BUF_SIZE;
        eval->linebuf = apr_pcalloc(eval->pool, eval->lsize);
    }
    if (eval->holdbuf == NULL) {
        eval->hsize = INIT_BUF_SIZE;
        eval->holdbuf = apr_pcalloc(eval->pool, eval->hsize);
    }
    if (eval->genbuf == NULL) {
        eval->gsize = INIT_BUF_SIZE;
        eval->genbuf = apr_pcalloc(eval->pool, eval->gsize);
    }
    eval->lspend = eval->linebuf;
    eval->hspend = eval->holdbuf;
    eval->lcomend = &eval->genbuf[71];

    for (i = 0; i < sizeof(eval->abuf) / sizeof(eval->abuf[0]); i++)
        eval->abuf[i] = NULL;
    eval->aptr = eval->abuf;
    eval->pending = NULL;
    eval->inar = apr_pcalloc(eval->pool, commands->nrep * sizeof(unsigned char));
    eval->nrep = commands->nrep;

    eval->dolflag = 0;
    eval->sflag = 0;
    eval->jflag = 0;
    eval->delflag = 0;
    eval->lreadyflag = 0;
    eval->quitflag = 0;
    eval->finalflag = 1; /* assume we're evaluating only one file/stream */
    eval->numpass = 0;
    eval->nullmatch = 0;
    eval->col = 0;

    for (i = 0; i < commands->nfiles; i++) {
        const char* filename = commands->fname[i];
        if (apr_file_open(&eval->fcode[i], filename,
                          APR_WRITE | APR_CREATE, APR_OS_DEFAULT,
                          eval->pool) != APR_SUCCESS) {
            eval_errf(eval, SEDERR_COMES, filename);
            return APR_EGENERAL;
        }
    }

    return APR_SUCCESS;
}

/*
 * sed_destroy_eval
 */
void sed_destroy_eval(sed_eval_t *eval)
{
    int i;
    /* eval->linebuf, eval->holdbuf, eval->genbuf and eval->inar are allocated
     * on pool. It will be freed when pool will be freed */
    for (i = 0; i < eval->commands->nfiles; i++) {
        if (eval->fcode[i] != NULL) {
            apr_file_close(eval->fcode[i]);
            eval->fcode[i] = NULL;
        }
    }
}

/*
 * sed_eval_file
 */
apr_status_t sed_eval_file(sed_eval_t *eval, apr_file_t *fin, void *fout)
{
    for (;;) {
        char buf[1024];
        apr_size_t read_bytes = 0;

        read_bytes = sizeof(buf);
        if (apr_file_read(fin, buf, &read_bytes) != APR_SUCCESS)
            break;

        if (sed_eval_buffer(eval, buf, read_bytes, fout) != APR_SUCCESS)
            return APR_EGENERAL;

        if (eval->quitflag)
            return APR_SUCCESS;
    }

    return sed_finalize_eval(eval, fout);
}

/*
 * sed_eval_buffer
 */
apr_status_t sed_eval_buffer(sed_eval_t *eval, const char *buf, int bufsz, void *fout)
{
    apr_status_t rv;

    if (eval->quitflag)
        return APR_SUCCESS;

    if (!sed_canbe_finalized(eval->commands)) {
        /* Commands were not finalized properly. */
        const char* error = sed_get_finalize_error(eval->commands, eval->pool);
        if (error) {
            eval_errf(eval, error);
            return APR_EGENERAL;
        }
    }

    eval->fout = fout;

    /* Process leftovers */
    if (bufsz && eval->lreadyflag) {
        eval->lreadyflag = 0;
        eval->lspend--;
        *eval->lspend = '\0';
        rv = execute(eval);
        if (rv != APR_SUCCESS)
            return rv;
    }

    while (bufsz) {
        char *n;
        int llen;

        n = memchr(buf, '\n', bufsz);
        if (n == NULL)
            break;

        llen = n - buf;
        if (llen == bufsz - 1) {
            /* This might be the last line; delay its processing */
            eval->lreadyflag = 1;
            break;
        }

        appendmem_to_linebuf(eval, buf, llen + 1);
        --eval->lspend;
        /* replace new line character with NULL */
        *eval->lspend = '\0';
        buf += (llen + 1);
        bufsz -= (llen + 1);
        rv = execute(eval);
        if (rv != APR_SUCCESS)
            return rv;
        if (eval->quitflag)
            break;
    }

    /* Save the leftovers for later */
    if (bufsz) {
        appendmem_to_linebuf(eval, buf, bufsz);
    }

    return APR_SUCCESS;
}

/*
 * sed_finalize_eval
 */
apr_status_t sed_finalize_eval(sed_eval_t *eval, void *fout)
{
    if (eval->quitflag)
        return APR_SUCCESS;

    if (eval->finalflag)
        eval->dolflag = 1;

    eval->fout = fout;

    /* Process leftovers */
    if (eval->lspend > eval->linebuf) {
        apr_status_t rv;

        if (eval->lreadyflag) {
            eval->lreadyflag = 0;
            eval->lspend--;
        } else {
            /* Code can probably reach here when last character in output
             * buffer is not a newline.
             */
            /* Assure space for NULL */
            append_to_linebuf(eval, "");
        }

        *eval->lspend = '\0';
        rv = execute(eval);
        if (rv != APR_SUCCESS)
            return rv;
    }

    eval->quitflag = 1;

    return APR_SUCCESS;
}

/*
 * execute
 */
static apr_status_t execute(sed_eval_t *eval)
{
    sed_reptr_t *ipc = eval->commands->ptrspace;
    step_vars_storage step_vars;
    apr_status_t rv = APR_SUCCESS;

    eval->lnum++;

    eval->sflag = 0;

    if (eval->pending) {
        ipc = eval->pending;
        eval->pending = NULL;
    }

    memset(&step_vars, 0, sizeof(step_vars));

    while (ipc->command) {
        char *p1;
        char *p2;
        int c;

        p1 = ipc->ad1;
        p2 = ipc->ad2;

        if (p1) {

            if (eval->inar[ipc->nrep]) {
                if (*p2 == CEND) {
                    p1 = 0;
                } else if (*p2 == CLNUM) {
                    c = (unsigned char)p2[1];
                    if (eval->lnum > eval->commands->tlno[c]) {
                        eval->inar[ipc->nrep] = 0;
                        if (ipc->negfl)
                            goto yes;
                        ipc = ipc->next;
                        continue;
                    }
                    if (eval->lnum == eval->commands->tlno[c]) {
                        eval->inar[ipc->nrep] = 0;
                    }
                } else if (match(eval, p2, 0, &step_vars)) {
                    eval->inar[ipc->nrep] = 0;
                }
            } else if (*p1 == CEND) {
                if (!eval->dolflag) {
                    if (ipc->negfl)
                        goto yes;
                    ipc = ipc->next;
                    continue;
                }
            } else if (*p1 == CLNUM) {
                c = (unsigned char)p1[1];
                if (eval->lnum != eval->commands->tlno[c]) {
                    if (ipc->negfl)
                        goto yes;
                    ipc = ipc->next;
                    continue;
                }
                if (p2)
                    eval->inar[ipc->nrep] = 1;
            } else if (match(eval, p1, 0, &step_vars)) {
                if (p2)
                    eval->inar[ipc->nrep] = 1;
            } else {
                if (ipc->negfl)
                    goto yes;
                ipc = ipc->next;
                continue;
            }
        }

        if (ipc->negfl) {
            ipc = ipc->next;
            continue;
        }

yes:
        rv = command(eval, ipc, &step_vars);
        if (rv != APR_SUCCESS)
            return rv;

        if (eval->quitflag)
            return APR_SUCCESS;

        if (eval->pending)
            return APR_SUCCESS;

        if (eval->delflag)
            break;

        if (eval->jflag) {
            eval->jflag = 0;
            if ((ipc = ipc->lb1) == 0) {
                ipc = eval->commands->ptrspace;
                break;
            }
        } else
            ipc = ipc->next;
    }

    if (!eval->commands->nflag && !eval->delflag) {
        rv = wline(eval, eval->linebuf, eval->lspend - eval->linebuf);
        if (rv != APR_SUCCESS)
            return rv;
    }

    if (eval->aptr > eval->abuf)
        rv = arout(eval);

    eval->delflag = 0;

    eval->lspend = eval->linebuf;

    return rv;
}

/*
 * match
 */
static int match(sed_eval_t *eval, char *expbuf, int gf,
                 step_vars_storage *step_vars)
{
    char   *p1;
    int circf;

    if(gf) {
        if(*expbuf)    return(0);
        step_vars->locs = p1 = step_vars->loc2;
    } else {
        p1 = eval->linebuf;
        step_vars->locs = 0;
    }

    circf = *expbuf++;
    return(sed_step(p1, expbuf, circf, step_vars));
}

/*
 * substitute
 */
static int substitute(sed_eval_t *eval, sed_reptr_t *ipc,
                      step_vars_storage *step_vars)
{
    if(match(eval, ipc->re1, 0, step_vars) == 0)    return(0);

    eval->numpass = 0;
    eval->sflag = 0;        /* Flags if any substitution was made */
    if (dosub(eval, ipc->rhs, ipc->gfl, step_vars) != APR_SUCCESS)
        return -1;

    if(ipc->gfl) {
        while(*step_vars->loc2) {
            if(match(eval, ipc->re1, 1, step_vars) == 0) break;
            if (dosub(eval, ipc->rhs, ipc->gfl, step_vars) != APR_SUCCESS)
                return -1;
        }
    }
    return(eval->sflag);
}

/*
 * dosub
 */
static apr_status_t dosub(sed_eval_t *eval, char *rhsbuf, int n,
                          step_vars_storage *step_vars)
{
    char *lp, *sp, *rp;
    int c;
    apr_status_t rv = APR_SUCCESS;

    if(n > 0 && n < 999) {
        eval->numpass++;
        if(n != eval->numpass) return APR_SUCCESS;
    }
    eval->sflag = 1;
    lp = eval->linebuf;
    sp = eval->genbuf;
    rp = rhsbuf;
    sp = place(eval, sp, lp, step_vars->loc1);
    while ((c = *rp++) != 0) {
        if (c == '&') {
            sp = place(eval, sp, step_vars->loc1, step_vars->loc2);
            if (sp == NULL)
                return APR_EGENERAL;
        }
        else if (c == '\\') {
            c = *rp++;
            if (c >= '1' && c < NBRA+'1') {
                sp = place(eval, sp, step_vars->braslist[c-'1'],
                           step_vars->braelist[c-'1']);
                if (sp == NULL)
                    return APR_EGENERAL;
            }
            else
                *sp++ = c;
          } else
            *sp++ = c;
        if (sp >= eval->genbuf + eval->gsize) {
            /* expand genbuf and set the sp appropriately */
            grow_gen_buffer(eval, eval->gsize + 1024, &sp);
        }
    }
    lp = step_vars->loc2;
    step_vars->loc2 = sp - eval->genbuf + eval->linebuf;
    append_to_genbuf(eval, lp, &sp);
    copy_to_linebuf(eval, eval->genbuf);
    return rv;
}

/*
 * place
 */
static char *place(sed_eval_t *eval, char *asp, char *al1, char *al2)
{
    char *sp = asp;
    int n = al2 - al1;
    unsigned int reqsize = (sp - eval->genbuf) + n + 1;

    if (eval->gsize < reqsize) {
        grow_gen_buffer(eval, reqsize, &sp);
    }
    memcpy(sp, al1, n);
    return sp + n;
}

/*
 * command
 */
static apr_status_t command(sed_eval_t *eval, sed_reptr_t *ipc,
                            step_vars_storage *step_vars)
{
    int    i;
    char   *p1, *p2;
    const char *p3;
    int length;
    char sz[32]; /* 32 bytes enough to store 64 bit integer in decimal */
    apr_status_t rv = APR_SUCCESS;


    switch(ipc->command) {

        case ACOM:
            if(eval->aptr >= &eval->abuf[SED_ABUFSIZE]) {
                eval_errf(eval, SEDERR_TMAMES, eval->lnum);
            } else {
                *eval->aptr++ = ipc;
                *eval->aptr = NULL;
            }
            break;

        case CCOM:
            eval->delflag = 1;
            if(!eval->inar[ipc->nrep] || eval->dolflag) {
                for (p1 = ipc->re1; *p1; p1++)
                    ;
                rv = wline(eval, ipc->re1, p1 - ipc->re1);
            }
            break;
        case DCOM:
            eval->delflag++;
            break;
        case CDCOM:
            p1 = eval->linebuf;

            while(*p1 != '\n') {
                if(*p1++ == 0) {
                    eval->delflag++;
                    return APR_SUCCESS;
                }
            }

            p1++;
            copy_to_linebuf(eval, p1);
            eval->jflag++;
            break;

        case EQCOM:
            length = apr_snprintf(sz, sizeof(sz), "%d", (int) eval->lnum);
            rv = wline(eval, sz, length);
            break;

        case GCOM:
            copy_to_linebuf(eval, eval->holdbuf);
            break;

        case CGCOM:
            append_to_linebuf(eval, "\n");
            append_to_linebuf(eval, eval->holdbuf);
            break;

        case HCOM:
            copy_to_holdbuf(eval, eval->linebuf);
            break;

        case CHCOM:
            append_to_holdbuf(eval, "\n");
            append_to_holdbuf(eval, eval->linebuf);
            break;

        case ICOM:
            for (p1 = ipc->re1; *p1; p1++);
            rv = wline(eval, ipc->re1, p1 - ipc->re1);
            break;

        case BCOM:
            eval->jflag = 1;
            break;


        case LCOM:
            p1 = eval->linebuf;
            p2 = eval->genbuf;
            eval->genbuf[72] = 0;
            while(*p1)
                if((unsigned char)*p1 >= 040) {
                    if(*p1 == 0177) {
                        p3 = rub;
                        while ((*p2++ = *p3++) != 0)
                            if(p2 >= eval->lcomend) {
                                *p2 = '\\';
                                rv = wline(eval, eval->genbuf,
                                           strlen(eval->genbuf));
                                if (rv != APR_SUCCESS)
                                    return rv;
                                p2 = eval->genbuf;
                            }
                        p2--;
                        p1++;
                        continue;
                    }
                    if(!isprint(*p1 & 0377)) {
                        *p2++ = '\\';
                        if(p2 >= eval->lcomend) {
                            *p2 = '\\';
                            rv = wline(eval, eval->genbuf,
                                       strlen(eval->genbuf));
                            if (rv != APR_SUCCESS)
                                return rv;
                            p2 = eval->genbuf;
                        }
                        *p2++ = (*p1 >> 6) + '0';
                        if(p2 >= eval->lcomend) {
                            *p2 = '\\';
                            rv = wline(eval, eval->genbuf,
                                       strlen(eval->genbuf));
                            if (rv != APR_SUCCESS)
                                return rv;
                            p2 = eval->genbuf;
                        }
                        *p2++ = ((*p1 >> 3) & 07) + '0';
                        if(p2 >= eval->lcomend) {
                            *p2 = '\\';
                            rv = wline(eval, eval->genbuf,
                                       strlen(eval->genbuf));
                            if (rv != APR_SUCCESS)
                                return rv;
                            p2 = eval->genbuf;
                        }
                        *p2++ = (*p1++ & 07) + '0';
                        if(p2 >= eval->lcomend) {
                            *p2 = '\\';
                            rv = wline(eval, eval->genbuf,
                                       strlen(eval->genbuf));
                            if (rv != APR_SUCCESS)
                                return rv;
                            p2 = eval->genbuf;
                        }
                    } else {
                        *p2++ = *p1++;
                        if(p2 >= eval->lcomend) {
                            *p2 = '\\';
                            rv = wline(eval, eval->genbuf,
                                       strlen(eval->genbuf));
                            if (rv != APR_SUCCESS)
                                return rv;
                            p2 = eval->genbuf;
                        }
                    }
                } else {
                    p3 = trans[(unsigned char)*p1-1];
                    while ((*p2++ = *p3++) != 0)
                        if(p2 >= eval->lcomend) {
                            *p2 = '\\';
                            rv = wline(eval, eval->genbuf,
                                       strlen(eval->genbuf));
                            if (rv != APR_SUCCESS)
                                return rv;
                            p2 = eval->genbuf;
                        }
                    p2--;
                    p1++;
                }
            *p2 = 0;
            rv = wline(eval, eval->genbuf, strlen(eval->genbuf));
            break;

        case NCOM:
            if(!eval->commands->nflag) {
                rv = wline(eval, eval->linebuf, eval->lspend - eval->linebuf);
                if (rv != APR_SUCCESS)
                    return rv;
            }

            if(eval->aptr > eval->abuf) {
                rv = arout(eval);
                if (rv != APR_SUCCESS)
                    return rv;
            }
            eval->lspend = eval->linebuf;
            eval->pending = ipc->next;

            break;
        case CNCOM:
            if(eval->aptr > eval->abuf) {
                rv = arout(eval);
                if (rv != APR_SUCCESS)
                    return rv;
            }
            append_to_linebuf(eval, "\n");
            eval->pending = ipc->next;
            break;

        case PCOM:
            rv = wline(eval, eval->linebuf, eval->lspend - eval->linebuf);
            break;
        case CPCOM:
            for (p1 = eval->linebuf; *p1 != '\n' && *p1 != '\0'; p1++);
            rv = wline(eval, eval->linebuf, p1 - eval->linebuf);
            break;

        case QCOM:
            if (!eval->commands->nflag) {
                rv = wline(eval, eval->linebuf, eval->lspend - eval->linebuf);
                if (rv != APR_SUCCESS)
                    break;
            }

            if(eval->aptr > eval->abuf) {
                rv = arout(eval);
                if (rv != APR_SUCCESS)
                    return rv;
            }

            eval->quitflag = 1;
            break;
        case RCOM:
            if(eval->aptr >= &eval->abuf[SED_ABUFSIZE]) {
                eval_errf(eval, SEDERR_TMRMES, eval->lnum);
            } else {
                *eval->aptr++ = ipc;
                *eval->aptr = NULL;
            }
            break;

        case SCOM:
            i = substitute(eval, ipc, step_vars);
            if (i == -1) {
                return APR_EGENERAL;
            }
            if(ipc->pfl && eval->commands->nflag && i) {
                if(ipc->pfl == 1) {
                    rv = wline(eval, eval->linebuf, eval->lspend -
                               eval->linebuf);
                    if (rv != APR_SUCCESS)
                        return rv;
                } else {
                    for (p1 = eval->linebuf; *p1 != '\n' && *p1 != '\0'; p1++);
                    rv = wline(eval, eval->linebuf, p1 - eval->linebuf);
                    if (rv != APR_SUCCESS)
                        return rv;
                }
            }
            if (i && (ipc->findex >= 0) && eval->fcode[ipc->findex])
                apr_file_printf(eval->fcode[ipc->findex], "%s\n",
                                eval->linebuf);
            break;

        case TCOM:
            if(eval->sflag == 0)  break;
            eval->sflag = 0;
            eval->jflag = 1;
            break;

        case WCOM:
            if (ipc->findex >= 0)
                apr_file_printf(eval->fcode[ipc->findex], "%s\n",
                                eval->linebuf);
            break;
        case XCOM:
            copy_to_genbuf(eval, eval->linebuf);
            copy_to_linebuf(eval, eval->holdbuf);
            copy_to_holdbuf(eval, eval->genbuf);
            break;

        case YCOM:
            p1 = eval->linebuf;
            p2 = ipc->re1;
            while((*p1 = p2[(unsigned char)*p1]) != 0)    p1++;
            break;
    }
    return rv;
}

/*
 * arout
 */
static apr_status_t arout(sed_eval_t *eval)
{
    apr_status_t rv = APR_SUCCESS;
    eval->aptr = eval->abuf - 1;
    while (*++eval->aptr) {
        if ((*eval->aptr)->command == ACOM) {
            char *p1;

            for (p1 = (*eval->aptr)->re1; *p1; p1++);
            rv = wline(eval, (*eval->aptr)->re1, p1 - (*eval->aptr)->re1);
            if (rv != APR_SUCCESS)
                return rv;
        } else {
            apr_file_t *fi = NULL;
            char buf[512];
            apr_size_t n = sizeof(buf);

            if (apr_file_open(&fi, (*eval->aptr)->re1, APR_READ, 0, eval->pool)
                              != APR_SUCCESS)
                continue;
            while ((apr_file_read(fi, buf, &n)) == APR_SUCCESS) {
                if (n == 0)
                    break;
                rv = eval->writefn(eval->fout, buf, n);
                if (rv != APR_SUCCESS) {
                    apr_file_close(fi);
                    return rv;
                }
                n = sizeof(buf);
            }
            apr_file_close(fi);
        }
    }
    eval->aptr = eval->abuf;
    *eval->aptr = NULL;
    return rv;
}

/*
 * wline
 */
static apr_status_t wline(sed_eval_t *eval, char *buf, int sz)
{
    apr_status_t rv = APR_SUCCESS;
    rv = eval->writefn(eval->fout, buf, sz);
    if (rv != APR_SUCCESS)
        return rv;
    rv = eval->writefn(eval->fout, "\n", 1);
    return rv;
}

