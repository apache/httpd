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
#include "apr_strings.h"
#include "libsed.h"
#include "sed.h"
#include "regexp.h"

#define CCEOF 22

static int fcomp(sed_commands_t *commands, apr_file_t *fin);
static char *compsub(sed_commands_t *commands,
                     sed_comp_args *compargs, char *rhsbuf);
static int rline(sed_commands_t *commands, apr_file_t *fin,
                 char *lbuf, char *lbend);
static char *address(sed_commands_t *commands, char *expbuf,
                     apr_status_t* status);
static char *text(sed_commands_t *commands, char *textbuf, char *endbuf);
static sed_label_t *search(sed_commands_t *commands);
static char *ycomp(sed_commands_t *commands, char *expbuf);
static char *comple(sed_commands_t *commands, sed_comp_args *compargs,
                    char *x1, char *ep, char *x3, char x4);
static sed_reptr_t *alloc_reptr(sed_commands_t *commands);
static int check_finalized(const sed_commands_t *commands);

void command_errf(sed_commands_t *commands, const char *fmt, ...)
{
    if (commands->errfn && commands->pool) {
        va_list args;
        const char* error;
        va_start(args, fmt);
        error = apr_pvsprintf(commands->pool, fmt, args);
        commands->errfn(commands->data, error);
        va_end(args);
    }
}

/*
 * sed_init_commands
 */
apr_status_t sed_init_commands(sed_commands_t *commands, sed_err_fn_t *errfn, void *data,
                               apr_pool_t *p)
{
    memset(commands, 0, sizeof(*commands));

    commands->errfn = errfn;
    commands->data = data;

    commands->labtab = commands->ltab;
    commands->lab = commands->labtab + 1;
    commands->pool = p;

    commands->respace = apr_pcalloc(p, RESIZE);
    if (commands->respace == NULL) {
        command_errf(commands, SEDERR_OOMMES);
        return APR_EGENERAL;
    }

    commands->rep = alloc_reptr(commands);
    if (commands->rep == NULL)
        return APR_EGENERAL;

    commands->rep->ad1 = commands->respace;
    commands->reend = &commands->respace[RESIZE - 1];
    commands->labend = &commands->labtab[SED_LABSIZE];
    commands->canbefinal = 1;

    return APR_SUCCESS;
}

/*
 * sed_destroy_commands
 */
void sed_destroy_commands(sed_commands_t *commands)
{
}

/*
 * sed_compile_string
 */
apr_status_t sed_compile_string(sed_commands_t *commands, const char *s)
{
    apr_status_t rv;

    commands->earg = s;
    commands->eflag = 1;

    rv = fcomp(commands, NULL);
    if (rv == APR_SUCCESS)
        commands->canbefinal = check_finalized(commands);

    commands->eflag = 0;

    return (rv != 0 ? APR_EGENERAL : APR_SUCCESS);
}

/*
 * sed_compile_file
 */
apr_status_t sed_compile_file(sed_commands_t *commands, apr_file_t *fin)
{
    apr_status_t rv = fcomp(commands, fin);
    return (rv != 0 ? APR_EGENERAL : APR_SUCCESS);
}

/*
 * sed_get_finalize_error
 */
char* sed_get_finalize_error(const sed_commands_t *commands, apr_pool_t* pool)
{
    const sed_label_t *lab;
    if (commands->depth) {
        return SEDERR_TMOMES;
    }

    /* Empty branch chain is not a issue */
    for (lab = commands->labtab + 1; lab < commands->lab; lab++) {
        char *error;
        if (lab->address == 0) {
            error = apr_psprintf(pool, SEDERR_ULMES, lab->asc);
            return error;
        }

        if (lab->chain) {
            return SEDERR_INTERNAL;
        }
    }
    return NULL;
}

/*
 * sed_canbe_finalized
 */
int sed_canbe_finalized(const sed_commands_t *commands)
{
    return commands->canbefinal;
}

/*
 * check_finalized
 */
static int check_finalized(const sed_commands_t *commands)
{
    const sed_label_t *lab;
    if (commands->depth) {
        return 0;
    }

    /* Empty branch chain is not a issue */
    for (lab = commands->labtab + 1; lab < commands->lab; lab++) {
        if (lab->address == 0 || (lab->chain)) {
            return 0;
        }
    }
    return 1;
}

/*
 * dechain
 */
static void dechain(sed_label_t *lpt, sed_reptr_t *address)
{
    sed_reptr_t *rep;
    if ((lpt == NULL) || (lpt->chain == NULL) || (address == NULL))
        return;
    rep = lpt->chain;
    while (rep->lb1) {
        sed_reptr_t *next;

        next = rep->lb1;
        rep->lb1 = address;
        rep = next;
    }
    rep->lb1 = address;
    lpt->chain = NULL;
}

/*
 * fcomp
 */
static int fcomp(sed_commands_t *commands, apr_file_t *fin)
{
    char *p, *op, *tp;
    sed_reptr_t *pt, *pt1;
    int i, ii;
    sed_label_t *lpt;
    char fnamebuf[APR_PATH_MAX];
    apr_status_t status;
    sed_comp_args compargs;

    op = commands->lastre;
    if (!commands->linebuf) {
        commands->linebuf = apr_pcalloc(commands->pool, LBSIZE + 1);
    }

    if (rline(commands, fin, commands->linebuf,
              (commands->linebuf + LBSIZE + 1)) < 0)
        return 0;
    if (*commands->linebuf == '#') {
        if (commands->linebuf[1] == 'n')
            commands->nflag = 1;
    }
    else {
        commands->cp = commands->linebuf;
        goto comploop;
    }

    for (;;) {
        if (rline(commands, fin, commands->linebuf,
                  (commands->linebuf + LBSIZE + 1)) < 0)
            break;

        commands->cp = commands->linebuf;

comploop:
        while (*commands->cp == ' ' || *commands->cp == '\t')
            commands->cp++;
        if (*commands->cp == '\0' || *commands->cp == '#')
            continue;
        if (*commands->cp == ';') {
            commands->cp++;
            goto comploop;
        }

        p = address(commands, commands->rep->ad1, &status);
        if (status != APR_SUCCESS) {
            command_errf(commands, SEDERR_CGMES, commands->linebuf);
            return -1;
        }

        if (p == commands->rep->ad1) {
            if (op)
                commands->rep->ad1 = op;
            else {
                command_errf(commands, SEDERR_NRMES);
                return -1;
            }
        } else if (p == 0) {
            p = commands->rep->ad1;
            commands->rep->ad1 = 0;
        } else {
            op = commands->rep->ad1;
            if (*commands->cp == ',' || *commands->cp == ';') {
                commands->cp++;
                commands->rep->ad2 = p;
                p = address(commands, commands->rep->ad2, &status);
                if ((status != APR_SUCCESS) || (p == 0)) {
                    command_errf(commands, SEDERR_CGMES, commands->linebuf);
                    return -1;
                }
                if (p == commands->rep->ad2)
                    commands->rep->ad2 = op;
                else
                    op = commands->rep->ad2;
            } else
                commands->rep->ad2 = 0;
        }

        if(p > &commands->respace[RESIZE-1]) {
            command_errf(commands, SEDERR_TMMES, commands->linebuf);
            return -1;
        }

        while (*commands->cp == ' ' || *commands->cp == '\t')
            commands->cp++;

swit:
        switch(*commands->cp++) {
        default:
            command_errf(commands, SEDERR_UCMES, commands->linebuf);
            return -1;

        case '!':
            commands->rep->negfl = 1;
            goto swit;

        case '{':
            commands->rep->command = BCOM;
            commands->rep->negfl = !(commands->rep->negfl);
            commands->cmpend[commands->depth++] = &commands->rep->lb1;
            commands->rep = alloc_reptr(commands);
            commands->rep->ad1 = p;
            if (*commands->cp == '\0')
                continue;
            goto comploop;

        case '}':
            if (commands->rep->ad1) {
                command_errf(commands, SEDERR_AD0MES, commands->linebuf);
                return -1;
            }

            if (--commands->depth < 0) {
                command_errf(commands, SEDERR_TMCMES);
                return -1;
            }
            *commands->cmpend[commands->depth] = commands->rep;

            commands->rep->ad1 = p;
            continue;

        case '=':
            commands->rep->command = EQCOM;
            if (commands->rep->ad2) {
                command_errf(commands, SEDERR_AD1MES, commands->linebuf);
                return -1;
            }
            break;

        case ':':
            if (commands->rep->ad1) {
                command_errf(commands, SEDERR_AD0MES, commands->linebuf);
                return -1;
            }

            while (*commands->cp++ == ' ');
            commands->cp--;

            tp = commands->lab->asc;
            while ((*tp++ = *commands->cp++)) {
                if (tp >= &(commands->lab->asc[8])) {
                    command_errf(commands, SEDERR_LTLMES, commands->linebuf);
                    return -1;
                }
            }
            *--tp = '\0';

            if ((lpt = search(commands)) != NULL) {
                if (lpt->address) {
                    command_errf(commands, SEDERR_DLMES, commands->linebuf);
                    return -1;
                }
                dechain(lpt, commands->rep);
            } else {
                commands->lab->chain = 0;
                lpt = commands->lab;
                if (++commands->lab >= commands->labend) {
                    command_errf(commands, SEDERR_TMLMES, commands->linebuf);
                    return -1;
                }
            }
            lpt->address = commands->rep;
            commands->rep->ad1 = p;

            continue;

        case 'a':
            commands->rep->command = ACOM;
            if (commands->rep->ad2) {
                command_errf(commands, SEDERR_AD1MES, commands->linebuf);
                return -1;
            }
            if (*commands->cp == '\\')
                commands->cp++;
            if (*commands->cp++ != '\n') {
                command_errf(commands, SEDERR_CGMES, commands->linebuf);
                return -1;
            }
            commands->rep->re1 = p;
            p = text(commands, commands->rep->re1, commands->reend);
            if (p == NULL)
                return -1;
            break;

        case 'c':
            commands->rep->command = CCOM;
            if (*commands->cp == '\\') commands->cp++;
            if (*commands->cp++ != ('\n')) {
                command_errf(commands, SEDERR_CGMES, commands->linebuf);
                return -1;
            }
            commands->rep->re1 = p;
            p = text(commands, commands->rep->re1, commands->reend);
            if (p == NULL)
                return -1;
            break;

        case 'i':
            commands->rep->command = ICOM;
            if (commands->rep->ad2) {
                command_errf(commands, SEDERR_AD1MES, commands->linebuf);
                return -1;
            }
            if (*commands->cp == '\\') commands->cp++;
            if (*commands->cp++ != ('\n')) {
                command_errf(commands, SEDERR_CGMES, commands->linebuf);
                return -1;
            }
            commands->rep->re1 = p;
            p = text(commands, commands->rep->re1, commands->reend);
            if (p == NULL)
                return -1;
            break;

        case 'g':
            commands->rep->command = GCOM;
            break;

        case 'G':
            commands->rep->command = CGCOM;
            break;

        case 'h':
            commands->rep->command = HCOM;
            break;

        case 'H':
            commands->rep->command = CHCOM;
            break;

        case 't':
            commands->rep->command = TCOM;
            goto jtcommon;

        case 'b':
            commands->rep->command = BCOM;
jtcommon:
            while (*commands->cp++ == ' ');
            commands->cp--;

            if (*commands->cp == '\0') {
                if ((pt = commands->labtab->chain) != NULL) {
                    while ((pt1 = pt->lb1) != NULL)
                        pt = pt1;
                    pt->lb1 = commands->rep;
                } else
                    commands->labtab->chain = commands->rep;
                break;
            }
            tp = commands->lab->asc;
            while ((*tp++ = *commands->cp++))
                if (tp >= &(commands->lab->asc[8])) {
                    command_errf(commands, SEDERR_LTLMES, commands->linebuf);
                    return -1;
                }
            commands->cp--;
            *--tp = '\0';

            if ((lpt = search(commands)) != NULL) {
                if (lpt->address) {
                    commands->rep->lb1 = lpt->address;
                } else {
                    pt = lpt->chain;
                    while ((pt1 = pt->lb1) != NULL)
                        pt = pt1;
                    pt->lb1 = commands->rep;
                }
            } else {
                commands->lab->chain = commands->rep;
                commands->lab->address = 0;
                if (++commands->lab >= commands->labend) {
                    command_errf(commands, SEDERR_TMLMES, commands->linebuf);
                    return -1;
                }
            }
            break;

        case 'n':
            commands->rep->command = NCOM;
            break;

        case 'N':
            commands->rep->command = CNCOM;
            break;

        case 'p':
            commands->rep->command = PCOM;
            break;

        case 'P':
            commands->rep->command = CPCOM;
            break;

        case 'r':
            commands->rep->command = RCOM;
            if (commands->rep->ad2) {
                command_errf(commands, SEDERR_AD1MES, commands->linebuf);
                return -1;
            }
            if (*commands->cp++ != ' ') {
                command_errf(commands, SEDERR_CGMES, commands->linebuf);
                return -1;
            }
            commands->rep->re1 = p;
            p = text(commands, commands->rep->re1, commands->reend);
            if (p == NULL)
                return -1;
            break;

        case 'd':
            commands->rep->command = DCOM;
            break;

        case 'D':
            commands->rep->command = CDCOM;
            commands->rep->lb1 = commands->ptrspace;
            break;

        case 'q':
            commands->rep->command = QCOM;
            if (commands->rep->ad2) {
                command_errf(commands, SEDERR_AD1MES, commands->linebuf);
                return -1;
            }
            break;

        case 'l':
            commands->rep->command = LCOM;
            break;

        case 's':
            commands->rep->command = SCOM;
            commands->sseof = *commands->cp++;
            commands->rep->re1 = p;
            p = comple(commands, &compargs, (char *) 0, commands->rep->re1,
                       commands->reend, commands->sseof);
            if (p == NULL)
                return -1;
            if (p == commands->rep->re1) {
                if (op)
                    commands->rep->re1 = op;
                else {
                    command_errf(commands, SEDERR_NRMES);
                    return -1;
                }
            } else
                op = commands->rep->re1;
            commands->rep->rhs = p;

            p = compsub(commands, &compargs, commands->rep->rhs);
            if ((p) == NULL)
                return -1;

            if (*commands->cp == 'g') {
                commands->cp++;
                commands->rep->gfl = 999;
            } else if (commands->gflag)
                commands->rep->gfl = 999;

            if (*commands->cp >= '1' && *commands->cp <= '9') {
                i = *commands->cp - '0';
                commands->cp++;
                while (1) {
                    ii = *commands->cp;
                    if (ii < '0' || ii > '9')
                        break;
                    i = i*10 + ii - '0';
                    if (i > 512) {
                        command_errf(commands, SEDERR_TOOBIG, commands->linebuf);
                        return -1;
                    }
                    commands->cp++;
                }
                commands->rep->gfl = i;
            }

            if (*commands->cp == 'p') {
                commands->cp++;
                commands->rep->pfl = 1;
            }

            if (*commands->cp == 'P') {
                commands->cp++;
                commands->rep->pfl = 2;
            }

            if (*commands->cp == 'w') {
                commands->cp++;
                if (*commands->cp++ !=  ' ') {
                    command_errf(commands, SEDERR_SMMES, commands->linebuf);
                    return -1;
                }
                if (text(commands, fnamebuf, &fnamebuf[APR_PATH_MAX]) == NULL) {
                    command_errf(commands, SEDERR_FNTL, commands->linebuf);
                    return -1;
                }
                for (i = commands->nfiles - 1; i >= 0; i--)
                    if (strcmp(fnamebuf,commands->fname[i]) == 0) {
                        commands->rep->findex = i;
                        goto done;
                    }
                if (commands->nfiles >= NWFILES) {
                    command_errf(commands, SEDERR_TMWFMES);
                    return -1;
                }
                commands->fname[commands->nfiles] =
                            apr_pstrdup(commands->pool, fnamebuf);
                if (commands->fname[commands->nfiles] == NULL) {
                    command_errf(commands, SEDERR_OOMMES);
                    return -1;
                }
                commands->rep->findex = commands->nfiles++;
            }
            break;

        case 'w':
            commands->rep->command = WCOM;
            if (*commands->cp++ != ' ') {
                command_errf(commands, SEDERR_SMMES, commands->linebuf);
                return -1;
            }
            if (text(commands, fnamebuf, &fnamebuf[APR_PATH_MAX]) == NULL) {
                command_errf(commands, SEDERR_FNTL, commands->linebuf);
                return -1;
            }
            for (i = commands->nfiles - 1; i >= 0; i--)
                if (strcmp(fnamebuf, commands->fname[i]) == 0) {
                    commands->rep->findex = i;
                    goto done;
                }
            if (commands->nfiles >= NWFILES) {
                command_errf(commands, SEDERR_TMWFMES);
                return -1;
            }
            if ((commands->fname[commands->nfiles] =
                        apr_pstrdup(commands->pool, fnamebuf)) == NULL) {
                command_errf(commands, SEDERR_OOMMES);
                return -1;
            }

            commands->rep->findex = commands->nfiles++;
            break;

        case 'x':
            commands->rep->command = XCOM;
            break;

        case 'y':
            commands->rep->command = YCOM;
            commands->sseof = *commands->cp++;
            commands->rep->re1 = p;
            p = ycomp(commands, commands->rep->re1);
            if (p == NULL)
                return -1;
            break;
        }
done:
        commands->rep = alloc_reptr(commands);

        commands->rep->ad1 = p;

        if (*commands->cp++ != '\0') {
            if (commands->cp[-1] == ';')
                goto comploop;
            command_errf(commands, SEDERR_CGMES, commands->linebuf);
            return -1;
        }
    }
    commands->rep->command = 0;
    commands->lastre = op;

    return 0;
}

static char *compsub(sed_commands_t *commands,
                     sed_comp_args *compargs, char *rhsbuf)
{
    char   *p, *q;

    p = rhsbuf;
    q = commands->cp;
    for(;;) {
        if(p > &commands->respace[RESIZE-1]) {
            command_errf(commands, SEDERR_TMMES, commands->linebuf);
            return NULL;
        }
        if((*p = *q++) == '\\') {
            p++;
            if(p > &commands->respace[RESIZE-1]) {
                command_errf(commands, SEDERR_TMMES, commands->linebuf);
                return NULL;
            }
            *p = *q++;
            if(*p > compargs->nbra + '0' && *p <= '9') {
                command_errf(commands, SEDERR_DOORNG, commands->linebuf);
                return NULL;
            }
            p++;
            continue;
        }
        if(*p == commands->sseof) {
            *p++ = '\0';
            commands->cp = q;
            return(p);
        }
          if(*p++ == '\0') {
            command_errf(commands, SEDERR_EDMOSUB, commands->linebuf);
            return NULL;
        }
    }
}

/*
 * rline
 */
static int rline(sed_commands_t *commands, apr_file_t *fin,
                 char *lbuf, char *lbend)
{
    char   *p;
    const char *q;
    int    t;
    apr_size_t bytes_read;

    p = lbuf;

    if(commands->eflag) {
        if(commands->eflag > 0) {
            commands->eflag = -1;
            q = commands->earg;
            while((t = *q++) != '\0') {
                if(t == '\n') {
                    commands->saveq = q;
                    goto out1;
                }
                if (p < lbend)
                    *p++ = t;
                if(t == '\\') {
                    if((t = *q++) == '\0') {
                        commands->saveq = NULL;
                        return(-1);
                    }
                    if (p < lbend)
                        *p++ = t;
                }
            }
            commands->saveq = NULL;

        out1:
            if (p == lbend) {
                command_errf(commands, SEDERR_CLTL);
                return -1;
            }
            *p = '\0';
            return(1);
        }
        if((q = commands->saveq) == 0)    return(-1);

        while((t = *q++) != '\0') {
            if(t == '\n') {
                commands->saveq = q;
                goto out2;
            }
            if(p < lbend)
                *p++ = t;
            if(t == '\\') {
                if((t = *q++) == '\0') {
                    commands->saveq = NULL;
                    return(-1);
                }
                if (p < lbend)
                    *p++ = t;
            }
        }
        commands->saveq = NULL;

    out2:
        if (p == lbend) {
            command_errf(commands, SEDERR_CLTL);
            return -1;
        }
        *p = '\0';
        return(1);
    }

    bytes_read = 1;
    /* XXX extremely inefficient 1 byte reads */
    while (apr_file_read(fin, &t, &bytes_read) != APR_SUCCESS) {
        if(t == '\n') {
            if (p == lbend) {
                command_errf(commands, SEDERR_CLTL);
                return -1;
            }
            *p = '\0';
            return(1);
        }
        if (p < lbend)
            *p++ = t;
        if(t == '\\') {
            bytes_read = 1;
            if (apr_file_read(fin, &t, &bytes_read) != APR_SUCCESS) {
                return -1;
            }
            if(p < lbend)
                *p++ = t;
        }
        bytes_read = 1;
    }
    return(-1);
}

/*
 * address
 */
static char *address(sed_commands_t *commands, char *expbuf,
                     apr_status_t* status)
{
    char   *rcp;
    apr_int64_t lno;
    sed_comp_args compargs;

    *status = APR_SUCCESS;
    if(*commands->cp == '$') {
        if (expbuf > &commands->respace[RESIZE-2]) {
            command_errf(commands, SEDERR_TMMES, commands->linebuf);
            *status = APR_EGENERAL;
            return NULL;
        }
        commands->cp++;
        *expbuf++ = CEND;
        *expbuf++ = CCEOF;
        return(expbuf);
    }
    if (*commands->cp == '/' || *commands->cp == '\\' ) {
        if ( *commands->cp == '\\' )
            commands->cp++;
        commands->sseof = *commands->cp++;
        return(comple(commands, &compargs, (char *) 0, expbuf, commands->reend,
                      commands->sseof));
    }

    rcp = commands->cp;
    lno = 0;

    while(*rcp >= '0' && *rcp <= '9')
        lno = lno*10 + *rcp++ - '0';

    if(rcp > commands->cp) {
        if (expbuf > &commands->respace[RESIZE-3]) {
            command_errf(commands, SEDERR_TMMES, commands->linebuf);
            *status = APR_EGENERAL;
            return NULL;
        }
        *expbuf++ = CLNUM;
        *expbuf++ = commands->nlno;
        commands->tlno[commands->nlno++] = lno;
        if(commands->nlno >= SED_NLINES) {
            command_errf(commands, SEDERR_TMLNMES);
            *status = APR_EGENERAL;
            return NULL;
        }
        *expbuf++ = CCEOF;
        commands->cp = rcp;
        return(expbuf);
    }
    return(NULL);
}

/*
 * text
 */
static char *text(sed_commands_t *commands, char *textbuf, char *tbend)
{
    char   *p, *q;

    p = textbuf;
    q = commands->cp;
#ifndef S5EMUL
    /*
     * Strip off indentation from text to be inserted.
     */
    while(*q == '\t' || *q == ' ')    q++;
#endif
    for(;;) {

        if(p > tbend)
            return(NULL);    /* overflowed the buffer */
        if((*p = *q++) == '\\')
            *p = *q++;
        if(*p == '\0') {
            commands->cp = --q;
            return(++p);
        }
#ifndef S5EMUL
        /*
         * Strip off indentation from text to be inserted.
         */
        if(*p == '\n') {
            while(*q == '\t' || *q == ' ')    q++;
        }
#endif
        p++;
    }
}


/*
 * search
 */
static sed_label_t *search(sed_commands_t *commands)
{
    sed_label_t *rp;
    sed_label_t *ptr;

    rp = commands->labtab;
    ptr = commands->lab;
    while (rp < ptr) {
        if (strcmp(rp->asc, ptr->asc) == 0)
            return rp;
        rp++;
    }

    return 0;
}

/*
 * ycomp
 */
static char *ycomp(sed_commands_t *commands, char *expbuf)
{
    char    c;
    int cint; /* integer value of char c */
    char *ep, *tsp;
    int i;
    char    *sp;

    ep = expbuf;
    if(ep + 0377 > &commands->respace[RESIZE-1]) {
        command_errf(commands, SEDERR_TMMES, commands->linebuf);
        return NULL;
    }
    sp = commands->cp;
    for(tsp = commands->cp; (c = *tsp) != commands->sseof; tsp++) {
        if(c == '\\')
            tsp++;
        if(c == '\0' || c == '\n') {
            command_errf(commands, SEDERR_EDMOSTR, commands->linebuf);
            return NULL;
        }
    }
    tsp++;
    memset(ep, 0, 0400);

    while((c = *sp++) != commands->sseof) {
        c &= 0377;
        if(c == '\\' && *sp == 'n') {
            sp++;
            c = '\n';
        }
        cint = (int) c;
        if((ep[cint] = *tsp++) == '\\' && *tsp == 'n') {
            ep[cint] = '\n';
            tsp++;
        }
        if(ep[cint] == commands->sseof || ep[cint] == '\0') {
            command_errf(commands, SEDERR_TSNTSS, commands->linebuf);
        }
    }
    if(*tsp != commands->sseof) {
        if(*tsp == '\0') {
            command_errf(commands, SEDERR_EDMOSTR, commands->linebuf);
        }
        else {
            command_errf(commands, SEDERR_TSNTSS, commands->linebuf);
        }
        return NULL;
    }
    commands->cp = ++tsp;

    for(i = 0; i < 0400; i++)
        if(ep[i] == 0)
            ep[i] = i;

    return(ep + 0400);
}

/*
 * comple
 */
static char *comple(sed_commands_t *commands, sed_comp_args *compargs,
                    char *x1, char *ep, char *x3, char x4)
{
    char *p;

    p = sed_compile(commands, compargs, ep + 1, x3, x4);
    if(p == ep + 1)
        return(ep);
    *ep = compargs->circf;
    return(p);
}

/*
 * alloc_reptr
 */
static sed_reptr_t *alloc_reptr(sed_commands_t *commands)
{
    sed_reptr_t *var;

    var = apr_pcalloc(commands->pool, sizeof(sed_reptr_t));
    if (var == NULL) {
        command_errf(commands, SEDERR_OOMMES);
        return 0;
    }

    var->nrep = commands->nrep;
    var->findex = -1;
    commands->nrep++;

    if (commands->ptrspace == NULL)
        commands->ptrspace = var;
    else
        commands->ptrend->next = var;

    commands->ptrend = var;
    commands->labtab->address = var;
    return var;
}


