/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

#include "at.h"
#include <errno.h>
#include <ctype.h>

#define AT_SUCCESS 0
#define AT_EGENERAL 14
#define min(a, b) ((a < b) ? a : b)

int at_begin(at_t *t, int total)
{
    char buf[32];
    at_snprintf(buf, 32, "1..%d", total);
    return at_report(t, buf);
}

static int test_cleanup(void *data)
{
    at_t *t = data;
    if (t->current < t->plan)
        return at_report(t, "Bail out!");
    else
        return at_report(t, "END");
}

void at_end(at_t *t)
{
    test_cleanup(t);
    free(t);
}

int at_comment(at_t *t, const char *fmt, va_list vp)
{
    int s;
    char buf[256], *b = buf + 2;
    char *end;
    int rv;
    rv = at_vsnprintf(b, 250, fmt, vp);

    if (rv <= 0)
        return EINVAL;


    end = b + min(rv, 250);

    buf[0] = '#';
    buf[1] = ' ';

    if (rv >= 250) {
        end[-1] = '.';
        *end++ = '.';
        *end++ = '.';
        *end++ = '\n';
        *end = 0;
    }
    else if (end[-1] != '\n') {
        *end++ = '\n';
        *end = 0;
    }

    b = buf;
    while (1) {
        char *eol;

        eol = strchr(b + 2, '\n');
        *eol = 0;
        s = at_report(t, b);
        if (s != AT_SUCCESS || eol == end - 1)
            break;

        b    = eol - 1;
        b[0] = '#';
        b[1] = ' ';
    }

    return s;
}

void at_ok(at_t *t, int is_ok, const char *label, const char *file, int line)
{
    char format[] = "not ok %d - %s # %s (%s:%d) test %d in %s";
    char *end = format + 10;
    char *fmt = is_ok ? format + 4 : format;
    char buf[256];
    const char *comment = NULL;
    int rv, is_fatal = 0, is_skip = 0, is_todo = 0;

    t->current++;

    if (*t->fatal == t->current) {
        t->fatal++;
        is_fatal = 1;
    }

    if (*t->skip == t->current) {
        t->skip++;
        is_skip = 1;
    }

    if (*t->todo == t->current) {
        t->todo++;
        is_todo = 1;
    }
    
    if (AT_FLAG_TODO(t->flags))
        is_todo = 1;

    if (AT_FLAG_CONCISE(t->flags))
        format[9] = '\0';
    else if (is_ok && ! is_todo && !AT_FLAG_TRACE(t->flags))
        format[14] = '\0';
    else if (is_fatal && ! is_ok)
        comment = "fatal";
    else
        comment = is_todo ? "todo" : is_skip ? "skip" : "at";

    rv = at_snprintf(buf, 256, fmt, t->current + t->prior,
                     label, comment,  file, line, t->current, t->name);

    if (rv <= 0)
        exit(-1);

    end = buf + min(rv, 250);

    if (rv >= 250) {
        *end++ = '.';
        *end++ = '.';
        *end++ = '.';
        *end = '\0';
    }

    if (memchr(buf, '\n', rv) != NULL || at_report(t, buf) != AT_SUCCESS)
        exit(-1);

    if (!is_ok && is_fatal) {
        while (t->current++ < t->plan) {
            at_snprintf(buf, 256, "not ok %d # skipped: aborting test %s",
                        t->prior + t->current, t->name);
            at_report(t, buf);
        }
        longjmp(*t->abort, 0);
    }
}

struct at_report_file {
    at_report_t module;
    FILE *file;
};

static int at_report_file_write(at_report_t *ctx, const char *msg)
{
    struct at_report_file *r = (struct at_report_file *)ctx;
    FILE *f = r->file;
    size_t len = strlen(msg);
    size_t bytes_written;
    int status;

    bytes_written = fwrite(msg, sizeof(char), len, f);
    if (bytes_written != len)
        return errno;

    status = putc('\n', f);
    if (status == EOF)
        return errno;

    return fflush(f);
}

at_report_t *at_report_file_make(FILE *f)
{
    struct at_report_file *r = malloc(sizeof *r);
    r->module.func = at_report_file_write;
    r->file = f;
    return &r->module;
}

void at_report_file_cleanup(at_report_t *r)
{
    free(r);
}

struct at_report_local {
    at_report_t  module;
    at_t        *t;
    at_report_t *saved_report;
    const int   *saved_fatal;
    const int   *saved_skip;
    const int   *saved_todo;
    int          dummy_fatal;
    char        *file;
    int          line;
    int          passed;
};

static int report_local_cleanup(void *data)
{
    struct at_report_local *q = data;
    dAT = q->t;
    char label[32];

    at_snprintf(label, 32, "collected %d passing tests", q->passed);

    AT->report = q->saved_report;
    AT->fatal  = q->saved_fatal;
    AT->skip   = q->saved_skip;
    AT->todo   = q->saved_todo;

    at_ok(q->t, 1, label, q->file, q->line);

    free(q->file);
    free(q);

    return AT_SUCCESS;
}

void at_report_delocalize(at_t *AT) {
    report_local_cleanup(AT->report);
}

static int at_report_local_write(at_report_t *ctx, const char *msg)
{
    char buf[256];
    struct at_report_local *q = (struct at_report_local *)ctx;
    dAT = q->t;

    if (strncmp(msg, "not ok", 6) == 0) {
        q->saved_report->func(q->saved_report, msg);
        report_local_cleanup(q);
        while (AT->current++ < AT->plan) {
            at_snprintf(buf, 256, "not ok %d # skipped: aborting test %s",
                        AT->prior + AT->current, AT->name);
            at_report(AT, buf);
        }
        longjmp(*AT->abort, 0);
    }
    else if (strncmp(msg, "ok", 2) == 0) {
        AT->current--;
        q->passed++;
    }
    return AT_SUCCESS;
}

void at_report_local(at_t *AT, const char *file, int line)
{
    struct at_report_local *q = malloc(sizeof *q);
    size_t len;

    q->module.func = at_report_local_write;
    q->t = AT;
    q->saved_report = AT->report;
    q->saved_fatal = AT->fatal;
    q->saved_skip = AT->skip;
    q->saved_todo = AT->todo;
    q->dummy_fatal = 0;
    q->line = line;
    q->passed = 0;

    len = strlen(file) + 1;
    q->file = (char*)malloc(len);
    memcpy(q->file, file, len);

    AT->fatal = AT->skip = AT->todo = &q->dummy_fatal;
    AT->report = &q->module;

    if (*q->saved_fatal == AT->current + 1)
        q->saved_fatal++;

}

at_t *at_create(unsigned char flags, at_report_t *report)
{
    at_t *t = calloc(sizeof *t, 1);
    t->flags = flags;
    t->report = report;
    return t;
}

static int* at_list(const char *spec)
{
    int prev, current = 0, count = 0, idx = 0, *elts;
    const char *start = spec;

    do {
        while (*spec && !isdigit((unsigned char)*spec))
            ++spec;
        prev = current;
        current = (int)strtol(spec, (char **)(void *)&spec, 10);
        ++count;

    } while (prev <= current);

    elts = malloc(++count * sizeof *elts);
    spec = start;
    current = 0;

    do {
        while (*spec && !isdigit((unsigned char)*spec))
            ++spec;
        prev = current;
        current = (int)strtol(spec, (char **)(void *)&spec, 10);
        elts[idx++] = current;

    } while (prev <= current);

    elts[idx] = 0; /* sentinel */

    return elts;
}

#define at_free_lists do { if (flist) free((void *)flist);       \
                           if (slist) free((void *)slist);       \
                           if (tlist) free((void *)tlist); } while (0)

int at_run(at_t *AT, const at_test_t *test)
{
    int dummy = 0;
    const int *flist = NULL, *slist = NULL, *tlist = NULL;
    jmp_buf j;

    AT->current = 0;
    AT->prior   += AT->plan;
    AT->name    = test->name;
    AT->plan    = test->plan;

    if (test->fatals)
        flist = AT->fatal = at_list(test->fatals);
    else
        AT->fatal = &dummy;

    if (test->skips)
        slist = AT->skip = at_list(test->skips);
    else
        AT->skip = &dummy;

    if (test->todos)
        tlist = AT->todo = at_list(test->todos);
    else
        AT->todo = &dummy;

    AT->abort = &j;
    if (setjmp(j) == 0) {
        test->func(AT, test->ctx);
        at_free_lists;
        return AT_SUCCESS;
    }
    at_free_lists;
    AT->abort = NULL;
    return AT_EGENERAL;
}

int at_snprintf(char *buf, int size, const char *format, ...)
{
    va_list args;
    int status;
    va_start(args, format);
    status = at_vsnprintf(buf, size, format, args);
    va_end(args);
    return status;
}

int at_vsnprintf(char *buf, int size, const char *format, va_list args)
{
#ifdef _MSC_VER
    int status = _vsnprintf(buf, size, format, args);
    /* Make Microsoft's _vsnprintf behave like C99 vsnprintf on overflow:
     * NULL-terminate, and return the number of chars printed minus one. */
    if (status < 0) {
        if (errno != EINVAL) {
            status = size - 1;
            buf[status] = '\0';
        }
    }
    return status;
#else 
    return vsnprintf(buf, size, format, args);
#endif /* _MSC_VER */
}

