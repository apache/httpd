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


/* at.h: TAP-compliant C utilities for the Apache::Test framework. */

#ifndef AT_H
#define AT_H

#include <stdarg.h>
#include <stdlib.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

typedef struct at_t at_t;
typedef struct at_report_t at_report_t;

typedef int (*at_report_function_t)(at_report_t *r, const char *msg);
typedef void(*at_test_function_t)(at_t *t, void *ctx);
typedef struct at_test_t at_test_t;

struct at_test_t {
    const char          *name;
    at_test_function_t   func;
    int                  plan;
    void                *ctx;
    const char          *fatals;
    const char          *skips;
    const char          *todos;
};

struct at_report_t {
    at_report_function_t func;
};

/* Private, portable snprintf implementation. 
 */
int at_snprintf(char *buf, int size, const char *format, ...);
int at_vsnprintf(char *buf, int size, const char *format, va_list args); 

/* We only need one at_t struct per test suite, so lets call it *AT.
 * The mnemonic we follow is that (for lowercase foo) "AT_foo(bar)"
 * should be syntactically equivalent to "at_foo(AT, bar)".
 *
 * Terminology: test == an at_test_t,
 *              check == an assertion which produces TAP.
 */

#define dAT at_t *AT

struct at_t {
    int                  current; /* current check for this test */
    int                  prior;   /* total # of checks prior to this test */
    const char          *name;    /* name of current test */
    int                  plan;    /* total # of checks in this test */
    const int           *fatal;   /* list of unrecoverables */
    const int           *skip;    /* list of ignorabe assertions */
    const int           *todo;    /* list of expected failures */
    at_report_t         *report  ;/* handles the results of each check */
    unsigned char        flags;   /* verbosity: concise, trace, debug, etc. */
    jmp_buf             *abort;   /* where fatals go to die */
};



static inline
int at_report(at_t *t, const char *msg) {
    at_report_t *r = t->report;
    return r->func(r, msg);
}
#define AT_report(msg) at_report(AT, msg)

/* The core assertion checker; the rest just wind up invoking this one. */
void at_ok(at_t *t, int is_ok, const char *label, const char *file, int line);
#define AT_ok(is_ok, label) at_ok(AT, is_ok, label, __FILE__, __LINE__)

at_t *at_create(unsigned char flags, at_report_t *report);
int at_begin(at_t *t, int total);
#define AT_begin(total) at_begin(AT, total)

int at_run(at_t *AT, const at_test_t *test);
#define AT_run(test) at_run(AT, test)

void at_end(at_t *t);
#define AT_end() at_end(AT)


#define AT_FLAG_TODO(f)       ((f) & 8)
#define AT_FLAG_TODO_ON(f)    ((f) |= 8)
#define AT_FLAG_TODO_OFF(f)   ((f) &= ~8)
#define AT_FLAG_DEBUG(f)       ((f) & 4)
#define AT_FLAG_DEBUG_ON(f)    ((f) |= 4)
#define AT_FLAG_DEBUG_OFF(f)   ((f) &= ~4)
#define AT_FLAG_TRACE(f)       ((f) & 2)
#define AT_FLAG_TRACE_ON(f)    ((f) |= 2)
#define AT_FLAG_TRACE_OFF(f)   ((f) &= ~2)
#define AT_FLAG_CONCISE(f)     ((f) & 1)
#define AT_FLAG_CONCISE_ON(f)  ((f) |= 1)
#define AT_FLAG_CONCISE_OFF(f) ((f) &= ~1)

#define AT_todo_on()       AT_FLAG_TODO_ON(AT->flags)
#define AT_todo_off()      AT_FLAG_TODO_OFF(AT->flags)
#define AT_debug_on()      AT_FLAG_DEBUG_ON(AT->flags)
#define AT_debug_off()     AT_FLAG_DEBUG_OFF(AT->flags)
#define AT_trace_on()      AT_FLAG_TRACE_ON(AT->flags)
#define AT_trace_off()     AT_FLAG_TRACE_OFF(AT->flags)
#define AT_concise_on()    AT_FLAG_CONCISE_ON(AT->flags)
#define AT_concise_off()   AT_FLAG_CONCISE_OFF(AT->flags)



/* Additional reporting utils.
   These emit TAP comments, and are not "checks". */

int at_comment(at_t *t, const char *fmt, va_list vp);

static inline
void at_debug(at_t *t, const char *fmt, ...) {
    va_list vp;
    va_start(vp, fmt);
    if (AT_FLAG_DEBUG(t->flags))
        at_comment(t, fmt, vp);
    va_end(vp);
}

static inline
void at_trace(at_t *t, const char *fmt, ...) {
    va_list vp;
    va_start(vp, fmt);
    if (AT_FLAG_TRACE(t->flags))
        at_comment(t, fmt, vp);
    va_end(vp);
}


/* These are "checks". */

static inline
void at_check(at_t *t, int is_ok, const char *label, const char *file,
           int line, const char *fmt, ...)
{
    va_list vp;

    va_start(vp, fmt);
    if (AT_FLAG_TRACE(t->flags)) {
        char format[32] = "testing: %s (%s:%d)";
        at_trace(t, format, label, file, line);

        if (fmt != NULL) {
            char *f;
            at_snprintf(format, sizeof format, " format: %s", fmt);
            at_trace(t, "%s", format);
            memcpy(format, "   left:", 8);
            f = format + strlen(format);
            at_snprintf(f, sizeof format - strlen(format), "\n  right: %s", fmt);
            at_comment(t, format, vp);
        }
    }
    else if (AT_FLAG_DEBUG(t->flags) && !is_ok) {
        char format[32] = "testing: %s (%s:%d)";
        at_debug(t, format, label, file, line);

        if (fmt != NULL) {
            char *f;
            at_snprintf(format, sizeof format, " format: %s", fmt);
            at_debug(t, "%s", format);
            memcpy(format, "   left:", 8);
            f = format + strlen(format);
            at_snprintf(f, sizeof format - strlen(format), "\n  right: %s", fmt);
            at_comment(t, format, vp);
        }
    }
    va_end(vp);
    at_ok(t, is_ok, label, file, line);
}


#define AT_mem_ne(a, b, n) do {                                         \
    unsigned sz = n;                                                    \
    const void *left = a, *right = b;                                   \
    char fmt[] =  ", as %u-byte struct pointers";                       \
    char buf[256] = #a " != " #b;                                       \
    const unsigned blen = sizeof(#a " != " #b);                         \
    at_snprintf(buf + blen - 1, 256 - blen, fmt, sz);                   \
    at_snprintf(fmt, sizeof(fmt), "%%.%us", sz);                        \
    at_check(AT, memcmp(left, right, sz), buf, __FILE__, __LINE__,      \
           fmt, left, right);                                           \
} while (0)                                                             \

#define AT_mem_eq(a, b, n) do {                                         \
    unsigned sz = n;                                                    \
    const void *left = a, *right = b;                                   \
    char fmt[] =  ", as %u-byte struct pointers";                       \
    char buf[256] = #a " == " #b;                                       \
    const unsigned blen = sizeof(#a " == " #b);                         \
    at_snprintf(buf + blen - 1, 256 - blen , fmt, sz);                  \
    at_snprintf(fmt, sizeof(fmt), "%%.%us", sz);                        \
    at_check(AT, !memcmp(left, right, sz), buf, __FILE__, __LINE__,     \
           fmt, left, right);                                           \
} while (0)



#define AT_str_eq(a, b) do {                                            \
    const char *left = a, *right = b;                                   \
    at_check(AT,!strcmp(left, right), #a " == " #b ", as strings",      \
            __FILE__, __LINE__, "%s", left, right);                     \
} while (0)


#define AT_str_ne(a, b) do {                                           \
    const char *left = a, *right = b;                                  \
    at_check(AT, strcmp(left, right), #a " != " #b ", as strings",     \
            __FILE__, __LINE__, "%s", left, right);                    \
} while (0)

#define AT_ptr_eq(a, b) do {                                    \
    const void *left = a, *right = b;                           \
    at_check(AT, left == right, #a " == " #b ", as pointers",   \
            __FILE__, __LINE__, "%p", left, right);             \
} while (0)

#define AT_ptr_ne(a, b) do {                                    \
    const void *left = a, *right = b;                           \
    at_check(AT, left != right, #a " != " #b ", as pointers",   \
            __FILE__, __LINE__, "%p", left, right);             \
} while (0)


#define AT_int_eq(a, b) do {                                    \
    const int left = a, right = b;                              \
    at_check(AT, left == right, #a " == " #b ", as integers",   \
            __FILE__, __LINE__, "%d", left, right);             \
} while (0)

#define AT_int_ne(a, b) do {                                    \
    const int left = a, right = b;                              \
    at_check(AT, left != right, #a " != " #b ", as integers",   \
            __FILE__, __LINE__, "%d", left, right);             \
} while (0)

#define AT_is_null(a)  AT_ptr_eq(a, NULL)
#define AT_not_null(a) AT_ptr_ne(a, NULL)


/* XXX these two macro checks evaluate a & b more than once, but the
 * upshot is that they don't care too much about their types.
 */

#define AT_EQ(a, b, fmt) at_check(AT, ((a) == (b)), #a " == " #b,\
                                  __FILE__, __LINE__, fmt, a, b)
#define AT_NE(a, b, fmt) at_check(AT, ((a) != (b)), #a " != " #b,\
                                  __FILE__, __LINE__, fmt, a, b)


static inline
void at_skip(at_t *t, int n, const char *reason, const char *file, int line) {
    char buf[256];
    while (n-- > 0) {
        ++t->current;
        at_snprintf(buf, 256, "ok %d - %s (%d) #skipped: %s (%s:%d)",
                    t->current + t->prior, t->name, t->current, reason, file, line);
        at_report(t, buf);
    }
}

#define AT_skip(n, reason) at_skip(AT, n, reason, __FILE__, __LINE__)


/* Report utilities. */

at_report_t *at_report_file_make(FILE *f);
inline
static at_report_t *at_report_stdout_make(void)
{
    return at_report_file_make(stdout);
}
void at_report_file_cleanup(at_report_t *r);
#define at_report_stdout_cleanup(r) at_report_file_cleanup(r)

void at_report_local(at_t *AT, const char *file, int line);
#define AT_localize() at_report_local(AT, __FILE__, __LINE__)
void at_report_delocalize(at_t *AT);
#define AT_delocalize() at_report_delocalize(AT)

#endif /* AT_H */
