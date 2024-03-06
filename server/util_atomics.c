#include "ap_atomics.h"
#include "httpd.h"

#include "apr.h"
#include "apr_atomic.h"


/* Platform checks */
#if APR_HAVE_LIMITS_H
#include <limits.h> /* for INT/LONG_MAX */
#else
#error "<limits.h> required"
#endif
#if INT_MAX == APR_INT32_MAX && UINT_MAX == APR_UINT32_MAX
AP_BUILD_ASSERT(sizeof(int) == sizeof(apr_int32_t));
AP_BUILD_ASSERT(sizeof(unsigned int) == sizeof(apr_uint32_t));
#else
#error "[U]INT_MAX not supported"
#endif
#if LONG_MAX == APR_INT32_MAX && ULONG_MAX == APR_UINT32_MAX
AP_BUILD_ASSERT(sizeof(long) == sizeof(apr_int32_t));
AP_BUILD_ASSERT(sizeof(unsigned long) == sizeof(apr_uint32_t));
#elif LONG_MAX == APR_INT64_MAX && ULONG_MAX == APR_UINT64_MAX
AP_BUILD_ASSERT(sizeof(long) == sizeof(apr_int64_t));
AP_BUILD_ASSERT(sizeof(unsigned long) == sizeof(apr_uint64_t));
#else
#error "[U]LONG_MAX not supported"
#endif
#if APR_SIZEOF_VOIDP == 4
AP_BUILD_ASSERT(sizeof(apr_size_t) == sizeof(apr_uint32_t));
#elif APR_SIZEOF_VOIDP == 8
AP_BUILD_ASSERT(sizeof(apr_size_t) == sizeof(apr_uint64_t));
#else
#error "sizeof(void*) not supported"
#endif
#if (~0 != -1)
#error "2's complement integer representation required"
#endif


/* Atomics for pointers (use APR's) */

static AP_FORCE_INLINE
void *atomic_ptr_xchg(void *volatile *ptr, void *with)
{
    return apr_atomic_xchgptr((void *)ptr, with);
}

static AP_FORCE_INLINE
void *atomic_ptr_cas(void *volatile *ptr, void *with, const void *cmp)
{
    return apr_atomic_casptr((void *)ptr, with, cmp);
}

#if 0 /* not used for now */
static AP_FORCE_INLINE
void *atomic_ptr_get(void *volatile *ptr)
{
    return atomic_ptr_cas(ptr, NULL, NULL);
}

static AP_FORCE_INLINE
void atomic_ptr_set(void *volatile *ptr, void *to)
{
    (void)atomic_ptr_xchg(ptr, to);
}
#endif


/* Atomics for uint32_t (use APR's) */

static AP_FORCE_INLINE
apr_uint32_t atomic_uint32_get(apr_uint32_t volatile *val)
{
    return apr_atomic_read32(val);
}

static AP_FORCE_INLINE
void atomic_uint32_set(apr_uint32_t volatile *val,
                       apr_uint32_t to)
{
    apr_atomic_set32(val, to);
}

static AP_FORCE_INLINE
apr_uint32_t atomic_uint32_xchg(apr_uint32_t volatile *val,
                                apr_uint32_t with)
{
    return apr_atomic_xchg32(val, with);
}

static AP_FORCE_INLINE
apr_uint32_t atomic_uint32_cas(apr_uint32_t volatile *val,
                               apr_uint32_t with, apr_uint32_t cmp)
{
    return apr_atomic_cas32(val, with, cmp);
}

static AP_FORCE_INLINE
apr_uint32_t atomic_uint32_add(apr_uint32_t volatile *val,
                               apr_uint32_t add)
{
    return apr_atomic_add32(val, add);
}

static AP_FORCE_INLINE
apr_uint32_t atomic_uint32_add_sat(apr_uint32_t volatile *val,
                                   apr_uint32_t add)
{
    apr_uint32_t old, cmp = APR_UINT32_MAX;
    old = atomic_uint32_get(val);
    while (old != cmp) {
        cmp = old;
        old = atomic_uint32_cas(val,
                                old < APR_UINT32_MAX - add ? old + add : APR_UINT32_MAX,
                                cmp);
    }
    return old;
}

static AP_FORCE_INLINE
apr_uint32_t atomic_uint32_sub(apr_uint32_t volatile *val,
                               apr_uint32_t sub)
{
    return apr_atomic_add32(val, -sub);
}

static AP_FORCE_INLINE
apr_uint32_t atomic_uint32_sub_sat(apr_uint32_t volatile *val,
                                   apr_uint32_t sub)
{
    apr_uint32_t old, cmp = 0;
    old = atomic_uint32_get(val);
    while (old != cmp) {
        cmp = old;
        old = atomic_uint32_cas(val,
                                old > sub ? old - sub : 0,
                                cmp);
    }
    return old;
}


/* Atomics for int32_t (uses uint32_t's for unsigned/safe wrap semantics) */

static AP_FORCE_INLINE
apr_int32_t atomic_int32_get(apr_int32_t volatile *val)
{
    return (apr_int32_t)atomic_uint32_get((void *)val);
}

static AP_FORCE_INLINE
void atomic_int32_set(apr_int32_t volatile *val,
                      apr_int32_t to)
{
    atomic_uint32_set((void *)val, to);
}

static AP_FORCE_INLINE
apr_int32_t atomic_int32_xchg(apr_int32_t volatile *val,
                              apr_int32_t with)
{
    return (apr_int32_t)atomic_uint32_xchg((void *)val, with);
}

static AP_FORCE_INLINE
apr_int32_t atomic_int32_cas(apr_int32_t volatile *val,
                             apr_int32_t with, apr_int32_t cmp)
{
    return (apr_int32_t)atomic_uint32_cas((void *)val, with, cmp);
}

static AP_FORCE_INLINE
apr_int32_t atomic_int32_add(apr_int32_t volatile *val,
                             apr_int32_t add)
{
    return (apr_int32_t)atomic_uint32_add((void *)val, add);
}

static AP_FORCE_INLINE
apr_int32_t atomic_int32_add_sat(apr_int32_t volatile *val,
                                 apr_int32_t add)
{
    apr_int32_t old, cmp;
    old = atomic_int32_get(val);
    if (add < 0 && old != APR_INT32_MIN) {
        do {
            cmp = old;
            old = atomic_int32_cas(val,
                                   old < APR_INT32_MIN - add ? APR_INT32_MIN : old + add,
                                   cmp);
        } while (old != cmp);
    }
    else if (add > 0 && old != APR_INT32_MAX) {
        do {
            cmp = old;
            old = atomic_int32_cas(val,
                                   old > APR_INT32_MAX - add ? APR_INT32_MAX : old + add,
                                   cmp);
        } while (old != cmp);
    }
    return old;
}

static AP_FORCE_INLINE
apr_int32_t atomic_int32_sub(apr_int32_t volatile *val,
                             apr_int32_t sub)
{
    return (apr_int32_t)atomic_uint32_sub((void *)val, sub);
}

static AP_FORCE_INLINE
apr_int32_t atomic_int32_sub_sat(apr_int32_t volatile *val,
                                 apr_int32_t sub)
{
    apr_int32_t old, cmp;
    old = atomic_int32_get(val);
    if (sub < 0 && old != APR_INT32_MAX) {
        do {
            cmp = old;
            old = atomic_int32_cas(val,
                                   old > APR_INT32_MAX + sub ? APR_INT32_MAX : old - sub,
                                   cmp);
        } while (old != cmp);
    }
    else if (sub > 0 && old != APR_INT32_MIN) {
        do {
            cmp = old;
            old = atomic_int32_cas(val,
                                   old < APR_INT32_MIN + sub ? APR_INT32_MIN : old - sub,
                                   cmp);
        } while (old != cmp);
    }
    return old;
}


/* Atomics for uint64_t (uses APR's) */

#if APR_SIZEOF_VOIDP == 8 /* not implemented/needed on 32bit platforms */

static AP_FORCE_INLINE
apr_uint64_t atomic_uint64_get(apr_uint64_t volatile *val)
{
#if APR_VERSION_AT_LEAST(1,7,4) /* APR 64bit atomics not safe before 1.7.4 */
    return apr_atomic_read64(val);
#else /* Use atomics for 64bit pointers */
    void *volatile *val_p = (void *)(apr_uintptr_t)val;
    AP_DEBUG_ASSERT((apr_uintptr_t)val_p % sizeof(void*) == 0);
    return (apr_uintptr_t)atomic_ptr_cas(val_p, NULL, NULL);
#endif
}

static AP_FORCE_INLINE
void atomic_uint64_set(apr_uint64_t volatile *val,
                       apr_uint64_t to)
{
#if APR_VERSION_AT_LEAST(1,7,4) /* APR 64bit atomics not safe before 1.7.4 */
    apr_atomic_set64(val, to);
#else /* Use atomics for 64bit pointers */
    void *volatile *val_p = (void *)(apr_uintptr_t)val;
    AP_DEBUG_ASSERT((apr_uintptr_t)val_p % sizeof(void*) == 0);
    (void)atomic_ptr_xchg(val_p, (void *)(apr_uintptr_t)to);
#endif
}

static AP_FORCE_INLINE
apr_uint64_t atomic_uint64_xchg(apr_uint64_t volatile *val,
                                apr_uint64_t with)
{
#if APR_VERSION_AT_LEAST(1,7,4) /* APR 64bit atomics not safe before 1.7.4 */
    return apr_atomic_xchg64(val, with);
#else /* Use atomics for 64bit pointers */
    void *volatile *val_p = (void *)(apr_uintptr_t)val;
    AP_DEBUG_ASSERT((apr_uintptr_t)val_p % sizeof(void*) == 0);
    return (apr_uintptr_t)atomic_ptr_xchg(val_p, (void *)(apr_uintptr_t)with);
#endif
}

static AP_FORCE_INLINE
apr_uint64_t atomic_uint64_cas(apr_uint64_t volatile *val,
                               apr_uint64_t with, apr_uint64_t cmp)
{
#if APR_VERSION_AT_LEAST(1,7,4) /* APR 64bit atomics not safe before 1.7.4 */
    return apr_atomic_cas64(val, with, cmp);
#else /* Use atomics for 64bit pointers */
    void *volatile *val_p = (void *)(apr_uintptr_t)val;
    AP_DEBUG_ASSERT((apr_uintptr_t)val_p % sizeof(void*) == 0);
    return (apr_uintptr_t)atomic_ptr_cas(val_p, (void *)(apr_uintptr_t)with,
                                         (void *)(apr_uintptr_t)cmp);
#endif
}

static AP_FORCE_INLINE
apr_uint64_t atomic_uint64_add(apr_uint64_t volatile *val,
                               apr_uint64_t add)
{
#if APR_VERSION_AT_LEAST(1,7,4) /* APR 64bit atomics not safe before 1.7.4 */
    return apr_atomic_add64(val, add);
#else
    apr_uint64_t old, cmp;
    old = atomic_uint64_get(val);
    do {
        cmp = old;
        old = (apr_uintptr_t)atomic_ptr_cas((void *volatile *)val,
                                            (void *)(apr_uintptr_t)(old + add),
                                            (void *)(apr_uintptr_t)cmp);
    } while (old != cmp);
    return old;
#endif
}

static AP_FORCE_INLINE
apr_uint64_t atomic_uint64_add_sat(apr_uint64_t volatile *val,
                                   apr_uint64_t add)
{
    apr_uint64_t old, cmp = APR_UINT64_MAX;
    old = atomic_uint64_get(val);
    while (old != cmp) {
        cmp = old;
        old = atomic_uint64_cas(val,
                                old < APR_UINT64_MAX - add ? old + add : APR_UINT64_MAX,
                                cmp);
    }
    return old;
}

static AP_FORCE_INLINE
apr_uint64_t atomic_uint64_sub(apr_uint64_t volatile *val,
                               apr_uint64_t sub)
{
#if APR_VERSION_AT_LEAST(1,7,4) /* APR 64bit atomics not safe before 1.7.4 */
    return apr_atomic_add64(val, -sub);
#else
    apr_uint64_t old, cmp;
    old = atomic_uint64_get(val);
    do {
        cmp = old;
        old = (apr_uintptr_t)atomic_ptr_cas((void *volatile *)val,
                                            (void *)(apr_uintptr_t)(old - sub),
                                            (void *)(apr_uintptr_t)cmp);
    } while (old != cmp);
    return old;
#endif
}

static AP_FORCE_INLINE
apr_uint64_t atomic_uint64_sub_sat(apr_uint64_t volatile *val,
                                   apr_uint64_t sub)
{
    apr_uint64_t old, cmp = 0;
    old = atomic_uint64_get(val);
    while (old != cmp) {
        cmp = old;
        old = atomic_uint64_cas(val,
                                old > sub ? old - sub : 0,
                                cmp);
    }
    return old;
}


/* Atomics for int64_t (uses uint_64t's for unsigned/safe wrap semantics) */

static AP_FORCE_INLINE
apr_int64_t atomic_int64_get(apr_int64_t volatile *val)
{
    return (apr_int64_t)atomic_uint64_get((void *)val);
}

static AP_FORCE_INLINE
void atomic_int64_set(apr_int64_t volatile *val,
                      apr_int64_t to)
{
    atomic_uint64_set((void *)val, to);
}

static AP_FORCE_INLINE
apr_int64_t atomic_int64_xchg(apr_int64_t volatile *val,
                              apr_int64_t with)
{
    return (apr_int64_t)atomic_uint64_xchg((void *)val, with);
}

static AP_FORCE_INLINE
apr_int64_t atomic_int64_cas(apr_int64_t volatile *val,
                             apr_int64_t with, apr_int64_t cmp)
{
    return (apr_int64_t)atomic_uint64_cas((void *)val, with, cmp);
}

static AP_FORCE_INLINE
apr_int64_t atomic_int64_add(apr_int64_t volatile *val,
                             apr_int64_t add)
{
    return (apr_int64_t)atomic_uint64_add((void *)val, add);
}

static AP_FORCE_INLINE
apr_int64_t atomic_int64_add_sat(apr_int64_t volatile *val,
                                 apr_int64_t add)
{
    apr_int64_t old, cmp;
    old = atomic_int64_get(val);
    if (add < 0 && old != APR_INT64_MIN) {
        do {
            cmp = old;
            old = atomic_int64_cas(val,
                                   old < APR_INT64_MIN - add ? APR_INT64_MIN : old + add,
                                   cmp);
        } while (old != cmp);
    }
    else if (add > 0 && old != APR_INT64_MAX) {
        do {
            cmp = old;
            old = atomic_int64_cas(val,
                                   old > APR_INT64_MAX - add ? APR_INT64_MAX : old + add,
                                   cmp);
        } while (old != cmp);
    }
    return old;
}

static AP_FORCE_INLINE
apr_int64_t atomic_int64_sub(apr_int64_t volatile *val,
                             apr_int64_t sub)
{
    return (apr_int64_t)atomic_uint64_sub((void *)val, sub);
}

static AP_FORCE_INLINE
apr_int64_t atomic_int64_sub_sat(apr_int64_t volatile *val,
                                 apr_int64_t sub)
{
    apr_int64_t old, cmp;
    old = atomic_int64_get(val);
    if (sub < 0 && old != APR_INT64_MAX) {
        do {
            cmp = old;
            old = atomic_int64_cas(val,
                                   old > APR_INT64_MAX + sub ? APR_INT64_MAX : old - sub,
                                   cmp);
        } while (old != cmp);
    }
    else if (sub > 0 && old != APR_INT64_MIN) {
        do {
            cmp = old;
            old = atomic_int64_cas(val,
                                   old < APR_INT64_MIN + sub ? APR_INT64_MIN : old - sub,
                                   cmp);
        } while (old != cmp);
    }
    return old;
}

#endif /* APR_SIZEOF_VOIDP == 8 */


/* Atomics for int (uses int32_t's on all platforms we care about) */

AP_DECLARE(int) ap_atomic_int_get(int volatile *val)
{
    return atomic_int32_get((void *)val);
}

AP_DECLARE(void) ap_atomic_int_set(int volatile *val,
                                   int to)
{
    atomic_int32_set((void *)val, to);
}

AP_DECLARE(int) ap_atomic_int_xchg(int volatile *val,
                                   int with)
{
    return atomic_int32_xchg((void *)val, with);
}

AP_DECLARE(int) ap_atomic_int_cas(int volatile *val,
                                  int with, int cmp)
{
    return atomic_int32_cas((void *)val, with, cmp);
}

AP_DECLARE(int) ap_atomic_int_add(int volatile *val,
                                  int add)
{
    return atomic_int32_add((void *)val, add);
}

AP_DECLARE(int) ap_atomic_int_add_sat(int volatile *val,
                                      int add)
{
    return atomic_int32_add_sat((void *)val, add);
}

AP_DECLARE(int) ap_atomic_int_sub(int volatile *val,
                                  int sub)
{
    return atomic_int32_sub((void *)val, sub);
}

AP_DECLARE(int) ap_atomic_int_sub_sat(int volatile *val,
                                      int sub)
{
    return atomic_int32_sub_sat((void *)val, sub);
}


/* Atomics for unsigned int (uses uint32_t's on all platforms we care about) */

AP_DECLARE(unsigned int) ap_atomic_uint_get(unsigned int volatile *val)
{
    return atomic_uint32_get((void *)val);
}

AP_DECLARE(void) ap_atomic_uint_set(unsigned int volatile *val,
                                    unsigned int to)
{
    atomic_uint32_set((void *)val, to);
}

AP_DECLARE(unsigned int) ap_atomic_uint_xchg(unsigned int volatile *val,
                                             unsigned int with)
{
    return atomic_uint32_xchg((void *)val, with);
}

AP_DECLARE(unsigned int) ap_atomic_uint_cas(unsigned int volatile *val,
                                            unsigned int with, unsigned int cmp)
{
    return atomic_uint32_cas((void *)val, with, cmp);
}

AP_DECLARE(unsigned int) ap_atomic_uint_add(unsigned int volatile *val,
                                            unsigned int add)
{
    return atomic_uint32_add((void *)val, add);
}

AP_DECLARE(unsigned int) ap_atomic_uint_add_sat(unsigned int volatile *val,
                                                unsigned int add)
{
    return atomic_uint32_add_sat((void *)val, add);
}

AP_DECLARE(unsigned int) ap_atomic_uint_sub(unsigned int volatile *val,
                                            unsigned int sub)
{
    return atomic_uint32_sub((void *)val, sub);
}

AP_DECLARE(unsigned int) ap_atomic_uint_sub_sat(unsigned int volatile *val,
                                                unsigned int sub)
{
    return atomic_uint32_sub_sat((void *)val, sub);
}


/* Atomics for long (uses int32_t's or int64_t's depending on LONG_MAX) */

AP_DECLARE(long) ap_atomic_long_get(long volatile *val)
{
#if LONG_MAX == APR_INT32_MAX
    return atomic_int32_get((void *)val);
#elif LONG_MAX == APR_INT64_MAX
    return atomic_int64_get((void *)val);
#endif
}

AP_DECLARE(void) ap_atomic_long_set(long volatile *val,
                                    long to)
{
#if LONG_MAX == APR_INT32_MAX
    atomic_int32_set((void *)val, to);
#elif LONG_MAX == APR_INT64_MAX
    atomic_int64_set((void *)val, to);
#endif
}

AP_DECLARE(long) ap_atomic_long_xchg(long volatile *val,
                                     long with)
{
#if LONG_MAX == APR_INT32_MAX
    return atomic_int32_xchg((void *)val, with);
#elif LONG_MAX == APR_INT64_MAX
    return atomic_int64_xchg((void *)val, with);
#endif
}

AP_DECLARE(long) ap_atomic_long_cas(long volatile *val,
                                    long with, long cmp)
{
#if LONG_MAX == APR_INT32_MAX
    return atomic_int32_cas((void *)val, with, cmp);
#elif LONG_MAX == APR_INT64_MAX
    return atomic_int64_cas((void *)val, with, cmp);
#endif
}

AP_DECLARE(long) ap_atomic_long_add(long volatile *val,
                                    long add)
{
#if LONG_MAX == APR_INT32_MAX
    return atomic_int32_add((void *)val, add);
#elif LONG_MAX == APR_INT64_MAX
    return atomic_int64_add((void *)val, add);
#endif
}

AP_DECLARE(long) ap_atomic_long_add_sat(long volatile *val,
                                        long add)
{
#if LONG_MAX == APR_INT32_MAX
    return atomic_int32_add_sat((void *)val, add);
#elif LONG_MAX == APR_INT64_MAX
    return atomic_int64_add_sat((void *)val, add);
#endif
}

AP_DECLARE(long) ap_atomic_long_sub(long volatile *val,
                                    long sub)
{
#if LONG_MAX == APR_INT32_MAX
    return atomic_int32_sub((void *)val, sub);
#elif LONG_MAX == APR_INT64_MAX
    return atomic_int64_sub((void *)val, sub);
#endif
}

AP_DECLARE(long) ap_atomic_long_sub_sat(long volatile *val,
                                        long sub)
{
#if LONG_MAX == APR_INT32_MAX
    return atomic_int32_sub_sat((void *)val, sub);
#elif LONG_MAX == APR_INT64_MAX
    return atomic_int64_sub_sat((void *)val, sub);
#endif
}


/* Atomics for unsigned long (uses uint32_t's or uint64_t's depending on ULONG_MAX) */

AP_DECLARE(unsigned long) ap_atomic_ulong_get(unsigned long volatile *val)
{
#if ULONG_MAX == APR_UINT32_MAX
    return atomic_uint32_get((void *)val);
#elif ULONG_MAX == APR_UINT64_MAX
    return atomic_uint64_get((void *)val);
#endif
}

AP_DECLARE(void) ap_atomic_ulong_set(unsigned long volatile *val,
                                     unsigned long to)
{
#if ULONG_MAX == APR_UINT32_MAX
    atomic_uint32_set((void *)val, to);
#elif ULONG_MAX == APR_UINT64_MAX
    atomic_uint64_set((void *)val, to);
#endif
}

AP_DECLARE(unsigned long) ap_atomic_ulong_xchg(unsigned long volatile *val,
                                               unsigned long with)
{
#if ULONG_MAX == APR_UINT32_MAX
    return atomic_uint32_xchg((void *)val, with);
#elif ULONG_MAX == APR_UINT64_MAX
    return atomic_uint64_xchg((void *)val, with);
#endif
}

AP_DECLARE(unsigned long) ap_atomic_ulong_cas(unsigned long volatile *val,
                                              unsigned long with, unsigned long cmp)
{
#if ULONG_MAX == APR_UINT32_MAX
    return atomic_uint32_cas((void *)val, with, cmp);
#elif ULONG_MAX == APR_UINT64_MAX
    return atomic_uint64_cas((void *)val, with, cmp);
#endif
}

AP_DECLARE(unsigned long) ap_atomic_ulong_add(unsigned long volatile *val,
                                              unsigned long add)
{
#if ULONG_MAX == APR_UINT32_MAX
    return atomic_uint32_add((void *)val, add);
#elif ULONG_MAX == APR_UINT64_MAX
    return atomic_uint64_add((void *)val, add);
#endif
}

AP_DECLARE(unsigned long) ap_atomic_ulong_add_sat(unsigned long volatile *val,
                                                  unsigned long add)
{
#if ULONG_MAX == APR_UINT32_MAX
    return atomic_uint32_add_sat((void *)val, add);
#elif ULONG_MAX == APR_UINT64_MAX
    return atomic_uint64_add_sat((void *)val, add);
#endif
}

AP_DECLARE(unsigned long) ap_atomic_ulong_sub(unsigned long volatile *val,
                                              unsigned long sub)
{
#if ULONG_MAX == APR_UINT32_MAX
    return atomic_uint32_sub((void *)val, sub);
#elif ULONG_MAX == APR_UINT64_MAX
    return atomic_uint64_sub((void *)val, sub);
#endif
}

AP_DECLARE(unsigned long) ap_atomic_ulong_sub_sat(unsigned long volatile *val,
                                                  unsigned long sub)
{
#if ULONG_MAX == APR_UINT32_MAX
    return atomic_uint32_sub_sat((void *)val, sub);
#elif ULONG_MAX == APR_UINT64_MAX
    return atomic_uint64_sub_sat((void *)val, sub);
#endif
}


/* Atomics for size_t (uses uint32_t's or uint64_t's depending on sizeof(void*)) */

AP_DECLARE(apr_size_t) ap_atomic_size_get(apr_size_t volatile *val)
{
#if APR_SIZEOF_VOIDP == 4
    return atomic_uint32_get((void *)val);
#elif APR_SIZEOF_VOIDP == 8
    return atomic_uint64_get((void *)val);
#endif
}

AP_DECLARE(void) ap_atomic_size_set(apr_size_t volatile *val,
                                    apr_size_t to)
{
#if APR_SIZEOF_VOIDP == 4
    atomic_uint32_set((void *)val, to);
#elif APR_SIZEOF_VOIDP == 8
    atomic_uint64_set((void *)val, to);
#endif
}

AP_DECLARE(apr_size_t) ap_atomic_size_xchg(apr_size_t volatile *val,
                                           apr_size_t with)
{
#if APR_SIZEOF_VOIDP == 4
    return atomic_uint32_xchg((void *)val, with);
#elif APR_SIZEOF_VOIDP == 8
    return atomic_uint64_xchg((void *)val, with);
#endif
}

AP_DECLARE(apr_size_t) ap_atomic_size_cas(apr_size_t volatile *val,
                                          apr_size_t with, apr_size_t cmp)
{
#if APR_SIZEOF_VOIDP == 4
    return atomic_uint32_cas((void *)val, with, cmp);
#elif APR_SIZEOF_VOIDP == 8
    return atomic_uint64_cas((void *)val, with, cmp);
#endif
}

AP_DECLARE(apr_size_t) ap_atomic_size_add(apr_size_t volatile *val,
                                          apr_size_t add)
{
#if APR_SIZEOF_VOIDP == 4
    return atomic_uint32_add((void *)val, add);
#elif APR_SIZEOF_VOIDP == 8
    return atomic_uint64_add((void *)val, add);
#endif
}

AP_DECLARE(apr_size_t) ap_atomic_size_add_sat(apr_size_t volatile *val,
                                              apr_size_t add)
{
#if APR_SIZEOF_VOIDP == 4
    return atomic_uint32_add_sat((void *)val, add);
#elif APR_SIZEOF_VOIDP == 8
    return atomic_uint64_add_sat((void *)val, add);
#endif
}

AP_DECLARE(apr_size_t) ap_atomic_size_sub(apr_size_t volatile *val,
                                          apr_size_t sub)
{
#if APR_SIZEOF_VOIDP == 4
    return atomic_uint32_sub((void *)val, sub);
#elif APR_SIZEOF_VOIDP == 8
    return atomic_uint64_sub((void *)val, sub);
#endif
}

AP_DECLARE(apr_size_t) ap_atomic_size_sub_sat(apr_size_t volatile *val,
                                              apr_size_t sub)
{
#if APR_SIZEOF_VOIDP == 4
    return atomic_uint32_sub_sat((void *)val, sub);
#elif APR_SIZEOF_VOIDP == 8
    return atomic_uint64_sub_sat((void *)val, sub);
#endif
}
