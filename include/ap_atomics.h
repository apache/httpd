#include "ap_config.h"

#include "apr.h"


/* Atomics for int (uses int32_t's on all platforms we care about) */

AP_DECLARE(int) ap_atomic_int_get(int volatile *val);

AP_DECLARE(void) ap_atomic_int_set(int volatile *val, int to);

AP_DECLARE(int) ap_atomic_int_xchg(int volatile *val, int with);

AP_DECLARE(int) ap_atomic_int_cas(int volatile *val, int with, int cmp);

AP_DECLARE(int) ap_atomic_int_add(int volatile *val, int add);

AP_DECLARE(int) ap_atomic_int_add_sat(int volatile *val, int add);

AP_DECLARE(int) ap_atomic_int_sub(int volatile *val, int sub);

AP_DECLARE(int) ap_atomic_int_sub_sat(int volatile *val, int sub);


/* Atomics for unsigned int (uses uint32_t's on all platforms we care about) */

AP_DECLARE(unsigned int) ap_atomic_uint_get(unsigned int volatile *val);

AP_DECLARE(void) ap_atomic_uint_set(unsigned int volatile *val,
                                    unsigned int to);

AP_DECLARE(unsigned int) ap_atomic_uint_xchg(unsigned int volatile *val,
                                             unsigned int with);

AP_DECLARE(unsigned int) ap_atomic_uint_cas(unsigned int volatile *val,
                                            unsigned int with,
                                            unsigned int cmp);

AP_DECLARE(unsigned int) ap_atomic_uint_add(unsigned int volatile *val,
                                            unsigned int add);

AP_DECLARE(unsigned int) ap_atomic_uint_add_sat(unsigned int volatile *val,
                                                unsigned int add);

AP_DECLARE(unsigned int) ap_atomic_uint_sub(unsigned int volatile *val,
                                            unsigned int sub);

AP_DECLARE(unsigned int) ap_atomic_uint_sub_sat(unsigned int volatile *val,
                                                unsigned int sub);


/* Atomics for long (uses int32_t's or int64_t's depending on LONG_MAX) */

AP_DECLARE(long) ap_atomic_long_get(long volatile *val);

AP_DECLARE(void) ap_atomic_long_set(long volatile *val, long to);

AP_DECLARE(long) ap_atomic_long_xchg(long volatile *val, long with);

AP_DECLARE(long) ap_atomic_long_cas(long volatile *val, long with, long cmp);

AP_DECLARE(long) ap_atomic_long_add(long volatile *val, long add);

AP_DECLARE(long) ap_atomic_long_add_sat(long volatile *val, long add);

AP_DECLARE(long) ap_atomic_long_sub(long volatile *val, long sub);

AP_DECLARE(long) ap_atomic_long_sub_sat(long volatile *val, long sub);


/* Atomics for unsigned long (uses uint32_t's or uint64_t's depending on ULONG_MAX) */

AP_DECLARE(unsigned long) ap_atomic_ulong_get(unsigned long volatile *val);

AP_DECLARE(void) ap_atomic_ulong_set(unsigned long volatile *val,
                                     unsigned long to);

AP_DECLARE(unsigned long) ap_atomic_ulong_xchg(unsigned long volatile *val,
                                               unsigned long with);

AP_DECLARE(unsigned long) ap_atomic_ulong_cas(unsigned long volatile *val,
                                              unsigned long with,
                                              unsigned long cmp);

AP_DECLARE(unsigned long) ap_atomic_ulong_add(unsigned long volatile *val,
                                              unsigned long add);

AP_DECLARE(unsigned long) ap_atomic_ulong_add_sat(unsigned long volatile *val,
                                                  unsigned long add);

AP_DECLARE(unsigned long) ap_atomic_ulong_sub(unsigned long volatile *val,
                                              unsigned long sub);

AP_DECLARE(unsigned long) ap_atomic_ulong_sub_sat(unsigned long volatile *val,
                                                  unsigned long sub);


/* Atomics for size_t (uses uint32_t's or uint64_t's depending on sizeof(void*)) */

AP_DECLARE(apr_size_t) ap_atomic_size_get(apr_size_t volatile *val);

AP_DECLARE(void) ap_atomic_size_set(apr_size_t volatile *val,
                                    apr_size_t to);

AP_DECLARE(apr_size_t) ap_atomic_size_xchg(apr_size_t volatile *val,
                                           apr_size_t with);

AP_DECLARE(apr_size_t) ap_atomic_size_cas(apr_size_t volatile *val,
                                          apr_size_t with,
                                          apr_size_t cmp);

AP_DECLARE(apr_size_t) ap_atomic_size_add(apr_size_t volatile *val,
                                          apr_size_t add);

AP_DECLARE(apr_size_t) ap_atomic_size_add_sat(apr_size_t volatile *val,
                                              apr_size_t add);

AP_DECLARE(apr_size_t) ap_atomic_size_sub(apr_size_t volatile *val,
                                          apr_size_t sub);

AP_DECLARE(apr_size_t) ap_atomic_size_sub_sat(apr_size_t volatile *val,
                                              apr_size_t sub);
