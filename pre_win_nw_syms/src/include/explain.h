
#ifdef __cplusplus
extern "C" {
#endif

#ifndef EXPLAIN
#define DEF_Explain
#define Explain0(f)
#define Explain1(f,a1)
#define Explain2(f,a1,a2)
#define Explain3(f,a1,a2,a3)
#define Explain4(f,a1,a2,a3,a4)
#define Explain5(f,a1,a2,a3,a4,a5)
#define Explain6(f,a1,a2,a3,a4,a5,a6)
#else
#include "http_log.h"
#define DEF_Explain
#define Explain0(f) \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f)
#define Explain1(f,a1) \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1)
#define Explain2(f,a1,a2) \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1,a2)
#define Explain3(f,a1,a2,a3) \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1,a2,a3)
#define Explain4(f,a1,a2,a3,a4) \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1,a2,a3,a4)
#define Explain5(f,a1,a2,a3,a4,a5)  \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1,a2,a3,a4,a5)
#define Explain6(f,a1,a2,a3,a4,a5,a6)   \
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL, \
                    f,a1,a2,a3,a4,a5,a6)

#endif

#ifdef __cplusplus
}
#endif
