
#include <stdarg.h>

extern void err(int status, const char *fmt, ...);
extern void verr(int status, const char *fmt, va_list ap);
extern void errx(int status, const char *fmt, ...);
extern void verrx(int status, const char *fmt, va_list ap);
extern void warn(const char *fmt, ...);
extern void vwarn(const char *fmt, va_list ap);
extern void warnx(const char *fmt, ...);
extern void vwarnx(const char *fmt, va_list ap);
