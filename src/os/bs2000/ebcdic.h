#ifndef AP_EBCDIC_H
#define AP_EBCDIC_H  "$Id: ebcdic.h,v 1.8 2000/06/21 14:36:32 martin Exp $"

#include <sys/types.h>

extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
API_EXPORT(void *) ebcdic2ascii(void *dest, const void *srce, size_t count);
API_EXPORT(void *) ascii2ebcdic(void *dest, const void *srce, size_t count);

#endif /*AP_EBCDIC_H*/
