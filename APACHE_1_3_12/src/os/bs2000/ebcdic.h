#ifndef AP_EBCDIC_H
#define AP_EBCDIC_H  "$Id: ebcdic.h,v 1.7 2000/01/07 16:04:12 martin Exp $"

#include <sys/types.h>

extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
void *ebcdic2ascii(void *dest, const void *srce, size_t count);
void *ascii2ebcdic(void *dest, const void *srce, size_t count);

#endif /*AP_EBCDIC_H*/
