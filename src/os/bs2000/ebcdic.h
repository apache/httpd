#ifndef AP_EBCDIC_H
#define AP_EBCDIC_H  "$Id: ebcdic.h,v 1.6 1999/12/09 16:55:54 martin Exp $"

#include <sys/types.h>

extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
void *ebcdic2ascii(void *dest, const void *srce, size_t count);
void *ascii2ebcdic(void *dest, const void *srce, size_t count);

/* Provide backward compatibility until all EBCDIC platforms
 * have switched to using ebcdic2ascii() only: 
 */
#define ebcdic2ascii_strictly(_to,_from,_len) ebcdic2ascii(_to,_from,_len)

#endif /*AP_EBCDIC_H*/
