# For gcc
CC= gcc
# For ANSI compilers
#CC= cc

#For Optimization
#CFLAGS= -O2
#For debugging
CFLAGS= -g
# For SCO ODT
#EXTRA_LIBS= -lcrypt_i

INCLUDES= -I../src

RM= /bin/rm -f
#--- You shouldn't have to edit anything else. ---

.c.o: 
	$(CC) -c $(CFLAGS) $(INCLUDES) $<

TARGETS=htpasswd htdigest unescape inc2shtml httpd_monitor rotatelogs

all: $(TARGETS)

aux:
	make all CC=gcc CFLAGS=-O2

ibm:
	make all CC=gcc

sun:
	make all CC=gcc

hp:
	make all CC=gcc

sgi:
	make all CC=cc

decmips:
	make all CC=cc

decaxp:
	make all CC=cc

sco5:
	make all CC=cc

sco3:
	make all CC=cc EXTRA_LIBS=-lcrypt_i


tar: htpasswd unescape
	$(RM) htpasswd unescape

htpasswd: htpasswd.c
	$(CC) $(CFLAGS) htpasswd.c -o htpasswd $(EXTRA_LIBS)

htdigest: htdigest.c
	$(CC) $(CFLAGS) htdigest.c -o htdigest

unescape: unescape.c
	$(CC) $(CFLAGS) unescape.c -o unescape

inc2shtml: inc2shtml.c
	$(CC) $(CFLAGS) inc2shtml.c -o inc2shtml

httpd_monitor: httpd_monitor.c
	$(CC) $(INCLUDES) $(CFLAGS) httpd_monitor.c -o httpd_monitor

clean:
	rm -f $(TARGETS)

