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
# For OS/2 port
#EXTRA_LIBS= -llibufc


INCLUDES= -I../src

RM= /bin/rm -f
#--- You shouldn't have to edit anything else. ---

.c.o: 
	$(CC) -c $(CFLAGS) $(INCLUDES) $<

TARGETS=htpasswd htdigest httpd_monitor rotatelogs logresolve

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


tar: htpasswd 
	$(RM) htpasswd

htpasswd: htpasswd.c
	$(CC) $(CFLAGS) htpasswd.c -o htpasswd $(EXTRA_LIBS)

htdigest: htdigest.c
	$(CC) $(CFLAGS) htdigest.c -o htdigest

httpd_monitor: httpd_monitor.c
	$(CC) $(INCLUDES) $(CFLAGS) httpd_monitor.c -o httpd_monitor

rotatelogs: rotatelogs.c
	$(CC) $(INCLUDES) $(CFLAGS) rotatelogs.c -o rotatelogs

logresolve: logresolve.c
	$(CC) $(INCLUDES) $(CFLAGS) logresolve.c -o logresolve

clean:
	rm -f $(TARGETS)

