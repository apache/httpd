# For gcc
CC= gcc
# For ANSI compilers
#CC= cc

#For Optimization
#CFLAGS= -O2
#For debugging
CFLAGS= -g -Wall
# For SCO ODT
#EXTRA_LIBS= -lcrypt_i
# For OS/2 port
#EXTRA_LIBS= -llibufc -lsocket

# If you turned on extra status logging with the -DSTATUS flag in the
# Configuration file, you _must_ uncomment the following line for
# httpd_monitor to work (remember that httpd_monitor only works if
# you are using a scoreboard file -- on most systems the scoreboard
# will be held in memory and httpd_monitor will not work)
STATUS=-DSTATUS

INCLUDES= -I../src -I../src/regex

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
	$(CC) $(INCLUDES) $(CFLAGS) $(STATUS) httpd_monitor.c -o httpd_monitor

rotatelogs: rotatelogs.c
	$(CC) $(INCLUDES) $(CFLAGS) rotatelogs.c -o rotatelogs

logresolve: logresolve.c
	$(CC) $(INCLUDES) $(CFLAGS) logresolve.c -o logresolve $(EXTRA_LIBS)

clean:
	rm -f $(TARGETS)

