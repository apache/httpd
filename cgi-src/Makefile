# For gcc
CC= gcc
# For ANSI compilers
#CC= cc

#For Optimization
#CFLAGS= -O2
#For debugging
CFLAGS= -g

RM= /bin/rm -f
#--- You shouldn't have to edit anything else. ---

.c.o: 
	$(CC) -c $(CFLAGS) $<

all: query post-query imagemap jj phf

att:
	make all CC=gcc CFLAGS="-O2 -DNO_STDLIB_H"

aux:
	make all CC=gcc CFLAGS=-O2

aix3:
	make all CC=gcc

aix4:
	make all CC=gcc

hp-gcc:
	make all CC=gcc

hp-cc:
	make all CC=cc CFLAGS=-Ae

linux:
	make all CC=gcc

netbsd:	
	make all CC=cc

next:
	make all CC=cc

osf1:
	make all CC=cc

sgi:
	make all CC=cc

solaris:
	make all CC=gcc

sunos:
	make all CC=gcc

svr4:
	make all CC=cc

ultrix:
	make all CC=gcc

post-query: post-query.o util.o
	$(CC) post-query.o util.o -o ../cgi-bin/post-query

query: query.o util.o
	$(CC) query.o util.o -o ../cgi-bin/query

imagemap: imagemap.o
	$(CC) imagemap.o -o ../cgi-bin/imagemap

jj: jj.o util.o
	$(CC) jj.o util.o -o ../cgi-bin/jj

phf: phf.o util.o
	$(CC) phf.o util.o -o ../cgi-bin/phf

change-passwd: change-passwd.o util.o
	$(CC) change-passwd.o util.o -o ../sec-cgi/change-passwd

clean:
	rm -f *.o ../cgi-bin/post-query ../cgi-bin/query ../sec-cgi/change-passwd ../cgi-bin/phf ../cgi-bin/jj ../cgi-bin/imagemap

