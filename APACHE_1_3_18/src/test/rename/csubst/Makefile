
CC = gcc
CFLAGS = -O2 -I.
LDFLAGS = 
LIBS = 

LEX  = flex
YACC = bison -y

PROG = csubst
OBJS = csubst.o lexer.o util.o

.c.o:
	$(CC) $(CFLAGS) -c $<

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROG) $(OBJS) $(LIBS)

lexer.c: lexer.l
	$(LEX) lexer.l
	mv lex.yy.c lexer.c

clean: 
	-rm -f $(PROG) *.o

distclean: clean 

realclean: distclean
	-rm -f lexer.c

mostlyclean: clean

