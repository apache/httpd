#
# Makefile for building the default Apache
#
# This Makefile builds either a "standard" or a "lint" Apache. If you
# want to build a custom Apache, read the instructions in the src/
# directory in the file INSTALL.
#
PERL=/usr/bin/perl
SERVERROOT=/usr/local/apache

all: src/httpd 

src/httpd:
	(cd src; \
	  test ! -f Configuration && cp Configuration.tmpl Configuration; \
	  ./Configure -file Configuration; $(MAKE) all support)

lint: 
	(cd src; $(PERL) ./helpers/MakeLint; \
	 ./Configure -file Configuration.lint; \
	 $(MAKE) all support)

install: src/httpd
	-src/helpers/InstallApache $(SERVERROOT)

clean:
	(cd src; make clean)
