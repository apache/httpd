# Makefile for the Apache httpd. 

# For normal machines with ANSI compilers
# CC= cc
# For Suns or other non-ANSI platforms. Please make sure your gcc is
# 2.0 or later, as 1.40 seems to create bad code for the Sun 4.
CC= gcc -Wall

# CFLAGS, compile flags.

# If you want no reverse hostname resolution, use -DMINIMAL_DNS
# If you want to have more secure hostname resolution at the cost of some 
# performance, use -DMAXIMUM_DNS

#CFLAGS= -O2 
CFLAGS= -g 

# Modules precompiled with the server.  Note that these must also be
# in the list in modules.c in order to be active.

MODULES = mod_mime.o mod_access.o mod_alias.o mod_cgi.o mod_include.o \
	mod_dir.o mod_auth.o mod_auth_dbm.o mod_negotiation.o mod_userdir.o \
	mod_log_common.o mod_asis.o

# Place here any extra libraries you may need to link to. 
# If you want DBM auth, -lndbm is commonly required.
EXTRA_LIBS=

# AUX_CFLAGS are system-specific control flags.
# NOTE: IF YOU DO NOT CHOOSE ONE OF THESE, EDIT httpd.h AND CHOOSE
# SETTINGS FOR THE SYSTEM FLAGS. IF YOU DON'T, BAD THINGS WILL HAPPEN.

# For SunOS 4
AUX_CFLAGS= -DSUNOS4
# For Solaris 2.
# AUX_CFLAGS= -DSOLARIS2 -DFCNTL_SERIALIZED_ACCEPT
# EXTRA_LIBS= -lsocket -lnsl
# For SGI IRIX. Use the EXTRA_LIBS line if you're using NIS and want
# user-supported directories
#AUX_CFLAGS= -DIRIX -DFCNTL_SERIALIZED_ACCEPT
#EXTRA_LIBS= -lsun
# For HP-UX
#AUX_CFLAGS= -DHPUX
# For AIX
#AUX_CFLAGS= -DAIX -U__STR__
# For Ultrix
#AUX_CFLAGS= -DULTRIX
# For DEC OSF/1
#AUX_CFLAGS= -DOSF1
# For NeXT
#AUX_CFLAGS= -DNEXT
# For Sequent
#AUX_CFLAGS= -DSEQUENT
# For Linux -m486 ONLY IF YOU HAVE 486 BINARY SUPPORT IN KERNEL
#AUX_CFLAGS= -DLINUX -DFCNTL_SERIALIZED_ACCEPT
# For A/UX
#AUX_CFLAGS= -DAUX
#EXTRA_LIBS= -lbsd -lposix -s
# For SCO ODT
# libcrypt_i available from sosco.sco.com, files /SLS/lng225b.Z and
# /SLS/lng225b.ltr.Z
#AUX_CFLAGS= -DSCO
#EXTRA_LIBS= -lPW -lsocket -lmalloc -lcrypt_i
# For SVR4
#AUX_CFLAGS= -DSVR4
#EXTRA_LIBS= -lsocket -lnsl -lc
# For Amdahl UTS 2.1
# -Xa enables ANSI mode, -eft is expanded types
#AUX_CFLAGS= -Xa -eft -DUTS21
#EXTRA_LIBS= -lsocket -lbsd -la
# For HP/Apollo Domain/OS
#AUX_CFLAGS= -DAPOLLO
# For NetBSD/FreeBSD/BSDI 2.x
# -m486 only if you are running on Intel 486/586
#AUX_CFLAGS= -m486
# BSDI doesn't need -lcrypt
#EXTRA_LIBS= -lcrypt

# Place here any flags you may need upon linking, such as a flag to
# prevent dynamic linking (if desired)
LFLAGS= 

# You shouldn't have to edit anything else.

OBJS= alloc.o http_main.o http_core.o http_config.o http_request.o \
  http_log.o http_protocol.o rfc931.o util.o util_script.o modules.o $(MODULES)

.c.o:
	$(CC) -c $(CFLAGS) $(AUX_CFLAGS) $<

all: httpd

httpd: $(OBJS)
	$(CC) $(LFLAGS) -o httpd $(OBJS) $(EXTRA_LIBS)

clean:
	rm -f httpd $(OBJS) *pure*

#Dependencies
#Core code
$(OBJS): Makefile httpd.h alloc.h conf.h

http_config.o http_core.o http_main.o util.o: http_conf_globals.h
http_config.o http_core.o http_main.o: http_config.h http_log.h
http_log.o http_protocol.o http_request.o modules.o: http_config.h
http_config.o http_core.o http_protocol.o http_request.o: http_core.h
http_protocol.o http_request.o util_script.o: http_log.h
http_core.o http_main.o http_protocol.o http_request.o: http_main.h
http_core.o http_main.o http_protocol.o http_request.o: http_protocol.h
http_config.o http_main.o http_request.o: http_request.h
http_main.o: scoreboard.h

#Modules
$(MODULES): http_config.h
mod_dld.o: http_conf_globals.h
mod_ai_backcompat.o mod_auth.o mod_auth_dbm.o mod_cgi.o mod_dir.o: http_core.h
mod_imap.o mod_include.o mod_negotiation.o: http_core.h
mod_asis.o mod_auth.o mod_auth_dbm.o mod_cgi.o mod_dir.o: http_core.h
mod_imap.o mod_include.o mod_negotiation.o: http_log.h
mod_asis.o mod_cgi.o mod_dir.o mod_imap.o mod_include.o: http_main.h
mod_asis.o mod_auth.o mod_auth_dbm.o mod_cgi.o mod_dir.o: http_protocol.h
mod_imap.o mod_include.o: http_protocol.h
mod_cgi.o mod_dir.o mod_imap.o mod_include.o mod_negotiation.o: http_request.h
mod_asis.o mod_cgi.o mod_dir.o mod_imap.o mod_include.o: util_script.h

#Utils
util.o: http_conf_globals.h
util_script.o: http_core.h http_main.h http_protocol.h util_script.h
