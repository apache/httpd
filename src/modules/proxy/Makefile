# ====================================================================
# Copyright (c) 1995 The Apache Group.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. All advertising materials mentioning features or use of this
#    software must display the following acknowledgment:
#    "This product includes software developed by the Apache Group
#    for use in the Apache HTTP server project (http://www.apache.org/)."
#
# 4. The names "Apache Server" and "Apache Group" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission.
#
# 5. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by the Apache Group
#    for use in the Apache HTTP server project (http://www.apache.org/)."
#
# THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
# EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
# ====================================================================
#
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Group and was originally based
# on public domain software written at the National Center for
# Supercomputing Applications, University of Illinois, Urbana-Champaign.
# For more information on the Apache Group and the Apache HTTP server
# project, please see <http://www.apache.org/>.
# 
# Makefile for the Apache proxy library
# 
# $Id: Makefile,v 1.1 1996/09/26 12:35:16 chuck Exp $
#

SHELL = /bin/sh

INCDIR=../..

# define -DEXPLAIN if you want verbose debugging output
CFLAGS=-I. -I$(INCDIR) $(AUX_CFLAGS)

# Internal stuff, should not need changing.
OBJS=mod_proxy.o
PROXYSRC=mod_proxy.c

default:	lib

lib:	$(OBJS)
	rm -f libproxy.a
	ar crv libproxy.a $(OBJS)
	$(RANLIB) libproxy.a

# dependencies
mod_proxy.o: $(INCDIR)/http_log.h
mod_proxy.o: $(INCDIR)/http_main.h
mod_proxy.o: $(INCDIR)/http_protocol.h
mod_proxy.o: $(INCDIR)/md5.h
mod_proxy.o: $(INCDIR)/explain.h

# various forms of cleanup
tidy:
	rm -f *.out

clean:	tidy
	rm -f *.o libproxy.a
