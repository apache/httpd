# ====================================================================
# Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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
# Makefile for the Apache example module
# 

#
# This normally lives in modules/example under the Apache source
# directory.  If the depth or relationship changes, the following line
# may need to be changed.
#
INCDIR=../..

#
# Everything below this point should be invariant.
#
SHELL=/bin/sh

#
# We inherit the definitions of CC, AUX_CFLAGS, and RANLIB from an
# upline make(1) call.
#
CFLAGS=-I$(INCDIR) $(AUX_CFLAGS)

MODULES=mod_example.o
OBJS= \
    $(MODULES)

#
# Now the rules saying how things are built.
#
.c.o:
	$(CC) -c $(CFLAGS) $<

all:	$(OBJS)

clean:
	rm -f $(OBJS) 

#
# Finally, what depnds upon which, so make can figure out what it needs
# to do.
#

#
# Make sure that things get rebuilt if the Makefiles are changed.
#
$(OBJS): \
    Makefile \
    $(INCDIR)/Makefile

mod_example.o: \
    $(INCDIR)/httpd.h \
    $(INCDIR)/http_config.h \
    $(INCDIR)/http_core.h \
    $(INCDIR)/http_log.h \
    $(INCDIR)/http_main.h \
    $(INCDIR)/http_protocol.h \
    $(INCDIR)/util_script.h \
    mod_example.c
