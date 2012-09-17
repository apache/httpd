top_srcdir   = /Users/jim/src/asf/code/dev/httpd-trunk
top_builddir = /Users/jim/src/asf/code/dev/httpd-trunk
srcdir       = /Users/jim/src/asf/code/dev/httpd-trunk/test
builddir     = /Users/jim/src/asf/code/dev/httpd-trunk/test
VPATH        = /Users/jim/src/asf/code/dev/httpd-trunk/test

# no targets: we don't want to build anything by default. if you want the
# test programs, then "make test"
TARGETS =

bin_PROGRAMS =

PROGRAM_LDADD        = $(EXTRA_LDFLAGS) $(PROGRAM_DEPENDENCIES) $(EXTRA_LIBS)
PROGRAM_DEPENDENCIES =  \
	$(top_srcdir)/srclib/apr-util/libaprutil.la \
	$(top_srcdir)/srclib/apr/libapr.la

include $(top_builddir)/build/rules.mk

test: $(bin_PROGRAMS)

# example for building a test proggie
# dbu_OBJECTS = dbu.lo
# dbu: $(dbu_OBJECTS)
#	$(LINK) $(dbu_OBJECTS) $(PROGRAM_LDADD)
