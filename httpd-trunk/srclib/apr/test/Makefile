srcdir = .


# PROGRAMS includes all test programs built on this platform.
# STDTEST_PORTABLE
#   test programs invoked via standard user interface, run on all platforms
# TESTS
#   test modules invoked through the abts suite (./testall)
# STDTEST_NONPORTABLE
#   test programs invoked via standard user interface, not portable
# OTHER_PROGRAMS
#   programs such as sendfile, that have to be invoked in a special sequence
#   or with special parameters
# TESTALL_COMPONENTS
#   programs such as globalmutexchild which the various TESTS will invoke
#   to validate process creation, pipes, dso mechansims and so forth

STDTEST_PORTABLE = \
	testlockperf \
	testmutexscope \
	testall

TESTS = testtime.lo teststr.lo testvsn.lo testipsub.lo testshm.lo \
	testmmap.lo testud.lo testtable.lo testsleep.lo testpools.lo \
	testfmt.lo testfile.lo testdir.lo testfileinfo.lo testrand.lo \
	testdso.lo testoc.lo testdup.lo testsockets.lo testproc.lo \
	testpoll.lo testlock.lo testsockopt.lo testpipe.lo testthread.lo \
	testhash.lo testargs.lo testnames.lo testuser.lo testpath.lo \
	testenv.lo testprocmutex.lo testfnmatch.lo testatomic.lo testflock.lo \
	testsock.lo testglobalmutex.lo teststrnatcmp.lo testfilecopy.lo \
	testtemp.lo testlfs.lo testcond.lo

OTHER_PROGRAMS = \
	sendfile \
	echod \
	sockperf

TESTALL_COMPONENTS = \
	globalmutexchild \
	libmod_test.la \
	mod_test.la \
	occhild \
	proc_child \
	readchild \
	sockchild \
	testshmproducer \
	testshmconsumer \
	tryread

PROGRAMS = $(TESTALL_COMPONENTS) $(STDTEST_PORTABLE) $(STDTEST_NONPORTABLE) \
	   $(OTHER_PROGRAMS)

TARGETS = $(PROGRAMS)

# bring in rules.mk for standard functionality
include /Users/jim/src/asf/code/dev/httpd-trunk/srclib/apr/build/apr_rules.mk

LOCAL_LIBS=../libapr-${APR_MAJOR_VERSION}.la

CLEAN_TARGETS = testfile.tmp lfstests/*.bin \
	data/test*.txt data/test*.dat data/apr.testshm.shm

CLEAN_SUBDIRS = internal

INCDIR=../include
INCLUDES=-I$(INCDIR) -I$(srcdir)/../include

# link programs using -no-install to get real executables not
# libtool wrapper scripts which link an executable when first run.
LINK_PROG = $(LIBTOOL) $(LTFLAGS) --mode=link $(LT_LDFLAGS) $(COMPILE) \
	     $(ALL_LDFLAGS) -o $@

# STDTEST_PORTABLE;

abts.lo: $(srcdir)/abts.c $(srcdir)/abts.h $(srcdir)/abts_tests.h \
	 $(srcdir)/testutil.h

testutil.lo: $(srcdir)/abts.c $(srcdir)/abts.h $(srcdir)/abts_tests.h \
	     $(srcdir)/testutil.h

OBJECTS_testall = abts.lo testutil.lo $(TESTS) $(LOCAL_LIBS)
testall: $(OBJECTS_testall)
	$(LINK_PROG) $(OBJECTS_testall) $(ALL_LIBS)
# For VPATH builds; where we have no ./data, copy us some data
# if we wait until 'make check', then 'make; ./testall' fails;
	if test ! -d "./data"; then cp -r $(srcdir)/data data; fi

OBJECTS_testlockperf = testlockperf.lo $(LOCAL_LIBS)
testlockperf: $(OBJECTS_testlockperf)
	$(LINK_PROG) $(OBJECTS_testlockperf) $(ALL_LIBS)

OBJECTS_testmutexscope = testmutexscope.lo $(LOCAL_LIBS)
testmutexscope: $(OBJECTS_testmutexscope)
	$(LINK_PROG) $(OBJECTS_testmutexscope) $(ALL_LIBS)

# OTHER_PROGRAMS;

OBJECTS_echod = echod.lo $(LOCAL_LIBS)
echod: $(OBJECTS_echod)
	$(LINK_PROG) $(OBJECTS_echod) $(ALL_LIBS)

OBJECTS_sendfile = sendfile.lo $(LOCAL_LIBS)
sendfile: $(OBJECTS_sendfile)
	$(LINK_PROG) $(OBJECTS_sendfile) $(ALL_LIBS)

OBJECTS_sockperf = sockperf.lo $(LOCAL_LIBS)
sockperf: $(OBJECTS_sockperf)
	$(LINK_PROG) $(OBJECTS_sockperf) $(ALL_LIBS)

# TESTALL_COMPONENTS;

OBJECTS_globalmutexchild = globalmutexchild.lo $(LOCAL_LIBS)
globalmutexchild: $(OBJECTS_globalmutexchild)
	$(LINK_PROG) $(OBJECTS_globalmutexchild) $(ALL_LIBS)

# Note -prefer-pic is only supported with libtool-1.4+
mod_test.lo: $(srcdir)/mod_test.c
	$(LIBTOOL) $(LTFLAGS) --mode=compile $(COMPILE) -prefer-pic -o $@ \
	  -c $(srcdir)/mod_test.c

OBJECTS_mod_test = mod_test.lo
mod_test.la: $(OBJECTS_mod_test)
	$(LIBTOOL) $(LTFLAGS) --mode=link $(COMPILE) -rpath `pwd` -module \
	  -avoid-version $(LT_LDFLAGS) $(ALL_LDFLAGS) -o $@ \
	  $(OBJECTS_mod_test)

OBJECTS_libmod_test = mod_test.lo $(LOCAL_LIBS)
libmod_test.la: $(OBJECTS_libmod_test)
	$(LIBTOOL) $(LTFLAGS) --mode=link $(COMPILE) -rpath `pwd` \
	  -avoid-version $(LT_LDFLAGS) $(ALL_LDFLAGS) -o $@ \
	  $(OBJECTS_libmod_test) $(ALL_LIBS)

OBJECTS_occhild = occhild.lo $(LOCAL_LIBS)
occhild: $(OBJECTS_occhild)
	$(LINK_PROG) $(OBJECTS_occhild) $(ALL_LIBS)

OBJECTS_proc_child = proc_child.lo $(LOCAL_LIBS)
proc_child: $(OBJECTS_proc_child)
	$(LINK_PROG) $(OBJECTS_proc_child) $(ALL_LIBS)

OBJECTS_readchild = readchild.lo $(LOCAL_LIBS)
readchild: $(OBJECTS_readchild)
	$(LINK_PROG) $(OBJECTS_readchild) $(ALL_LIBS)

OBJECTS_sockchild = sockchild.lo $(LOCAL_LIBS)
sockchild: $(OBJECTS_sockchild)
	$(LINK_PROG) $(OBJECTS_sockchild) $(ALL_LIBS)

OBJECTS_testshmconsumer = testshmconsumer.lo $(LOCAL_LIBS)
testshmconsumer: $(OBJECTS_testshmconsumer) $(LOCAL_LIBS)
	$(LINK_PROG) $(OBJECTS_testshmconsumer) $(ALL_LIBS)

OBJECTS_testshmproducer = testshmproducer.lo $(LOCAL_LIBS)
testshmproducer: $(OBJECTS_testshmproducer)
	$(LINK_PROG) $(OBJECTS_testshmproducer) $(ALL_LIBS)

OBJECTS_tryread = tryread.lo $(LOCAL_LIBS)
tryread: $(OBJECTS_tryread)
	$(LINK_PROG) $(OBJECTS_tryread) $(ALL_LIBS)

check: $(TESTALL_COMPONENTS) $(STDTEST_PORTABLE) $(STDTEST_NONPORTABLE)
	teststatus=0; \
	progfailed=""; \
	for prog in $(STDTEST_PORTABLE) $(STDTEST_NONPORTABLE); do \
		./$$prog; \
		status=$$?; \
		if test $$status != 0; then \
			teststatus=$$status; \
			progfailed="$$progfailed $$prog"; \
		fi; \
	done; \
	if test $$teststatus != 0; then \
		echo "Programs failed:$$progfailed"; \
	fi; \
	exit $$teststatus

# DO NOT REMOVE
