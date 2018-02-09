DISTCLEAN_TARGETS = apxs apachectl dbmmanage log_server_status \
	logresolve.pl phf_abuse_log.cgi split-logfile envvars-std

CLEAN_TARGETS = suexec

bin_PROGRAMS = htpasswd htdigest htdbm ab logresolve httxt2dbm
sbin_PROGRAMS = htcacheclean rotatelogs $(NONPORTABLE_SUPPORT)
TARGETS  = $(bin_PROGRAMS) $(sbin_PROGRAMS)

PROGRAM_LDADD        = $(UTIL_LDFLAGS) $(PROGRAM_DEPENDENCIES) $(EXTRA_LIBS) $(AP_LIBS)
PROGRAM_DEPENDENCIES = 

include $(top_builddir)/build/rules.mk

install:
	@test -d $(DESTDIR)$(bindir) || $(MKINSTALLDIRS) $(DESTDIR)$(bindir)
	@test -d $(DESTDIR)$(sbindir) || $(MKINSTALLDIRS) $(DESTDIR)$(sbindir)
	@test -d $(DESTDIR)$(libexecdir) || $(MKINSTALLDIRS) $(DESTDIR)$(libexecdir)
	@cp -p $(top_builddir)/server/httpd.exp $(DESTDIR)$(libexecdir)
	@for i in apxs dbmmanage; do \
	    if test -f "$(builddir)/$$i"; then \
	        cp -p $$i $(DESTDIR)$(bindir); \
	        chmod 755 $(DESTDIR)$(bindir)/$$i; \
	    fi ; \
	done
	@for i in apachectl; do \
	    if test -f "$(builddir)/$$i"; then \
	        cp -p $$i $(DESTDIR)$(sbindir); \
	        chmod 755 $(DESTDIR)$(sbindir)/$$i; \
	    fi ; \
	done
	@if test -f "$(builddir)/envvars-std"; then \
	    cp -p envvars-std $(DESTDIR)$(sbindir); \
	    if test ! -f $(DESTDIR)$(sbindir)/envvars; then \
	        cp -p envvars-std $(DESTDIR)$(sbindir)/envvars ; \
	    fi ; \
	fi

htpasswd.lo: passwd_common.h
passwd_common.lo: passwd_common.h
htpasswd_OBJECTS = htpasswd.lo passwd_common.lo
htpasswd: $(htpasswd_OBJECTS)
	$(LINK) $(htpasswd_LTFLAGS) $(htpasswd_OBJECTS) $(PROGRAM_LDADD) $(CRYPT_LIBS)

htdigest_OBJECTS = htdigest.lo
htdigest: $(htdigest_OBJECTS)
	$(LINK) $(htdigest_LTFLAGS) $(htdigest_OBJECTS) $(PROGRAM_LDADD)

rotatelogs_OBJECTS = rotatelogs.lo
rotatelogs: $(rotatelogs_OBJECTS)
	$(LINK) $(rotatelogs_LTFLAGS) $(rotatelogs_OBJECTS) $(PROGRAM_LDADD)

logresolve_OBJECTS = logresolve.lo
logresolve: $(logresolve_OBJECTS)
	$(LINK) $(logresolve_LTFLAGS) $(logresolve_OBJECTS) $(PROGRAM_LDADD)

htdbm.lo: passwd_common.h
htdbm_OBJECTS = htdbm.lo passwd_common.lo
htdbm: $(htdbm_OBJECTS)
	$(LINK) $(htdbm_LTFLAGS) $(htdbm_OBJECTS) $(PROGRAM_LDADD) $(CRYPT_LIBS)

ab_OBJECTS = ab.lo
ab_LDADD = $(PROGRAM_LDADD) $(MATH_LIBS) $(ab_LIBS)
ab.lo: ab.c
	$(LIBTOOL) --mode=compile $(CC) $(ab_CFLAGS) $(ALL_CFLAGS) $(ALL_CPPFLAGS) \
	    $(ALL_INCLUDES) $(PICFLAGS) $(LTCFLAGS) -c $< && touch $@
ab: $(ab_OBJECTS)
	$(LIBTOOL) --mode=link $(CC) $(ALL_CFLAGS) $(PILDFLAGS) \
	    $(LT_LDFLAGS) $(ALL_LDFLAGS) -o $@ $(ab_LTFLAGS) $(ab_OBJECTS) $(ab_LDADD)

checkgid_OBJECTS = checkgid.lo
checkgid: $(checkgid_OBJECTS)
	$(LINK) $(checkgid_LTFLAGS) $(checkgid_OBJECTS) $(PROGRAM_LDADD)

suexec_OBJECTS = suexec.lo
suexec: $(suexec_OBJECTS)
	$(LINK) $(suexec_OBJECTS)

htcacheclean_OBJECTS = htcacheclean.lo
htcacheclean: $(htcacheclean_OBJECTS)
	$(LINK) $(htcacheclean_LTFLAGS) $(htcacheclean_OBJECTS) $(PROGRAM_LDADD)

httxt2dbm_OBJECTS = httxt2dbm.lo
httxt2dbm: $(httxt2dbm_OBJECTS)
	$(LINK) $(httxt2dbm_LTFLAGS) $(httxt2dbm_OBJECTS) $(PROGRAM_LDADD)

fcgistarter_OBJECTS = fcgistarter.lo
fcgistarter: $(fcgistarter_OBJECTS)
	$(LINK) $(fcgistarter_LTFLAGS) $(fcgistarter_OBJECTS) $(PROGRAM_LDADD)
