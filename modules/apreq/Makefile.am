TEST_CONFIG_SCRIPT = package Apache::TestMM; filter_args(); generate_script("t/TEST")
mod_apreq2_la_LDFLAGS = -export-dynamic -module -avoid-version \
                        `@APREQ_CONFIG@ --link-libtool --libs` @APR_LTFLAGS@
mod_apreq2_la_SOURCES = apreq_private_apache2.h handle.c filter.c

pkgcfgdir = `@APACHE2_APXS@ -q SYSCONFDIR`
pkgincludedir = `@APACHE2_APXS@ -q INCLUDEDIR`/@APREQ_LIBNAME@
pkglibdir = `@APACHE2_APXS@ -q LIBEXECDIR`

AM_CPPFLAGS = @APACHE2_INCLUDES@ @APR_INCLUDES@

if BUILD_HTTPD

# XXX FIXME: static builds don't work anymore
# mod_apreq2 needs to be built from httpd-2.X, e.g.
#
# % cd ../httpd-2.X;
# % ./configure --with-module=filters:../httpd-apreq-2/module/apache2/mod_apreq2.c ...
#
# See the INSTALL file for details.

@APACHE2_HTTPD@:
	cd @APACHE2_SRC@ && $(MAKE)

all-local: @APACHE2_HTTPD@

else

pkginclude_HEADERS = apreq_module_apache2.h
pkglib_LTLIBRARIES = mod_apreq2.la

install-exec-local :
	@echo "----------------------------------------------------------------------"
	@echo "Before you can use mod_apreq2, you must ensure that an appropriate"
	@echo "\"LoadModule\" line appears in your webserver's config file:"
	@echo "$(pkgcfgdir)/httpd.conf"
	@echo 
	@echo "LoadModule apreq_module    $(pkglibdir)/mod_apreq2.so"
	@echo "----------------------------------------------------------------------"

endif
