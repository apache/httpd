libmod_http.la: http_core.lo http_protocol.lo http_request.lo http_filters.lo chunk_filter.lo byterange_filter.lo
	$(MOD_LINK) http_core.lo http_protocol.lo http_request.lo http_filters.lo chunk_filter.lo byterange_filter.lo $(MOD_HTTP_LDADD)
mod_mime.la: mod_mime.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_mime.lo $(MOD_MIME_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_http.la
shared =  mod_mime.la
