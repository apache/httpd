libmod_http.la: http_core.lo http_protocol.lo http_request.lo http_filters.lo chunk_filter.lo byterange_filter.lo http_etag.lo
	$(MOD_LINK) http_core.lo http_protocol.lo http_request.lo http_filters.lo chunk_filter.lo byterange_filter.lo http_etag.lo $(MOD_HTTP_LDADD)
libmod_mime.la: mod_mime.lo
	$(MOD_LINK) mod_mime.lo $(MOD_MIME_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_http.la libmod_mime.la
shared = 
