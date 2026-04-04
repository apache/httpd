# -- Example programs --

# -- server: standalone HTTP/3 server (OpenSSL + nghttp3) --
add_executable(example_server server.c)
set_target_properties(example_server PROPERTIES OUTPUT_NAME server)
target_link_libraries(example_server PRIVATE openssl nghttp3)
apply_target_flags(example_server)

# -- quic_client_test: HTTP/3 client (OpenSSL + nghttp3 + APR) --
add_executable(example_quic_client_test quic_client_test.c)
set_target_properties(example_quic_client_test PROPERTIES OUTPUT_NAME quic_client_test)
target_link_libraries(example_quic_client_test PRIVATE openssl nghttp3 apr)
apply_target_flags(example_quic_client_test)

# -- biomemexample: BIO memory example (OpenSSL only) --
add_executable(example_biomemexample biomemexample.c)
set_target_properties(example_biomemexample PROPERTIES OUTPUT_NAME biomemexample)
target_link_libraries(example_biomemexample PRIVATE openssl)
apply_target_flags(example_biomemexample)

# -- apr_miniserver: APR server (APR only) --
add_executable(example_apr_miniserver miniserver.c)
set_target_properties(example_apr_miniserver PROPERTIES OUTPUT_NAME apr_miniserver)
target_link_libraries(example_apr_miniserver PRIVATE apr)
apply_target_flags(example_apr_miniserver)

# -- quic_server_test: requires OpenSSL internal headers and static archives --
# ossl_quic_tserver_* symbols are hidden in libssl.so; only accessible via libssl.a.
if(NOT MISSING_OPENSSL_STATIC AND TARGET openssl_static)
  add_executable(example_quic_server_test quic_server_test.c)
  set_target_properties(example_quic_server_test PROPERTIES OUTPUT_NAME quic_server_test)
  target_link_libraries(example_quic_server_test PRIVATE openssl_static nghttp3)
  apply_target_flags(example_quic_server_test)
endif()
