import pytest
import re

from pyhttpd.conf import HttpdConf
from .env import TCPFaker

magic_numbers = b"\x41\x42"
send_headers_type = b"\x04"
send_chunk_type = b"\x03"
status_code_200 = b"\x00\xc8"
status_msg_ok = b"OK"
ajp_max_size = 8192


def ajp_packet_from_tomcat(body):
    return magic_numbers + len(body).to_bytes(2, "big") + body


class _AJPFaker(TCPFaker):

    @staticmethod
    def max_size_message(data):
        body = send_headers_type + b"\x00" * (ajp_max_size - 1)
        return ajp_packet_from_tomcat(body)

    @staticmethod
    def num_headers_len(data):
        # message_type(send_headers) + status_code_200 + len(inner_body)
        # + "OK"
        body = (send_headers_type
                + status_code_200
                + len(status_msg_ok).to_bytes(2, "big")
                + status_msg_ok
                + b"\x00")
        return ajp_packet_from_tomcat(body)

    @staticmethod
    def missing_null_terminator(data):
        # message_type(send_headers) + status_code_200 + len(inner_body)
        # + "OK" without null terminator
        body = (send_headers_type
                + status_code_200
                + len(status_msg_ok).to_bytes(2, "big")
                + status_msg_ok)
        return ajp_packet_from_tomcat(body)

    @staticmethod
    def tiny_body_chunk(data):
        # message_type(send_body_chunk) + chunk_size(0xffff),3 bytes total
        chunk_body = (send_chunk_type + b"\xff\xff")
        return ajp_packet_from_tomcat(chunk_body)


class TestProxyAjp:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        if not env.has_shared_module("proxy_ajp"):
            pytest.skip("mod_proxy_ajp not available")
        faker = _AJPFaker("127.0.0.1", env.http_port2)
        faker.start()
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port)
        conf.add([
            f"ProxyPass / ajp://127.0.0.1:{env.http_port2}/",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield faker
        faker.stop()

    def test_proxy_004_01(self, env, _class_scope):
        _class_scope._make_response = _AJPFaker.max_size_message
        r = env.curl_get(env.mkurl("http", "test1", "/"))
        assert r.response["status"] == 503
        try:
            found = env.httpd_error_log.scan_recent(
                re.compile(r'.*AH01081:.*'), timeout=5)
        except TimeoutError:
            found = False

        assert found
        env.httpd_error_log.ignore_recent(
            lognos=["AH01081", "AH01080", "AH01031", "AH00878", "AH00992"])

    def test_proxy_004_02(self, env, _class_scope):
        _class_scope._make_response = _AJPFaker.tiny_body_chunk
        env.curl_get(env.mkurl("http", "test1", "/"))
        try:
            found = env.httpd_error_log.scan_recent(
                re.compile(r'.*ajp_parse_data: Message too small.*'),
                timeout=5)
        except TimeoutError:
            found = False

        assert found
        env.httpd_error_log.ignore_recent(
            lognos=["AH00893"],
            matches=[r'.*ajp_parse_data: Message too small.*'])

    def test_proxy_004_03(self, env, _class_scope):
        _class_scope._make_response = _AJPFaker.num_headers_len
        r = env.curl_get(env.mkurl("http", "test1", "/"))
        assert r.exit_code == 0

        _class_scope._make_response = _AJPFaker.missing_null_terminator
        r = env.curl_get(env.mkurl("http", "test1", "/"))
        assert r.exit_code == 0

        try:
            found = env.httpd_error_log.scan_recent(
                re.compile(r'.*AH03229: ajp_msg_get_uint16.*'), timeout=5)
        except TimeoutError:
            found = False
        assert found

        try:
            found = env.httpd_error_log.scan_recent(
                re.compile(r'.*AH03229: ajp_msg_get_string.*'), timeout=5)
        except TimeoutError:
            found = False
        assert found

        env.httpd_error_log.ignore_recent(
            lognos=["AH03229", "AH10405", "AH00985", "AH00893"])
