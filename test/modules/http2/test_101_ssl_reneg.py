import re
import pytest

from .env import H2Conf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        domain = f"ssl.{env.http_tld}"
        conf = H2Conf(env, extras={
            'base': [
                "SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384",
                f"<Directory \"{env.server_dir}/htdocs/ssl-client-verify\">",
                "    Require all granted",
                "    SSLVerifyClient require",
                "    SSLVerifyDepth 0",
                "</Directory>"
            ],
            domain: [
                "Protocols h2 http/1.1",
                "<Location /renegotiate/cipher>",
                "    SSLCipherSuite ECDHE-RSA-CHACHA20-POLY1305",
                "</Location>",
                "<Location /renegotiate/err-doc-cipher>",
                "    SSLCipherSuite ECDHE-RSA-CHACHA20-POLY1305",
                "    ErrorDocument 403 /forbidden.html",
                "</Location>",
                "<Location /renegotiate/verify>",
                "    SSLVerifyClient require",
                "</Location>",
                f"<Directory \"{env.server_dir}/htdocs/sslrequire\">",
                "    SSLRequireSSL",
                "</Directory>",
                f"<Directory \"{env.server_dir}/htdocs/requiressl\">",
                "    Require ssl",
                "</Directory>",
        ]})
        conf.add_vhost(domains=[domain], port=env.https_port,
                       doc_root=f"{env.server_dir}/htdocs")
        conf.install()
        # the dir needs to exists for the configuration to have effect
        env.mkpath("%s/htdocs/ssl-client-verify" % env.server_dir)
        env.mkpath("%s/htdocs/renegotiate/cipher" % env.server_dir)
        env.mkpath("%s/htdocs/sslrequire" % env.server_dir)
        env.mkpath("%s/htdocs/requiressl" % env.server_dir)
        assert env.apache_restart() == 0

    # access a resource with SSL renegotiation, using HTTP/1.1
    def test_h2_101_01(self, env):
        url = env.mkurl("https", "ssl", "/renegotiate/cipher/")
        r = env.curl_get(url, options=["-v", "--http1.1", "--tlsv1.2", "--tls-max", "1.2"])
        assert 0 == r.exit_code, f"{r}"
        assert r.response
        assert 403 == r.response["status"]
        
    # try to renegotiate the cipher, should fail with correct code
    def test_h2_101_02(self, env):
        url = env.mkurl("https", "ssl", "/renegotiate/cipher/")
        r = env.curl_get(url, options=[
            "-vvv", "--tlsv1.2", "--tls-max", "1.2", "--ciphers", "ECDHE-RSA-AES256-GCM-SHA384"
        ])
        assert 0 != r.exit_code
        assert not r.response
        assert re.search(r'HTTP_1_1_REQUIRED \(err 13\)', r.stderr)
        
    # try to renegotiate a client certificate from Location 
    # needs to fail with correct code
    def test_h2_101_03(self, env):
        url = env.mkurl("https", "ssl", "/renegotiate/verify/")
        r = env.curl_get(url, options=["-vvv", "--tlsv1.2", "--tls-max", "1.2"])
        assert 0 != r.exit_code
        assert not r.response
        assert re.search(r'HTTP_1_1_REQUIRED \(err 13\)', r.stderr)
        
    # try to renegotiate a client certificate from Directory 
    # needs to fail with correct code
    def test_h2_101_04(self, env):
        url = env.mkurl("https", "ssl", "/ssl-client-verify/index.html")
        r = env.curl_get(url, options=["-vvv", "--tlsv1.2", "--tls-max", "1.2"])
        assert 0 != r.exit_code, f"{r}"
        assert not r.response
        assert re.search(r'HTTP_1_1_REQUIRED \(err 13\)', r.stderr)
        
    # make 10 requests on the same connection, none should produce a status code
    # reported by erki@example.ee
    def test_h2_101_05(self, env):
        r = env.run([env.h2load, "-n", "10", "-c", "1", "-m", "1", "-vvvv",
                     f"{env.https_base_url}/ssl-client-verify/index.html"])
        assert 0 == r.exit_code
        r = env.h2load_status(r)
        assert 10 == r.results["h2load"]["requests"]["total"]
        assert 10 == r.results["h2load"]["requests"]["started"]
        assert 10 == r.results["h2load"]["requests"]["done"]
        assert 0 == r.results["h2load"]["requests"]["succeeded"]
        assert 0 == r.results["h2load"]["status"]["2xx"]
        assert 0 == r.results["h2load"]["status"]["3xx"]
        assert 0 == r.results["h2load"]["status"]["4xx"]
        assert 0 == r.results["h2load"]["status"]["5xx"]

    # Check that "SSLRequireSSL" works on h2 connections
    # See <https://bz.apache.org/bugzilla/show_bug.cgi?id=62654>
    def test_h2_101_10a(self, env):
        url = env.mkurl("https", "ssl", "/sslrequire/index.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert 404 == r.response["status"]

    # Check that "require ssl" works on h2 connections
    # See <https://bz.apache.org/bugzilla/show_bug.cgi?id=62654>
    def test_h2_101_10b(self, env):
        url = env.mkurl("https", "ssl", "/requiressl/index.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert 404 == r.response["status"]
        
    # Check that status works with ErrorDoc, see pull #174, fixes #172
    def test_h2_101_11(self, env):
        url = env.mkurl("https", "ssl", "/renegotiate/err-doc-cipher")
        r = env.curl_get(url, options=[
            "-vvv", "--tlsv1.2", "--tls-max", "1.2", "--ciphers", "ECDHE-RSA-AES256-GCM-SHA384"
        ])
        assert 0 != r.exit_code
        assert not r.response
        assert re.search(r'HTTP_1_1_REQUIRED \(err 13\)', r.stderr)
