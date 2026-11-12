import glob
import os
import re
import subprocess

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pyhttpd.conf import HttpdConf
from pyhttpd.depends import needs_dependency
from .env import FiltersTestEnv

# mod_crypto's ENCRYPT and DECRYPT filters, in both filter stacks, with and
# without a configured CryptoIV, for bodies below, at and above CryptoSize.
# The filters work in rounds of CryptoSize input bytes, so sizes around the
# round boundary are the interesting ones.

KEY = bytes(range(32))
IV = bytes(range(100, 116))
SIZE = 4096
SIZES = [0, 1, 15, 16, 17, SIZE - 1, SIZE, SIZE + 1, SIZE + 16, 3 * SIZE,
         3 * SIZE + 1, 100000]


def plain(size):
    return bytes((i * 7 + size) & 0xff for i in range(size))


def encrypt(iv, data):
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(KEY), modes.CBC(iv)).encryptor()
    return enc.update(padder.update(data) + padder.finalize()) + enc.finalize()


def decrypt(iv, data):
    unpadder = padding.PKCS7(128).unpadder()
    dec = Cipher(algorithms.AES(KEY), modes.CBC(iv)).decryptor()
    return unpadder.update(dec.update(data) + dec.finalize()) + unpadder.finalize()


def crypto_driver(env):
    """The name of an apr crypto driver this apr-util has, or None.
    Naming a driver that cannot be loaded keeps httpd from starting."""
    bindir = env.get_apxs_var("APR_BINDIR")
    for config, subdir in [("apu-1-config", "apr-util-1"),
                           ("apr-2-config", "apr-2")]:
        config = os.path.join(bindir, config)
        if not os.path.isfile(config):
            continue
        p = subprocess.run([config, "--link-ld"], capture_output=True, text=True)
        m = re.search(r'-L(\S+)', p.stdout)
        if not m:
            continue
        pattern = os.path.join(m.group(1), subdir, "apr_crypto_*.so")
        for so in sorted(glob.glob(pattern)):
            m = re.match(r'apr_crypto_(\w+?)(-\d+)?\.so$', os.path.basename(so))
            if m:
                return m.group(1)
    return None


@needs_dependency("mod_crypto", FiltersTestEnv.has_shared_module("crypto"),
                  reason="mod_crypto not available")
class TestCrypto:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        driver = crypto_driver(env)
        env.require(driver is not None, "no apr crypto driver available",
                    dep="apr_crypto")
        docs = os.path.join(env.server_dir, "htdocs", "crypto")
        for sub in ["plain", "enc-iv", "enc-noiv"]:
            os.makedirs(os.path.join(docs, sub), exist_ok=True)
        key_file = os.path.join(env.gen_dir, "crypto.key")
        iv_file = os.path.join(env.gen_dir, "crypto.iv")
        for fname, content in [(key_file, KEY), (iv_file, IV)]:
            with open(fname, "wb") as fd:
                fd.write(content)
        for size in SIZES:
            data = plain(size)
            iv = os.urandom(16)
            for sub, content in [("plain", data),
                                 ("enc-iv", encrypt(IV, data)),
                                 ("enc-noiv", iv + encrypt(iv, data))]:
                with open(os.path.join(docs, sub, str(size)), "wb") as fd:
                    fd.write(content)

        def location(path, filter_dir, flt, with_iv):
            return [
                f"<Location {path}>",
                f"    Set{filter_dir}Filter {flt}",
                f"    CryptoSize {SIZE}",
                "    CryptoCipher aes256 cbc",
                f"    CryptoKey file:{key_file}",
                f"    CryptoIV file:{iv_file}" if with_iv else "    CryptoIV none",
                "</Location>",
            ]

        conf = HttpdConf(env)
        conf.add(f"CryptoDriver {driver}")
        conf.start_vhost(domains=[f"crypto.{env.http_tld}"],
                         port=env.http_port, doc_root="htdocs/crypto")
        conf.add([
            f"Alias /enc-iv {docs}/plain",
            f"Alias /enc-noiv {docs}/plain",
            f"Alias /dec-iv {docs}/enc-iv",
            f"Alias /dec-noiv {docs}/enc-noiv",
        ])
        conf.add(location("/enc-iv", "Output", "ENCRYPT", True))
        conf.add(location("/enc-noiv", "Output", "ENCRYPT", False))
        conf.add(location("/dec-iv", "Output", "DECRYPT", True))
        conf.add(location("/dec-noiv", "Output", "DECRYPT", False))
        for path in ["/in-enc-iv", "/in-enc-noiv", "/in-dec-iv", "/in-dec-noiv"]:
            conf.add(f"Alias {path} {env.server_dir}/htdocs/cgi")
        conf.add(location("/in-enc-iv", "Input", "ENCRYPT", True))
        conf.add(location("/in-enc-noiv", "Input", "ENCRYPT", False))
        conf.add(location("/in-dec-iv", "Input", "DECRYPT", True))
        conf.add(location("/in-dec-noiv", "Input", "DECRYPT", False))
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, path):
        r = env.curl_get(env.mkurl("http", "crypto", path))
        assert r.exit_code == 0, r
        assert r.response["status"] == 200, r
        return r.response["body"]

    def post(self, env, path, data):
        fpath = os.path.join(env.gen_dir, "crypto-body")
        with open(fpath, "wb") as fd:
            fd.write(data)
        r = env.curl_get(env.mkurl("http", "crypto", f"{path}/echo.py"),
                         options=["--data-binary", f"@{fpath}",
                                  "-H", "Content-Type: application/octet-stream"])
        assert r.exit_code == 0, r
        assert r.response["status"] == 200, r
        return r.response["body"]

    # ENCRYPT output filter, configured iv: the output is the ciphertext
    @pytest.mark.parametrize("size", SIZES)
    def test_filters_005_01(self, env, size):
        assert self.get(env, f"/enc-iv/{size}") == encrypt(IV, plain(size))

    # ENCRYPT output filter, generated iv: the iv leads the ciphertext
    @pytest.mark.parametrize("size", SIZES)
    def test_filters_005_02(self, env, size):
        body = self.get(env, f"/enc-noiv/{size}")
        assert len(body) == 16 + len(encrypt(IV, plain(size)))
        assert decrypt(body[:16], body[16:]) == plain(size)

    # DECRYPT output filter, configured iv
    @pytest.mark.parametrize("size", SIZES)
    def test_filters_005_03(self, env, size):
        assert self.get(env, f"/dec-iv/{size}") == plain(size)

    # DECRYPT output filter, iv read from the stream
    @pytest.mark.parametrize("size", SIZES)
    def test_filters_005_04(self, env, size):
        assert self.get(env, f"/dec-noiv/{size}") == plain(size)

    # ENCRYPT input filter, configured iv
    @pytest.mark.parametrize("size", SIZES)
    def test_filters_005_05(self, env, size):
        body = self.post(env, "/in-enc-iv", plain(size))
        assert body == encrypt(IV, plain(size))

    # ENCRYPT input filter, generated iv
    @pytest.mark.parametrize("size", SIZES)
    def test_filters_005_06(self, env, size):
        body = self.post(env, "/in-enc-noiv", plain(size))
        assert len(body) == 16 + len(encrypt(IV, plain(size)))
        assert decrypt(body[:16], body[16:]) == plain(size)

    # DECRYPT input filter, configured iv
    @pytest.mark.parametrize("size", SIZES)
    def test_filters_005_07(self, env, size):
        body = self.post(env, "/in-dec-iv", encrypt(IV, plain(size)))
        assert body == plain(size)

    # DECRYPT input filter, iv read from the stream
    @pytest.mark.parametrize("size", SIZES)
    def test_filters_005_08(self, env, size):
        iv = os.urandom(16)
        body = self.post(env, "/in-dec-noiv", iv + encrypt(iv, plain(size)))
        assert body == plain(size)
