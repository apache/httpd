import logging
import os
import pytest

from pyhttpd.conf import HttpdConf
from .samples import SAMPLES, write_samples

log = logging.getLogger(__name__)

# (sample, mod_mime_magic type, mod_mime_magic encoding, mod_mime_libmagic type)
# mod_mime_magic uses the stock conf/magic and its token-based text
# detection, which knows nothing of most of these, so many are untyped.
EXPECTED = [
    ("html", "text/html", None, "text/html"),
    ("html-doctype", None, None, "text/html"),
    ("text", None, None, "text/plain"),
    ("text-utf8", None, None, "text/plain"),
    ("text-latin1", None, None, "text/plain"),
    ("csrc", "text/plain", None, "text/x-c"),
    ("json", None, None, "application/json"),
    ("xml", "text/xml", None, "text/xml"),
    ("rfc822", "message/rfc822", "7bit", "message/rfc822"),
    ("shell", None, None, "text/x-shellscript"),
    ("png", "image/png", None, "image/png"),
    ("gif", "image/gif", None, "image/gif"),
    ("pdf", None, None, "application/pdf"),
    ("gzip", "application/octet-stream", "x-gzip", "application/gzip"),
    ("elf", None, None, "application/x-executable"),
    ("binary", None, None, None),
    ("empty", "text/plain", None, "text/plain"),
    ("png.txt", "text/plain", None, "text/plain"),
]


def get_headers(env, host, path):
    r = env.curl_get(env.mkurl("http", host, path))
    assert r.response, "no response: server may have crashed"
    assert r.response["status"] == 200, r.response
    h = r.response["header"]
    return h.get("content-type"), h.get("content-encoding")


class TestCompare:
    """The same files served by mod_mime_magic (vhost test1) and by
    mod_mime_libmagic (vhost test2)."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        if not env.has_libmagic_module:
            pytest.skip("mod_mime_libmagic is not built")
        for vhost in ["test1", "test2"]:
            write_samples(os.path.join(env.server_dir, "htdocs", vhost, "cmp"))
        # No MimeMagicFile in the main server, so test2 inherits no
        # magic rules and only mod_mime_libmagic runs there.
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f'MimeMagicFile "{env.prefix}/conf/magic"',
            f"test2.{env.http_tld}": "MimeLibmagic On",
        })
        conf.add_vhost_test1()
        conf.add_vhost_test2()
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize(["name", "mm_type", "mm_enc", "lm_type"], EXPECTED)
    def test_metadata_003_01_mime_magic(self, env, name, mm_type, mm_enc, lm_type):
        assert get_headers(env, "test1", f"/cmp/{name}") == (mm_type, mm_enc)

    @pytest.mark.parametrize(["name", "mm_type", "mm_enc", "lm_type"], EXPECTED)
    def test_metadata_003_02_libmagic(self, env, name, mm_type, mm_enc, lm_type):
        assert get_headers(env, "test2", f"/cmp/{name}") == (lm_type, None)

    # Log a side-by-side table of what the two modules actually report.
    def test_metadata_003_03_report(self, env):
        rows = [("sample", "mod_mime_magic", "mod_mime_libmagic")]
        for name in list(SAMPLES) + ["png.txt"]:
            mm = get_headers(env, "test1", f"/cmp/{name}")
            lm = get_headers(env, "test2", f"/cmp/{name}")
            fmt = lambda t: f"{t[0]}" + (f" ({t[1]})" if t[1] else "")
            rows.append((name, fmt(mm), fmt(lm)))
        widths = [max(len(r[i]) for r in rows) for i in range(3)]
        table = "\n".join("  ".join(c.ljust(widths[i]) for i, c in enumerate(r))
                          for r in rows)
        log.info("content types reported:\n%s", table)
        with open(os.path.join(env.gen_dir, "mime-compare.txt"), "w") as f:
            f.write(table + "\n")
