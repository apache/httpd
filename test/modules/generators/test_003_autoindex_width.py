import os
import re
import textwrap

import pytest

from pyhttpd.conf import HttpdConf

# NameWidth padding used to measure a filename with strlen(), which counts
# UTF-8 bytes, not terminal columns: a multi-byte character (e.g. a 3-byte
# CJK character, which only occupies 2 columns in a monospaced rendering)
# made the padding overcompensate, throwing the following columns out of
# alignment (BZ 70101). A plain ASCII name and a CJK name are placed so
# that the CJK one has fewer display columns but more bytes, which is
# exactly the case that byte-counting gets backwards.
ASCII_NAME = "abcde12345.txt"           # 14 bytes, 14 columns
CJK_NAME = "中文测试.txt"  # 16 bytes, 12 columns

# A name made of 4-byte UTF-8 characters that fall outside every "wide"
# range ai_utf8_colwidth() recognizes (e.g. U+1F600, an emoji): each
# character is 1 display column but 4 raw bytes, a 4:1 byte-to-column
# ratio. Forcing NameWidth below the name's display width exercises the
# truncation path with this worst-case ratio.
EMOJI_NAME = ("\U0001F600" * 30) + ".txt"
TRUNC_NAME_WIDTH = 20

# Under IndexOptions Charset=ISO-8859-1, each byte of a name is one
# rendered column: there is no multi-byte decoding to do. LATIN1_NAME's
# raw bytes (written with the filesystem's UTF-8 locale) happen to also
# form a valid 2-byte UTF-8 sequence ("é" -> 0xC3 0xA9), which is
# common for accented Latin-1 names. If width measurement decodes it as
# UTF-8 regardless of the declared charset, it undercounts this name by
# one column against a same-byte-length measurement that doesn't.
LATIN1_ASCII_NAME = "plainfile1234.txt"      # 17 bytes, 17 columns
LATIN1_NAME = "abécd.txt"               # 10 bytes, 10 columns under ISO-8859-1


class TestAutoindexWidth:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_docs_dir, "autoindex_width")
        os.makedirs(doc_dir, exist_ok=True)
        with open(os.path.join(doc_dir, ASCII_NAME), "w") as f:
            f.write("hello\n")
        with open(os.path.join(doc_dir, CJK_NAME), "w", encoding="utf-8") as f:
            f.write("hello\n")

        trunc_dir = os.path.join(env.server_docs_dir, "autoindex_trunc")
        os.makedirs(trunc_dir, exist_ok=True)
        with open(os.path.join(trunc_dir, EMOJI_NAME), "w", encoding="utf-8") as f:
            f.write("hello\n")

        latin1_dir = os.path.join(env.server_docs_dir, "autoindex_latin1")
        os.makedirs(latin1_dir, exist_ok=True)
        with open(os.path.join(latin1_dir, LATIN1_ASCII_NAME), "w") as f:
            f.write("hello\n")
        with open(os.path.join(latin1_dir, LATIN1_NAME), "w", encoding="utf-8") as f:
            f.write("hello\n")

        conf = HttpdConf(env, extras={
            "base": textwrap.dedent(f"""
            <Directory "{doc_dir}">
                Options +Indexes
                IndexOptions Charset=UTF-8 NameWidth=* FancyIndexing \
                             SuppressIcon SuppressDescription
            </Directory>
            <Directory "{trunc_dir}">
                Options +Indexes
                IndexOptions Charset=UTF-8 NameWidth={TRUNC_NAME_WIDTH} \
                             FancyIndexing SuppressIcon SuppressDescription
            </Directory>
            <Directory "{latin1_dir}">
                Options +Indexes
                IndexOptions Charset=ISO-8859-1 NameWidth=* FancyIndexing \
                             SuppressIcon SuppressDescription
            </Directory>
            """),
        })
        conf.install()
        assert env.apache_restart() == 0

    # The two rows must end up at the same total display column right
    # before the "Last modified" field: (display width of the visible
    # name) + (padding spaces) must be equal for both, even though the
    # CJK name is shorter in columns but longer in bytes than the ASCII
    # one.
    def test_generators_003_01(self, env):
        r = env.curl_get(env.mkurl("http", "htdocs", "/autoindex_width/"))
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")

        ascii_m = re.search(r'>' + re.escape(ASCII_NAME) + r'</a>( *)', body)
        cjk_m = re.search(r'>' + re.escape(CJK_NAME) + r'</a>( *)', body)
        assert ascii_m and cjk_m, f"could not find both names in: {body}"

        ascii_total = len(ASCII_NAME) + len(ascii_m.group(1))
        cjk_total = 12 + len(cjk_m.group(1))
        assert ascii_total == cjk_total, \
            f"columns not aligned: ascii row ends at {ascii_total}, " \
            f"cjk row ends at {cjk_total}"

    # With a fixed NameWidth smaller than the name's display width, the
    # name gets truncated into name_scratch. Each 4-byte, non-wide
    # character the truncation keeps costs 4 raw bytes for 1 of the
    # (name_width - 3) display columns budgeted to it, so the truncated
    # byte length can be up to 4x the column budget -- this must not
    # overflow name_scratch nor corrupt whatever pool memory follows it
    # (observed, pre-fix, as stray bytes leaking into the padding that
    # is supposed to separate the name from "Last modified").
    def test_generators_003_02(self, env):
        r = env.curl_get(env.mkurl("http", "htdocs", "/autoindex_trunc/"))
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")

        visible_chars = TRUNC_NAME_WIDTH - 3
        expected_trunc = ("\U0001F600" * visible_chars) + "..&gt;"
        m = re.search(r'>' + re.escape(expected_trunc)
                       + r'</a>( *)(\d{4}-\d{2}-\d{2})', body)
        assert m, \
            "truncated name not followed by clean padding and a " \
            f"timestamp (possible pool corruption): {body}"

    # IndexOptions Charset only ever controls the declared Content-Type;
    # width measurement must follow suit rather than decoding every name
    # as UTF-8 regardless. With a single-byte charset declared, the two
    # rows must align on byte count the same way test_generators_003_01
    # aligns on UTF-8 display width.
    def test_generators_003_03(self, env):
        r = env.curl_get(env.mkurl("http", "htdocs", "/autoindex_latin1/"))
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")

        ascii_m = re.search(r'>' + re.escape(LATIN1_ASCII_NAME) + r'</a>( *)',
                             body)
        latin1_m = re.search(r'>' + re.escape(LATIN1_NAME) + r'</a>( *)', body)
        assert ascii_m and latin1_m, f"could not find both names in: {body}"

        ascii_total = len(LATIN1_ASCII_NAME) + len(ascii_m.group(1))
        latin1_total = 10 + len(latin1_m.group(1))
        assert ascii_total == latin1_total, \
            f"columns not aligned: ascii row ends at {ascii_total}, " \
            f"latin1 row ends at {latin1_total}"
