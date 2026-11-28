import http.client
import os
import shutil
import struct
import time

import pytest

from pyhttpd.conf import HttpdConf

# SDBM page size, see apr-util dbm/sdbm/sdbm_private.h
SDBM_PBLKSIZ = 1024


def _sdbm_read_page(page):
    """Return the (key, value) pairs stored in an SDBM page."""
    n = struct.unpack_from("=h", page, 0)[0]
    ino = struct.unpack_from(f"={n + 1}h", page, 0)
    pairs = []
    end = SDBM_PBLKSIZ
    for i in range(1, n, 2):
        pairs.append((page[ino[i]:end], page[ino[i + 1]:ino[i]]))
        end = ino[i + 1]
    return pairs


def _sdbm_make_page(pairs):
    """Pack (key, value) pairs into an SDBM page, as putpair() does."""
    page = bytearray(SDBM_PBLKSIZ)
    ino = [0]
    off = SDBM_PBLKSIZ
    for key, val in pairs:
        off -= len(key)
        page[off:off + len(key)] = key
        ino.append(off)
        off -= len(val)
        page[off:off + len(val)] = val
        ino.append(off)
    ino[0] = len(ino) - 1
    struct.pack_into(f"={len(ino)}h", page, 0, *ino)
    return bytes(page)


def _sdbm_update(pag_file, match, update):
    """Replace the value of the one pair whose key contains 'match'."""
    with open(pag_file, "rb") as fd:
        data = bytearray(fd.read())
    found = 0
    for start in range(0, len(data), SDBM_PBLKSIZ):
        page = bytes(data[start:start + SDBM_PBLKSIZ])
        if len(page) < SDBM_PBLKSIZ:
            break
        pairs = _sdbm_read_page(page)
        if not any(match in key for key, _ in pairs):
            continue
        pairs = [(key, update(val) if match in key else val)
                 for key, val in pairs]
        data[start:start + SDBM_PBLKSIZ] = _sdbm_make_page(pairs)
        found += 1
    assert found == 1, f"expected one page with key {match!r}, found {found}"
    with open(pag_file, "wb") as fd:
        fd.write(data)


class TestSocacheTruncated:

    BODY = b"socache test body\n"

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("socache_dbm"),
                    "mod_socache_dbm not built", dep="mod_socache_dbm")
        cache_dir = os.path.join(env.gen_dir, "socache")
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
        os.makedirs(cache_dir)
        TestSocacheTruncated.DBM = os.path.join(cache_dir, "cache")
        docs = os.path.join(env.server_docs_dir, "test1", "socache")
        os.makedirs(docs, exist_ok=True)
        fpath = os.path.join(docs, "entry.bin")
        with open(fpath, "wb") as fd:
            fd.write(self.BODY)
        # old enough for a heuristic freshness lifetime of a few hours
        old = time.time() - 86400
        os.utime(fpath, (old, old))
        base = []
        mod_path = os.path.join(env.libexec_dir, "mod_socache_dbm.so")
        if os.path.isfile(mod_path):
            base.append(f'LoadModule socache_dbm_module "{mod_path}"')
        base.extend([
            f'CacheSocache dbm:{TestSocacheTruncated.DBM}',
            'CacheHeader on',
        ])
        conf = HttpdConf(env, extras={
            'base': base,
            f"test1.{env.http_tld}": [
                'CacheEnable socache /socache/',
            ],
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0, env.apachectl_stderr

    @staticmethod
    def _get(env, conn):
        conn.request("GET", "/socache/entry.bin", headers={
            "Host": f"test1.{env.http_tld}:{env.http_port}",
        })
        r = conn.getresponse()
        return r.status, r.getheader("X-Cache", ""), r.read()

    def test_cache_002_01_truncated_entry(self, env):
        """A socache entry cut short right after the CR that ends the
        request headers must not make the body length underflow."""
        pag_file = f"{TestSocacheTruncated.DBM}.pag"
        conn = http.client.HTTPConnection(env.http_addr, env.http_port,
                                          timeout=10)
        try:
            status, xcache, body = self._get(env, conn)
            assert status == 200
            assert body == self.BODY
            if not os.path.isfile(pag_file):
                pytest.skip("default APR DBM is not SDBM, cannot edit the "
                            "cache entry")
            # served from the cache, which leaves the entire entry in
            # the recycled buffer the next lookup on this connection uses
            status, xcache, body = self._get(env, conn)
            assert status == 200
            assert xcache.startswith("HIT"), xcache
            assert body == self.BODY

            def truncate(val):
                assert val.endswith(b"\r\n\r\n" + self.BODY), val
                # keep only the CR of the request headers' final CRLF
                return val[:-(len(self.BODY) + 1)]
            _sdbm_update(pag_file, b"/socache/entry.bin", truncate)

            status, xcache, body = self._get(env, conn)
            assert status == 200
            assert xcache.startswith("HIT"), xcache
            assert len(body) <= len(self.BODY)
        finally:
            conn.close()
