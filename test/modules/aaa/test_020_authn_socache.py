"""mod_authn_socache cache-key separation.

Each area under /socache/ is one directory whose low.txt and high.txt
are backed by different htpasswd files holding the same user with a
different password in each file. The areas differ only in how the two
sources are told apart:

- byname:   distinct AuthName per file
- byctx:    distinct AuthnCacheContext per file
- samename: neither; the mod_authn_socache documentation states that
            the default context shares cache entries in this case
"""

from .env import AAATestEnv


class TestAuthnSocache:

    def url(self, env, path):
        return env.mkurl("http", "aaa", path)

    def get(self, env, path, password):
        user = AAATestEnv.SOCACHE_USER
        return env.curl_get(self.url(env, path),
                            options=["-u", f"{user}:{password}"])

    def check_separated(self, env, area):
        low = AAATestEnv.SOCACHE_PASSWORD_LOW
        high = AAATestEnv.SOCACHE_PASSWORD_HIGH
        r = self.get(env, f"/socache/{area}/low.txt", low)
        assert r.response["status"] == 200
        assert r.response["body"].decode() == f"socache-{area}-low\n"
        # The password of the sibling source must not authenticate here,
        # neither before nor after its own entry is cached.
        r = self.get(env, f"/socache/{area}/high.txt", low)
        assert r.response["status"] == 401
        r = self.get(env, f"/socache/{area}/high.txt", high)
        assert r.response["status"] == 200
        assert r.response["body"].decode() == f"socache-{area}-high\n"
        r = self.get(env, f"/socache/{area}/low.txt", high)
        assert r.response["status"] == 401
        # A wrong password is rejected even with a warm cache.
        r = self.get(env, f"/socache/{area}/low.txt", "wrongpass2617")
        assert r.response["status"] == 401
        # The 401 responses above are the assertions, not failures.
        env.httpd_error_log.ignore_recent(lognos=["AH01617"])

    def test_socache_001_separated_by_authname(self, env):
        self.check_separated(env, "byname")

    def test_socache_002_separated_by_context(self, env):
        self.check_separated(env, "byctx")

    def test_socache_003_shared_when_undifferentiated(self, env):
        # Same directory, same AuthName, no custom context: the entries
        # are shared, as documented for the default AuthnCacheContext.
        # The first successful login populates the entry, and the cached
        # hash then also answers for the sibling source until it expires.
        low = AAATestEnv.SOCACHE_PASSWORD_LOW
        high = AAATestEnv.SOCACHE_PASSWORD_HIGH
        r = self.get(env, "/socache/samename/low.txt", low)
        assert r.response["status"] == 200
        r = self.get(env, "/socache/samename/high.txt", low)
        assert r.response["status"] == 200
        r = self.get(env, "/socache/samename/high.txt", high)
        assert r.response["status"] == 401
        env.httpd_error_log.ignore_recent(lognos=["AH01617"])
