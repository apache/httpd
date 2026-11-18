"""mod_authn_dbd's extra query columns must survive a socache cache hit.

AuthDBDUserPWQuery may select columns beyond the password (documented
feature: modules/aaa/mod_authn_dbd.c exports each extra column as
AUTHENTICATE_<NAME> in r->subprocess_env). With AuthBasicProvider
"socache dbd", the first (uncached) login goes through
authn_dbd_password() and gets those variables; mod_authn_socache then
caches only the password hash. Every following login for the same user,
while the cache entry is still fresh, is answered by mod_authn_socache's
own check_password() directly from the cached hash -- authn_dbd_password()
is never called again, so AUTHENTICATE_* is silently absent (PR 65172).
"""

from .env import AAATestEnv


class TestAuthnDbdSocacheCache:

    def url(self, env):
        return env.mkurl("http", "aaa", "/dbd/cgi/whoami.py")

    def whoami(self, env, user=AAATestEnv.DBD_USER):
        r = env.curl_get(self.url(env), options=[
            "-u", f"{user}:{AAATestEnv.DBD_PASSWORD}",
        ])
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200, f"{r}"
        return r.response["body"].decode()

    def test_authn_dbd_017_role_survives_cached_login(self, env):
        # First login: a cache miss, goes through the real DBD query.
        body1 = self.whoami(env)
        assert f"user={AAATestEnv.DBD_USER}" in body1
        assert f"role={AAATestEnv.DBD_ROLE}" in body1, \
            f"AUTHENTICATE_ROLE missing on the first (uncached) login: {body1!r}"

        # Second login with the same credentials, within AuthnCacheTimeout:
        # a cache hit. Unpatched, AUTHENTICATE_ROLE silently disappears here
        # because authn_dbd_password() (the only code that sets it) is
        # never invoked for a cache hit.
        body2 = self.whoami(env)
        assert f"user={AAATestEnv.DBD_USER}" in body2
        assert f"role={AAATestEnv.DBD_ROLE}" in body2, \
            f"AUTHENTICATE_ROLE lost on a cached login: {body2!r}"

    def test_authn_dbd_017_long_role_not_cached(self, env):
        # The role does not fit in a cache value with the hash: the login
        # must not be cached, so that every one goes through the DBD query
        # and gets the role, rather than a cache hit without it.
        user = AAATestEnv.DBD_LONG_USER
        for _ in range(2):
            body = self.whoami(env, user=user)
            assert f"user={user}" in body
            assert f"role={AAATestEnv.DBD_LONG_ROLE}" in body, \
                f"AUTHENTICATE_ROLE missing: {body!r}"
