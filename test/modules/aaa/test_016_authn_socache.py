"""mod_authn_socache: caching of credentials found by another provider.

The "socache" authn provider only ever answers from its cache, and it never
fills the cache itself: a backing provider (mod_authn_file here) hands over
what it found once it has located a user, if AuthnCacheProvideFor names it.
So socache is listed first and the backing provider after it; the first
request for a user falls through to the file, later ones are answered from
the cache until the entry expires.

Whether an answer came from the cache is not visible in the response, so
these tests make the two sources disagree. A request with the password P1
fills the cache; the password file is then rewritten to hold P2 instead.
From then on an answer from the cache accepts P1 and rejects P2, and an
answer from the file does the opposite.

The cache outlives a test, so each test has a user name of its own.
"""

import os
import time

import pytest

from pyhttpd.conf import HttpdConf
from . import digest_client as dc
from .env import AAATestEnv

P1 = "firstpass2617"
P2 = "secondpass2617"

BODY = "authn-socache-secret\n"

# A second document in each directory, for a <Files> section to give a
# password file of its own.
OTHER = "other.txt"

# Seconds, for the location whose entries are to expire under test.
SHORT_TIMEOUT = 2

# What mod_auth_basic and mod_auth_digest log for a wrong password and
# for an unknown user.
AUTH_FAILURES = ["AH01617", "AH01618", "AH01794", "AH01790"]


def _docdir(env, name):
    return os.path.join(env.server_docs_dir, "socache", name)


def _make_docdir(env, name):
    d = _docdir(env, name)
    os.makedirs(d, exist_ok=True)
    for fname in "secret.txt", OTHER:
        with open(os.path.join(d, fname), 'wb') as fd:
            fd.write(BODY.encode())
    return d


def _basic_lines(pwfile, cache_lines):
    return [
        'AuthType Basic',
        'AuthName "AAA Basic Realm"',
        'AuthBasicProvider socache file',
        f'AuthUserFile "{pwfile}"',
        *cache_lines,
        'Require valid-user',
    ]


def _digest_lines(pwfile, cache_lines):
    return [
        'AuthType Digest',
        f'AuthName "{AAATestEnv.REALM}"',
        'AuthDigestProvider socache file',
        f'AuthUserFile "{pwfile}"',
        *cache_lines,
        'Require valid-user',
    ]


def _directory(env, name, lines):
    return [f'<Directory "{_make_docdir(env, name)}">',
            *(f"    {l}" for l in lines),
            '</Directory>']


# Class scoped, to outlast the error log check made after each test.
@pytest.fixture(scope='class')
def _expect_auth_failures(env):
    env.httpd_error_log.add_ignored_lognos(AUTH_FAILURES)
    yield
    env.httpd_error_log.remove_ignored_lognos(AUTH_FAILURES)


@pytest.mark.usefixtures("_expect_auth_failures")
class _SocacheBase:

    @pytest.fixture(scope='class')
    @classmethod
    def basic_pwfile(cls, env):
        return os.path.join(env.server_dir, "socache-basic.passwd")

    @pytest.fixture(scope='class')
    @classmethod
    def basic_pwfile2(cls, env):
        return os.path.join(env.server_dir, "socache-basic2.passwd")

    @pytest.fixture(scope='class')
    @classmethod
    def digest_pwfile(cls, env):
        return os.path.join(env.server_dir, "socache-digest.passwd")

    def url(self, env, name, fname="secret.txt"):
        return env.mkurl("http", "aaa", f"/socache/{name}/{fname}")

    def basic(self, env, name, user, password, fname="secret.txt"):
        """The status of a Basic authenticated request."""
        r = env.curl_get(self.url(env, name, fname),
                         options=["-u", f"{user}:{password}"])
        assert r.exit_code == 0, r.stderr
        if r.response["status"] == 200:
            assert r.response["body"].decode() == BODY
        return r.response["status"]

    def digest(self, env, name, user, password):
        """The status of a Digest authenticated request, answering a
        fresh challenge."""
        url = self.url(env, name)
        r = env.curl_get(url)
        assert r.response["status"] == 401
        challenge = dc.DigestChallenge.parse(
            r.response["header"]["www-authenticate"])
        auth = dc.build_authorization(
            user, challenge, password, method="GET",
            uri=f"/socache/{name}/secret.txt")
        r = env.curl_get(url, options=["-H", f"Authorization: {auth}"])
        assert r.exit_code == 0, r.stderr
        if r.response["status"] == 200:
            assert r.response["body"].decode() == BODY
        return r.response["status"]


class TestAuthnSocache(_SocacheBase):
    """Run for the default socache provider, when no AuthnCacheSOCache
    is given, and for shmcb by name."""

    @pytest.fixture(autouse=True, scope='class', params=[None, "shmcb"],
                    ids=["default", "shmcb"])
    @classmethod
    def _class_scope(cls, env, request, basic_pwfile, basic_pwfile2,
                     digest_pwfile):
        AAATestEnv.write_basic_pwfile(basic_pwfile, {})
        AAATestEnv.write_basic_pwfile(basic_pwfile2, {})
        env.write_digest_pwfile(digest_pwfile, {})
        cached = ['AuthnCacheProvideFor file']
        conf = HttpdConf(env)
        if request.param:
            conf.add(f'AuthnCacheSOCache {request.param}')
        for name, cache_lines in [
            ("basic", cached),
            # Caches for a provider which is not the one in use.
            ("other", ['AuthnCacheProvideFor dbm']),
            ("none", []),
            ("dir1", cached),
            ("dir2", cached),
            ("literal1", cached + ['AuthnCacheContext shared']),
            ("literal2", cached + ['AuthnCacheContext shared']),
            ("literal3", cached + ['AuthnCacheContext another']),
            ("server1", cached + ['AuthnCacheContext server']),
            ("server2", cached + ['AuthnCacheContext server']),
            ("timeout", cached + [f'AuthnCacheTimeout {SHORT_TIMEOUT}']),
        ]:
            conf.add(_directory(env, name,
                                _basic_lines(basic_pwfile, cache_lines)))
        # One directory with two password files: OTHER has its own.
        for name, other_lines in [
            ("files", []),
            ("files-context", ['AuthnCacheContext other-file']),
        ]:
            conf.add(_directory(env, name, [
                *_basic_lines(basic_pwfile, cached),
                f'<Files "{OTHER}">',
                f'    AuthUserFile "{basic_pwfile2}"',
                *(f"    {l}" for l in other_lines),
                '</Files>',
            ]))
        for name, cache_lines in [
            ("digest", cached),
            ("digest-none", []),
        ]:
            conf.add(_directory(env, name,
                                _digest_lines(digest_pwfile, cache_lines)))
        with env.preserved_test_conf():
            conf.install()
            assert env.apache_restart() == 0
            yield

    def test_authn_socache_160_cached_entry_is_used(self, env, basic_pwfile):
        """A user the backing provider has found is authenticated from the
        cache afterwards, whatever the backing provider would now say."""
        user = "user160"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, "basic", user, P1) == 200
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P2})
        assert self.basic(env, "basic", user, P1) == 200
        AAATestEnv.write_basic_pwfile(basic_pwfile, {})
        assert self.basic(env, "basic", user, P1) == 200

    def test_authn_socache_161_cached_entry_rejects_wrong_password(
            self, env, basic_pwfile):
        """A password which does not match the cached entry is refused
        outright, not passed on to the backing provider."""
        user = "user161"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, "basic", user, P1) == 200
        assert self.basic(env, "basic", user, "wrong") == 401
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P2})
        assert self.basic(env, "basic", user, P2) == 401
        assert self.basic(env, "basic", user, P1) == 200

    def test_authn_socache_162_wrong_password_first(self, env, basic_pwfile):
        """A wrong password is refused when the backing provider answers,
        and that failed attempt caches the user's entry all the same."""
        user = "user162"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, "basic", user, "wrong") == 401
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P2})
        assert self.basic(env, "basic", user, "wrong") == 401
        assert self.basic(env, "basic", user, P1) == 200

    def test_authn_socache_163_unknown_user_not_cached(
            self, env, basic_pwfile):
        """A user the backing provider does not know is refused and
        nothing is remembered about it, so it can log in once created."""
        user = "user163"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {"someone": P1})
        assert self.basic(env, "basic", user, P1) == 401
        assert self.basic(env, "basic", user, P1) == 401
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, "basic", user, P1) == 200

    @pytest.mark.parametrize("name", ["other", "none"])
    def test_authn_socache_164_provide_for_gates_caching(
            self, env, basic_pwfile, name):
        """Nothing is cached for a backing provider AuthnCacheProvideFor
        does not name, nor where the directive is absent."""
        user = f"user164{name}"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, name, user, P1) == 200
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P2})
        assert self.basic(env, name, user, P1) == 401
        assert self.basic(env, name, user, P2) == 200

    def test_authn_socache_165_directory_context(self, env, basic_pwfile):
        """With the default "directory" AuthnCacheContext an entry is only
        good for the directory of the request which cached it."""
        user = "user165"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, "dir1", user, P1) == 200
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P2})
        assert self.basic(env, "dir2", user, P1) == 401
        assert self.basic(env, "dir2", user, P2) == 200
        # and the two entries stay apart
        AAATestEnv.write_basic_pwfile(basic_pwfile, {})
        assert self.basic(env, "dir1", user, P1) == 200
        assert self.basic(env, "dir1", user, P2) == 401
        assert self.basic(env, "dir2", user, P2) == 200
        assert self.basic(env, "dir2", user, P1) == 401

    def test_authn_socache_166_literal_context(self, env, basic_pwfile):
        """Locations with the same literal AuthnCacheContext share their
        entries, and not with one which has a different context."""
        user = "user166"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, "literal1", user, P1) == 200
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P2})
        assert self.basic(env, "literal2", user, P1) == 200
        assert self.basic(env, "literal2", user, P2) == 401
        assert self.basic(env, "literal3", user, P1) == 401
        assert self.basic(env, "literal3", user, P2) == 200

    def test_authn_socache_167_server_context(self, env, basic_pwfile):
        """Locations with the "server" AuthnCacheContext share their
        entries across the server, and not with other contexts."""
        user = "user167"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, "server1", user, P1) == 200
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P2})
        assert self.basic(env, "server2", user, P1) == 200
        assert self.basic(env, "server2", user, P2) == 401
        assert self.basic(env, "basic", user, P1) == 401

    def test_authn_socache_168_timeout(self, env, basic_pwfile):
        """An entry is dropped once AuthnCacheTimeout has passed, and the
        backing provider is asked again."""
        user = "user168"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, "timeout", user, P1) == 200
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P2})
        assert self.basic(env, "timeout", user, P1) == 200
        time.sleep(SHORT_TIMEOUT + 1)
        assert self.basic(env, "timeout", user, P1) == 401
        assert self.basic(env, "timeout", user, P2) == 200

    def test_authn_socache_169_restart_empties_cache(self, env, basic_pwfile):
        """The cache does not survive a restart."""
        user = "user169"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, "basic", user, P1) == 200
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P2})
        assert self.basic(env, "basic", user, P1) == 200
        assert env.apache_restart() == 0
        assert self.basic(env, "basic", user, P1) == 401
        assert self.basic(env, "basic", user, P2) == 200

    def test_authn_socache_170_digest_cached_entry_is_used(
            self, env, digest_pwfile):
        """The hash the backing provider found for a Digest user is served
        from the cache afterwards."""
        user = "user170"
        env.write_digest_pwfile(digest_pwfile, {user: P1})
        assert self.digest(env, "digest", user, P1) == 200
        env.write_digest_pwfile(digest_pwfile, {user: P2})
        assert self.digest(env, "digest", user, P1) == 200
        assert self.digest(env, "digest", user, P2) == 401
        env.write_digest_pwfile(digest_pwfile, {})
        assert self.digest(env, "digest", user, P1) == 200

    def test_authn_socache_171_digest_not_cached_without_provide_for(
            self, env, digest_pwfile):
        """No Digest hash is cached where AuthnCacheProvideFor is absent."""
        user = "user171"
        env.write_digest_pwfile(digest_pwfile, {user: P1})
        assert self.digest(env, "digest-none", user, P1) == 200
        env.write_digest_pwfile(digest_pwfile, {user: P2})
        assert self.digest(env, "digest-none", user, P1) == 401
        assert self.digest(env, "digest-none", user, P2) == 200

    def test_authn_socache_172_digest_unknown_user_not_cached(
            self, env, digest_pwfile):
        """A Digest user the backing provider does not know is refused and
        can log in once created."""
        user = "user172"
        env.write_digest_pwfile(digest_pwfile, {})
        assert self.digest(env, "digest", user, P1) == 401
        env.write_digest_pwfile(digest_pwfile, {user: P1})
        assert self.digest(env, "digest", user, P1) == 200

    def test_authn_socache_173_files_share_directory_context(
            self, env, basic_pwfile, basic_pwfile2):
        """With the default "directory" AuthnCacheContext, documents in
        one directory share their entries even where they use different
        password files."""
        user = "user173"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        AAATestEnv.write_basic_pwfile(basic_pwfile2, {user: P2})
        assert self.basic(env, "files", user, P1) == 200
        assert self.basic(env, "files", user, P1, OTHER) == 200
        assert self.basic(env, "files", user, P2, OTHER) == 401

    def test_authn_socache_174_files_context(
            self, env, basic_pwfile, basic_pwfile2):
        """An AuthnCacheContext of its own keeps the entries for a
        document with a different password file apart from those of the
        rest of the directory."""
        user = "user174"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        AAATestEnv.write_basic_pwfile(basic_pwfile2, {user: P2})
        for _ in range(2):
            # first from the password files, then from the cache
            assert self.basic(env, "files-context", user, P1) == 200
            assert self.basic(env, "files-context", user, P1, OTHER) == 401
            assert self.basic(env, "files-context", user, P2, OTHER) == 200
            assert self.basic(env, "files-context", user, P2) == 401
        AAATestEnv.write_basic_pwfile(basic_pwfile, {})
        AAATestEnv.write_basic_pwfile(basic_pwfile2, {})
        assert self.basic(env, "files-context", user, P1) == 200
        assert self.basic(env, "files-context", user, P2, OTHER) == 200


class TestAuthnSocacheHtaccess(_SocacheBase):
    """AuthnCacheProvideFor given only in .htaccess files."""

    @pytest.fixture(autouse=True, scope='class', params=[True],
                    ids=["enabled"])
    @classmethod
    def enabled(cls, env, request, basic_pwfile):
        AAATestEnv.write_basic_pwfile(basic_pwfile, {})
        d = _make_docdir(env, "htaccess")
        with open(os.path.join(d, ".htaccess"), 'w') as fd:
            fd.write('\n'.join(_basic_lines(
                basic_pwfile, ['AuthnCacheProvideFor file'])))
            fd.write('\n')
        conf = HttpdConf(env)
        if request.param:
            conf.add('AuthnCacheEnable')
        conf.add([f'<Directory "{d}">',
                  '    AllowOverride AuthConfig',
                  '</Directory>'])
        with env.preserved_test_conf():
            conf.install()
            assert env.apache_restart() == 0
            yield request.param

    def test_authn_socache_180_htaccess(self, env, basic_pwfile, enabled):
        """AuthnCacheEnable sets the cache up for .htaccess files to use
        where the configuration itself has no AuthnCacheProvideFor.
        Without it authentication works, uncached."""
        user = "user180"
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P1})
        assert self.basic(env, "htaccess", user, P1) == 200
        AAATestEnv.write_basic_pwfile(basic_pwfile, {user: P2})
        if enabled:
            assert self.basic(env, "htaccess", user, P1) == 200
            assert self.basic(env, "htaccess", user, P2) == 401
        else:
            assert self.basic(env, "htaccess", user, P1) == 401
            assert self.basic(env, "htaccess", user, P2) == 200


class TestAuthnSocacheConfig:

    def test_authn_socache_190_unknown_socache_provider(self, env):
        """AuthnCacheSOCache naming a provider which is not loaded is a
        configuration error."""
        r = env.configtest(['Require all granted'],
                           extra_top_lines=['AuthnCacheSOCache no-such'])
        assert r.exit_code != 0
        assert "Unknown socache provider 'no-such'" in r.stderr

    def test_authn_socache_191_socache_global_only(self, env):
        """AuthnCacheSOCache and AuthnCacheEnable are refused inside a
        virtual host."""
        for directive in ['AuthnCacheSOCache shmcb', 'AuthnCacheEnable']:
            r = env.configtest(['Require all granted'], extra_top_lines=[
                '<VirtualHost *:*>', directive, '</VirtualHost>'])
            assert r.exit_code != 0, directive
            assert directive.split()[0] in r.stderr
