"""mod_authn_socache: the cache key must keep protection spaces apart.

construct_key() builds the socache key from the context, provider, auth
type, user and realm.  When those fields are joined with a plain ':'
delimiter, a field that itself contains a ':' can shift a field boundary,
so two different (user, realm) tuples can produce the same key.  With Digest
authentication the username is client-supplied and may contain a ':', so a
low-privilege account named "victim:admin" in the realm "zone" collides with
the user "victim" in the realm "admin:zone":

    <context>:dbd:digest:victim:admin:zone   (user "victim:admin", realm "zone")
    <context>:dbd:digest:victim:admin:zone   (user "victim",       realm "admin:zone")

A backing provider that keeps the fields apart (mod_authn_dbd, with the user
and realm in separate columns) authenticates the two correctly, but once the
first is cached the second is answered from the colliding entry.  The
attacker primes the entry from the realm it controls, then authenticates as
the target user in the target realm with the wrong password.  RFC 9110
Section 11.5 scopes credentials to their protection space (origin plus
realm), so this must not happen: the key has to be injective.
"""

import hashlib
import os
import sqlite3

import pytest

from pyhttpd.conf import HttpdConf
from . import digest_client as dc

BODY = "authn-socache-dbd-key-secret\n"

# A low-privilege account whose name contains the ':' delimiter, and the
# target account it must not be able to impersonate.
ATTACKER = "victim:admin"
ATTACKER_REALM = "zone"
ATTACKER_PASSWORD = "lowpass2617"

VICTIM = "victim"
VICTIM_REALM = "admin:zone"
VICTIM_PASSWORD = "highpass2617"

# auth_digest/authn_dbd log a password mismatch and a missing user.
AUTH_FAILURES = ["AH01790", "AH01794", "AH01760"]


def _ha1(user, realm, password):
    return hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()


def _docdir(env, name):
    return os.path.join(env.server_docs_dir, "skey", name)


def _make_docdir(env, name):
    d = _docdir(env, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "secret.txt"), 'wb') as fd:
        fd.write(BODY.encode())
    return d


def _digest_dir(env, name, realm, require, context, dbpath):
    return [
        f'<Directory "{_make_docdir(env, name)}">',
        '    AuthType Digest',
        f'    AuthName "{realm}"',
        '    AuthDigestProvider socache dbd',
        '    AuthDBDUserRealmQuery "SELECT hash FROM users '
        'WHERE user = %s AND realm = %s"',
        '    AuthnCacheProvideFor dbd',
        f'    AuthnCacheContext {context}',
        f'    {require}',
        '</Directory>',
    ]


@pytest.fixture(scope='class')
def _expect_auth_failures(env):
    env.httpd_error_log.add_ignored_lognos(AUTH_FAILURES)
    yield
    env.httpd_error_log.remove_ignored_lognos(AUTH_FAILURES)


@pytest.mark.usefixtures("_expect_auth_failures")
class TestAuthnSocacheDbdKey:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        # DBDriver loads the driver while reading the configuration, so an
        # apr-util without the sqlite3 driver (e.g. vcpkg's on Windows)
        # would fail the whole server: check it alone first.
        driver = "sqlite3"
        r = env.configtest(["Require all granted"],
                           extra_top_lines=[f"DBDriver {driver}"])
        env.require(r.exit_code == 0 or driver not in r.stderr,
                    f"no {driver} DBD driver in apr-util",
                    dep=f"apr_dbd_{driver}", detected=r.stderr.strip())
        assert r.exit_code == 0, r.stderr
        # A credential database that, unlike a flat htdigest/htpasswd file,
        # keeps user and realm in separate columns and so is not itself
        # ambiguous: only the socache key is under test.
        dbpath = os.path.join(env.server_dir, "authn-skey.sqlite")
        if os.path.exists(dbpath):
            os.remove(dbpath)
        db = sqlite3.connect(dbpath)
        db.execute("CREATE TABLE users (user TEXT, realm TEXT, hash TEXT)")
        db.executemany("INSERT INTO users VALUES (?, ?, ?)", [
            (ATTACKER, ATTACKER_REALM,
             _ha1(ATTACKER, ATTACKER_REALM, ATTACKER_PASSWORD)),
            (VICTIM, VICTIM_REALM,
             _ha1(VICTIM, VICTIM_REALM, VICTIM_PASSWORD)),
        ])
        db.commit()
        db.close()

        conf = HttpdConf(env)
        conf.add(f'DBDriver sqlite3')
        conf.add(f'DBDParams "{dbpath}"')
        conf.add('AuthnCacheSOCache shmcb')
        # Collision pair: both sides share one AuthnCacheContext.
        conf.add(_digest_dir(env, "zone_a", ATTACKER_REALM,
                             "Require valid-user", "collide", dbpath))
        conf.add(_digest_dir(env, "admin_b", VICTIM_REALM,
                             f"Require user {VICTIM}", "collide", dbpath))
        # Control side in its own context, so the legitimate checks are
        # independent of the collision test's cache state.
        conf.add(_digest_dir(env, "ctl_b", VICTIM_REALM,
                             f"Require user {VICTIM}", "control", dbpath))
        conf.install()
        assert env.apache_restart() == 0

    def _digest(self, env, name, user, realm, password):
        """Status of a Digest GET answering a fresh challenge."""
        uri = f"/skey/{name}/secret.txt"
        url = env.mkurl("http", "aaa", uri)
        r = env.curl_get(url)
        assert r.response["status"] == 401
        challenge = dc.DigestChallenge.parse(
            r.response["header"]["www-authenticate"])
        assert challenge.realm == realm
        auth = dc.build_authorization(user, challenge, password,
                                      method="GET", uri=uri)
        r = env.curl_get(url, options=["-H", f"Authorization: {auth}"])
        assert r.exit_code == 0, r.stderr
        return r.response["status"]

    def test_017_01_legitimate_user(self, env):
        """The real victim authenticates in its own realm."""
        assert self._digest(env, "ctl_b", VICTIM, VICTIM_REALM,
                            VICTIM_PASSWORD) == 200

    def test_017_02_wrong_password_rejected(self, env):
        """The attacker's password is not the victim's password."""
        assert self._digest(env, "ctl_b", VICTIM, VICTIM_REALM,
                            ATTACKER_PASSWORD) == 401

    def test_017_03_cross_realm_bypass_closed(self, env):
        """Priming the attacker's colliding entry must not authenticate
        the victim with the wrong password in the target realm."""
        # Prime: the attacker authenticates in the realm it controls.
        assert self._digest(env, "zone_a", ATTACKER, ATTACKER_REALM,
                            ATTACKER_PASSWORD) == 200
        # Attack: victim / attacker's password in the target realm.
        assert self._digest(env, "admin_b", VICTIM, VICTIM_REALM,
                            ATTACKER_PASSWORD) == 401
