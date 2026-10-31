import glob
import os

import pytest

# support/passwd_common.h
ERR_FILEPERM = 1
ERR_SYNTAX = 2
ERR_PWMISMATCH = 3
ERR_BADUSER = 6


@pytest.fixture(autouse=True, scope='module')
def _have_htdbm(env):
    if not os.path.isfile(os.path.join(env.bin_dir, 'htdbm')):
        pytest.skip("htdbm is not installed")


class TestHtdbmNullDeref:
    """BZ 69404: "-l" (list) does not require or consume a username, and
    "-n" (no file) never opens a database, but "-x" (delete), "-v"
    (verify) and "-l" itself all need a username and/or an open database.
    Combining "-l" with "-x"/"-v", or "-n" with "-v"/"-x"/"-l", used to
    leave htdbm->username or htdbm->dbm NULL and crash with SIGSEGV (or,
    for "-l"+"-n", silently print "(null)" and exit 0) instead of being
    rejected as a usage error. Each combination below is isolated into
    its own test so a regression in one check does not hide behind
    another."""

    @pytest.fixture
    def dbm(self, env):
        # the DBM library decides on the file name extensions
        base = os.path.join(env.gen_dir, 'htdbm-null-deref')
        for f in glob.glob(base + '*'):
            os.remove(f)
        return base

    def htdbm(self, env, *args):
        return env.run([os.path.join(env.bin_dir, 'htdbm'), *args])

    def assert_usage_error(self, r):
        assert r.exit_code == ERR_SYNTAX, \
            f"expected a usage error (exit {ERR_SYNTAX}), got exit " \
            f"{r.exit_code}: {r.stderr}"

    # "-l" (no username needed/consumed) + "-x" (needs one)
    def test_core_014_01(self, env, dbm):
        r = self.htdbm(env, '-l', '-x', dbm)
        self.assert_usage_error(r)

    # "-x" + "-l", reversed order: the rejection must not depend on which
    # of the two conflicting options was parsed last
    def test_core_014_02(self, env, dbm):
        r = self.htdbm(env, '-x', '-l', dbm)
        self.assert_usage_error(r)

    # "-l" + "-v" (needs a username too)
    def test_core_014_03(self, env, dbm):
        r = self.htdbm(env, '-l', '-v', dbm)
        self.assert_usage_error(r)

    # "-n" (never opens a database) + "-v" (needs one)
    def test_core_014_04(self, env):
        r = self.htdbm(env, '-n', '-v', 'someuser')
        self.assert_usage_error(r)

    # "-v" + "-n", reversed order
    def test_core_014_05(self, env):
        r = self.htdbm(env, '-v', '-n', 'someuser')
        self.assert_usage_error(r)

    # "-n" + "-x"
    def test_core_014_06(self, env):
        r = self.htdbm(env, '-n', '-x', 'someuser')
        self.assert_usage_error(r)

    # "-n" + "-l"
    def test_core_014_07(self, env):
        r = self.htdbm(env, '-n', '-l')
        self.assert_usage_error(r)

    # "-l" + "-n", reversed order: this used to skip the username
    # altogether (no helper call involved) and print "(null):<hash>"
    # with exit code 0
    def test_core_014_08(self, env):
        r = self.htdbm(env, '-l', '-n')
        self.assert_usage_error(r)
        assert b'(null)' not in r.stdout + r.stderr

    # "-n" + "-x" + "-l" all at once
    def test_core_014_09(self, env):
        r = self.htdbm(env, '-n', '-x', '-l')
        self.assert_usage_error(r)

    # positive control: a normal create/verify/list/delete cycle still
    # works, so rejecting bad combinations did not turn valid ones into
    # usage errors too
    def test_core_014_10(self, env, dbm):
        r = self.htdbm(env, '-c', '-b', dbm, 'bob', 'secret')
        assert r.exit_code == 0, r.stderr
        r = self.htdbm(env, '-b', '-v', dbm, 'bob', 'secret')
        assert r.exit_code == 0, r.stderr
        r = self.htdbm(env, '-l', dbm)
        assert r.exit_code == 0, r.stderr
        assert b'bob' in r.stdout + r.stderr
        r = self.htdbm(env, '-x', dbm, 'bob')
        assert r.exit_code == 0, r.stderr

    # positive control: "-n" on its own (no conflicting command) still
    # just hashes and prints, without touching a database
    def test_core_014_11(self, env):
        r = self.htdbm(env, '-nb', 'someuser', 'somepass')
        assert r.exit_code == 0, r.stderr
        assert b'someuser:' in r.stdout + r.stderr

    # positive control: listing a database that is open but empty is not
    # a usage error, and must keep exiting 0 as before this fix
    def test_core_014_12(self, env, dbm):
        r = self.htdbm(env, '-c', '-b', dbm, 'bob', 'secret')
        assert r.exit_code == 0, r.stderr
        r = self.htdbm(env, '-x', dbm, 'bob')
        assert r.exit_code == 0, r.stderr
        r = self.htdbm(env, '-l', dbm)
        assert r.exit_code == 0, r.stderr

    # positive control: a verify that is reached validly (no "-l"/"-n"
    # involved) still reports a password mismatch, not a usage error
    def test_core_014_13(self, env, dbm):
        r = self.htdbm(env, '-c', '-b', dbm, 'bob', 'secret')
        assert r.exit_code == 0, r.stderr
        r = self.htdbm(env, '-b', '-v', dbm, 'bob', 'wrong')
        assert r.exit_code == ERR_PWMISMATCH, r.stderr

    # positive control: deleting a username that is not in the database
    # still reports ERR_BADUSER, not a usage error
    def test_core_014_14(self, env, dbm):
        r = self.htdbm(env, '-c', '-b', dbm, 'bob', 'secret')
        assert r.exit_code == 0, r.stderr
        r = self.htdbm(env, '-x', dbm, 'nosuchuser')
        assert r.exit_code == ERR_BADUSER, r.stderr

    # a rejected "-l"+"-x" must not touch an already-populated database:
    # the record must still be there afterwards, unchanged
    def test_core_014_15(self, env, dbm):
        r = self.htdbm(env, '-c', '-b', dbm, 'bob', 'secret')
        assert r.exit_code == 0, r.stderr
        r = self.htdbm(env, '-l', '-x', dbm)
        self.assert_usage_error(r)
        r = self.htdbm(env, '-b', '-v', dbm, 'bob', 'secret')
        assert r.exit_code == 0, r.stderr
