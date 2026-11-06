import glob
import os
import select
import sys
import time

import pytest

# SHA1 of "secret", as written by htpasswd -s
SECRET_HASH = "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ="


def run_with_tty(argv, passwords, timeout=10):
    """Run argv on a pseudo terminal and answer every password prompt.

    dbmmanage reads passwords from /dev/tty, so they cannot be piped to it.
    Returns the exit code and the output.
    """
    import pty
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(argv[0], argv)
    out = b''
    todo = list(passwords)
    end = time.time() + timeout
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if not ready:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        out += data
        if todo and b'assword' in data:
            os.write(fd, todo.pop(0).encode() + b'\n')
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode(errors='replace')


@pytest.fixture(autouse=True, scope='module')
def _have_dbmmanage(env):
    if not os.path.isfile(os.path.join(env.bin_dir, 'dbmmanage')):
        pytest.skip("dbmmanage is not installed")


@pytest.mark.skipif(sys.platform == 'win32', reason="dbmmanage reads from /dev/tty")
class TestDbmmanageSha1:

    @pytest.fixture
    def dbm(self, env):
        # the DBM library decides on the file name extensions
        base = os.path.join(env.gen_dir, 'dbmmanage-sha1')
        for f in glob.glob(base + '*'):
            os.remove(f)
        return base

    def dbmmanage(self, env, *args, passwords=()):
        argv = [os.path.join(env.bin_dir, 'dbmmanage'), '-s', *args]
        return run_with_tty(argv, passwords)

    # SHA1 passwords need Digest::SHA, which is part of Perl. They must not
    # require Digest::SHA1, which has to be installed from CPAN.
    def test_core_013_01(self, env, dbm):
        rc, out = self.dbmmanage(env, dbm, 'adduser', 'u1',
                                 passwords=['secret', 'secret'])
        assert rc == 0, out
        assert f"hashed to {SECRET_HASH} using sha1" in out, out
        rc, out = self.dbmmanage(env, dbm, 'view', 'u1')
        assert rc == 0, out
        assert f"u1:{SECRET_HASH}" in out, out

    def test_core_013_02(self, env, dbm):
        rc, out = self.dbmmanage(env, dbm, 'add', 'u1', SECRET_HASH)
        assert rc == 0, out
        rc, out = self.dbmmanage(env, dbm, 'check', 'u1', passwords=['secret'])
        assert rc == 0, out
        assert 'sha1 password ok' in out, out

    def test_core_013_03(self, env, dbm):
        rc, out = self.dbmmanage(env, dbm, 'add', 'u1', SECRET_HASH)
        assert rc == 0, out
        rc, out = self.dbmmanage(env, dbm, 'check', 'u1', passwords=['wrong'])
        assert 'sha1 password mismatch' in out, out
