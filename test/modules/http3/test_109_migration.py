import pytest

from .env import H3Conf, known_bug


class TestMigration:
    """Verify that a QUIC connection survives client address migration."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    def test_h3_109_01_nat_rebinding(self, env):
        """A request after the client rebinds to a new UDP port succeeds."""
        client = env.h3_client(timeout=5)
        r1, r2, port1, port2 = client.migrate_and_get("/001.html")
        assert port1 != port2, "local ports must differ"
        assert r1.status == 200, f"pre-migration request failed: {r1}"
        migrated = r2 is not None and r2.status == 200
        known_bug(not migrated,
                  "QUIC connection lost after client address change"
                  " (OpenSSL QUIC does not support connection migration)")
        assert migrated, f"post-migration request failed: {r2}"
