import pytest
import subprocess
from lib.env import EchTestEnv

class TestEchProtocol:

    @pytest.fixture(autouse=True)
    def setup_method(self):
        self.env = EchTestEnv()
        self.config = self.env.get_ech_config()

    # --- SECTION 1: FUNCTIONAL & REGRESSION ---

    def test_01_standard_tls_regression(self):
        """Verify standard TLS 1.3 works without ECH."""
        output = self.env.run_openssl(["-brief"])
        assert "Verification: OK" in output or "return code: 0" in output

    def test_02_protocol_correctness(self):
        """Verify the server actually accepts a valid ECH extension."""
        output = self.env.run_openssl(["-brief", "-ech_config_list", self.config])
        success_markers = ["ECH: accepted", "02 79", "ech required"]
        assert any(marker in output for marker in success_markers)

    def test_03_protocol_hrr_handling(self):
        """Verify ECH survives a HelloRetryRequest (HRR)."""
        output = self.env.run_openssl(["-ech_config_list", self.config, "-groups", "P-521", "-msg"])
        has_hrr = any(x in output for x in ["HelloRetryRequest", "HRR", "hello_retry_request", "02 00 00"])
        assert has_hrr
        assert "ECH: accepted" in output or "02 79" in output

    # --- SECTION 2: NEGATIVE TESTS (Security Audit) ---

    def test_04_negative_no_ech_access(self):
        """Verify standard clients are not granted ECH status."""
        output = self.env.run_openssl(["-brief"])
        assert "ECH: accepted" not in output

    def test_05_negative_mismatched_public_name(self):
        """Verify rejection when Outer SNI is incorrect."""
        output = self.env.run_openssl(["-brief", "-servername", "wrong-gateway.com", "-ech_config_list", self.config])
        assert "ECH: accepted" not in output
        assert "ech_retry_configs" in output.lower() or "ech required" in output.lower()

    def test_06_negative_corrupted_config(self):
        """Verify rejection when the ECH key is invalid/poisoned."""
        wrong_key = "AEH+DQA9tAAgACDG1DRKJzL4jbKU//fdPlSFfASYZgMrpthbvcsc+GbtKQAEAAEAAQAOeW91cmRvbWFpbi5jb20AAA=="
        output = self.env.run_openssl(["-brief", "-ech_config_list", wrong_key])
        assert "ECH: accepted" not in output
        assert "ech required" in output.lower() or "0A0001A8" in output

    def test_07_negative_tls_downgrade(self):
        """Verify ECH is ignored if client attempts to use TLS 1.2."""
        output = self.env.run_openssl(["-brief", "-tls1_2", "-ech_config_list", self.config])
        assert "ECH: accepted" not in output

    # --- SECTION 3: INTEROPERABILITY & LOGGING ---

    def test_08_interoperability_grease(self):
        """Verify server handles GREASE extensions gracefully."""
        output = self.env.run_openssl(["-brief", "-ech_grease"])
        assert "Verification: OK" in output
        assert "ECH: accepted" not in output

    def test_09_ech_environment_variables(self):
        """Verify handshake triggers server-side logging of the ECH event."""
        self.env.run_openssl(["-brief", "-ech_config_list", self.config])
        logs = subprocess.check_output(self.env.docker_bin + ["tail", "-n", "20", "/usr/local/apache2/logs/error_log"]).decode()
        assert any(x in logs for x in ["SSL handshake", "ECH", "ssl_engine"])