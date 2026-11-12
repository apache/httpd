import subprocess
import os
import time
import pytest
from lib.env import EchTestEnv

class TestServerRobustness:

    @pytest.fixture(autouse=True)
    def setup_method(self):
        self.env = EchTestEnv()
        self.config_path = "infrastructure/conf/ech/ECH_key.pem"

    def test_01_missing_key_file(self):
        """Requirement: Verify server handles missing ECH key file."""
        os.rename(self.config_path, self.config_path + ".bak")

        try:
            subprocess.run(["docker-compose", "-f", "infrastructure/docker-compose.yml", "restart", "ech-server"])
            time.sleep(2)

            status = subprocess.check_output(["docker", "inspect", "-f", "{{.State.Running}}", "ech-server"]).decode().strip()

            assert status == "false", "Server should not be running without its ECH key file"

        finally:
            if os.path.exists(self.config_path + ".bak"):
                os.rename(self.config_path + ".bak", self.config_path)
            subprocess.run(["docker-compose", "-f", "infrastructure/docker-compose.yml", "restart", "ech-server"])

    def test_02_invalid_directive_syntax(self):
        subprocess.run(["docker", "exec", "ech-server", "cp", "/usr/local/apache2/conf/httpd.conf.bak", "/usr/local/apache2/conf/httpd.conf"])
        
        subprocess.run(["docker", "exec", "ech-server", "sed", "-i", "s/SSLECHKeyDir/INVALID_COMMAND/", "/usr/local/apache2/conf/httpd.conf"])
        
        subprocess.run(["docker", "restart", "ech-server"])
        time.sleep(2)

        result = subprocess.run(["docker", "logs", "ech-server"], capture_output=True, text=True)
        logs = result.stdout + result.stderr

        assert "Syntax error" in logs or "Invalid command" in logs
