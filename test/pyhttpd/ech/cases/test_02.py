import pytest
from lib.env import EchTestEnv

class TestEchBrowser:

    @pytest.fixture(autouse=True)
    def setup_method(self):
        self.env = EchTestEnv()
        self.ech_config = self.env.get_ech_config()
        if not self.ech_config:
            pytest.fail("ECH Config not found in infrastructure/conf/ech/")

    def test_01_browser_handshake_success(self):
        """Test: Standard ECH Handshake via Firefox."""
        page_source = self.env.run_browser(self.ech_config)
        assert "ECH Decryption Successful" in page_source

    def test_02_browser_with_grease(self):
        """Test: ECH with GREASE enabled via Firefox."""
        page_source = self.env.run_browser(self.ech_config, use_grease=True)
        assert "ECH Decryption Successful" in page_source