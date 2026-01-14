import os
import sys
import time
import pytest
import re
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

class TestEch:

    @pytest.fixture(autouse=True)
    def setup_paths(self):
        """Pre-test setup: Locates keys and extracts the ECHConfig string."""
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.ech_key_path = os.path.join(self.base_dir, "conf", "ech", "ECH_key.pem")

        if os.path.exists(self.ech_key_path):
            with open(self.ech_key_path, 'r') as f:
                content = f.read()
                match = re.search(r"-----BEGIN ECHCONFIG-----(.*?)-----END ECHCONFIG-----", content, re.DOTALL)
                if match:
                    self.ech_config = match.group(1).replace("\n", "").strip()
                    print(f"\n[DEBUG] Extracted ECHConfig: {self.ech_config[:25]}...")
                else:
                    pytest.fail("Found ECH_key.pem but no 'BEGIN ECHCONFIG' block inside!")
        else:
            pytest.fail(f"ECH Key not found at {self.ech_key_path}. Run your key-gen script first.")

    def test_ech_handshake(self):
        """The core interoperability test between Firefox and Apache."""
        options = Options()
        options.add_argument("-headless")

        # 1. ECH Discovery Simulation: Manually feeding the key to the browser
        options.set_preference("network.dns.echconfig.enabled", True)
        options.set_preference("network.dns.local_echconfig", self.ech_config)

        # 2. Trust Injection: Allows Selenium to bypass 'Self-Signed' or 'Local CA' warnings
        options.set_preference("security.enterprise_roots.enabled", True)

        driver = webdriver.Firefox(options=options)

        try:
            print("[STEP] Initiating ECH Handshake with https://localhost...")
            driver.get("https://ech-test.fyp.local")

            time.sleep(2) 

            # 3. Verification: If Apache decrypted the ECH, it serves the 'Inner' content
            assert "It works" in driver.page_source
            assert driver.title == "It works! Apache httpd"
            print("[SUCCESS] Content verified. ECH decryption confirmed on server.")

        except Exception as e:
            pytest.fail(f"Handshake failed or connection timed out: {e}")
            
        finally:
            driver.quit()
