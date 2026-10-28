"""CMake's header generator must work without pytest or test dependencies."""
import subprocess
import sys
from pathlib import Path


def test_header_generator_standalone(tmp_path):
    script = Path(__file__).parent / "pytest_suite" / "gen_test_header.py"
    dest = tmp_path / "apache_httpd_test.h"
    # -I ignores PYTHONPATH; -S excludes site-packages. This is the direct
    # invocation used by CMake, from outside the test project.
    result = subprocess.run([sys.executable, "-I", "-S", str(script), str(dest)],
                            cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    header = dest.read_text()
    assert "#define APACHE_HTTPD_TEST_MODULE(name)" in header
    assert "#define APACHE_HTTPD_TEST_HANDLER NULL" in header
