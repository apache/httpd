import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

import pytest

from pyhttpd.depends import needs_dependency

from .md_conf import MDConf
from .md_env import MDTestEnv
from .md_cert_util import MDCertUtil


@needs_dependency("ACME test server", MDTestEnv.has_acme_server(),
                  reason="no ACME test server configured",
                  detected=f"ACME={MDTestEnv.get_acme_server()}")
@pytest.mark.skipif(not MDTestEnv.is_pebble(), reason="requires Pebble renewalInfo override")
class TestARI:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env, acme):
        env.APACHE_CONF_SRC = "data/test_auto"
        acme.start(config="default")
        env.check_acme()

    @pytest.fixture(autouse=True, scope="function")
    def _method_scope(self, env, request):
        assert env.apache_stop() == 0
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    def _issue_cert(self, env, domain, keys=None):
        conf = MDConf(env)
        conf.add("LogLevel md:debug")
        conf.add("MDCheckInterval 1s")
        conf.add_renew_window("1%")
        if keys:
            conf.add(f"MDPrivateKeys {keys}")
        conf.add_md([domain])
        conf.add_vhost([domain])
        conf.install()
        assert env.apache_restart() == 0, f"{env.apachectl_stderr}"
        assert env.await_completion([domain], restart=False)
        assert env.apache_restart() == 0, f"{env.apachectl_stderr}"
        env.check_md_complete(domain)
        cert_file = env.store_domain_file(domain, "pubcert.pem")
        assert os.path.isfile(cert_file)
        return cert_file

    def _set_renewal_info(self, env, cert_file, response):
        with open(cert_file) as fd:
            pem = fd.read()
        payload = json.dumps({"Certificate": pem,
                              "ARIResponse": response if isinstance(response, str) else json.dumps(response)})
        r = env.curl_post_data(
            "https://localhost:15000/set-renewal-info/", payload,
            options=["--insecure", "-H", "Content-Type: application/json"])
        assert r.exit_code == 0, r.stderr
        assert r.response and r.response["status"] == 200, r

    @staticmethod
    def _new_log_lines(env, position):
        with open(env.httpd_error_log.path, encoding="utf-8", errors="replace") as fd:
            fd.seek(position)
            return fd.read()

    def _query_ari(self, env, domain, marker, timeout=20, keys=None):
        # MDConf disables ARI by default.
        conf = MDConf(env)
        conf.add("LogLevel md:debug")
        conf.add("MDCheckInterval 1s")
        conf.add_renew_window("1%")
        if keys:
            conf.add(f"MDPrivateKeys {keys}")
        conf.add("MDRenewViaARI on")
        conf.add_md([domain])
        conf.add_vhost([domain])
        conf.install()
        position = os.path.getsize(env.httpd_error_log.path)
        assert env.apache_restart() == 0, f"{env.apachectl_stderr}"
        deadline = time.monotonic() + timeout
        lines = ""
        while time.monotonic() < deadline:
            lines = self._new_log_lines(env, position)
            if marker in lines:
                assert "ARI is enabled" in lines, lines
                return lines
            time.sleep(0.2)
        pytest.fail("No ARI response was processed after restart:\n" + lines)

    @staticmethod
    def _window(start, end):
        return {"suggestedWindow": {
            "start": start.isoformat().replace("+00:00", "Z"),
            "end": end.isoformat().replace("+00:00", "Z"),
        }}

    @pytest.mark.parametrize("duration,explanation", [
        (timedelta(days=1), False),
        (timedelta(minutes=1), False),
        (timedelta(days=1), True),
    ], ids=["day", "minute", "explanation"])
    def test_md_703_001(self, env, duration, explanation):
        domain = self.test_domain
        cert_file = self._issue_cert(env, domain)
        start = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=5)
        end = start + duration
        response = self._window(start, end)
        if explanation:
            response["explanationURL"] = "https://example.invalid/ari"
        self._set_renewal_info(env, cert_file, response)
        lines = self._query_ari(env, domain, "CA advises renew via ARI at ")
        assert "GET #0 ARI from" in lines, lines
        assert "CA advises renew via ARI between" in lines, lines
        chosen = re.search(r"CA advises renew via ARI at "
                           r"(\w{3}, \d\d \w{3} \d{4} \d\d:\d\d:\d\d GMT)", lines)
        assert chosen is not None, lines
        when = datetime.strptime(chosen.group(1), "%a, %d %b %Y %H:%M:%S GMT")
        when = when.replace(tzinfo=timezone.utc)
        assert start <= when < end, (start, when, end)
        if explanation:
            assert "for explanation see https://example.invalid/ari" in lines

    @pytest.mark.parametrize("case", ["equal", "reversed", "missing"])
    def test_md_703_002(self, env, case):
        domain = self.test_domain
        cert_file = self._issue_cert(env, domain)
        start = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=5)
        end = start if case == "equal" else start - timedelta(minutes=1)
        response = {} if case == "missing" else self._window(start, end)
        self._set_renewal_info(env, cert_file, response)
        lines = self._query_ari(env, domain, "no ARI available")
        assert "GET #0 ARI from" in lines, lines
        marker = ("renewal info from CA incomplete" if case == "missing"
                  else "CA advises weird renewal between")
        assert marker in lines, lines
        assert "CA advises renew via ARI at " not in lines, lines
        env.httpd_error_log.ignore_recent(
            matches=[r".*CA advises weird renewal between.*",
                     r".*renewal info from CA incomplete.*"])

    def test_md_703_003(self, env):
        domain = self.test_domain
        cert_file = self._issue_cert(env, domain)
        not_after = MDCertUtil(cert_file).get_not_after()
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        start = not_after + timedelta(days=1)
        self._set_renewal_info(env, cert_file,
                               self._window(start, start + timedelta(days=1)))
        lines = self._query_ari(env, domain, "up for configured renewal in")
        assert "GET #0 ARI from" in lines, lines
        assert "no ARI available" not in lines, lines
        assert "CA advises renew via ARI at " not in lines, lines


    @pytest.mark.parametrize("case,marker", [
        ("missing-start", "renewal info from CA incomplete"),
        ("missing-end", "renewal info from CA incomplete"),
        ("bad-start", "error parsing CA renew start time"),
        ("bad-end", "error parsing CA renew end time"),
        ("wrong-type", "renewal info from CA incomplete"),
        ("malformed-json", "error retrieving ARI from"),
    ], ids=["missing-start", "missing-end", "bad-start", "bad-end",
            "wrong-type", "malformed-json"])
    def test_md_703_004(self, env, case, marker):
        domain = self.test_domain
        cert_file = self._issue_cert(env, domain)
        start = datetime.now(timezone.utc) + timedelta(minutes=5)
        response = self._window(start, start + timedelta(minutes=1))
        if case.startswith("missing-"):
            del response["suggestedWindow"][case.removeprefix("missing-")]
        elif case.startswith("bad-"):
            response["suggestedWindow"][case.removeprefix("bad-")] = "invalid"
        elif case == "wrong-type":
            response["suggestedWindow"]["start"] = 42
        else:
            response = "{"
        self._set_renewal_info(env, cert_file, response)
        lines = self._query_ari(env, domain, "no ARI available")
        assert marker in lines, lines
        assert "CA advises renew via ARI at " not in lines, lines
        expected_logs = [rf".*{marker}.*"]
        if case == "malformed-json":
            for message in ["failed to load JSON file:", "parsing JSON body"]:
                assert message in lines, lines
                expected_logs.append(rf".*{message}.*")
        env.httpd_error_log.ignore_recent(matches=expected_logs)

    @pytest.mark.parametrize("keys,invalid_first", [
        ("rsa2048 secp256r1", False),
        ("secp256r1 rsa2048", False),
        ("rsa2048 secp256r1", True),
    ], ids=["rsa-first", "ec-first", "invalid-first"])
    def test_md_703_005(self, env, keys, invalid_first):
        domain = self.test_domain
        self._issue_cert(env, domain, keys=keys)
        start = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=5)
        specs = keys.split()
        for i, spec in enumerate(specs):
            cert_file = env.store_domain_file(domain, env.cert_fname(spec))
            end = start + timedelta(minutes=1)
            response = self._window(start, start if invalid_first and i == 0 else end)
            response["explanationURL"] = f"https://example.invalid/ari/{i}"
            self._set_renewal_info(env, cert_file, response)
            if i == 0:
                start -= timedelta(minutes=2)
        lines = self._query_ari(env, domain, "CA advises renew via ARI at ", keys=keys)
        assert "assessing ARI status for 2 certificates" in lines, lines
        assert "GET #0 ARI from" in lines and "GET #1 ARI from" in lines, lines
        assert "for explanation see https://example.invalid/ari/1" in lines, lines
        chosen = re.search(r"CA advises renew via ARI at "
                           r"(\w{3}, \d\d \w{3} \d{4} \d\d:\d\d:\d\d GMT)", lines)
        assert chosen is not None, lines
        when = datetime.strptime(chosen.group(1), "%a, %d %b %Y %H:%M:%S GMT")
        assert start <= when.replace(tzinfo=timezone.utc) < start + timedelta(minutes=1)
        if invalid_first:
            assert "CA advises weird renewal between" in lines, lines
            env.httpd_error_log.ignore_recent(matches=[r".*CA advises weird renewal between.*"])

    def test_md_703_006(self, env):
        domain = self.test_domain
        cert_file = self._issue_cert(env, domain)
        serial = MDCertUtil(cert_file).get_serial_number()
        start = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=15)
        self._set_renewal_info(env, cert_file,
                               self._window(start, start + timedelta(seconds=1)))
        lines = self._query_ari(env, domain, "CA advises renew via ARI at ")
        assert "CA advises renew via ARI now" not in lines, lines
        assert datetime.now(timezone.utc) < start, lines
        assert env.await_completion([domain], restart=False)
        staged = env.store_staged_file(domain, "pubcert.pem")
        assert MDCertUtil(staged).get_serial_number() != serial
        with open(env.httpd_error_log.path, encoding="utf-8") as fd:
            assert "CA advises renew via ARI now" in fd.read()

    @pytest.mark.parametrize("offset", [timedelta(hours=2, minutes=30),
                                      -timedelta(hours=3, minutes=30)],
                             ids=["positive-offset", "negative-offset"])
    def test_md_703_007(self, env, offset):
        domain = self.test_domain
        cert_file = self._issue_cert(env, domain)
        start = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=5)
        end = start + timedelta(minutes=1)
        zone = timezone(offset)
        self._set_renewal_info(env, cert_file,
                               self._window(start.astimezone(zone), end.astimezone(zone)))
        lines = self._query_ari(env, domain, "CA advises renew via ARI at ")
        chosen = re.search(r"CA advises renew via ARI at "
                           r"(\w{3}, \d\d \w{3} \d{4} \d\d:\d\d:\d\d GMT)", lines)
        assert chosen is not None, lines
        when = datetime.strptime(chosen.group(1), "%a, %d %b %Y %H:%M:%S GMT")
        assert start <= when.replace(tzinfo=timezone.utc) < end, (start, when, end)

    def test_md_703_008(self, env):
        domain = self.test_domain
        cert_file = self._issue_cert(env, domain)
        start = datetime.now(timezone.utc).replace(microsecond=250000) + timedelta(minutes=5)
        end = start.replace(microsecond=750000)
        self._set_renewal_info(env, cert_file, self._window(start, end))
        lines = self._query_ari(env, domain, "CA advises renew via ARI at ")
        assert "CA advises weird renewal between" not in lines, lines
        chosen = re.search(r"CA advises renew via ARI at "
                           r"(\w{3}, \d\d \w{3} \d{4} \d\d:\d\d:\d\d GMT)", lines)
        assert chosen is not None, lines
        when = datetime.strptime(chosen.group(1), "%a, %d %b %Y %H:%M:%S GMT")
        assert when.replace(tzinfo=timezone.utc) == start.replace(microsecond=0)
