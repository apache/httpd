import os

import pytest

from pyhttpd.conf import HttpdConf

# set_options() enforces AllowOverride's per-option "Options=X" restriction
# itself, independently of the override-class check in invoke_cmd() that
# implements Nonfatal=Override. An .htaccess option outside that per-option
# allowance used to always fail the whole request with a 500, even with
# Nonfatal=Override configured (BZ 69835).
AH_OPTION_IGNORED = "AH10681"


class TestAllowOverrideNonfatal:

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_docs_dir, "allowoverride")
        os.makedirs(doc_dir, exist_ok=True)
        with open(os.path.join(doc_dir, "index.html"), "w") as f:
            f.write("ok\n")
        with open(os.path.join(doc_dir, ".htaccess"), "w") as f:
            f.write("Options +FollowSymLinks\n")
        conf = HttpdConf(env, extras={
            "base": f"""
            <Directory "{doc_dir}">
                Options +ExecCGI +Includes +SymLinksIfOwnerMatch -FollowSymLinks
                AllowOverride Nonfatal=Override Options=Includes
            </Directory>
            """,
        })
        conf.install()
        assert env.apache_restart() == 0
        env.httpd_error_log.add_ignored_lognos([AH_OPTION_IGNORED])

    # FollowSymLinks is outside what "Options=Includes" permits, so the
    # .htaccess attempt to enable it must be rejected and ignored -- not
    # turn the whole request into a 500 -- since the directory also sets
    # Nonfatal=Override.
    def test_core_013_01(self, env):
        env.httpd_error_log.clear_log()
        r = env.curl_get(env.mkurl("http", "htdocs", "/allowoverride/index.html"))
        assert r.response["status"] == 200
        with open(env.httpd_error_log.path) as fd:
            log = fd.read()
        assert AH_OPTION_IGNORED in log
        assert "not allowed here" not in log


# A rejected "Options" directive must leave the inherited option set
# untouched, not just skip applying the one forbidden token while still
# mutating/replacing the rest of the effective state (BZ 69835 follow-up).
# Both absolute ("Options X") and merge ("Options +X") syntax are covered,
# using SSI processing (Options Includes) as the observable effect: if
# Includes ends up disabled for the directory, mod_include passes the
# "#echo" tag through unprocessed instead of evaluating it.
SSI_MARKER = '<!--#echo var="DOCUMENT_NAME" -->'
AH_INCLUDES_NOT_SET = "AH01374"


def _write_ssi_dir(env, name):
    doc_dir = os.path.join(env.server_docs_dir, name)
    os.makedirs(doc_dir, exist_ok=True)
    with open(os.path.join(doc_dir, "index.shtml"), "w") as f:
        f.write(SSI_MARKER + "\n")
    return doc_dir


class TestAllowOverrideNonfatalAbsoluteState:

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        single_dir = _write_ssi_dir(env, "allowoverride_abs_single")
        with open(os.path.join(single_dir, ".htaccess"), "w") as f:
            f.write("Options FollowSymLinks\n")
        mixed_dir = _write_ssi_dir(env, "allowoverride_abs_mixed")
        with open(os.path.join(mixed_dir, ".htaccess"), "w") as f:
            f.write("Options FollowSymLinks Includes\n")
        conf = HttpdConf(env, extras={
            "base": f"""
            <Directory "{single_dir}">
                Options +ExecCGI +Includes -FollowSymLinks
                AllowOverride Nonfatal=Override Options=Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            <Directory "{mixed_dir}">
                Options +ExecCGI +Includes -FollowSymLinks
                AllowOverride Nonfatal=Override Options=Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            """,
        })
        conf.install()
        assert env.apache_restart() == 0
        env.httpd_error_log.add_ignored_lognos([AH_OPTION_IGNORED, AH_INCLUDES_NOT_SET])

    # "Options FollowSymLinks" (absolute syntax): FollowSymLinks is outside
    # "Options=Includes", so under Nonfatal=Override the directive must be
    # ignored entirely, not reset the directory's options to None.
    def test_core_013_02(self, env):
        r = env.curl_get(env.mkurl("http", "htdocs", "/allowoverride_abs_single/index.shtml"))
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")
        assert SSI_MARKER not in body

    # "Options FollowSymLinks Includes": one listed option (Includes) is
    # permitted, but the directive as a whole still contains a forbidden
    # token, so the whole directive -- not just the bad token -- must be
    # ignored, leaving the inherited Includes in place.
    def test_core_013_03(self, env):
        r = env.curl_get(env.mkurl("http", "htdocs", "/allowoverride_abs_mixed/index.shtml"))
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")
        assert SSI_MARKER not in body


class TestAllowOverrideNonfatalMergeState:

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        mixed_dir = _write_ssi_dir(env, "allowoverride_merge_mixed")
        with open(os.path.join(mixed_dir, ".htaccess"), "w") as f:
            f.write("Options +Includes +FollowSymLinks\n")
        forbidden_dir = _write_ssi_dir(env, "allowoverride_merge_forbidden")
        with open(os.path.join(forbidden_dir, ".htaccess"), "w") as f:
            f.write("Options +FollowSymLinks\n")
        allowed_dir = _write_ssi_dir(env, "allowoverride_merge_allowed")
        with open(os.path.join(allowed_dir, ".htaccess"), "w") as f:
            f.write("Options +Includes\n")
        conf = HttpdConf(env, extras={
            "base": f"""
            <Directory "{mixed_dir}">
                Options +ExecCGI -Includes -FollowSymLinks
                AllowOverride Nonfatal=Override Options=Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            <Directory "{forbidden_dir}">
                Options +ExecCGI -Includes -FollowSymLinks
                AllowOverride Nonfatal=Override Options=Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            <Directory "{allowed_dir}">
                Options +ExecCGI -Includes -FollowSymLinks
                AllowOverride Nonfatal=Override Options=Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            """,
        })
        conf.install()
        assert env.apache_restart() == 0
        env.httpd_error_log.add_ignored_lognos([AH_OPTION_IGNORED, AH_INCLUDES_NOT_SET])

    # "Options +Includes +FollowSymLinks": Includes alone would be allowed,
    # but FollowSymLinks is forbidden, so the complete directive must be
    # ignored -- Includes must NOT leak in by applying only the allowed
    # token while silently dropping the forbidden one.
    def test_core_013_04(self, env):
        r = env.curl_get(env.mkurl("http", "htdocs", "/allowoverride_merge_mixed/index.shtml"))
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")
        assert SSI_MARKER in body

    # "Options +FollowSymLinks": the only token is forbidden, directive is
    # ignored, inherited (disabled) Includes is unaffected.
    def test_core_013_05(self, env):
        r = env.curl_get(env.mkurl("http", "htdocs", "/allowoverride_merge_forbidden/index.shtml"))
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")
        assert SSI_MARKER in body

    # "Options +Includes": the only token is permitted, so normal merge
    # behavior is unaffected by the Nonfatal=Override handling and Includes
    # is actually enabled.
    def test_core_013_06(self, env):
        r = env.curl_get(env.mkurl("http", "htdocs", "/allowoverride_merge_allowed/index.shtml"))
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")
        assert SSI_MARKER not in body


class TestAllowOverrideNonfatalSyntaxError:

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_docs_dir, "allowoverride_syntax_error")
        os.makedirs(doc_dir, exist_ok=True)
        with open(os.path.join(doc_dir, "index.html"), "w") as f:
            f.write("ok\n")
        with open(os.path.join(doc_dir, ".htaccess"), "w") as f:
            f.write("Options +FollowSymLinks +BogusOption\n")
        conf = HttpdConf(env, extras={
            "base": f"""
            <Directory "{doc_dir}">
                Options +ExecCGI -Includes -FollowSymLinks
                AllowOverride Nonfatal=Override Options=Includes
            </Directory>
            """,
        })
        conf.install()
        assert env.apache_restart() == 0
        env.httpd_error_log.add_ignored_lognos([AH_OPTION_IGNORED])

    # A Nonfatal=Override-forbidden token earlier in the line must not
    # cause a genuine syntax error later in the same directive to be
    # skipped: "BogusOption" is not a real option, so this must still be
    # a 500, exactly as without Nonfatal=Override.
    def test_core_013_07(self, env):
        r = env.curl_get(env.mkurl("http", "htdocs", "/allowoverride_syntax_error/index.html"))
        assert r.response["status"] == 500
