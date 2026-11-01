"""SSL-CT must join its service thread before APR destroys the child pool."""
import os
import time

from pyhttpd.conf import HttpdConf


def test_ssl_ct_clean_shutdown(env):
    env.require(env.has_shared_module("ssl_ct"), "mod_ssl_ct was not built",
                dep="mod_ssl_ct", detected=f"no mod_ssl_ct.so in {env.libexec_dir}")
    assert env.apache_stop() == 0
    scts = os.path.join(env.server_dir, "scts")
    os.makedirs(scts, exist_ok=True)
    conf = HttpdConf(env)
    if "ssl_ct" not in env.static_modules():
        conf.add(f'LoadModule ssl_ct_module "{env.libexec_dir}/mod_ssl_ct.so"')
    conf.add([
        f'CTSCTStorage "{scts}"',
        "LogLevel ssl_ct:debug",
    ])
    conf.add_vhost_test1()
    conf.install()
    assert env.apache_restart() == 0, env.apachectl_stderr
    # The service thread checks MPM state once per second. Stop while it is
    # asleep: in an APR pool-debug build, the join from pchild's pre-cleanup
    # deadlocked with apr_thread_exit() while the thread's pool shared
    # pchild's mutex. Keep shutdown warnings visible to the fixtures.
    time.sleep(0.1)
    assert env.apache_stop() == 0
    env.check_error_log()
