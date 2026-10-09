<!-- Briefly describe the change and the problem it solves.
     Reference a Bugzilla PR number if one exists. -->

---

- [ ] This PR does not report or address a security vulnerability
      (see [`SECURITY.md`](/apache/httpd/blob/trunk/SECURITY.md) and
      <https://www.apache.org/security/#reporting-a-vulnerability>).
- [ ] Code follows the [httpd style guide](https://httpd.apache.org/dev/styleguide.html).
- [ ] New log messages (level debug or higher) use an *empty* `APLOGNO()` tag;
      numbers are assigned by a committer at merge time (see `docs/log-message-tags/README`).
- [ ] If the change is user-visible, a `changes-entries/*.txt` file is included,
      following the template in `README.CHANGES` (not needed otherwise).
- [ ] Test cases based on pyhttpd are included where appropriate, in the
      `test/modules/xxx` directory matching the `modules/xxx` module source,
      or `test/modules/core` for core server changes. On Unix, verify these
      pass locally with e.g. `make check-pytest PYTEST_DIRS=test/modules/xxx`.
