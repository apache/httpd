# AGENTS.md - Apache HTTP Server

This is the source for the Apache HTTP Server (httpd), written in C on
top of APR and APR-util. Development happens on `trunk`; fixes are
proposed for backport to the `2.4.x` stable branch afterwards, so make
changes against `trunk` unless told otherwise.

Layout:

- `server/` — core server; `server/mpm/` holds the MPMs
- `modules/<category>/` — modules, e.g. `modules/ssl`, `modules/proxy`
- `include/` — public API headers
- `os/` — platform-specific code
- `support/` — utilities such as `htpasswd`, `rotatelogs`, `apxs`
- `test/` — `test/pyhttpd` framework and `test/modules` test suites
- `docs/manual/` — the manual (XML sources)
- `changes-entries/` — pending CHANGES entries

## Code style

Follow the [httpd style guide](https://httpd.apache.org/dev/styleguide.html),
and match the surrounding code.

Code must compile in C89: no `//` comments, no declarations after
statements, no C99 features such as `bool`, designated initializers or
variable-length arrays. `--enable-maintainer-mode` builds with
`-std=c89 -Werror`, which catches the first two but not every C99
extension GCC accepts. A C99 feature may be used only under
`#ifdef AP_HAVE_C99` (or `AP_HAVE_DESIGNATED_INITIALIZER`), both defined
in `include/ap_config.h`, with a C89 fallback in the `#else` branch; see
`include/http_log.h`.

## Building

A git checkout has no `configure` script; generate it with `buildconf`,
pointing it at an APR source tree (apr-util is looked for alongside it),
then configure and build:

```
./buildconf --with-apr=/path/to/apr
./configure --enable-maintainer-mode
make -j$(nproc)
```

Every `Makefile` in the tree is generated from a `Makefile.in`. Editing
`Makefile.in` alone does nothing — `make` reads the generated `Makefile`,
which is stale until regenerated. After editing any `Makefile.in`,
regenerate all Makefiles from the top level:

```
./config.status
```

Then verify the target actually shows up in the regenerated `Makefile`
before relying on it (e.g. `grep '^new-target:' Makefile`).

If any autoconf-level input has changed (`configure.in`, an `.m4` file,
etc.), regenerate `configure` with `buildconf` (nothing in the build does
this for you), then rerun `configure` exactly as it was originally invoked,
rather than guessing the flags:

```
./buildconf --with-apr=/path/to/apr
./config.nice
```

## Testing

Always provide test cases based on pyhttpd where possible; especially
when fixing bugs, adding features, or changing code with poor existing
test coverage.

Tests should be placed in the `test/modules/xxx` directory matching
the `modules/xxx` module source, or `test/modules/core` for core
server or MPM changes. On Unix, verify these pass locally by running
`make check-pytest PYTEST_DIRS=test/modules/xxx` — this can be done
without running `make install` first.

## Validating changes

After editing any `.github/workflows/*.yml` file or any script the
workflows run, check them before committing:

```
./test/gha-sanity-check.sh
```

It catches YAML and shell syntax errors before they reach CI, where the
turnaround is minutes rather than seconds. If python3 has no `yaml`
module the workflow files are skipped, so check for `SKIP` in the output.

For a script the workflows do not run, `bash -n path/to/script.sh`
directly.

## Documentation

Update the manual when adding or removing configuration directives, or
changing their behaviour. Read `docs/manual/AGENTS.md` before editing
the manual.

Edit only the English source, `foo.xml`. Leave alone the generated
`.html*` files, the `.xml.meta` files, and the translations
(`foo.xml.fr` etc.), which their translators update.

A new directive or module gets a `<compatibility>` line naming the
release it first appears in, e.g. `Available in version 2.5.1 and
later.` for trunk.

After editing any XML under `docs/`, check it is well-formed and valid
against its DTD:

```
./test/gha-docs-check.sh docs/manual/mod/mod_foo.xml
```

With no arguments it checks every file under `docs/`. It needs
`xmllint` and the XHTML DTDs from an XML catalog (`xhtml1-dtds` on
Fedora); nothing is fetched from the network.

## Change entries

Every *user-visible* change must be documented in CHANGES. Read
`README.CHANGES` before adding one: it defines the `changes-entries/`
mechanism, the `*) mod_foo: ...` template, the `core:` prefix for
`server/*.[ch]`, and the crediting rules.

**Write it for the user, not the developer.** A changes entry states the
user-visible effect — what an admin, a client, or a module author sees
differently — not how the code achieves it. This is the opposite of the
commit message. Name no functions, struct fields, or internal identifiers:
a reader does not know what `err_headers_out` is, so "added the header to
`err_headers_out`" is wrong where "kept the header on error responses" is
right. Don't describe the mechanism at all; name any directive or header
involved, and keep it to three lines at most. The how belongs in the
commit message, which sits right beside it.

**A changes entry is not always required.** Only user-visible (or
module-author-visible) changes need one: bug fixes, new directives or
modules, behaviour changes, API changes. Anything with no externally
visible effect needs none — code cleanups and refactoring, test-only
changes, CI/workflow changes, comment and documentation fixes. When in
doubt, ask rather than adding one by reflex.

## Pull requests

Before creating a pull request, show the proposed subject and description
and wait for approval. Pushing the branch first is fine; it is the PR text
that needs confirming.

Push the branch to the contributor's own fork, never to the `apache/httpd`
remote (commonly `origin`). Inspect `git remote -v` and choose the remote
whose URL points at the fork (e.g. `github.com:<user>/httpd.git`); if none
exists, ask rather than guessing. The PR is then opened from the fork branch
against `apache/httpd` `trunk` (`--head <user>:<branch>`). If a branch was
pushed to the `apache/httpd` remote by mistake, tell the user so they can
delete it.

Adding commits to a PR that is already pushed is fine as long as they are
covered by the workflows' `paths-ignore` and so will not trigger CI:
`changes-entries/*`, `STATUS`, `CHANGES`, `README*`, `**.md` (and check
`.github/workflows/*.yml` for the current list). A change confined to
`docs/**` is also fine: it runs only the quick Sanity workflow, not the
build. A change that touches anything else waits for the user's say-so,
since it costs a CI run on their PR.

Never force-push a branch that has been pushed (amending or rebasing a
published commit needs one) without explicit confirmation. To change
something already committed and pushed, add a new commit instead, or ask.

Keep the description short: a few sentences on what the change does, plus
anything a reviewer cannot get from the diff, such as a constraint which
explains why it was done this way. Nothing else. No restating the commit
message, no listing the tests when their names already say it, no account
of how it was verified, no marketing. If it runs past about ten lines, cut
it.

Write it in GitHub-Flavored Markdown. Put anything the reader would type or
that names code in `backticks` — variables, directive names, function and
symbol names, filenames, command names, header names such as
`Authentication-Info`. Put config snippets, commands and sample output in
fenced code blocks, tagged with a language where one fits (` ```apache ` for
httpd config). A `##` heading is fine when the description genuinely has more
than one part worth separating, but a few sentences needs none, so most PRs
have no headings.

Do not hard-wrap it. GitHub renders the description as Markdown and reflows
it to the reader's width, so text wrapped at a fixed column comes out ragged.
Write each paragraph as one long line and let it wrap, with a blank line
between paragraphs; a list item is likewise one long line. This is the
opposite of a commit message, which is plain text and stays wrapped by hand.

This applies to the body however it is supplied. Writing it into a file for
`gh pr create --body-file` (or a heredoc) invites wrapping it at the
terminal width out of habit — don't. Each paragraph stays one line in the
file, however long.
