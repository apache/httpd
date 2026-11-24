# GitHub CI emulation for Apache httpd (act + Docker)

Run the Linux jobs of httpd's GitHub Actions CI workflow
(`.github/workflows/linux.yml`) on your own machine, for any commit of trunk or
2.4.x. Use it to check changes to the workflow, `test/travis_run_linux.sh`,
`Makefile.in` or `test/` before pushing, to reproduce a CI failure with a
shell in the same environment, or when the hosted Linux queue is long.

You need `act`, Docker and a git checkout of httpd. It was written and tested
against an arm64 Linux Docker engine. The scripts pick the container
architecture from `uname -m`, but nothing has been run on x86_64, Windows or
WSL. On Windows, work from a WSL shell.

## How it works

* [act](https://github.com/nektos/act) reads the workflow and runs one job in a
  Docker container built from an image that imitates GitHub's `ubuntu-24.04`
  runner.
* `prepare.sh` exports a committed ref of your checkout (`git archive`) into a
  scratch tree, `$CI_EMU/src`, and patches that copy in four small ways so the
  workflow runs under act (see "Deviations"). Your checkout is not touched.
  Uncommitted changes are not tested; commit them first, on a throw-away branch
  if you like.
* `run-job.sh "<matrix name>"` runs one entry of the `build` job's matrix with
  the packages, `configure` flags, environment and `test/travis_run_linux.sh`
  from the workflow.

Not covered: the other workflows (`windows.yml`, `sanity.yml`) and the GitHub
caches (APR and httpd are built from scratch each run). `upload-artifact` fails
under act with "Unable to get the ACTIONS_RUNTIME_TOKEN env variable"; ignore
it.

## Differences from the hosted runner

| | GitHub runner | Here |
|---|---|---|
| CPU | x86_64; arm64 only for the "64-bit ARM" entries | the architecture of your Docker engine |
| User | `runner`, with sudo | the same (created in the image) |
| PID 1 | init | `docker --init` |
| `$GITHUB_ENV` in step `if:` | honoured | not honoured (deviation 2) |
| `go`, for the pebble step | present | absent unless you add it (see Dockerfile) |

Matrix entries with `os: ubuntu-24.04-arm` are not mapped by
`-P ubuntu-latest=...`, so run the entry of the same name without `, 64-bit
ARM`; the container runs on your engine's architecture anyway.

## Prerequisites

* Docker (Engine or Desktop) with the daemon running; `docker info` must work
  for your user.
* `act`: from your package manager, a release binary from
  <https://github.com/nektos/act/releases>, or `gh extension install
  https://github.com/nektos/gh-act`. Tested with 0.2.90.
* `git`, `tar`, `perl`, a POSIX shell. `gh` is optional (comparing with real
  runs).
* Network access from the container (apt, GitHub, Go modules).
* About 2 GB for the image, plus the container and the scratch tree.

## Setting it up

Pick a directory for the harness. The scripts read both paths from the
environment:

    export CI_EMU=$HOME/ci-emul          # scripts, scratch tree, logs
    export REPO=$HOME/src/httpd          # the httpd git checkout
    mkdir -p "$CI_EMU/out" && cd "$CI_EMU"

### 1. The runner image

    docker pull ghcr.io/catthehacker/ubuntu:act-24.04

The image is on ghcr.io (not Docker Hub) and has amd64 and arm64 variants. If
`DOCKER_DEFAULT_PLATFORM` is set in your environment to another architecture,
unset it or add `--platform` to the pull.

`Dockerfile.act` adds what the hosted image has and the act one lacks:

```dockerfile
FROM ghcr.io/catthehacker/ubuntu:act-24.04
# The hosted image has apt assume "yes"; this one does not.
RUN echo 'APT::Get::Assume-Yes "true";' > /etc/apt/apt.conf.d/90assumeyes
# linux.yml picks /usr/sbin/php-fpm*, which the hosted image ships.
RUN apt-get update && apt-get install -y php8.3-fpm golang-go && rm -rf /var/lib/apt/lists/*
# httpd's default "User #-1" fails as root, and the hosted runner is not root.
RUN useradd -m -u 1001 -s /bin/bash runner \
 && echo 'runner ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/runner
```

`golang-go` is for the "Install pebble" step of the `TEST_MD` jobs. Without
`go` that step only warns ("pebble install failed; modules/md tests will be
skipped") and every `modules/md` test skips. The distribution's Go is older
than the Go 1.24 that pebble v2 needs; `go install` fetches the toolchain
itself. Installing `golang-go` by hand in a running container worked. The
Dockerfile line has not been built.

    docker build -f Dockerfile.act -t act-ubuntu-24.04-ci:local .

### 2. `prepare.sh`

```sh
#!/bin/sh
# usage: prepare.sh [ref]     (default HEAD of $REPO; a branch, tag or sha)
set -e
REPO=${REPO:?set REPO to the httpd git checkout}
CI_EMU=${CI_EMU:-$(cd "$(dirname "$0")" && pwd)}
ref=${1:-HEAD}
src=$CI_EMU/src
git -C "$REPO" rev-parse --verify -q "$ref^{commit}" >/dev/null \
    || { echo "prepare.sh: no such commit in $REPO: $ref" >&2; exit 2; }
/bin/rm -rf "$src"; mkdir -p "$src"
git -C "$REPO" archive "$ref" | tar -x -C "$src"
cd "$src"

# 1: /etc/hosts is a bind mount in Docker; "sed -i" cannot rename over it
perl -pi -e 's|^(\s*)sudo sed -i "/ip6-/d" /etc/hosts|$1sudo sh -c "sed /ip6-/d /etc/hosts > /tmp/hosts.new \&\& cat /tmp/hosts.new > /etc/hosts"|' \
    test/travis_before_linux.sh
grep -q 'hosts.new' test/travis_before_linux.sh || { echo "fix 1 did not apply" >&2; exit 1; }

# 2: act does not feed $GITHUB_ENV into step "if:" expressions
perl -pi -e 's/if: \$\{\{ ! \( env\.SKIP_TESTING \|\| env\.NO_TEST_FRAMEWORK \) \}\}/if: \${{ ! ( contains(matrix.env, \x27SKIP_TESTING\x27) || contains(matrix.env, \x27NO_TEST_FRAMEWORK\x27) ) }}/' \
    .github/workflows/linux.yml
grep -q "contains(matrix.env, 'NO_TEST_FRAMEWORK')" .github/workflows/linux.yml \
    || { echo "fix 2 did not apply" >&2; exit 1; }

# 3: act's $GITHUB_ENV parser rejects the trailing blank line of a multi-line matrix.env
perl -pi -e 's/echo "\$\{\{ matrix\.env \}\}" >> \$GITHUB_ENV/echo "\${{ matrix.env }}" | sed "\/^\$\/d" >> \$GITHUB_ENV/' \
    .github/workflows/linux.yml
grep -q 'sed "/^\$/d" >> \$GITHUB_ENV' .github/workflows/linux.yml \
    || { echo "fix 3 did not apply" >&2; exit 1; }

# 4: -f matters; .gitignore lists /build/PrintPath but it is tracked upstream
git init -q; git add -Af >/dev/null
git -c user.name=ci -c user.email=ci@example.com commit -qm "emulation snapshot of $ref"
echo "prepared $ref in $src"
```

### 3. `run-job.sh`

```sh
#!/bin/sh
# usage: run-job.sh 'Python pytest test suites'
CI_EMU=${CI_EMU:-$(cd "$(dirname "$0")" && pwd)}
cd "$CI_EMU/src" || exit 1
case $(uname -m) in
    x86_64|amd64) arch=linux/amd64 ;;
    *)            arch=linux/arm64 ;;
esac
# Keep the previous run's container (as -prev) rather than deleting it.
if docker inspect httpd-github-ci >/dev/null 2>&1; then
  docker rm -f httpd-github-ci-prev >/dev/null 2>&1
  docker rename httpd-github-ci httpd-github-ci-prev
fi
act push -W .github/workflows/linux.yml -j build \
  --matrix "name:${1:-Python pytest test suites}" \
  -P ubuntu-latest=act-ubuntu-24.04-ci:local --pull=false \
  --container-architecture "$arch" \
  --container-options "--init --user runner" --reuse
rc=$?
# act cannot name the container, so rename it for later inspection.
c=$(docker ps -a --format '{{.Names}}' | grep '^act-' | head -1)
[ -n "$c" ] && docker rename "$c" httpd-github-ci && echo "container renamed: $c -> httpd-github-ci"
exit $rc
```

* `-P ubuntu-latest=...` maps the runner label to the local image;
  `--pull=false` stops act looking for it on a registry.
* `--init` gives the container a real PID 1, so orphaned CGI processes are
  reaped; `--user runner` runs the job as the non-root user from the image.
* `--reuse` keeps the container after a successful run (a failed job's
  container is kept as well, unless `--rm` is given).

`chmod +x prepare.sh run-job.sh`.

## Running a job

    cd "$CI_EMU"
    ./prepare.sh origin/2.4.x       # or trunk, a branch, a tag, a sha
    ./run-job.sh 'Python pytest test suites' > out/job.log 2>&1

* The argument is the `name:` of a matrix entry of the `build` job; list them:
  `grep -n '^          - name:' src/.github/workflows/linux.yml`.
* Re-run `prepare.sh` after every commit you want tested; the job sees the
  last snapshot only.
* A full pytest job takes roughly 15 to 30 minutes (dependencies, APR, httpd,
  the suites). `tail -f out/job.log` shows progress; a log that stops growing
  while no `act` process is running means the job died.

### Narrowing a run

`travis_run_linux.sh` passes `PYTEST_ARGS` to `make check-all-pytest`: test
paths relative to `test/` and any pytest options (see `test/README.ci`). To use
it, after `prepare.sh` add a line to the `env:` block of the matrix entry in
`$CI_EMU/src/.github/workflows/linux.yml`, for example after `TEST_MD=1`:

    PYTEST_ARGS=modules/md/test_310_conf_store.py -v

The value may contain spaces. `prepare.sh` regenerates the file, so this is
not permanent. The build still runs in full; for fast repeat runs of the same
build use the kept container, below.

### Reading the result

    grep -n -E '❌|🏁|Job succeeded|Job failed|[0-9]+ passed|[0-9]+ failed|error in' out/job.log

The `Build and test` step's pytest summary (`N passed, M skipped, ...`) is the
line to compare with GitHub. Check that suites you care about did not skip: a
`::warning::pebble install failed` line means `modules/md` did not run.

## Inspecting and debugging in the kept container

The container is kept as `httpd-github-ci`, the run before it as
`httpd-github-ci-prev`. Its workspace is a Docker volume that act filled with a
copy of `$CI_EMU/src`, mounted at the same absolute path. The build (`check/`)
is in it, and editing files on the host does not change it. If Docker was
restarted, run `docker start httpd-github-ci` first.

    docker exec -it -u runner -w "$CI_EMU/src" httpd-github-ci bash

Run the pytest suites again against the existing build, without rebuilding:

    docker exec -u runner -w "$CI_EMU/src" httpd-github-ci bash -c '
      export PATH=$HOME/go/bin:$HOME/.local/bin:$PATH \
             PYHTTPD_CONFIG='"$CI_EMU"'/src/check/config.ini
      test/runtests.sh --apxs='"$CI_EMU"'/src/check/bin/apxs \
        --php-fpm=/usr/sbin/php-fpm8.3 modules/md/test_310_conf_store.py -q'

Tools missing from the image can be installed in the container with `sudo
apt-get install` (for example `gdb`, to take `thread apply all bt` of a hung
httpd child); they are lost when the container is removed. `docker cp` puts a
changed file into the container.

## Deviations, and why

`prepare.sh` applies these to the scratch copy only. It stops if one does not
apply, which is how a workflow change that breaks one gets noticed.

1. `/etc/hosts` is a bind mount in Docker, so `sed -i`, which renames a new
   file over it, fails. It is rewritten in place instead.
2. act does not feed `$GITHUB_ENV` into step `if:` conditions, so a step that
   GitHub skips for `NO_TEST_FRAMEWORK` jobs would run. The condition tests
   `matrix.env` instead.
3. act's `$GITHUB_ENV` parser rejects the blank line a multi-line `matrix.env`
   ends with and drops all of the job's variables, `TEST_*` included. Blank
   lines are filtered out of the write.
4. act copies the workspace honouring `.gitignore`, which lists
   `/build/PrintPath` although the file is tracked. Without it `configure`
   finds no perl and `apxs` gets a placeholder shebang. `git add -Af` in the
   snapshot commit includes it.

The image, not `prepare.sh`, supplies php-fpm, the non-root `runner` user and
(optionally) Go.

## Pitfalls

* `Cannot connect to the Docker daemon` / `failed to connect to the docker
  API`: the daemon is not running or your user may not use it.
* `No such image` for `catthehacker/ubuntu`: pull from `ghcr.io/...`, not Docker
  Hub. An architecture mismatch error from act: see `DOCKER_DEFAULT_PLATFORM`
  above, and `--container-architecture` in `run-job.sh`.
* Every test fails with connection refused, or httpd exits at start: the job ran
  as root. Keep `--user runner`.
* `modules/md` tests all skip: no `go`, so no pebble.
* Jobs that do not use `NO_TEST_FRAMEWORK` check out the Perl test framework
  from GitHub and need network access.
* A pytest run that was killed can leave httpd, php-fpm or CGI processes behind
  in the kept container; the next run then fails on busy ports. Kill them or
  start from a fresh container.

## Comparing with real CI

    gh run list --repo apache/httpd --workflow Linux --branch trunk --limit 5
    gh run view <run id> --repo apache/httpd --json jobs \
        --jq '.jobs[] | select(.conclusion=="failure") | [.databaseId,.name] | @tsv'
    gh run view --repo apache/httpd --job <job id> --log-failed

On a failed job the workflow uploads an `error_log-<job>` artifact (httpd error
logs and `config.log`):

    gh api repos/apache/httpd/actions/runs/<run id>/artifacts --jq '.artifacts[]|[.id,.name]|@tsv'
    gh api repos/apache/httpd/actions/artifacts/<artifact id>/zip > a.zip

Unzip it into an empty directory of its own. The `modules/` suites reuse one
log file that is truncated at every server start, so it holds only the last
server instance; run the test in the kept container to see the others.

The hosted result is the reference. A difference that the CPU architecture does
not explain is worth chasing.

## Files

    $CI_EMU/
      Dockerfile.act    runner image additions
      prepare.sh        export a ref + deviations
      run-job.sh        act invocation, container rename
      src/              the scratch tree act runs (regenerated)
      out/              logs
