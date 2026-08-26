#!/bin/bash -e
#
# Work out what identifies the contents of ~/root, and write it to
# $GITHUB_ENV as $ROOTID for the cache key to use.
#
# ~/root holds only the dependencies built from source, so the key
# covers those alone - not the job's own configuration.  Jobs which
# build the same dependencies then share one cache entry even where they
# configure or test httpd differently.  $ROOTID is left unset for a job
# which builds no dependencies at all, and the cache is skipped.
#
# Anything built from a branch is resolved to a commit here and the
# commit exported, so that the build uses exactly what the key names;
# resolving the branch again at build time would race with it moving.
# Tags and release tarballs are immutable, so the version is enough.

root=

# $1 = name, $2 = version, $3 = configure arguments, $4 = variable to
# export the resolved commit into.
function add_apx() {
    local name=$1
    local version=$2
    local config=$3
    local var=$4
    local sha

    if test -z "$version"; then
        return 0
    fi

    case "$version" in
      trunk|*.x)
        sha=`git ls-remote https://github.com/apache/${name}.git refs/heads/${version} | cut -f1`
        if test -z "$sha"; then
            : Could not resolve ${name} branch ${version} - check branch is valid?
            exit 1
        fi
        echo "${var}=${sha}" >> $GITHUB_ENV ;;
      *) sha=${version} ;;
    esac

    root="${root} ${name}-${version}-${sha}-${config}"
}

add_apx apr "${APR_VERSION-}" "${APR_CONFIG-}" APR_COMMIT
add_apx apr-util "${APU_VERSION-}" "${APU_CONFIG-}" APU_COMMIT

if test -n "${TEST_OPENSSL3-}"; then
    if test -n "${TEST_OPENSSL3_BRANCH-}"; then
        sha=`git ls-remote https://github.com/openssl/openssl refs/heads/${TEST_OPENSSL3_BRANCH} | cut -f1`
        if test -z "$sha"; then
            : Could not resolve openssl branch ${TEST_OPENSSL3_BRANCH} - check branch is valid?
            exit 1
        fi
        echo "OPENSSL_COMMIT=${sha}" >> $GITHUB_ENV
        root="${root} openssl-${TEST_OPENSSL3_BRANCH}-${sha}-${OPENSSL_CONFIG-}"
    else
        root="${root} openssl-${TEST_OPENSSL3}-${OPENSSL_CONFIG-}"
    fi
fi

if test -n "${TEST_NGHTTP2-}"; then
    root="${root} nghttp2-${TEST_NGHTTP2}"
fi

if test -n "${RUSTLS_VERSION-}"; then
    root="${root} rustls-${RUSTLS_VERSION}"
fi

if test -n "$root"; then
    # The compiler and every flag which reaches the build are baked into
    # the libraries, NOTEST_* included: APR adds those to the build too,
    # it just does not use them for ./configure.
    root="${root} CC=${CC-} CFLAGS=${CFLAGS-} CPPFLAGS=${CPPFLAGS-}"
    root="${root} LDFLAGS=${LDFLAGS-} LIBS=${LIBS-}"
    root="${root} NOTEST_CFLAGS=${NOTEST_CFLAGS-} NOTEST_CPPFLAGS=${NOTEST_CPPFLAGS-}"
    root="${root} NOTEST_LDFLAGS=${NOTEST_LDFLAGS-} NOTEST_LIBS=${NOTEST_LIBS-}"
    root="${root}${TEST_APR_TARBALL+ tarball}"
    : Dependencies:${root}
    echo ROOTID=`echo "$root" | md5sum - | sed 's/ .*//'` >> $GITHUB_ENV
else
    : No dependencies are built from source, so ~/root is not cached.
fi
