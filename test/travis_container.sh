#!/bin/sh -ex
DOCKER=`which podman || which docker`
export CONTAINER=${CONTAINER:-fedora}
HTTPD_TAG=travis_httpd_${CONTAINER}
DOCKERFILE=${DOCKERFILE:-test/travis_Dockerfile_${CONTAINER}}
if [ ! -r ${DOCKERFILE} ]; then
    echo No Dockerfile ${DOCKERFILE} found for ${CONTAINER}, cannot continue
    exit 1
fi    
$DOCKER build \
       --build-arg=CONTAINER=${CONTAINER} \
       --build-arg=APR_CONFIG \
       --build-arg=APR_VERSION \
       --build-arg=APU_CONFIG \
       --build-arg=APU_VERSION \
       --build-arg=CONFIG \
       -t ${HTTPD_TAG} \
       -f ${DOCKERFILE} .
$DOCKER run -e CONFIG -e BUILDCONFIG \
       ${HTTPD_TAG} \
        ./test/travis_run_linux.sh
