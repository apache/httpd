#!/bin/sh -ex
DOCKER=`which podman || which docker`
export CONTAINER=${CONTAINER:-fedora}
HTTPD_TAG=${HTTPD_TAG:-travis_httpd_${CONTAINER}}
DOCKERFILE=${DOCKERFILE:-test/travis_Dockerfile_${CONTAINER}}
if [ ! -r ${DOCKERFILE} ]; then
    echo No Dockerfile ${DOCKERFILE} found for ${CONTAINER}, cannot continue
    exit 1
fi    
$DOCKER build \
       ${CONTAINER:+--build-arg=CONTAINER=$CONTAINER} \
       ${APR_CONFIG:+--build-arg=APR_CONFIG=$APR_CONFIG} \
       ${APR_VERSION:+--build-arg=APR_VERSION=$APR_VERSION} \
       ${APU_CONFIG:+--build-arg=APU_CONFIG=$APU_CONFIG} \
       ${APU_VERSION:+--build-arg=APU_VERSION=$APU_VERSION} \
       ${CONFIG:+--build-arg=CONFIG=$CONFIG} \
       -t ${HTTPD_TAG} \
       -f ${DOCKERFILE} .
$DOCKER run \
       ${HTTPD_TAG} -e CONFIG \
        /home/build/build/httpd/test/travis_run_linux.sh
