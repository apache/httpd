#!/bin/bash
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script will populate a directory 'sni' with 3 sites, httpd.conf
# and certificates as to facilitate testing of TLS server name 
# indication support (RFC 4366) or SNI.
#


testcase=$1

[ -n "$testcase" ] || {
  echo "No testcase provided"
  exit 1
}

set -eo pipefail

[ -n "$testcase" ] || (echo No testcase provided; exit 1) >&2
[ -f "$testcase" ] || (echo Cannot find file "$testcase"; exit 1 ) >&2

set -x
thisdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
echo thisdir=$thisdir
#  dockerfile=${ENVIRON_DOCKERFILE:-Dockerfile.environs.opensuse.leap}
dockerfile=${ENVIRON_DOCKERFILE:-Dockerfile.environs.ubuntu}
[ -f "$dockerfile" ] || [ -z "$dockerfile" ] || {
    [[ ! -f $thisdir/$dockerfile ]] || dockerfile=$thisdir/$dockerfile
}
basename=$(basename "$testcase")
basename=${basename,,}
basename=${basename//:/_}
ident=apache.httpd.envtest
containername="$ident.${basename,,}"

docker_info="$(docker info >/dev/null 2>&1)" || ( >&2 echo "Docker doesn't seem to be running, try: docker info"; exit 1)

echo dockerfile=$dockerfile
docker build -t $ident.image -f $dockerfile $thisdir

map_port=""
[ -z "$EXPOSE_PORT" ] || map_port="-p $EXPOSE_PORT:80"
docker run $map_port --rm --name "$containername" --env REBUILD=1 -d -v"$thisdir/../../../../":/opt/environs/httpd -- $ident.image

in_cleanup=0

function cleanup {
    [ "$in_cleanup" != 1 ] || return
    in_cleanup=1
    if [ "$ret" != 0 ] && [ -n "$PAUSE_ON_FAILURE" ]; then
        read -rsn1 -p"Test failed, press any key to finish";echo
    fi
    [ "$ret" == 0 ] || echo FAIL $basename
    docker stop -t 0 "$containername" >&/dev/null || :
}

trap cleanup INT TERM EXIT
counter=1

# wait container start
until [ $counter -gt 10 ]; do
  sleep 0.5
  docker exec "$containername" pwd >& /dev/null && break
  ((counter++))
done

docker exec "$containername" pwd >& /dev/null || (echo Cannot start container; exit 1 ) >&2

echo "$*"
set +ex
docker exec -e TESTCASE="$testcase"  -i "$containername" bash -c "useradd $(id -nu) -u $(id -u) || :; chown $(id -nu) /opt/environs; sudo -u \#$(id -u) bash" < "$testcase"
ret=$?
if test $ret == 0; then
    echo PASS $testcase
else
    echo FAIL "$testcase ($ret)"
    ( exit $ret )
fi
