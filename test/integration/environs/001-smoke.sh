#!lib/test-in-container-environs.sh
set -ex

./environ.sh ap1 $(pwd)/httpd
! ap1/status.sh 2>/dev/null || ( echo "status.sh expected to return an error"; exit 1; )

ap1/start.sh
test ap1/status.sh || ( echo "status.sh expected to return no error"; exit 1; )

ap1/curl.sh && echo Apache server started properly at $(ap1/print_address.sh)

ap1/stop.sh

tail ap1/dt/error_log

! ap9*/status.sh 2>/dev/null || { echo "status.sh expected to return an error"; exit 1; }
