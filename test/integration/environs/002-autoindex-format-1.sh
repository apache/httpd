#!lib/test-in-container-environs.sh
set -ex

./environ.sh ap1 $(pwd)/httpd
# ap1/build.sh
ap1/start.sh
# autoindex is enabled by default
grep -q mod_autoindex ap1/httpd.conf

mkdir ap1/dt/folder1/
touch ap1/dt/folder1/file1.dat
touch ap1/dt/folder1/file2.dat

curl -s $(ap1/print_address.sh)/folder1?F=1
curl -s $(ap1/print_address.sh)/folder1?F=1 | grep -C10 file1.dat | grep file2.dat
curl -s $(ap1/print_address.sh)/folder1?F=1 | tidy -quiet -errors
