AC_MSG_CHECKING(for target platform)

case $host in
*beos*)
  OS="beos"
  OS_DIR=$OS
  ;;
*pc-os2-emx*)
  OS="os2"
  OS_DIR=$OS
  ;;
bs2000*)
  OS="unix"
  OS_DIR=$OS
  ;;
*cygwin*)
  OS="cygwin"
  OS_DIR="unix"
  ;;
*)
  OS="unix"
  OS_DIR=$OS;;
esac

AC_MSG_RESULT($OS)
APACHE_FAST_OUTPUT(os/${OS_DIR}/Makefile)
