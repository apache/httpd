AC_MSG_CHECKING(for target platform)

case $host in
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
*mingw32*)
  OS="win32"
  OS_DIR=$OS
  ;;
*)
  OS="unix"
  OS_DIR=$OS;;
esac

AC_MSG_RESULT($OS)
APACHE_FAST_OUTPUT(os/${OS_DIR}/Makefile)
