AC_MSG_CHECKING(for target platform)

#PLATFORM=`${CONFIG_SHELL-/bin/sh} $ac_config_guess`
PLATFORM=`$ac_config_guess`
LIBPRE=lib

case "$PLATFORM" in
*beos*)
  OS="beos"
  OS_DIR=os/$OS
  ;;
*pc-os2_emx*)
  LIBPRE=""
  OS="os2"
  OS_DIR=os/$OS
  ;;
bs2000*)
  OS="unix"
  OS_DIR=os/bs2000  # only the OS_DIR is platform specific.
  ;;
*)
  OS="unix"
  OS_DIR=os/$OS;;
esac


AC_MSG_RESULT($OS)
APACHE_FAST_OUTPUT($OS_DIR/Makefile)
