AC_MSG_CHECKING(for target platform)

PLATFORM=`${CONFIG_SHELL-/bin/sh} $ac_config_guess`

case "$PLATFORM" in
*beos*)
  OS="beos";;
*)
  OS="unix";;
esac

OS_DIR=os/$OS

AC_MSG_RESULT($OS)
APACHE_FAST_OUTPUT($OS_DIR/Makefile)
