AC_MSG_CHECKING(which OS this is)

dnl ## XXX - I'm not sure, but this might not handle the non-Unix case yet
OS=unix
OS_DIR=os/$OS

AC_MSG_RESULT([$OS])
APACHE_OUTPUT(os/$OS/Makefile)
