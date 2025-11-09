dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(loggers)

APACHE_MODULE(journald, Journald support, , , all, [
  new_systemd_found="yes"
  AC_CHECK_LIB(systemd, sd_journal_sendv, JOURNALD_LIBS="-lsystemd")
  if test -z "${JOURNALD_LIBS}"; then
    new_systemd_found="no"
    AC_CHECK_LIB(systemd-journal, sd_journal_sendv, JOURNALD_LIBS="-lsystemd-journal")
    AC_CHECK_LIB(systemd-id128, sd_id128_to_string, ID128_LIBS="-lsystemd-id128")
  fi
  AC_CHECK_HEADERS(systemd/sd-journal.h, [ap_HAVE_SD_JOURNAL_H="yes"], [ap_HAVE_SD_JOURNAL_H="no"])
  AC_CHECK_HEADERS(systemd/sd-id128.h, [ap_HAVE_SD_ID128_H="yes"], [ap_HAVE_SD_ID128_H="no"])
  if test $ap_HAVE_SD_JOURNAL_H = "no" || test $ap_HAVE_SD_ID128_H = "no" || test -z "${JOURNALD_LIBS}" || (test $new_systemd_found = "no" && test -z "${ID128_LIBS}"); then
    AC_MSG_WARN([Your system does not support Journald.])
    enable_journald="no"
  else
    APR_ADDTO(MOD_JOURNALD_LDADD, [$JOURNALD_LIBS])
    if test $new_systemd_found = "no"; then
      APR_ADDTO(MOD_JOURNALD_LDADD, [$ID128_LIBS])
    fi
  fi
])

APACHE_MODULE(syslog, logging to syslog, , , all, [
  AC_CHECK_HEADERS(syslog.h, [ap_HAVE_SYSLOG_H="yes"], [ap_HAVE_SYSLOG_H="no"])
  if test $ap_HAVE_SYSLOG_H = "no"; then
    AC_MSG_WARN([Your system does not support syslog.])
    enable_syslog="no"
  fi
])


APACHE_MODULE(log_json, logging in jsonn, , , most, [
  APACHE_CHECK_JANSSON
  if test "x$ac_cv_jansson" != "xyes" ; then
      AC_MSG_WARN([libjansson not found])
      enable_log_json="no"
  else
      APR_ADDTO(MOD_LOG_JSON_LDADD, [$ap_jansson_libs])
  fi
])

APACHE_MODULE(log_config, logging configuration.  You won't be able to log requests to the server without this module., , , yes)
APACHE_MODULE(log_debug, configurable debug logging, , , most)
APACHE_MODULE(log_forensic, forensic logging)

if test "x$enable_log_forensic" != "xno"; then
    # mod_log_forensic needs test_char.h
    APR_ADDTO(INCLUDES, [-I\$(top_builddir)/server])
fi   

APACHE_MODULE(logio, input and output logging, , , most)

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
