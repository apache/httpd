
APACHE_MODPATH_INIT(experimental)

if test "$ac_cv_ebcdic" = "yes"; then
# mod_charset_lite can be very useful on an ebcdic system, 
#   so include it by default
    APACHE_MODULE(charset_lite, character set translation, , , yes)
else
    APACHE_MODULE(charset_lite, character set translation, , , no)
fi

APACHE_MODULE(example, example and demo module, , , no)
APACHE_MODULE(case_filter, example uppercase conversion filter, , , no)
APACHE_MODULE(case_filter_in, example uppercase conversion input filter, , , no)
APACHE_MODULE(filter, smart filtering module, , , no)

APACHE_MODPATH_FINISH
