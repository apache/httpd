@r@
expression rv, s;
constant char [] format;
identifier level =~ "^APLOG_(EMERG|ALERT|CRIT|ERR|WARNING|NOTICE|INFO|STARTUP|DEBUG)$";
identifier fn =~ "^ap_log_(|r|c|p)error$";

@@
        fn( APLOG_MARK ,
(
        level
|
        level|APLOG_NOERROR
|
        level|APLOG_STARTUP
)
        ,rv, s
+       , APLOGNO()
        ,format, ...)
