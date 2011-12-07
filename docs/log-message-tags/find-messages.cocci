@r1@
expression rv, s;
constant char [] format;
identifier level =~ "^APLOG_(EMERG|ALERT|CRIT|ERR|WARNING|NOTICE|INFO|STARTUP|DEBUG)$";
identifier fn =~ "^ap_log_(|r|c|p)error$";

@@
        fn( APLOG_MARK ,
(
        level
|
        level|APLOG_NOERRNO
|
        level|APLOG_STARTUP
)
        ,rv, s
+       , APLOGNO()
        ,format, ...)

@r2@
expression rv, s, c;
constant char [] format;
identifier level =~ "^APLOG_(EMERG|ALERT|CRIT|ERR|WARNING|NOTICE|INFO|STARTUP|DEBUG)$";

@@
        ap_log_cserror( APLOG_MARK ,
(
        level
|
        level|APLOG_NOERRNO
|
        level|APLOG_STARTUP
)
        ,rv, s, c
+       , APLOGNO()
        ,format, ...)

@r3@
expression rv, p, s, cert;
constant char [] format;
identifier level =~ "^APLOG_(EMERG|ALERT|CRIT|ERR|WARNING|NOTICE|INFO|STARTUP|DEBUG)$";

@@
        ssl_log_xerror( SSLLOG_MARK ,
(
        level
|
        level|APLOG_NOERRNO
|
        level|APLOG_STARTUP
)
        ,rv, p, s , cert
+       , APLOGNO()
        ,format, ...)

@r4@
expression rv, rc, cert;
constant char [] format;
identifier level =~ "^APLOG_(EMERG|ALERT|CRIT|ERR|WARNING|NOTICE|INFO|STARTUP|DEBUG)$";
identifier fn =~ "^ssl_log_(r|c)xerror$";

@@
        fn( SSLLOG_MARK ,
(
        level
|
        level|APLOG_NOERRNO
|
        level|APLOG_STARTUP
)
        ,rv, rc , cert
+       , APLOGNO()
        ,format, ...)


