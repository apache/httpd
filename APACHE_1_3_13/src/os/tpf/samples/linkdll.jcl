//LINKDLL  JOB MSGLEVEL=(1,1),CLASS=G,MSGCLASS=S
/*ROUTE PRINT <your-id-here>
/*ROUTE PUNCH <your-id-here>
/*NOTIFY <your-id-here>
//CCLE JCLLIB ORDER=(SYS1.CBC.SCBCPRC,SYS1.CEE.SCEEPROC)
//PRELINK EXEC EDCPL,COND.LKED=(0,NE),
// PPARM='OMVS,DLLNAME(CHTA)',
// LREGSIZ='2048K',
// LPARM='AMODE=31,RMODE=ANY,LIST,XREF'
//PLKED.SYSLIB DD DISP=SHR,DSN=ACP.STUB.RLSE40
//             DD DISP=SHR,DSN=ACP.CLIB.RLSE40
//PLKED.OBJLIB DD DISP=SHR,DSN=ACP.MAIN.SYST.OBBSS
//             DD DISP=SHR,DSN=ACP.DF.MAIN.SYST.OBBSS
//             DD DISP=SHR,DSN=ACP.OBJ.RLSE40.BSS
//PLKED.OBJ01  DD PATH='/<your-path-here>/src/ap/ap_base64.o'
//PLKED.OBJ02  DD PATH='/<your-path-here>/src/ap/ap_checkpass.o'
//PLKED.OBJ03  DD PATH='/<your-path-here>/src/ap/ap_cpystrn.o'
//PLKED.OBJ04  DD PATH='/<your-path-here>/src/ap/ap_execve.o'
//PLKED.OBJ05  DD PATH='/<your-path-here>/src/ap/ap_fnmatch.o'
//PLKED.OBJ06  DD PATH='/<your-path-here>/src/ap/ap_getpass.o'
//PLKED.OBJ07  DD PATH='/<your-path-here>/src/ap/ap_md5c.o'
//PLKED.OBJ08  DD PATH='/<your-path-here>/src/ap/ap_sha1.o'
//PLKED.OBJ09  DD PATH='/<your-path-here>/src/ap/ap_signal.o'
//PLKED.OBJ10  DD PATH='/<your-path-here>/src/ap/ap_slack.o'
//PLKED.OBJ11  DD PATH='/<your-path-here>/src/ap/ap_snprintf.o'
//PLKED.OBJ12  DD PATH='/<your-path-here>/src/buildmark.o'
//PLKED.OBJ13  DD PATH='/<your-path-here>/src/main/alloc.o'
//PLKED.OBJ14  DD PATH='/<your-path-here>/src/main/buff.o'
//PLKED.OBJ15  DD PATH='/<your-path-here>/src/main/http_config.o'
//PLKED.OBJ16  DD PATH='/<your-path-here>/src/main/http_core.o'
//PLKED.OBJ17  DD PATH='/<your-path-here>/src/main/http_log.o'
//PLKED.OBJ18  DD PATH='/<your-path-here>/src/main/http_main.o'
//PLKED.OBJ19  DD PATH='/<your-path-here>/src/main/http_protocol.o'
//PLKED.OBJ20  DD PATH='/<your-path-here>/src/main/http_request.o'
//PLKED.OBJ21  DD PATH='/<your-path-here>/src/main/http_vhost.o'
//PLKED.OBJ22  DD PATH='/<your-path-here>/src/main/rfc1413.o'
//PLKED.OBJ23  DD PATH='/<your-path-here>/src/main/util.o'
//PLKED.OBJ24  DD PATH='/<your-path-here>/src/main/util_date.o'
//PLKED.OBJ25  DD PATH='/<your-path-here>/src/main/util_md5.o'
//PLKED.OBJ26  DD PATH='/<your-path-here>/src/main/util_script.o'
//PLKED.OBJ27  DD PATH='/<your-path-here>/src/main/util_uri.o'
//PLKED.OBJ28  DD PATH='/<your-path-here>/src/modules.o'
//PLKED.OBJ29  DD PATH='/<your-path-here>/src/modules/standard/mod_acce\
//             ss.o'
//PLKED.OBJ30  DD PATH='/<your-path-here>/src/modules/standard/mod_acti\
//             ons.o'
//PLKED.OBJ31  DD PATH='/<your-path-here>/src/modules/standard/mod_alia\
//             s.o'
//PLKED.OBJ32  DD PATH='/<your-path-here>/src/modules/standard/mod_asis\
//             .o'
//PLKED.OBJ33  DD PATH='/<your-path-here>/src/modules/standard/mod_auth\
//             .o'
//PLKED.OBJ34  DD PATH='/<your-path-here>/src/modules/standard/mod_auto\
//             index.o'
//PLKED.OBJ35  DD PATH='/<your-path-here>/src/modules/standard/mod_cgi.\
//             o'
//PLKED.OBJ36  DD PATH='/<your-path-here>/src/modules/standard/mod_dir.\
//             o'
//PLKED.OBJ37  DD PATH='/<your-path-here>/src/modules/standard/mod_env.\
//             o'
//PLKED.OBJ38  DD PATH='/<your-path-here>/src/modules/standard/mod_imap\
//             .o'
//PLKED.OBJ39  DD PATH='/<your-path-here>/src/modules/standard/mod_incl\
//             ude.o'
//PLKED.OBJ40  DD PATH='/<your-path-here>/src/modules/standard/mod_log_\
//             config.o'
//PLKED.OBJ41  DD PATH='/<your-path-here>/src/modules/standard/mod_mime\
//             .o'
//PLKED.OBJ42  DD PATH='/<your-path-here>/src/modules/standard/mod_nego\
//             tiation.o'
//PLKED.OBJ43  DD PATH='/<your-path-here>/src/modules/standard/mod_sete\
//             nvif.o'
//PLKED.OBJ44  DD PATH='/<your-path-here>/src/modules/standard/mod_stat\
//             us.o'
//PLKED.OBJ45  DD PATH='/<your-path-here>/src/modules/standard/mod_user\
//             dir.o'
//PLKED.OBJ46  DD PATH='/<your-path-here>/src/os/tpf/cgetop.o'
//PLKED.OBJ47  DD PATH='/<your-path-here>/src/os/tpf/ebcdic.o'
//PLKED.OBJ48  DD PATH='/<your-path-here>/src/os/tpf/os.o'
//PLKED.OBJ49  DD PATH='/<your-path-here>/src/os/tpf/os-inline.o'
//PLKED.OBJ50  DD PATH='/<your-path-here>/src/regex/regcomp.o'
//PLKED.OBJ51  DD PATH='/<your-path-here>/src/regex/regerror.o'
//PLKED.OBJ52  DD PATH='/<your-path-here>/src/regex/regexec.o'
//PLKED.OBJ53  DD PATH='/<your-path-here>/src/regex/regfree.o'
//PLKED.OBJ54  DD PATH='/<your-path-here>/src/lib/expat-lite/hashtable.\
//             o'
//PLKED.OBJ55  DD PATH='/<your-path-here>/src/lib/expat-lite/xmlparse.o\
//             '
//PLKED.OBJ56  DD PATH='/<your-path-here>/src/lib/expat-lite/xmlrole.o'
//PLKED.OBJ57  DD PATH='/<your-path-here>/src/lib/expat-lite/xmltok.o'
//PLKED.SYSIN DD *
 ORDER @@DLMHDR
 INCLUDE OBJLIB(CSTRTD40)
 INCLUDE OBJ01
 INCLUDE OBJ02
 INCLUDE OBJ03
 INCLUDE OBJ04
 INCLUDE OBJ05
 INCLUDE OBJ06
 INCLUDE OBJ07
 INCLUDE OBJ08
 INCLUDE OBJ09
 INCLUDE OBJ10
 INCLUDE OBJ11
 INCLUDE OBJ12
 INCLUDE OBJ13
 INCLUDE OBJ14
 INCLUDE OBJ15
 INCLUDE OBJ16
 INCLUDE OBJ17
 INCLUDE OBJ18
 INCLUDE OBJ19
 INCLUDE OBJ20
 INCLUDE OBJ21
 INCLUDE OBJ22
 INCLUDE OBJ23
 INCLUDE OBJ24
 INCLUDE OBJ25
 INCLUDE OBJ26
 INCLUDE OBJ27
 INCLUDE OBJ28
 INCLUDE OBJ29
 INCLUDE OBJ30
 INCLUDE OBJ31
 INCLUDE OBJ32
 INCLUDE OBJ33
 INCLUDE OBJ34
 INCLUDE OBJ35
 INCLUDE OBJ36
 INCLUDE OBJ37
 INCLUDE OBJ38
 INCLUDE OBJ39
 INCLUDE OBJ40
 INCLUDE OBJ41
 INCLUDE OBJ42
 INCLUDE OBJ43
 INCLUDE OBJ44
 INCLUDE OBJ45
 INCLUDE OBJ46
 INCLUDE OBJ47
 INCLUDE OBJ48
 INCLUDE OBJ49
 INCLUDE OBJ50
 INCLUDE OBJ51
 INCLUDE OBJ52
 INCLUDE OBJ53
 INCLUDE OBJ54
 INCLUDE OBJ55
 INCLUDE OBJ56
 INCLUDE OBJ57
 INCLUDE OBJLIB(CINET640)
/*
//*** WARNING *** NEVER change .LK to .OB in SYSLMOD!!!
//LKED.SYSLMOD DD DISP=OLD,DSN=<your-dsn-here>(CHTA<vv>)
//
