//APACH JOB MSGLEVEL=(1,1),CLASS=A,MSGCLASS=A
/*ROUTE PRINT XXXXXX.XXXXXX
/*ROUTE PUNCH XXXXXX.XXXXXX
/*NOTIFY XXXXXX.XXXXXX
//CCLE JCLLIB ORDER=(SYS1.CBC.SCBCPRC,SYS1.CEE.SCEEPROC)
//PRELINK EXEC EDCPL,COND.LKED=(0,NE),
// PPARM='OMVS,DLLNAME(pppp)',
// LREGSIZ='2048K',
// LPARM='AMODE=31,RMODE=ANY,LIST,XREF'
//PLKED.SYSLIB DD DISP=SHR,DSN=FSE0000.DEVP.STUB.OB
//             DD DISP=SHR,DSN=FSE0000.DEVP.CLIB.OB
//             DD DISP=SHR,DSN=ACP.CLIB.RLSE46.WEB
//             DD DISP=SHR,DSN=ACP.STUB.RLSE46.WEB
//             DD DISP=SHR,DSN=ACP.CLIB.RLSE40
//             DD DISP=SHR,DSN=ACP.STUB.RLSE40
//PLKED.SYSDEFSD DD DSN=APA0000.DEVP.IMPORTS.DSD(ppppvv),DISP=SHR
//PLKED.DSD DD DSN=APA0000.DEVP.IMPORTS.DSD,DISP=SHR
//PLKED.OBJLIB DD DISP=SHR,DSN=FSE0000.DEVP.TEST.OB
//             DD DISP=SHR,DSN=ACP.OBJ.RLSE46.WEB
//             DD DISP=SHR,DSN=ACP.OBJ.INTG98.NBS
//             DD DISP=SHR,DSN=ACP.MAIN.SYST.OBBSS
//             DD DISP=SHR,DSN=ACP.DF.MAIN.SYST.OBBSS
//             DD DISP=SHR,DSN=ACP.OBJ.RLSE40.BSS
//PLKED.OBJ1   DD PATH='/usr/local/apache/src/ap/ap_cpystrn.o'
//PLKED.OBJ2   DD PATH='/usr/local/apache/src/ap/ap_execve.o'
//PLKED.OBJ3   DD PATH='/usr/local/apache/src/ap/ap_signal.o'
//PLKED.OBJ4   DD PATH='/usr/local/apache/src/ap/ap_slack.o'
//PLKED.OBJ5   DD PATH='/usr/local/apache/src/ap/ap_snprintf.o'
//PLKED.OBJ6   DD PATH='/usr/local/apache/src/ap/ap_strings.o'
//PLKED.OBJ7   DD PATH='/usr/local/apache/src/os/tpf/ebcdic.o'
//PLKED.OBJ8   DD PATH='/usr/local/apache/src/os/tpf/os.o'
//PLKED.OBJ9   DD PATH='/usr/local/apache/src/os/tpf/os-inline.o'
//PLKED.OBJ10  DD PATH='/usr/local/apache/src/regex/regcomp.o'
//PLKED.OBJ11  DD PATH='/usr/local/apache/src/regex/regerror.o'
//PLKED.OBJ12  DD PATH='/usr/local/apache/src/regex/regexec.o'
//PLKED.OBJ13  DD PATH='/usr/local/apache/src/regex/regfree.o'
//PLKED.OBJ14  DD PATH='/usr/local/apache/src/main/alloc.o'
//PLKED.OBJ15  DD PATH='/usr/local/apache/src/main/buff.o'
//PLKED.OBJ16  DD PATH='/usr/local/apache/src/main/fnmatch.o'
//PLKED.OBJ17  DD PATH='/usr/local/apache/src/main/http_config.o'
//PLKED.OBJ18  DD PATH='/usr/local/apache/src/main/http_core.o'
//PLKED.OBJ19  DD PATH='/usr/local/apache/src/main/http_log.o'
//PLKED.OBJ20  DD PATH='/usr/local/apache/src/main/http_main.o'
//PLKED.OBJ21  DD PATH='/usr/local/apache/src/main/http_protocol.o'
//PLKED.OBJ22  DD PATH='/usr/local/apache/src/main/http_request.o'
//PLKED.OBJ23  DD PATH='/usr/local/apache/src/main/http_vhost.o'
//PLKED.OBJ24  DD PATH='/usr/local/apache/src/main/md5c.o'
//PLKED.OBJ25  DD PATH='/usr/local/apache/src/main/rfc1413.o'
//PLKED.OBJ26  DD PATH='/usr/local/apache/src/main/util.o'
//PLKED.OBJ27  DD PATH='/usr/local/apache/src/main/util_date.o'
//PLKED.OBJ28  DD PATH='/usr/local/apache/src/main/util_md5.o'
//PLKED.OBJ29  DD PATH='/usr/local/apache/src/main/util_script.o'
//PLKED.OBJ30  DD PATH='/usr/local/apache/src/main/util_uri.o'
//PLKED.OBJ31  DD PATH='/usr/local/apache/src/modules.o'
//PLKED.OBJ32  DD PATH='/usr/local/apache/src/buildmark.o'
//PLKED.OBJ33  DD PATH='/usr/local/apache/src/modules/standard/mod_auto\
//             index.o'
//PLKED.OBJ34  DD PATH='/usr/local/apache/src/modules/standard/mod_dir.\
//             o'
//PLKED.OBJ35  DD PATH='/usr/local/apache/src/modules/standard/mod_mime\
//             .o'
//PLKED.OBJ36  DD PATH='/usr/local/apache/src/modules/standard/mod_sete\
//             nvif.o'
//PLKED.OBJ37  DD PATH='/usr/local/apache/src/modules/standard/mod_alia\
//             s.o'
//PLKED.OBJ38  DD PATH='/usr/local/apache/src/modules/standard/mod_acce\
//             ss.o'
//PLKED.OBJ39  DD PATH='/usr/local/apache/src/modules/standard/mod_user\
//             dir.o'
//PLKED.OBJ40  DD PATH='/usr/local/apache/src/modules/standard/mod_spel\
//             ing.o'
//PLKED.OBJ41  DD PATH='/usr/local/apache/src/modules/standard/mod_nego\
//             tiation.o'
//PLKED.SYSIN DD *
 ORDER @@DLMHDR
 INCLUDE OBJLIB(CSTRTD40)
 INCLUDE OBJ1
 INCLUDE OBJ2
 INCLUDE OBJ3
 INCLUDE OBJ4
 INCLUDE OBJ5
 INCLUDE OBJ6
 INCLUDE OBJ7
 INCLUDE OBJ8
 INCLUDE OBJ9
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
/*
//*** WARNING *** NEVER change .LK to .OB in SYSLMOD!!!
//LKED.SYSLMOD DD DISP=OLD,DSN=xxxxxx.xxxx(ppppvv)
//
