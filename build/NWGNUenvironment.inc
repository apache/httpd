#
# Setup needed Tools and Libraries
#

ifeq "$(wildcard $(AP_WORK)/NWGNUcustom.ini)" "$(AP_WORK)/NWGNUcustom.ini"
include $(AP_WORK)/NWGNUcustom.ini
CUSTOM_INI = $(AP_WORK)/NWGNUcustom.ini
endif

ifndef VERBOSE
.SILENT:
endif

#
# Treat like an include
#
ifndef EnvironmentDefined

#
# simple macros for parsing makefiles
#
EOLIST:=
EMPTY :=
COMMA := ,
SPACE := $(EMPTY) $(EMPTY)

#
# Base environment
#

# Try and handle case issues
ifndef NOVELLLIBC
ifdef NovellLibC
NOVELLLIBC = $(NovellLibC)
endif
endif

ifndef NOVELLLIBC
NOVELLLIBC = C:/novell/ndk/libc
endif
ifneq "$(wildcard $(NOVELLLIBC)/include/ndkvers.h)" "$(NOVELLLIBC)/include/ndkvers.h"
$(error NOVELLLIBC does not point to a valid Novell LIBC SDK) 
endif

ifndef LDAPSDK
LDAPSDK = C:/novell/ndk/cldapsdk/NetWare/libc
endif
ifneq "$(wildcard $(LDAPSDK)/inc/ldap.h)" "$(LDAPSDK)/inc/ldap.h"
$(error LDAPSDK does not point to a valid Novell CLDAP SDK) 
endif

ifndef PCRESRC
PCRESRC = $(AP_WORK)/srclib/pcre
endif
ifneq "$(wildcard $(PCRESRC)/pcre-config.in)" "$(PCRESRC)/pcre-config.in"
$(error PCRESRC does not point to a valid PCRE source tree) 
endif

# This is a placeholder
# ifndef ZLIBSDK
# ZLIBSDK = C:/novell/ndk/zlibsdk
# endif

ifndef METROWERKS
METROWERKS = $(ProgramFiles)\Metrowerks\CodeWarrior
endif

# If LM_LICENSE_FILE isn't defined, define a variable that can be used to
# restart make with it defined
ifndef LM_LICENSE_FILE
NO_LICENSE_FILE = NO_LICENSE_FILE
endif

#
# Set the Release type that you want to build, possible values are:
#
#  debug	- full debug switches are set
#  noopt	- normal switches are set
#  release	- optimization switches are set (default)

ifdef reltype
RELEASE = $(reltype)
endif    

ifdef RELTYPE
RELEASE = $(RELTYPE)
endif

ifdef debug
RELEASE = debug
endif

ifdef DEBUG
RELEASE = debug
endif

ifdef noopt
RELEASE = noopt
endif

ifdef NOOPT
RELEASE = noopt
endif

ifdef optimized
RELEASE = release
endif

ifdef OPTIMIZED
RELEASE = release
endif

ifndef RELEASE
RELEASE = release
endif

OBJDIR = obj_$(RELEASE)

# Define minimum APR version to check for
APR_WANTED = 1003000

#
# Setup compiler information
#

# MetroWerks NLM tools
CC	= mwccnlm
CPP	= mwccnlm
LINK	= mwldnlm
LIB	= mwldnlm -type library -w nocmdline
WIN_CC	= mwcc

# Setup build tools
AWK	= awk

# Setup distribution tools
ZIP	= zip -qr9
7ZA	= 7za >NUL a

#
# Declare Command and tool macros here
#

ifeq ($(findstring /sh,$(SHELL)),/sh)
DEL	= rm -f $1
RMDIR	= rm -fr $1
MKDIR	= mkdir -p $1
COPY	= -cp -afv $1 $2
#COPYR	= -cp -afr $1/* $2
COPYR	= -rsync -aC $1/* $2
TOUCH	= -touch $1
ECHONL	= echo ""
DL	= '
CAT	= cat
else
ifeq "$(OS)" "Windows_NT"
DEL	= $(shell if exist $(subst /,\,$1) del /q /f 2>NUL $(subst /,\,$1))
RMDIR	= $(shell if exist $(subst /,\,$1)\NUL rd /q /s 2>NUL $(subst /,\,$1))
else
DEL	= $(shell if exist $(subst /,\,$1) del 2>NUL $(subst /,\,$1))
RMDIR	= $(shell if exist $(subst /,\,$1)\NUL deltree /y 2>NUL $(subst /,\,$1))
endif
ECHONL	= $(ComSpec) /c echo.
MKDIR	= $(shell if not exist $(subst /,\,$1)\NUL md 2>NUL $(subst /,\,$1))
COPY	= -copy /y 2>NUL $(subst /,\,$1) $(subst /,\,$2)
COPYR	= -xcopy /q /y /e 2>NUL $(subst /,\,$1) $(subst /,\,$2)
TOUCH	= -copy /b 2>&1>NUL $(subst /,\,$1) +,,
CAT	= type
endif

ifdef IPV6
ifndef USE_STDSOCKETS
USE_STDSOCKETS=1
endif
endif

NOVI	= $(NOVELLLIBC)/imports
PRELUDE	= $(NOVI)/libcpre.o

INCDIRS	= $(NOVELLLIBC)/include;
ifndef USE_STDSOCKETS
INCDIRS	+= $(NOVELLLIBC)/include/winsock;
endif
ifneq "$(LDAPSDK)" ""
INCDIRS += $(LDAPSDK)/inc;
endif
ifneq "$(ZLIBSDK)" ""
INCDIRS += $(ZLIBSDK);
endif
#ifneq "$(PCRESRC)" ""
#INCDIRS += $(PCRESRC);
#endif

DEFINES	= -DNETWARE 
ifndef USE_STDSOCKETS
DEFINES	+= -DUSE_WINSOCK
endif
ifndef DEBUG
DEFINES	+= -DNDEBUG
endif

ifdef USE_STDSOCKETS
VERSION_SKT = (BSDSOCK)
else
VERSION_SKT = (WINSOCK)
endif

# MetroWerks static Libraries
CLIB3S	= $(METROWERKS)/Novell Support/Metrowerks Support/Libraries/Runtime/mwcrtl.lib
MATH3S	=
PLIB3S	= $(METROWERKS)/Novell Support/Metrowerks Support/Libraries/MSL C++/MWCPP.lib

ifeq "$(OS)" "Windows_NT"
# MetroWerks Win32 build flags to create build tools
MWCW_MSL         = "$(METROWERKS)/MSL"
MWCW_W32         = "$(METROWERKS)/Win32-x86 Support"
CC_FOR_BUILD     = $(WIN_CC)
CFLAGS_FOR_BUILD =  -O2 -gccinc -nodefaults -proc 586 -w off
CFLAGS_FOR_BUILD += -ir $(MWCW_MSL) -ir $(MWCW_W32) -lr $(MWCW_MSL) -lr $(MWCW_W32)
CFLAGS_FOR_BUILD += -lMSL_All_x86.lib -lkernel32.lib -luser32.lib
else
# GNUC build flags to create build tools
CC_FOR_BUILD     = gcc
CFLAGS_FOR_BUILD = -Wall -O2
endif

# Base compile flags
# and prefix or precompiled header added here.

# The default flags are as follows:
#
# -c                    compile only, no link
# -gccinc               search directory of referencing file first for #includes
# -Cpp_exceptions off   disable C++ exceptions
# -RTTI off             disable C++ run-time typing information
# -align 4              align on 4 byte bounderies
# -w nocmdline          disable command-line driver/parser warnings
# -proc PII             generate code base on Pentium II instruction set
# -inst mmx             use MMX extensions (Not used)

CFLAGS += -c -w nocmdline -gccinc -Cpp_exceptions off -RTTI off -align 4 -proc PII

ifdef CC_MAX_ERRORS
CFLAGS += -maxerrors $(CC_MAX_ERRORS)
else
CFLAGS += -maxerrors 1
endif

ifeq "$(REQUIRE_PROTOTYPES)" "1"
CFLAGS += -r
endif

# -g                    generate debugging information
# -O0                   level 0 optimizations
ifeq "$(RELEASE)" "debug"
CFLAGS += -g -O0
endif

# -O4,p                 level 4 optimizations, optimize for speed
ifeq "$(RELEASE)" "release"
CFLAGS += -O4,p
endif

# -prefix pre_nw.h      #include pre_nw.h for all files
CFLAGS += -prefix pre_nw.h


ifneq ($(findstring /sh,$(SHELL)),/sh)
PATH:=$(PATH);$(METROWERKS)\bin;$(METROWERKS)\Other Metrowerks Tools\Command Line Tools
endif

#
# Declare major project deliverables output directories here
#

ifndef PORT
PORT = 80
endif

ifndef SSLPORT
SSLPORT = 443
endif

ifdef DEST
INSTALL = $(subst \,/,$(DEST))
ifeq (/, $(findstring /,$(INSTALL)))
INSTDIRS = $(INSTALL)
endif
endif

ifdef dest
INSTALL = $(subst \,/,$(dest))
ifeq (/, $(findstring /,$(INSTALL)))
INSTDIRS = $(INSTALL)
endif
endif

ifndef INSTALL
INSTALL = $(AP_WORK)/Dist
INSTDIRS = $(INSTALL)
endif

ifeq ($(MAKECMDGOALS),installdev)
ifndef BASEDIR
export BASEDIR = apache_$(VERSION_STR)-sdk
endif
else
ifndef BASEDIR
export BASEDIR = Apache$(VERSION_MAJMIN)
endif
endif

# Add support for building IPV6 alongside
ifneq "$(IPV6)" ""
DEFINES += -DNW_BUILD_IPV6
# INCDIRS := $(NOVELLLIBC)/include/winsock/IPV6;$(INCDIRS)

ifneq "$(findstring IPV6,$(OBJDIR))" "IPV6"
OBJDIR := $(OBJDIR)_IPV6
endif
        
ifneq "$(findstring IPV6,$(INSTALL))" "IPV6"
INSTALL := $(INSTALL)_IPV6
endif        

ifneq "$(findstring IPV6,$(INSTDIRS))" "IPV6"
INSTDIRS := $(INSTDIRS)_IPV6
endif

endif

INSTALLBASE = $(INSTALL)/$(BASEDIR)

INSTDEVDIRS = \
	$(INSTALL) \
	$(INSTALLBASE) \
	$(INSTALLBASE)/build \
	$(INSTALLBASE)/include \
	$(INSTALLBASE)/lib \
	$(EOLIST) 

INSTDIRS += \
	$(INSTALLBASE) \
	$(INSTALLBASE)/bin \
	$(INSTALLBASE)/cgi-bin \
	$(INSTALLBASE)/conf \
	$(INSTALLBASE)/conf/extra \
	$(INSTALLBASE)/error \
	$(INSTALLBASE)/htdocs \
	$(INSTALLBASE)/icons \
	$(INSTALLBASE)/logs \
	$(INSTALLBASE)/man \
	$(INSTALLBASE)/manual \
	$(INSTALLBASE)/modules \
	$(EOLIST) 

#
# Common directories
#

SRC		= $(subst \,/,$(AP_WORK))
APR		= $(subst \,/,$(APR_WORK))
APRUTIL		= $(subst \,/,$(APU_WORK))
APBUILD		= $(SRC)/build
STDMOD		= $(SRC)/modules
HTTPD		= $(SRC)/modules/http
DAV		= $(SRC)/modules/dav
NWOS		= $(SRC)/os/netware
SERVER		= $(SRC)/server
SUPMOD		= $(SRC)/support
APULDAP		= $(APRUTIL)/ldap
XML		= $(APRUTIL)/xml
APRTEST		= $(APR)/test
PCRE		= $(PCRESRC)

PREBUILD_INST	= $(SRC)/nwprebuild

#
# Internal Libraries
#

APRLIB		= $(APR)/$(OBJDIR)/aprlib.lib
APRUTLIB	= $(APRUTIL)/$(OBJDIR)/aprutil.lib
APULDAPLIB	= $(APULDAP)/$(OBJDIR)/apuldap.lib
STMODLIB	= $(STDMOD)/$(OBJDIR)/stdmod.lib
PCRELIB		= $(SRC)/$(OBJDIR)/pcre.lib
NWOSLIB		= $(NWOS)/$(OBJDIR)/netware.lib
SERVLIB		= $(SERVER)/$(OBJDIR)/server.lib
HTTPDLIB	= $(HTTPD)/$(OBJDIR)/httpd.lib
XMLLIB		= $(XML)/$(OBJDIR)/xmllib.lib

#
# Additional general defines
#

EnvironmentDefined = 1
endif # ifndef EnvironmentDefined

# This is always set so that it will show up in lower directories

ifdef Path
Path = $(PATH)
endif

