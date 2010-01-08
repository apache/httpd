#
# Setup needed Tools and Libraries
#

ifeq "$(wildcard $(AP_WORK)\NWGNUcustom.ini)" "$(AP_WORK)\NWGNUcustom.ini"
include $(AP_WORK)\NWGNUcustom.ini
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
ifndef NWSDKDIR
NWSDKDIR = c:\novell\ndk\NWSDK
endif

# LDAP SDK path
ifndef LDAPSDK
LDAPSDK = C:/novell/ndk/cldapsdk
endif

ifndef METROWERKS
METROWERKS = C:\Program Files\Metrowerks\CodeWarrior
endif

ifndef MWERKS
MWERKS = C:\Program Files\Metrowerks\CodeWarrior
endif

ifndef GNUTOOLS
GNUTOOLS = $(TOOLPATH)\cygwin\bin
endif

# If LM_LICENSE_FILE isn't defined, define a variable that can be used to
# restart make with it defined
ifndef LM_LICENSE_FILE
NO_LICENSE_FILE = NO_LICENSE_FILE
endif

#
# Set the Release type that you want to build, possible values are:
#
#  debug		- full debug switches are set
#  noopt		- normal switches are set (default)
#  optimized	- optimization switches are set

ifdef reltype
RELEASE=$(reltype)
endif

ifdef RELTYPE
RELEASE=$(RELTYPE)
endif

ifdef debug
RELEASE=debug
endif

ifdef DEBUG
RELEASE=debug
endif

ifdef optimized
RELEASE=optimized
endif

ifdef OPTIMIZED
RELEASE=optimized
endif

ifndef RELEASE
RELEASE = optimized
endif

ifeq "$(RELEASE)" "debug"
OBJDIR = Debug
endif

ifeq "$(RELEASE)" "noopt"
OBJDIR = Noopt
endif

ifeq "$(RELEASE)" "optimized"
OBJDIR = Release
endif

#
# Setup compiler information
#

# MetroWerks NLM tools
CC		= mwccnlm
CPP		= mwccnlm
LINK	= mwldnlm
LIB		= mwldnlm -type library -w nocmdline

NOVI	= $(NWSDKDIR)\imports

INCDIRS 	= $(NWSDKDIR)\include\nlm;$(NWSDKDIR)\include;$(NWSDKDIR)\include\winsock
ifdef WS295SDK
	INCDIRS += ;$(WS295SDK)\include
endif
ifndef CLIB_PRELUDE
	CLIB_PRELUDE = clibpre.o
endif

DEFINES		= -DNETWARE

#
# MetroWerks static Libraries

CLIB3S	= $(METROWERKS)\Novell Support\Metrowerks Support\Libraries\Runtime\mwcrtl.lib
#MATH3S	=
#PLIB3S	= $(METROWERKS)\NOvell Support\Metrowerks Support\Libraries\MSL C++\MWCPP.lib

# Base compile flags

CFLAGS = -c -nosyspath -relax_pointers -Cpp_exceptions off -RTTI off -align byte -w nocmdline -proc Pentium
   
ifeq "$(RELEASE)" "debug"
CFLAGS += -g
endif

ifeq "$(RELEASE)" "optimized"
CFLAGS += -opt all
endif

PATH:=$(PATH);$(METROWERKS)\bin;$(METROWERKS)\Other Metrowerks Tools\Command Line Tools

#
# Declare major project deliverables output directories here
#

ifdef DEST
INSTALL = $(DEST)
ifeq (\, $(findstring \,$(INSTALL)))
INSTDIRS = $(DEST)
endif
endif

ifdef dest
INSTALL = $(dest)
ifeq (\, $(findstring \,$(INSTALL)))
INSTDIRS = $(dest)
endif
endif

ifndef INSTALL
INSTALL = $(AP_WORK)\Dist
INSTDIRS = $(AP_WORK)\Dist
endif

INSTDIRS += \
	$(INSTALL)\Apache \
	$(INSTALL)\Apache\cgi-bin \
	$(INSTALL)\Apache\conf \
	$(INSTALL)\Apache\htdocs \
	$(INSTALL)\Apache\icons \
	$(INSTALL)\Apache\logs \
	$(INSTALL)\Apache\modules 
	
#
# Declare Command and tool macros here
#

# Os2LibPath is an extra check to see if we are on NT
ifdef Os2LibPath
OS = Windows_NT
endif

ifeq "$(OS)" "Windows_NT"
CMD=cmd /C
CHK=cmd /C if exist
CHKNOT=cmd /C if not exist
DEL = del /F
DELTREE = cmd /C rd /s/q
WINNT=1
else
CMD=command /C
CHK=command /C if exist
CHKNOT=command /C if not exist
DEL = del
DELTREE = deltree /y
endif


#
# Setup base C compiler flags
#

#
# Common directories
#

SRC			= $(AP_WORK)\src
AP			= $(AP_WORK)\src\ap
MAIN		= $(AP_WORK)\src\main
REGEX		= $(AP_WORK)\src\regex
STDMOD		= $(AP_WORK)\src\modules\standard
NWOS		= $(AP_WORK)\src\os\netware

#
# Internal Libraries
#

APLIB		= $(AP)\$(OBJDIR)\ap.lib
REGEXLIB	= $(REGEX)\$(OBJDIR)\regex.lib
STDMODLIB	= $(STDMOD)\$(OBJDIR)\stdmod.lib
NWOSLIB		= $(NWOS)\$(OBJDIR)\NetWare.lib

#
# Additional general defines
#
VERSION		= 1,3,0
			
EnvironmentDefined = 1
endif # ifndef EnvironmentDefined

# This is always set so that it will show up in lower directories

ifdef Path
Path = $(PATH)
endif

