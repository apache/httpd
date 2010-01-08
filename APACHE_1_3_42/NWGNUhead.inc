#
# Obtain the global build environment
#

include $(AP_WORK)\NWGNUenvironment.inc

#
# If an NWGNUmake.inc file exists in the current directory, bring it in.
#

ifeq "$(wildcard NWGNUmake.inc)" "NWGNUmake.inc"
include NWGNUmake.inc
endif

#
# Define base targets and rules
# 

TARGETS = libs nlms install clobber_libs clobber_nlms clean

.PHONY : $(TARGETS) default all help

default: $(SUBDIRS) libs nlms

all: $(SUBDIRS) libs nlms install

help :
	@echo targets for RELEASE=$(RELEASE):
	@echo (default) . . . . libs nlms
	@echo all . . . . . . . does everything (libs nlms install)
	@echo libs. . . . . . . builds all libs
	@echo nlms. . . . . . . builds all nlms
	@echo install . . . . . builds libs and nlms and copies install files to
	@echo                   "$(INSTALL)"
	@echo clean . . . . . . deletes $(OBJDIR) dirs, *.err, and *.map
	@echo clobber_all . . . deletes all possible output from the make
	@echo clobber_install . deletes all files in $(INSTALL)
	@$(CMD) echo.
	@echo Multiple targets can be used on a single nmake command line -
	@echo (i.e. $(MAKE) clean all)
	@$(CMD) echo.
	@echo You can also specify RELEASE=debug, RELEASE=noopt, or RELEASE=optimized
	@echo The default is RELEASE=optimized

clobber_all :: clean clobber_install

clobber_install ::
	-$(DELTREE) $(INSTALL) 2>NUL

$(TARGETS) :: $(SUBDIRS)

install :: nlms $(INSTDIRS)

$(INSTDIRS) :
	@echo creating $@
	$(CHKNOT) $@\NUL mkdir $@

#
# build recursive targets
#

$(SUBDIRS) : FORCE
ifneq "$(MAKECMDGOALS)" "clean"
	@echo Building $(CURDIR)/$@
endif
	$(MAKE) -C $@ $(MAKECMDGOALS) -f NWGNUmakefile RELEASE=$(RELEASE)
	$(CMD) echo.

FORCE:

#
# Standard targets
#

clean ::
	@echo Cleaning up $(CURDIR)
	-$(DELTREE) $(OBJDIR) 2> NUL
	$(CHK) *.err $(DEL) *.err
	$(CHK) *.map $(DEL) *.map
	$(CHK) *.d $(DEL) *.d
	$(CHK) *.tmp $(DEL) *.tmp
	$(CHK) *.sym $(DEL) *.sym
	-$(DELTREE) $(OBJDIR) 2> NUL

$(OBJDIR) ::
	$(CHKNOT) $(OBJDIR)\nul mkdir $(OBJDIR)

