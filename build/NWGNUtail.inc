#
# This contains final targets and should be included at the end of any
# NWGNUmakefile file
#

#
# If we are going to create an nlm, make sure we have assigned variables to
# use during the link.
#
echo NLM_NAME=$(NLM_NAME)
ifndef NLM_NAME
NLM_NAME = $(TARGET_nlm)
endif

ifndef NLM_DESCRIPTION
NLM_DESCRIPTION = $(NLM_NAME)
endif

ifndef NLM_THREAD_NAME
NLM_THREAD_NAME = $(NLM_NAME) Thread
endif

ifndef NLM_SCREEN_NAME
NLM_SCREEN_NAME = DEFAULT
endif

ifndef NLM_COPYRIGHT
NLM_COPYRIGHT = Copyright (c) 2000-2003 The Apache Software Foundation. All rights reserved.
endif

#
# Create dependency lists based on the files available
#

CCOPT_DEPENDS 	= \
				$(AP_WORK)\build\NWGNUhead.inc \
				$(AP_WORK)\build\NWGNUenvironment.inc \
				$(AP_WORK)\build\NWGNUtail.inc \
				NWGNUmakefile \
				$(CUSTOM_INI) \
				$(EOLIST)

CPPOPT_DEPENDS	= \
				$(AP_WORK)\build\NWGNUhead.inc \
				$(AP_WORK)\build\NWGNUenvironment.inc \
				$(AP_WORK)\build\NWGNUtail.inc \
				NWGNUmakefile \
				$(CUSTOM_INI) \
				$(EOLIST)

$(NLM_NAME)_LINKOPT_DEPENDS	= \
				$(TARGET_lib) \
				$(AP_WORK)\build\NWGNUenvironment.inc \
				NWGNUmakefile \
				$(AP_WORK)\build\NWGNUtail.inc \
				$(CUSTOM_INI) \
				$(VERSION_INC) \
				$(EOLIST)

ifeq "$(words $(strip $(TARGET_lib)))" "1"
LIB_NAME					= $(basename $(notdir $(TARGET_lib)))
$(LIB_NAME)_LIBLST_DEPENDS	= \
				$(FILES_lib_objs) \
				$(AP_WORK)\build\NWGNUenvironment.inc \
				NWGNUmakefile \
				$(AP_WORK)\build\NWGNUtail.inc \
				$(CUSTOM_INI) \
				$(EOLIST)
endif

ifeq "$(wildcard NWGNU$(LIB_NAME))" "NWGNU$(LIB_NAME)"
$(LIB_NAME)_LIBLST_DEPENDS	+= NWGNU$(LIB_NAME)
endif

ifeq "$(wildcard NWGNU$(NLM_NAME))" "NWGNU$(NLM_NAME)"
$(NLM_NAME)_LINKOPT_DEPENDS	+= NWGNU$(NLM_NAME)
CCOPT_DEPENDS 	+= NWGNU$(NLM_NAME)
CPPOPT_DEPENDS 	+= NWGNU$(NLM_NAME)
endif

#
# Generic compiler rules
#

$(AP_WORK)\build\NWGNUversion.inc : $(AP_WORK)\include\ap_release.h $(AP_WORK)\build\nw_ver.awk
	@echo Generating $(subst /,\,$@)
	awk -f $(AP_WORK)\build\nw_ver.awk $(AP_WORK)\include\ap_release.h > $(AP_WORK)\build\NWGNUversion.inc

-include $(AP_WORK)\build\NWGNUversion.inc

ifneq "$(strip $(VERSION_STR))" ""
VERSION_INC = $(AP_WORK)\build\NWGNUversion.inc
else
VERSION		= 2,0,0
VERSION_STR	= 2.0.0
endif


$(OBJDIR)/%.o: %.c $(OBJDIR)\cc.opt
	@echo Compiling $<
	$(CC) $< -o=$(OBJDIR)\$(@F) @$(OBJDIR)\cc.opt

$(OBJDIR)\cc.opt: $(CCOPT_DEPENDS)
	$(CHK) $@ $(DEL) $@
	@echo Generating $@
ifneq "$(strip $(CFLAGS))" ""
	@echo $(CFLAGS) >> $@
endif
ifneq "$(strip $(XCFLAGS))" ""
	@echo $(XCFLAGS) >> $@
endif
ifneq "$(strip $(XINCDIRS))" ""
	@echo $(foreach xincdir,$(strip $(subst ;,$(SPACE),$(XINCDIRS))),-I$(xincdir)) >> $@
endif
ifneq "$(strip $(INCDIRS))" ""
	@echo $(foreach incdir,$(strip $(subst ;,$(SPACE),$(INCDIRS))),-I$(incdir)) >> $@
endif
ifneq "$(strip $(DEFINES))" ""
	@echo $(DEFINES) >> $@
endif
ifneq "$(strip $(XDEFINES))" ""
	@echo $(XDEFINES) >> $@
endif

$(OBJDIR)/%.o: %.cpp $(OBJDIR)\cpp.opt
	@echo Compiling $<
	$(CPP) $< -o=$(OBJDIR)\$(@F) @$(OBJDIR)\cpp.opt

$(OBJDIR)\cpp.opt: $(CPPOPT_DEPENDS)
	$(CHK) $@ $(DEL) $@
	@echo Generating $@
ifneq "$(strip $(CFLAGS))" ""
	@echo $(CFLAGS) >> $@
endif
ifneq "$(strip $(XCFLAGS))" ""
	@echo $(XCFLAGS) >> $@
endif
ifneq "$(strip $(XINCDIRS))" ""
	@echo $(foreach xincdir,$(strip $(subst ;,$(SPACE),$(XINCDIRS))),-I$(xincdir)) >> $@
endif
ifneq "$(strip $(INCDIRS))" ""
	@echo $(foreach incdir,$(strip $(subst ;,$(SPACE),$(INCDIRS))),-I$(incdir)) >> $@
endif
ifneq "$(strip $(DEFINES))" ""
	@echo $(DEFINES) >> $@
endif
ifneq "$(strip $(XDEFINES))" ""
	@echo $(XDEFINES) >> $@
endif

#
# Rules to build libraries
#

# If we only have one target library then build it

ifeq "$(words $(strip $(TARGET_lib)))" "1"

$(TARGET_lib) : $(OBJDIR)\$(LIB_NAME)_lib.lst
	@echo Generating $@
	$(CHK) $(OBJDIR)\$(@F) $(DEL) $(OBJDIR)\$(@F)
	$(LIB) -o $(OBJDIR)\$(@F) @$?

$(OBJDIR)\$(LIB_NAME)_lib.lst: $($(LIB_NAME)_LIBLST_DEPENDS)
	$(CHK) $@ $(DEL) $@
	@echo Generating $@
ifneq "$(strip $(FILES_lib_objs))" ""
	@echo $(foreach objfile,$(FILES_lib_objs),$(subst /,\,$(objfile)) ) >> $@
endif

else # We must have more than one target library so load the individual makefiles

$(OBJDIR)/%.lib: NWGNU% $(AP_WORK)\build\NWGNUhead.inc $(AP_WORK)\build\NWGNUtail.inc $(AP_WORK)\build\NWGNUenvironment.inc FORCE
	@echo Calling $<
	$(MAKE) -f $< $(MAKECMDGOALS) RELEASE=$(RELEASE)

endif

#
# Rules to build nlms.
#

vpath libcpre.o $(NOVELLLIBC)\imports

# If we only have one target NLM then build it
ifeq "$(words $(strip $(TARGET_nlm)))" "1"

$(TARGET_nlm) : $(FILES_nlm_objs) $(FILES_nlm_libs) $(OBJDIR)\$(NLM_NAME)_link.opt
	@echo Linking $@
	$(LINK) @$(OBJDIR)\$(NLM_NAME)_link.opt

# This will force the link option file to be rebuilt if we change the
# corresponding makefile

$(OBJDIR)\$(NLM_NAME)_link.opt : $($(NLM_NAME)_LINKOPT_DEPENDS)
	$(CHK) $(OBJDIR)\$(@F) $(DEL) $(OBJDIR)\$(@F)
	$(CHK) $(OBJDIR)\$(NLM_NAME)_link.def $(DEL) $(OBJDIR)\$(NLM_NAME)_link.def
	@echo Generating $@
	@echo -warnings off >> $@
	@echo -zerobss >> $@
	@echo -desc "$(NLM_DESCRIPTION)" >> $@
	@echo -o $(TARGET_nlm) >> $@
ifneq "$(FILE_nlm_copyright)" ""
	@-type $(FILE_nlm_copyright) >> $@
else
	@echo -copy "$(NLM_COPYRIGHT)" >> $@
endif
ifeq "$(RELEASE)" "debug"
	@echo -g >> $@
	@echo -sym internal >> $@
	@echo -sym codeview4 >> $@
	@echo -osym $(OBJDIR)\$(NLM_NAME).sym >> $@
else
	@echo -sym internal >> $@
endif
	@echo -screenname "$(NLM_SCREEN_NAME)" >> $@
ifneq "$(NLM_VERSION)" ""
	@echo -nlmversion=$(NLM_VERSION) >> $@
else
	@echo -nlmversion=$(VERSION) >> $@
endif
	@echo -l $(NWOS) >> $@
	@echo -l $(AP)/$(OBJDIR) >> $@
	@echo -l $(APR)/$(OBJDIR) >> $@
	@echo -l $(APRUTIL)/$(OBJDIR) >> $@
	@echo -l $(PCRE)/$(OBJDIR) >> $@
	@echo -l $(HTTPD)/$(OBJDIR) >> $@
	@echo -l $(SERVER)/$(OBJDIR) >> $@
	@echo -l $(STDMOD)/$(OBJDIR) >> $@
	@echo -l $(NWOS)/$(OBJDIR) >> $@
	@echo -l "$(METROWERKS)/Novell Support/Metrowerks Support/Libraries/Runtime" >> $@
	@echo -l "$(METROWERKS)/Novell Support/Metrowerks Support/Libraries/MSL C++" >> $@
ifneq "$(IPV6)" ""
	@echo -l $(NOVELLLIBC)\include\winsock\IPV6 >> $@
endif
	@echo -l $(NOVELLLIBC)/imports >> $@
ifneq "$(LDAPSDK)" ""
	@echo -l $(LDAPSDK)/lib/nlm >> $@
endif
	@echo -l $(XML)/$(OBJDIR) >> $@
	@echo -nodefaults >> $@
	@echo -map $(OBJDIR)\$(NLM_NAME).map>> $@
	@echo -threadname "$(NLM_THREAD_NAME)" >> $@
ifneq "$(NLM_STACK_SIZE)" ""
	@echo -stacksize $(subst K,000,$(subst k,K,$(strip $(NLM_STACK_SIZE)))) >> $@
else
	@echo -stacksize 64000 >> $@
endif
ifneq "$(NLM_ENTRY_SYM)" ""
	@echo -entry $(NLM_ENTRY_SYM) >> $@
endif
ifneq "$(NLM_EXIT_SYM)" ""
	@echo -exit $(NLM_EXIT_SYM) >> $@
endif
ifneq "$(NLM_CHECK_SYM)" ""
	@echo -check $(NLM_CHECK_SYM) >> $@
endif
ifneq "$(NLM_FLAGS)" ""
	@echo -flags $(NLM_FLAGS) >> $@
endif
ifneq "$(strip $(FILES_nlm_objs))" ""
	@echo $(foreach objfile,$(strip $(FILES_nlm_objs)),$(subst /,\,$(objfile))) >> $@
endif
ifneq "$(FILES_nlm_libs)" ""
	@echo $(foreach libfile, $(notdir $(strip $(FILES_nlm_libs))),-l$(subst /,\,$(libfile))) >> $@
endif
	@echo -commandfile $(OBJDIR)\$(NLM_NAME)_link.def >> $@
ifneq "$(FILE_nlm_msg)" ""
	@echo Messages $(FILE_nlm_msg) >> $(OBJDIR)\$(NLM_NAME)_link.def
endif
ifneq "$(FILE_nlm_hlp)" ""
	@echo Help $(FILE_nlm_hlp) >> $(OBJDIR)\$(NLM_NAME)_link.def
endif
ifneq "$(FILES_nlm_modules)" ""
	@echo module $(foreach module,$(subst $(SPACE),$(COMMA),$(strip $(FILES_nlm_modules))),$(subst /,\,$(module))) >> $(OBJDIR)\$(NLM_NAME)_link.def
endif
ifneq "$(FILES_nlm_Ximports)" ""
	@echo Import $(foreach import,$(subst $(SPACE),$(COMMA),$(strip $(FILES_nlm_Ximports))),$(subst /,\,$(import))) >> $(OBJDIR)\$(NLM_NAME)_link.def
endif
ifneq "$(FILES_nlm_exports)" ""
	@echo Export $(foreach export,$(subst $(SPACE),$(COMMA),$(strip $(FILES_nlm_exports))),$(subst /,\,$(export))) >> $(OBJDIR)\$(NLM_NAME)_link.def
endif
ifneq "$(strip $(XLFLAGS))" ""
	@echo $(XLFLAGS) >> $(OBJDIR)\$(NLM_NAME)_link.def
endif

# if APACHE_UNIPROC is defined, don't include XDCData
ifndef APACHE_UNIPROC
ifneq "$(string $(XDCDATA))" ""
	@echo XDCData $(XDCDATA) >> $(OBJDIR)\$(NLM_NAME)_link.def
else
	@echo XDCData $(NWOS)\apache.xdc >> $(OBJDIR)\$(NLM_NAME)_link.def
endif
endif

else # more than one target so look for individual makefiles.

# Only include these if NO_LICENSE_FILE isn't set to prevent excessive
# recursion

ifndef NO_LICENSE_FILE

$(OBJDIR)/%.nlm: NWGNU% $(AP_WORK)\build\NWGNUhead.inc $(AP_WORK)\build\NWGNUtail.inc $(AP_WORK)\build\NWGNUenvironment.inc $(CUSTOM_INI) $(VERSION_INC) FORCE
	@echo Calling $<
	$(MAKE) -f $< $(MAKECMDGOALS) RELEASE=$(RELEASE)
	$(CMD) echo.

else

$(TARGET_nlm):

endif # NO_LICENSE_FILE

endif

