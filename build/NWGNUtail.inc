#
# This contains final targets and should be included at the end of any
# NWGNUmakefile file
#

#
# If we are going to create an nlm, make sure we have assigned variables to
# use during the link.
#
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
NLM_COPYRIGHT = Licensed under the Apache License, Version 2.0
endif

ifeq "$(NLM_FLAGS)" ""
NLM_FLAGS = AUTOUNLOAD, PSEUDOPREEMPTION
endif

ifeq "$(NLM_STACK_SIZE)" ""
NLM_STACK_SIZE = 65536
endif

ifeq "$(NLM_ENTRY_SYM)" ""
NLM_ENTRY_SYM = _LibCPrelude
endif

ifeq "$(NLM_EXIT_SYM)" ""
NLM_EXIT_SYM = _LibCPostlude
endif

ifeq "$(NLM_VERSION)" ""
NLM_VERSION = $(VERSION)
endif

#
# Create dependency lists based on the files available
#

STANDARD_DEPENDS	= \
				$(APBUILD)/NWGNUhead.inc \
				$(APBUILD)/NWGNUenvironment.inc \
				$(APBUILD)/NWGNUtail.inc \
				$(CUSTOM_INI) \
				$(EOLIST)

CCOPT_DEPENDS	= $(STANDARD_DEPENDS)

$(NLM_NAME)_LINKOPT_DEPENDS	= \
				$(TARGET_lib) \
				$(STANDARD_DEPENDS) \
				$(VERSION_INC) \
				$(EOLIST)

ifeq "$(words $(strip $(TARGET_lib)))" "1"
LIB_NAME			= $(basename $(notdir $(TARGET_lib)))
$(LIB_NAME)_LIBLST_DEPENDS	= \
				$(FILES_lib_objs) \
				$(STANDARD_DEPENDS) \
				$(CUSTOM_INI) \
				$(EOLIST)
endif

ifeq "$(wildcard NWGNU$(LIB_NAME))" "NWGNU$(LIB_NAME)"
$(LIB_NAME)_LIBLST_DEPENDS	+= NWGNU$(LIB_NAME)
CCOPT_DEPENDS	+= NWGNU$(LIB_NAME)
else
CCOPT_DEPENDS	+= NWGNUmakefile
endif

ifeq "$(wildcard NWGNU$(NLM_NAME))" "NWGNU$(NLM_NAME)"
$(NLM_NAME)_LINKOPT_DEPENDS	+= NWGNU$(NLM_NAME)
CCOPT_DEPENDS	+= NWGNU$(NLM_NAME)
else
CCOPT_DEPENDS	+= NWGNUmakefile
endif

CPPOPT_DEPENDS	= $(CCOPT_DEPENDS)

#
# Generic compiler rules
#

ifneq ($(MAKECMDGOALS),clean)
$(APBUILD)/NWGNUversion.inc: $(APBUILD)/nw_ver.awk $(SRC)/include/ap_release.h
#	@echo Generating $@
	@echo $(DL)GEN  $@$(DL)
	$(AWK) -f $^ > $@

-include $(APBUILD)/NWGNUversion.inc

ifneq "$(strip $(VERSION_STR))" ""
VERSION_INC = $(APBUILD)/NWGNUversion.inc
else
VERSION		= 2,2,0
VERSION_STR	= 2.2.0
VERSION_MAJMIN	= 22
endif
endif


ifeq "$(words $(strip $(TARGET_nlm)))" "1"

$(OBJDIR)/%.o: %.c $(OBJDIR)/$(NLM_NAME)_cc.opt
	@echo $(DL)CC   $<$(DL)
	$(CC) -o $@ $< @$(word 2, $^)

$(OBJDIR)/$(NLM_NAME)_cc.opt: $(CCOPT_DEPENDS)
	$(call DEL,$@)
	@echo $(DL)GEN  $@$(DL)
ifneq "$(strip $(CFLAGS))" ""
	@echo $(DL)$(CFLAGS)$(DL)>> $@
endif
ifneq "$(strip $(XCFLAGS))" ""
	@echo $(DL)$(XCFLAGS)$(DL)>> $@
endif
ifneq "$(strip $(XINCDIRS))" ""
	@echo $(DL)$(foreach xincdir,$(strip $(subst ;,$(SPACE),$(XINCDIRS))),-I$(xincdir))$(DL)>> $@
endif
ifneq "$(strip $(INCDIRS))" ""
	@echo $(DL)$(foreach incdir,$(strip $(subst ;,$(SPACE),$(INCDIRS))),-I$(incdir))$(DL)>> $@
endif
ifneq "$(strip $(DEFINES))" ""
	@echo $(DL)$(DEFINES)$(DL)>> $@
endif
ifneq "$(strip $(XDEFINES))" ""
	@echo $(DL)$(XDEFINES)$(DL)>> $@
endif

$(OBJDIR)/%.o: %.cpp $(OBJDIR)/$(NLM_NAME)_cpp.opt
	@echo $(DL)CC   $<$(DL)
	$(CC) -o $@ $< @$(word 2, $^)

$(OBJDIR)/$(NLM_NAME)_cpp.opt: $(CPPOPT_DEPENDS)
	$(call DEL,$@)
	@echo $(DL)GEN  $@$(DL)
ifneq "$(strip $(CFLAGS))" ""
	@echo $(DL)$(CFLAGS)$(DL)>> $@
endif
ifneq "$(strip $(XCFLAGS))" ""
	@echo $(DL)$(XCFLAGS)$(DL)>> $@
endif
ifneq "$(strip $(XINCDIRS))" ""
	@echo $(DL)$(foreach xincdir,$(strip $(subst ;,$(SPACE),$(XINCDIRS))),-I$(xincdir))$(DL)>> $@
endif
ifneq "$(strip $(INCDIRS))" ""
	@echo $(DL)$(foreach incdir,$(strip $(subst ;,$(SPACE),$(INCDIRS))),-I$(incdir))$(DL)>> $@
endif
ifneq "$(strip $(DEFINES))" ""
	@echo $(DL)$(DEFINES)$(DL)>> $@
endif
ifneq "$(strip $(XDEFINES))" ""
	@echo $(DL)$(XDEFINES)$(DL)>> $@
endif

endif # one target nlm

#
# Rules to build libraries
#

# If we only have one target library then build it

ifeq "$(words $(strip $(TARGET_lib)))" "1"

$(TARGET_lib) : $(OBJDIR)/$(LIB_NAME)_lib.lst
	$(call DEL,$@)
	@echo $(DL)AR   $@$(DL)
	$(LIB) -o $@ @$<

$(OBJDIR)/$(LIB_NAME)_lib.lst: $($(LIB_NAME)_LIBLST_DEPENDS)
	$(call DEL,$@)
ifneq "$(strip $(FILES_lib_objs))" ""
	@echo $(DL)GEN  $@$(DL)
	@echo $(DL)$(FILES_lib_objs)$(DL)>> $@
endif

else # We must have more than one target library so load the individual makefiles

$(OBJDIR)/%.lib: NWGNU% $(STANDARD_DEPENDS) FORCE
	@echo $(DL)Calling $<$(DL)
	$(MAKE) -f $< $(MAKECMDGOALS) RELEASE=$(RELEASE)

endif

#
# Rules to build nlms.
#

# If we only have one target NLM then build it
ifeq "$(words $(strip $(TARGET_nlm)))" "1"

$(TARGET_nlm) : $(FILES_nlm_objs) $(FILES_nlm_libs) $(OBJDIR)/$(NLM_NAME)_link.opt
	@echo $(DL)LINK $@$(DL)
	$(LINK) @$(OBJDIR)/$(NLM_NAME)_link.opt

# This will force the link option file to be rebuilt if we change the
# corresponding makefile

$(OBJDIR)/$(NLM_NAME)_link.opt : $($(NLM_NAME)_LINKOPT_DEPENDS)
	$(call DEL,$@)
	$(call DEL,$(@:.opt=.def))
	@echo $(DL)GEN  $@$(DL)
	@echo $(DL)-warnings off$(DL)>> $@
	@echo $(DL)-zerobss$(DL)>> $@
	@echo $(DL)-o $(TARGET_nlm)$(DL)>> $@
ifneq "$(FILE_nlm_copyright)" ""
	@$(CAT) $(FILE_nlm_copyright)>> $@
endif
ifeq "$(RELEASE)" "debug"
	@echo $(DL)-g$(DL)>> $@
	@echo $(DL)-sym internal$(DL)>> $@
	@echo $(DL)-sym codeview4$(DL)>> $@
	@echo $(DL)-osym $(OBJDIR)/$(NLM_NAME).sym$(DL)>> $@
else
	@echo $(DL)-sym internal$(DL)>> $@
endif
	@echo $(DL)-l $(SRC)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-l $(HTTPD)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-l $(SERVER)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-l $(STDMOD)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-l $(NWOS)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-l $(NWOS)$(DL)>> $@
	@echo $(DL)-l $(APR)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-l $(APR)$(DL)>> $@
	@echo $(DL)-l $(APRUTIL)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-l $(PCRE)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-l "$(METROWERKS)/Novell Support/Metrowerks Support/Libraries/Runtime"$(DL)>> $@
	@echo $(DL)-l "$(METROWERKS)/Novell Support/Metrowerks Support/Libraries/MSL C++"$(DL)>> $@
ifneq "$(IPV6)" ""
	@echo $(DL)-l $(NOVELLLIBC)/include/winsock/IPV6$(DL)>> $@
endif
	@echo $(DL)-l $(NOVELLLIBC)/imports$(DL)>> $@
ifneq "$(LDAPSDK)" ""
	@echo $(DL)-l $(LDAPSDK)/imports$(DL)>> $@
endif
	@echo $(DL)-l $(APULDAP)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-l $(XML)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-l $(SRC)/$(OBJDIR)$(DL)>> $@
	@echo $(DL)-nodefaults$(DL)>> $@
	@echo $(DL)-map $(OBJDIR)/$(NLM_NAME).map$(DL)>> $@
ifneq "$(strip $(XLFLAGS))" ""
	@echo $(DL)$(XLFLAGS)$(DL)>> $@
endif
ifneq "$(strip $(FILES_nlm_objs))" ""
	@echo $(DL)$(foreach objfile,$(strip $(FILES_nlm_objs)),$(objfile))$(DL)>> $@
endif
ifneq "$(FILES_nlm_libs)" ""
	@echo $(DL)$(foreach libfile, $(notdir $(strip $(FILES_nlm_libs))),-l$(libfile))$(DL)>> $@
endif
	@echo $(DL)-commandfile $(@:.opt=.def)$(DL)>> $@
	@echo $(DL)# Do not edit this file - it is created by make!$(DL)> $(@:.opt=.def) 
	@echo $(DL)# All your changes will be lost!!$(DL)>> $(@:.opt=.def) 
ifneq "$(FILE_nlm_msg)" ""
	@echo $(DL)Messages $(FILE_nlm_msg)$(DL)>> $(@:.opt=.def)
endif
ifneq "$(FILE_nlm_hlp)" ""
	@echo $(DL)Help $(FILE_nlm_hlp)$(DL)>> $(@:.opt=.def)
endif
ifeq "$(FILE_nlm_copyright)" ""
	@echo $(DL)copyright "$(NLM_COPYRIGHT)"$(DL)>> $(@:.opt=.def)
endif
	@echo $(DL)description "$(NLM_DESCRIPTION)"$(DL)>> $(@:.opt=.def)
	@echo $(DL)threadname "$(NLM_THREAD_NAME)"$(DL)>> $(@:.opt=.def)
	@echo $(DL)screenname "$(NLM_SCREEN_NAME)"$(DL)>> $(@:.opt=.def)
	@echo $(DL)stacksize $(subst K,000,$(subst k,K,$(strip $(NLM_STACK_SIZE))))$(DL)>> $(@:.opt=.def)
	@echo $(DL)version $(NLM_VERSION) $(DL)>> $(@:.opt=.def)
	@echo $(DL)start $(NLM_ENTRY_SYM)$(DL)>> $(@:.opt=.def)
	@echo $(DL)exit $(NLM_EXIT_SYM)$(DL)>> $(@:.opt=.def)
ifneq "$(NLM_CHECK_SYM)" ""
	@echo $(DL)check $(NLM_CHECK_SYM)$(DL)>> $(@:.opt=.def)
endif
	@echo $(DL)$(strip $(NLM_FLAGS))$(DL)>> $(@:.opt=.def)
ifneq "$(FILES_nlm_modules)" ""
	@echo $(DL)module $(foreach module,$(subst $(SPACE),$(COMMA),$(strip $(FILES_nlm_modules))),$(module))$(DL)>> $(@:.opt=.def)
endif
ifneq "$(FILES_nlm_Ximports)" ""
	@echo $(DL)import $(foreach import,$(subst $(SPACE),$(COMMA),$(strip $(FILES_nlm_Ximports))),$(import))$(DL)>> $(@:.opt=.def)
endif
ifneq "$(FILES_nlm_exports)" ""
	@echo $(DL)export $(foreach export,$(subst $(SPACE),$(COMMA),$(strip $(FILES_nlm_exports))),$(export))$(DL)>> $(@:.opt=.def)
endif
# if APACHE_UNIPROC is defined, don't include XDCData
ifndef APACHE_UNIPROC
ifneq "$(string $(XDCDATA))" ""
	@echo $(DL)xdcdata $(XDCDATA)$(DL)>> $(@:.opt=.def)
else
	@echo $(DL)xdcdata apache.xdc$(DL)>> $(@:.opt=.def)
endif
endif

else # more than one target so look for individual makefiles.

# Only include these if NO_LICENSE_FILE isn't set to prevent excessive
# recursion

ifndef NO_LICENSE_FILE

$(OBJDIR)/%.nlm: NWGNU% $($(NLM_NAME)_LINKOPT_DEPENDS) FORCE
	@echo $(DL)Calling $<$(DL)
	$(MAKE) -f $< $(MAKECMDGOALS) RELEASE=$(RELEASE)
	@$(ECHONL)

else

$(TARGET_nlm):

endif # NO_LICENSE_FILE

endif

