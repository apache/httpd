#
# This contains final targets and should be included at the end of any
# NWGNUmakefile.mak file
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

ifndef NLM_COPYRIGHT
NLM_COPYRIGHT = Copyright 2010 The Apache Software Foundation. Licensed under the Apache License Version 2.0.
endif

#
# Create dependency lists based on the files available
#

CCOPT_DEPENDS 	= $(AP_WORK)\NWGNUhead.inc NWGNUmakefile.mak $(OBJDIR)
CPPOPT_DEPENDS	= $(AP_WORK)\NWGNUhead.inc NWGNUmakefile.mak $(OBJDIR)

$(NLM_NAME)_LINKOPT_DEPENDS	= $(TARGET_lib) NWGNUmakefile.mak $(AP_WORK)\NWGNUtail.inc

ifeq "$(words $(strip $(TARGET_lib)))" "1"
LIB_NAME					= $(basename $(notdir $(TARGET_lib)))
$(LIB_NAME)_LIBLST_DEPENDS	= $(FILES_lib_objs) NWGNUmakefile.mak $(AP_WORK)\NWGNUtail.inc
endif

ifeq "$(wildcard NWGNU$(LIB_NAME).mak)" "NWGNU$(LIB_NAME).mak"
$(LIB_NAME)_LIBLST_DEPENDS	+= NWGNU$(LIB_NAME).mak
endif

ifeq "$(wildcard NWGNU$(NLM_NAME).mak)" "NWGNU$(NLM_NAME).mak"
$(NLM_NAME)_LINKOPT_DEPENDS	+= NWGNU$(NLM_NAME).mak
CCOPT_DEPENDS 	+= NWGNU$(NLM_NAME).mak
CPPOPT_DEPENDS 	+= NWGNU$(NLM_NAME).mak
endif

ifeq "$(wildcard NWGNUmake.inc)" "NWGNUmake.inc"
$(NLM_NAME)_LINKOPT_DEPENDS	+= NWGNUmake.inc
CCOPT_DEPENDS	+= NWGNUmake.inc
CPPOPT_DEPENDS	+= NWGNUmake.inc
endif

ifneq "$(findstring xdc,$(XLFLAGS))" ""
XDCFOUND = 1
endif

ifneq "$(findstring XDC,$(XLFLAGS))" ""
XDCFOUND = 1
endif

#
# Generic compiler rules
#

%.d: %.c $(OBJDIR)\cc.opt
	@echo Creating dependancy list for $<
	$(CC) $< -o $*.tmp -M @$(OBJDIR)\cc.opt
	$(GNUTOOLS)/sed 's/$*.o[ :]*/$(OBJDIR)\/$*.o : $@ /g' $*.tmp > $@ 
	-$(DEL) $*.tmp

%.d: %.cpp $(OBJDIR)\cpp.opt
	@echo Creating dependancy list for $<
	$(CC) $< -o $*.tmp -M @$(OBJDIR)\cpp.opt
	$(GNUTOOLS)/sed 's/$*.o[ :]*/$(OBJDIR)\/$*.o : $@ /g' $*.tmp > $@ 
	-$(DEL) $*.tmp

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

# Include autodependancy files
ifneq ($(MAKECMDGOALS),clean)
ifneq "$(strip $(FILES_lib_objs))" ""
-include $(patsubst $(OBJDIR)/%.o,%.d,$(FILES_lib_objs))
endif
endif

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

$(OBJDIR)/%.lib: NWGNU%.mak $(AP_WORK)\NWGNUhead.inc $(AP_WORK)\NWGNUtail.inc FORCE
	@echo Calling $<
	$(MAKE) -f $< $(MAKECMDGOALS) RELEASE=$(RELEASE)

endif

#
# Rules to build nlms. 
#

vpath clibpre.o $(NWSDKDIR)\imports

# If we only have one target NLM then build it
ifeq "$(words $(strip $(TARGET_nlm)))" "1"

# Include autodependancy files
ifneq ($(MAKECMDGOALS),clean)
ifneq "$(strip $(FILES_nlm_objs))" ""
-include $(patsubst $(OBJDIR)/%.o,%.d,$(FILES_nlm_objs))
endif
endif

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
	@echo -o $(OBJDIR)\$(NLM_NAME).nlm >> $@
ifneq "$(FILE_nlm_copyright)" ""
	@-type $(FILE_nlm_copyright) >> $@
endif
ifeq "$(RELEASE)" "debug"
	@echo -screenname "$(NLM_NAME) Screen" >> $@
	@echo -g >> $@
	@echo -sym internal >> $@
	@echo -sym codeview4 >> $@
	@echo -osym $(NLM_NAME).sym >> $@
else	
	@echo -screenname "Apache for NetWare" >> $@ 
endif	
	@echo -l $(NWOS) >> $@
	@echo -l $(AP)\$(OBJDIR) >> $@
	@echo -l $(REGEX)\$(OBJDIR) >> $@
	@echo -l $(STDMOD)\$(OBJDIR) >> $@
	@echo -l $(NWOS)\$(OBJDIR) >> $@
#	@echo -l "$(METROWERKS)\Novell Support\Metrowerks Support\Libraries\Runtime" >> $@
	@echo -l $(NWSDKDIR)\imports >> $@
	@echo -l $(LDAPSDK)\Netware\clib\imports >> $@
ifneq "$(strip $(XLFLAGS))" ""
	@echo $(strip $(XLFLAGS)) >> $@
endif
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
	@echo Description "$(NLM_DESCRIPTION)" >> $(OBJDIR)\$(NLM_NAME)_link.def
ifeq "$(FILE_nlm_copyright)" ""
	@echo Copyright "$(NLM_COPYRIGHT)" >> $(OBJDIR)\$(NLM_NAME)_link.def
endif
ifneq "$(NLM_VERSION)" ""
	@echo Version $(NLM_VERSION) >> $(OBJDIR)\$(NLM_NAME)_link.def 
else
	@echo Version $(VERSION) >> $(OBJDIR)\$(NLM_NAME)_link.def
endif
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
ifneq "$(XDCDATA)" ""
	@echo XDCData $(XDCDATA) >> $(OBJDIR)\$(NLM_NAME)_link.def
endif

else # more than one target so look for individual makefiles.

$(OBJDIR)/%.nlm: NWGNU%.mak $(AP_WORK)\NWGNUhead.inc $(AP_WORK)\NWGNUtail.inc FORCE
	@echo Calling $<
	$(MAKE) -f $< $(MAKECMDGOALS) RELEASE=$(RELEASE)

endif
