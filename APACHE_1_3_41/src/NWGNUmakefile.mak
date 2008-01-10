#
# Make sure all needed macro's are defined
#

#
# Get the 'head' of the build environment if necessary.  This includes default
# targets and paths to tools
#

ifndef EnvironmentDefined
include $(AP_WORK)\NWGNUhead.inc
endif

#
# These directories will be at the beginning of the include list, followed by
# INCDIRS
#
XINCDIRS	+= \
			$(SRC)\include \
			$(NWOS) \
			$(LDAPSDK)\netware\clib\inc \
			$(EOLIST)

#
# These flags will come after CFLAGS
#
XCFLAGS		+= \
			$(EOLIST)

#
# These defines will come after DEFINES
#
XDEFINES	+= \
			$(EOLIST)

#
# These flags will be added to the link.opt file
#
XLFLAGS		+= \
			$(EOLIST)

ifdef MULTIPROC
XDCDATA		= $(NWOS)\apache.xdc
endif

#
# These values will be appended to the correct variables based on the value of
# RELEASE
#
ifeq "$(RELEASE)" "debug"
XINCDIRS	+= \
			$(EOLIST)

XCFLAGS		+= \
			$(EOLIST)

XDEFINES	+= \
			$(EOLIST)

XLFLAGS		+= \
			$(EOLIST)
endif

ifeq "$(RELEASE)" "noopt"
XINCDIRS	+= \
			$(EOLIST)

XCFLAGS		+= \
			$(EOLIST)

XDEFINES	+= \
			$(EOLIST)

XLFLAGS		+= \
			$(EOLIST)
endif

ifeq "$(RELEASE)" "release"
XINCDIRS	+= \
			$(EOLIST)

XCFLAGS		+= \
			$(EOLIST)

XDEFINES	+= \
			$(EOLIST)

XLFLAGS		+= \
			$(EOLIST)
endif

#
# These are used by the link target if an NLM is being generated
# This is used by the link 'name' directive to name the nlm.  If left blank
# TARGET_nlm (see below) will be used.
#
NLM_NAME		= Apache

#
# This is used by the link '-desc ' directive. 
# If left blank, NLM_NAME will be used.
#
NLM_DESCRIPTION	= Apache Web Server

#
# This is used by the '-threadname' directive.  If left blank,
# NLM_NAME Thread will be used.
#
NLM_THREAD_NAME	= Apache

#
# If this is specified, it will override VERSION value in 
# $(AP_WORK)\NWGNUenvironment.inc
#
NLM_VERSION		=

#
# If this is specified, it will override the default of 64K
#
NLM_STACK_SIZE	= 65536

#
# If this is specified it will be used by the link '-entry' directive
#
NLM_ENTRY_SYM	=

#
# If this is specified it will be used by the link '-exit' directive
#
NLM_EXIT_SYM	=

#
# If this is specified it will be used by the link '-flags' directive
#
NLM_FLAGS		=

#
# Declare all target files (you must add your files here)
#

#
# If there is an NLM target, put it here
#
TARGET_nlm = \
	$(OBJDIR)/Apache.nlm \
	$(EOLIST)

#
# If there is an LIB target, put it here
#
TARGET_lib = \
	$(EOLIST)

#
# These are the OBJ files needed to create the NLM target above.
# Paths must all use the '/' character
#
FILES_nlm_objs = \
	$(OBJDIR)/main_nlm.o \
	$(EOLIST)

#
# These are the LIB files needed to create the NLM target above.
# These will be added as a library command in the link.opt file.
#
FILES_nlm_libs = \
	$(CLIB_PRELUDE) \
	$(EOLIST)

#
# These are the modules that the above NLM target depends on to load.
# These will be added as a module command in the link.opt file.
#
FILES_nlm_modules = \
	ApacheC \
	$(EOLIST)

#
# If the nlm has a msg file, put it's path here
#
FILE_nlm_msg =
 
#
# If the nlm has a hlp file put it's path here
#
FILE_nlm_hlp =

#
# If this is specified, it will override $(NWOS)\copyright.txt.
#
FILE_nlm_copyright =

#
# Any additional imports go here
#
FILES_nlm_Ximports = \
	@clib.imp \
	@nlmlib.imp \
	@threads.imp \
	@ldapsdk.imp \
	apache_main \
	__get_thread_data_area_ptr \
	init_tsd \
	init_name_space \
	ap_init_alloc \
	ap_destroy_pool \
	ap_make_array \
	ap_push_array \
	ap_make_table \
	ap_overlay_tables \
	ap_pstrdup \
	ap_table_set \
	ap_table_add \
	$(EOLIST)
 
#   
# Any symbols exported to here
#
FILES_nlm_exports = \
	$(EOLIST)
	
#   
# These are the OBJ files needed to create the LIB target above.
# Paths must all use the '/' character
#
FILES_lib_objs = \
	$(EOLIST)

#
# implement targets and dependancies (leave this section alone)
#

libs :: $(OBJDIR) $(TARGET_lib)

nlms :: libs $(TARGET_nlm)

#
# Updated this target to create necessary directories and copy files to the 
# correct place.  (See $(AP_WORK)\NWGNUhead.inc for examples)
#
install :: nlms FORCE
	copy $(OBJDIR)\Apache.nlm $(INSTALL)\Apache

#
# Any specialized rules here
#

$(OBJDIR)/%.o: $(NWOS)\%.c $(OBJDIR)\cc.opt
	@echo compiling $<
	$(CC) $< -o=$(OBJDIR)\$(@F) @$(OBJDIR)\cc.opt

%.d: $(NWOS)\%.c $(OBJDIR)\cc.opt
	@echo Creating dependancy list for $(notdir $<)
	$(CC) $< -o $*.tmp -M @$(OBJDIR)\cc.opt
	$(GNUTOOLS)/sed 's/$*.o[ :]*/$(OBJDIR)\/$*.o : $@ /g' $*.tmp > $@ 
	-$(DEL) $*.tmp

#
# Include the 'tail' makefile that has targets that depend on variables defined
# in this makefile
#

include $(AP_WORK)\NWGNUtail.inc

