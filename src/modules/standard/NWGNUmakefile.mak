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
			$(SRC)\lib\sdbm \
			$(NWOS) \
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
NLM_NAME		=

#
# This is used by the link '-desc ' directive. 
# If left blank, NLM_NAME will be used.
#
NLM_DESCRIPTION	=

#
# This is used by the '-threadname' directive.  If left blank,
# NLM_NAME Thread will be used.
#
NLM_THREAD_NAME	=

#
# If this is specified, it will override VERSION value in 
# $(AP_WORK)\NWGNUenvironment.inc
#
NLM_VERSION		=

#
# If this is specified, it will override the default of 64K
#
NLM_STACK_SIZE	=

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
	$(OBJDIR)/AuthDBM.nlm \
	$(OBJDIR)/AuthAnon.nlm \
	$(OBJDIR)/CERNMeta.nlm \
	$(OBJDIR)/Digest.nlm \
	$(OBJDIR)/Expires.nlm \
	$(OBJDIR)/forensic.nlm \
	$(OBJDIR)/Headers.nlm \
	$(OBJDIR)/Info.nlm \
	$(OBJDIR)/Rewrite.nlm \
	$(OBJDIR)/Speling.nlm \
	$(OBJDIR)/Status.nlm \
	$(OBJDIR)/uniqueid.nlm \
	$(OBJDIR)/Usrtrack.nlm \
	$(OBJDIR)/Vhost.nlm \
	$(EOLIST)

#
# If there is an LIB target, put it here
#
TARGET_lib = \
	$(OBJDIR)/stdmod.lib \
	$(EOLIST)

#
# These are the OBJ files needed to create the NLM target above.
# Paths must all use the '/' character
#
FILES_nlm_objs = \
	$(EOLIST)

#
# These are the LIB files needed to create the NLM target above.
# These will be added as a library command in the link.opt file.
#
FILES_nlm_libs = \
	$(EOLIST)

#
# These are the modules that the above NLM target depends on to load.
# These will be added as a module command in the link.opt file.
#
FILES_nlm_modules = \
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
	$(OBJDIR)/mod_access.o \
	$(OBJDIR)/mod_actions.o \
	$(OBJDIR)/mod_alias.o \
	$(OBJDIR)/mod_asis.o \
	$(OBJDIR)/mod_auth.o \
	$(OBJDIR)/mod_autoindex.o \
	$(OBJDIR)/mod_dir.o \
	$(OBJDIR)/mod_env.o \
	$(OBJDIR)/mod_imap.o \
	$(OBJDIR)/mod_include.o \
	$(OBJDIR)/mod_log_nw.o \
	$(OBJDIR)/mod_mime.o \
	$(OBJDIR)/mod_negotiation.o \
	$(OBJDIR)/mod_setenvif.o \
	$(OBJDIR)/mod_so.o \
	$(OBJDIR)/mod_userdir.o \
	$(EOLIST)

# Standard modules not linked statically

#	$(OBJDIR)/mod_auth_anon.obj \  dynamic
#	$(OBJDIR)/mod_auth_db.obj \
#	$(OBJDIR)/mod_auth_dbm.obj \
#	$(OBJDIR)/mod_cern_meta.obj \  dynamic
#	$(OBJDIR)/mod_cgi.obj \
#	$(OBJDIR)/mod_digest.obj \     dynamic
#	$(OBJDIR)/mod_expires.obj \    dynamic
#	$(OBJDIR)/mod_headers.obj \    dynamic
#	$(OBJDIR)/mod_info.obj \       dynamic
#	$(OBJDIR)/mod_log_agent.obj \
#	$(OBJDIR)/mod_log_referer.obj \
#	$(OBJDIR)/mod_mime_magic.obj \
#	$(OBJDIR)/mod_rewrite.obj \    dynamic
#	$(OBJDIR)/mod_speling.obj \    dynamic
#	$(OBJDIR)/mod_status.obj \     dynamic
#	$(OBJDIR)/mod_unique_id.obj \
#	$(OBJDIR)/mod_usertrack.obj \  dynamic

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
	copy $(OBJDIR)\*.nlm $(INSTALL)\APache\modules

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

