# Uses Xalan-C++ to build Apache html documentation.

workdir   := ../mod
xmlfiles  := $(wildcard $(workdir)/*.xml)
xmlfiles  := $(subst allmodules.xml,,$(xmlfiles))
htmlfiles := $(subst xml,html,$(xmlfiles))

html: $(htmlfiles)

# Xalan-C users use this:
#%.html : %.xml
#	xsl-c -v -OUT $@ -IN ./manual.xsl 

# Xalan-C++ users use this:
%.html : %.xml
	Xalan -v -o $@ $< ./manual.xsl 
