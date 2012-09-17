# Include for creating start/stop/restart NCF scripts.

instscripts:: FORCE $(INSTALLBASE)/ap2start.ncf $(INSTALLBASE)/ap2auto.ncf $(INSTALLBASE)/ap2rest.ncf $(INSTALLBASE)/ap2stop.ncf

$(INSTALLBASE)/ap2start.ncf:
	@echo $(DL)# NCF to start Apache 2.x in own address space$(DL)> $@
	@echo $(DL)# Make sure that httpstk is not listening on 80$(DL)>> $@
	@echo $(DL)# httpcloseport 80 /silent$(DL)>> $@
	@echo $(DL)# search add SYS:/$(BASEDIR)$(DL)>> $@
	@echo $(DL)load address space = $(BASEDIR) SYS:/$(BASEDIR)/apache2$(DL)>> $@
	@echo $(DL)# If you have problems with 3rd-party modules try to load in OS space.$(DL)>> $@
	@echo $(DL)# load SYS:/$(BASEDIR)/apache2$(DL)>> $@
	@$(ECHONL)>> $@

$(INSTALLBASE)/ap2auto.ncf:
	@echo $(DL)# NCF to start Apache 2.x in own address space$(DL)> $@
	@echo $(DL)# and let automatically restart in case it crashes$(DL)>> $@
	@echo $(DL)# Make sure that httpstk is not listening on 80$(DL)>> $@
	@echo $(DL)# httpcloseport 80 /silent$(DL)>> $@
	@echo $(DL)# search add SYS:/$(BASEDIR)$(DL)>> $@
	@echo $(DL)restart address space = $(BASEDIR) SYS:/$(BASEDIR)/apache2$(DL)>> $@
	@$(ECHONL)>> $@

$(INSTALLBASE)/ap2rest.ncf:
	@echo $(DL)# NCF to restart Apache 2.x in own address space$(DL)> $@
	@echo $(DL)apache2 restart -p $(BASEDIR)$(DL)>> $@
	@echo $(DL)# If you have loaded Apache2.x in OS space use the line below.$(DL)>> $@
	@echo $(DL)# apache2 restart$(DL)>> $@
	@$(ECHONL)>> $@

$(INSTALLBASE)/ap2stop.ncf:
	@echo $(DL)# NCF to stop Apache 2.x in own address space$(DL)> $@
	@echo $(DL)apache2 shutdown -p $(BASEDIR)$(DL)>> $@
	@echo $(DL)# If you have loaded Apache2.x in OS space use the line below.$(DL)>> $@
	@echo $(DL)# apache2 shutdown$(DL)>> $@
	@$(ECHONL)>> $@

$(INSTALLBASE)/ap2prod.ncf:
	@echo $(DL)# NCF to create a product record for Apache 2.x in product database$(DL)> $@
	@echo $(DL)PRODSYNC DEL APACHE$(VERSION_MAJMIN)$(DL)>> $@
	@echo $(DL)PRODSYNC ADD APACHE$(VERSION_MAJMIN) ProductRecord "$(VERSION_STR)" "Apache $(VERSION_STR) Webserver"$(DL)>> $@
	@$(ECHONL)>> $@

