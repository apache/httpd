# Include for creating start/stop/restart NCF scripts.

instscripts:: FORCE $(INSTALL)/$(BASEDIR)/ap2start.ncf $(INSTALL)/$(BASEDIR)/ap2auto.ncf $(INSTALL)/$(BASEDIR)/ap2rest.ncf $(INSTALL)/$(BASEDIR)/ap2stop.ncf $(INSTALL)/$(BASEDIR)/ap2prod.ncf

$(INSTALL)/$(BASEDIR)/ap2start.ncf:
	@echo # NCF to start Apache 2.x in own address space > $@
	@echo # Make sure that httpstk isn't listening on 80 >> $@
	@echo # httpcloseport 80 /silent >> $@
	@echo # search add SYS:/$(BASEDIR) >> $@
	@echo load address space = $(BASEDIR) SYS:/$(BASEDIR)/apache2 >> $@
	@echo # If you have problems with 3rd-party modules try to load in OS space. >> $@
	@echo # load $(BASEDIR)/apache2 >> $@
	@echo. >> $@

$(INSTALL)/$(BASEDIR)/ap2auto.ncf:
	@echo # NCF to start Apache 2.x in own address space > $@
	@echo # and let automatically restart in case it crashes >> $@
	@echo # Make sure that httpstk isn't listening on 80 >> $@
	@echo # httpcloseport 80 /silent >> $@
	@echo # search add SYS:/$(BASEDIR) >> $@
	@echo restart address space = $(BASEDIR) SYS:/$(BASEDIR)/apache2 >> $@
	@echo # If you have problems with 3rd-party modules try to load in OS space. >> $@
	@echo # load $(BASEDIR)/apache2 >> $@
	@echo. >> $@

$(INSTALL)/$(BASEDIR)/ap2rest.ncf:
	@echo # NCF to restart Apache 2.x in own address space > $@
	@echo apache2 restart -p $(BASEDIR) >> $@
	@echo # If you have loaded Apache2.x in OS space use the line below. >> $@
	@echo # apache2 restart >> $@
	@echo. >> $@

$(INSTALL)/$(BASEDIR)/ap2stop.ncf:
	@echo # NCF to stop Apache 2.x in own address space > $@
	@echo apache2 shutdown -p $(BASEDIR) >> $@
	@echo # If you have loaded Apache2.x in OS space use the line below. >> $@
	@echo # apache2 shutdown >> $@
	@echo. >> $@

$(INSTALL)/$(BASEDIR)/ap2prod.ncf:
	@echo # NCF to create a product record for Apache 2.x in product database > $@
	@echo PRODSYNC DEL APACHE$(VERSION_MAJMIN) >> $@
	@echo PRODSYNC ADD APACHE$(VERSION_MAJMIN) ProductRecord "$(VERSION_STR)" "Apache $(VERSION_STR) Webserver" >> $@
	@echo. >> $@


