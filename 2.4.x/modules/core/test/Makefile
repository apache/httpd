#
# mod_macro non regression tests

# where is apache
APA.dir	= /tmp/apache

# apache executable with mod macro loaded
HTTPD = \
	$(APA.dir)/bin/httpd \
	  -C 'LoadModule macro_module modules/mod_macro.so' \
	  -C "Define PWD $$PWD/conf"

# default target
.PHONY: default
default: clean

# run all non regression tests
.PHONY: check
check: check-out

# result directory
OUT	= out
out:
	mkdir $@

# test cases & results
F.conf	= $(wildcard conf/test*.conf)
F.out	= $(F.conf:conf/%.conf=$(OUT)/%.out)

# run all tests
.PHONY: run-test
run-test: $(F.out)

# generate & compare in a separate directory
.PHONY: check-out
check-out: out
	$(RM) out/*.out
	$(MAKE) OUT=out run-test
	diff -r out/ ref/

# generate & compare in the same directory
.PHONY: check-ref
check-ref:
	$(RM) ref/*.out
	$(MAKE) OUT=ref run-test
	svn diff ref/

# run one test case
# filter output so that it is portable
# use '|' sed separator because $PWD will contain plenty '/'
$(OUT)/%.out: conf/%.conf
	{ \
	  echo "# testing with $<" ; \
	  $(HTTPD) -f $$PWD/$< 2>&1 ; \
	  echo "# exit: $$?" ; \
	} > $@.tmp ; \
	sed -e "s|$$PWD|.|g" \
	    -e "s|^\[[\.a-zA-Z0-9 :]*\] ||" \
	    -e "s|\[pid [0-9]*:tid [0-9]*] ||" \
	    $@.tmp > $@ ; \
	$(RM) $@.tmp

# cleanup
.PHONY: clean
clean:
	$(RM) *~
	$(RM) -r out
