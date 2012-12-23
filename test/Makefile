# Test makefile for cvsps

PATH := ${PATH}:..


.SUFFIXES: .tst .repo .checkout

.tst.repo:
	python $<
.repo.checkout:
	cvs -d :local:${PWD}/$*.repo -Q checkout $* && mv $* $*.checkout

test: regress

testlist:
	@grep '^##' *.tst

TESTLOADS := $(shell ls -1 *.tst | sed '/.tst/s///')
rebuild:
	@-for file in $(TESTLOADS); do \
	    echo "Remaking $${file}.chk"; \
	    make --quiet $${file}.repo; \
	    cvsps --root :local:$${PWD}/$${file}.repo --fast-export -T "2012-12-18T15:24:32" $${file} | sed -e "/$${USER} <$${USER}>/s//foo <foo>/" >$${file}.chk; \
	done
regress:
	@-for file in $(TESTLOADS); do \
	    echo -n "  $${file} "; grep '##' $${file}.tst  || echo ' ## (no description)'; \
	    make --quiet $${file}.repo; \
	    cvsps --root :local:$${PWD}/$${file}.repo --fast-export -T "2012-12-18T15:24:32" $${file} | sed -e "/$${USER} <$${USER}>/s//foo <foo>/" | diff -u $${file}.chk -; \
	done
	@rm -f /tmp/regress

clean:
	rm -fr *.checkout *.repo *.pyc
