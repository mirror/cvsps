# Test makefile for cvsps

PATH := ${PATH}:..

test: regress

testlist:
	@grep '^##' *.tst

TESTLOADS := $(shell ls -1 *.tst | sed '/.tst/s///')
rebuild:
	@-for file in $(TESTLOADS); do \
	    echo "Remaking $${file}.chk"; \
	    python $${file}.tst | sed -e "/$${USER} <$${USER}>/s//foo <foo>/" >$${file}.chk; \
	done
regress:
	@echo "=== Running cvsps tests:"
	@-for file in $(TESTLOADS); do \
	    echo -n "  $${file} "; grep '##' $${file}.tst  || echo ' ## (no description)'; \
	    $${file}.tst | sed -e "/$${USER} <$${USER}>/s//foo <foo>/" | diff -u $${file}.chk -; \
	done
	@rm -f /tmp/regress

clean:
	rm -fr test*-checkout test*-repo *.pyc
