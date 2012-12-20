# Test makefile for cvsps

PATH := ${PATH}:..

testlist:
	@grep '^##' *.tst

TESTLOADS := $(shell ls -1 *.tst | sed '/.tst/s///')
rebuild:
	@-for file in $(TESTLOADS); do \
	    echo "Remaking $${file}.chk"; \
	    $${file}.tst >$${file}.chk; \
	done
regress:
	@echo "=== Running repodiffer tests:"
	@-for file in $(TESTLOADS); do \
	    echo -n "  $${file} "; grep '##' $${file}.tst  || echo ' ## (no description)'; \
	    $${file}.tst | diff -u $${file}.chk -; \
	done
	@rm -f /tmp/regress

clean:
	rm -fr test*-checkout test*-repo
