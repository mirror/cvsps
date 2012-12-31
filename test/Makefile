# Test makefile for cvsps

PATH := ${PATH}:..


.SUFFIXES: .tst .repo .checkout

.tst.repo:
	python $<
.repo.checkout:
	cvs -d :local:${PWD}/$*.repo -Q checkout $* && mv $* $*.checkout

test: s_regress t_test
	@echo "No diff output is good news."

rebuild: s_rebuild t_rebuild

testlist:
	@grep '^##' *.tst *.py

TESTLOADS := $(shell ls -1 *.tst | sed '/.tst/s///')
s_rebuild:
	@echo "$${USER} = foo <foo> -0500" >/tmp/cvsps;
	@-for file in $(TESTLOADS); do \
	    echo "Remaking $${file}.chk"; \
	    make --quiet $${file}.repo; \
	    cvsps --root :local:$${PWD}/$${file}.repo --fast-export -T "2012-12-18T15:24:32" -A /tmp/cvsps $${file} >$${file}.chk 2>&1; \
	done;
	@rm /tmp/cvsps
s_regress:
	@echo "$${USER} = foo <foo> -0500" >/tmp/cvsps;
	@-for file in $(TESTLOADS); do \
	    echo -n "  $${file} "; grep '##' $${file}.tst  || echo ' ## (no description)'; \
	    make --quiet $${file}.repo; \
	    cvsps --root :local:$${PWD}/$${file}.repo --fast-export -T "2012-12-18T15:24:32" -A /tmp/cvsps $${file} 2>&1 | diff -u $${file}.chk -; \
	done
	@rm -f /tmp/regress /tmp/cvsps

PYTESTS=t9601 t9602 t9603
t_test:
	@for pytest in $(PYTESTS); do \
		echo -n "  $${pytest} "; grep '##' $${pytest}.py  || echo ' ## (no description)'; \
		python $${pytest}.py 2>&1 | diff $${pytest}.err -; \
	done
t_rebuild:
	@for pytest in $(PYTESTS); do \
		echo "Remaking $${pytest}.err "; \
		python $${pytest}.py >$${pytest}.err 2>&1; \
	done

clean:
	rm -fr *.checkout *.repo *.pyc *.log
