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

neutralize.map:
	@echo "$${USER} = foo <foo> -0500" >neutralize.map

TESTLOADS := $(shell ls -1 *.tst | sed '/.tst/s///')
s_rebuild: neutralize.map
	@-for file in $(TESTLOADS); do \
	    echo "Remaking $${file}.chk"; \
	    make --quiet $${file}.repo; \
	    cvsps --root :local:$${PWD}/$${file}.repo --fast-export -T -A neutralize.map $${file} >$${file}.chk 2>&1; \
	done;
s_regress: neutralize.map
	@-for file in $(TESTLOADS); do \
	    echo -n "  $${file} "; grep '##' $${file}.tst  || echo ' ## (no description)'; \
	    make --quiet $${file}.repo; \
	    cvsps --root :local:$${PWD}/$${file}.repo --fast-export -T -A neutralize.map $${file} 2>&1 | diff -u $${file}.chk -; \
	done

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
	rm -fr neutralize.map *.checkout *.repo *.pyc *.log
