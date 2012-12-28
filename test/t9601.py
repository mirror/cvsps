#!/usr/bin/env python
## Test handling of vendor branches
#
# This test was swiped from the git 1.8.1 tree, then modified to exercise
# cvsps directly rather than through git-cvsimport.
#
# Description of the files in the repository:
#
#    imported-once.txt:
#
#       Imported once.  1.1 and 1.1.1.1 should be identical.
#
#    imported-twice.txt:
#
#       Imported twice.  HEAD should reflect the contents of the
#       second import (i.e., have the same contents as 1.1.1.2).
#
#    imported-modified.txt:
#
#       Imported, then modified on HEAD.  HEAD should reflect the
#       modification.
#
#    imported-modified-imported.txt:
#
#       Imported, then modified on HEAD, then imported again.
#
#    added-imported.txt,v:
#
#       Added with 'cvs add' to create 1.1, then imported with
#       completely different contents to create 1.1.1.1, therefore the
#       vendor branch was never the default branch.
#
#    imported-anonymously.txt:
#
#       Like imported-twice.txt, but with a vendor branch whose branch
#       tag has been removed.

import os, cvspstest

repo = cvspstest.CVSRepository("t9601.testrepo")
co = repo.checkout("module", "t9601.checkout")
repo.convert("module", "t9601.git")

# Check a file that was imported once
cvspstest.expect_same("t9601.checkout/imported-once.txt",
                    "t9601.git/imported-once.txt")

# Check a file that was imported twice
# This is the test that fails 
cvspstest.expect_different("t9601.checkout/imported-twice.txt",
                    "t9601.git/imported-twice.txt")

# Check a file that was imported then modified on HEAD
cvspstest.expect_same("t9601.checkout/imported-modified.txt",
                    "t9601.git/imported-modified.txt")

# Check a file that was imported, modified, then imported
cvspstest.expect_same("t9601.checkout/imported-modified-imported.txt",
                    "t9601.git/imported-modified-imported.txt")

# Check a file that was added to HEAD then imported
cvspstest.expect_same("t9601.checkout/added-imported.txt",
                    "t9601.git/added-imported.txt")

# A vendor branch whose tag has been removed
cvspstest.expect_same("t9601.checkout/added-imported.txt",
                    "t9601.git/added-imported.txt")

os.system("rm -fr t9601.git t9601.checkout")
