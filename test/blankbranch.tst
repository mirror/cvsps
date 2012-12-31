#!/usr/bin/env python
## Test for the daughter-branch bug

# This was the description:
#
# * This applies to files added to the source branch *after* a daughter
#   branch was created: if previously no commit was made on the daughter
#   branch they will erroneously be added to the daughter branch in git.

import cvspstest

repo = cvspstest.CVSRepository("blankbranch.repo")
repo.init()
repo.module("blankbranch")
co = repo.checkout("blankbranch", "blankbranch.checkout")

co.write("README", "The quick brown fox jumped over the lazy dog.\n")
co.add("README")
co.commit("This is a sample commit")

co.write("superfluous",
         "This is a superflous file, a sanity check for branch creation.\n")
co.add("superfluous")
co.commit("Should not generate an extra fileop after branching")

co.branch("samplebranch")
co.switch("HEAD")

co.write("feedyourhead", "I date myself with a Jefferson Airplane reference.\n")
co.add("feedyourhead")
co.commit("This file should not appear on the daughter branch")

repo.cleanup()

# end
