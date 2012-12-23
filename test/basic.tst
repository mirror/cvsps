#!/usr/bin/env python
## A branchy repo with deletions and only valid tags

import cvstest

repo = cvstest.CVSRepository("basic.repo")
repo.module("basic")
co = repo.checkout("basic", "basic.checkout")

co.write("README", "The quick brown fox jumped over the lazy dog.\n")
co.add("README")
co.commit("This is a sample commit")

co.write("README",
         "Now is the time for all good men to come to the aid of their country.\n")
co.commit("This is another sample commit")

co.write("doomed",
         "This is a doomed file.  Its destiny is to be deleted.\n")
co.add("doomed")
co.commit("Create a doomed file")

co.write("doomed",
         "The world will little note, nor long remember what we say here\n")
co.commit("Add a spacer commit")

co.tag("foo")	# Ordinary, legal tag name

co.write(".cvsignore","*.pyc\n")
co.add(".cvsignore")
co.commit("Check that .cvsignore -> .gitignore name translation works.")

co.write("README",
         "And now for something completely different.\n")
co.commit("The obligatory Monty Python reference")

co.remove("doomed")
co.commit("Testing file removal")

co.write("README",
         "The file 'doomed' should not be visible at this revision.\n")
co.commit("Only README should be visible here.")

co.branch("samplebranch")

# This will point at the same commit as the generated samplebranch_root
co.tag("random")

co.write("README", "This is alternate content for README.\n")
co.commit("Do we get branch detection right?")

co.switch("HEAD")

co.write("README", "I'm back in the saddle again.\n")
co.commit("This commit should alter the master branch.")

# The tilde should be stripped from the middle of this
co.tag("ill~egal")

repo.cleanup()

# end
