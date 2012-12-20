#!/bin/bash
## A branchy repo with deletions and only valid tags

. cvsfunctions.sh

cvscreate test1

cat >README <<EOF
The quick brown fox jumped over the lazy dog.
EOF
cvsadd README
cvscommit "This is a sample commit"

cat >README <<EOF
Now is the time for all good men to come to the aid of their country.
EOF
cvscommit "This is another sample commit"

cat >doomed <<EOF
This is a doomed file.  Its destiny is to be deleted.
EOF
cvsadd doomed
cvscommit "Create a doomed file"

cat >doomed <<EOF
The world will little note, nor long remember what we say here
EOF
cvscommit "Add a spacer commit"

cvstag foo

cat >.cvsignore <<EOF
*.pyc
EOF
cvsadd .cvsignore
cvscommit "Check that .cvsignore -> .gitignore name translation works."

cat >README <<EOF
And now for something completely different.
EOF
cvscommit "The obligatory Monty Python reference"

cvsremove doomed
cvscommit "Testing file removal"

cat >README <<EOF
The file 'doomed' should not be visible at this revision.
EOF
cvscommit "Only README should be visible here."

cvsbranch "samplebranch"

# This will point at the same commit as the generated samplebranch_root
cvstag random

cat >README <<EOF
This is alternate content for README.
EOF
cvscommit "Do we get branch detection right?"

cvsswitch HEAD

cat >README <<EOF
I'm back in the saddle again.
EOF
cvscommit "This commit should alter the master branch."

# The tilde should be stripped from the middle of this
cvstag "ill~egal"

# Doesn't matter what this date is, it just has to be constant
emit 2012-12-18T15:24:32
cvsdestroy

# end


