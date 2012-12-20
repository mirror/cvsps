# Utility functions for creating and manipulating test repositories

cvscreate() {
# Create a repo and a checkout of it, then go to the checkout
rm -fr ${1}-repo ${1}-checkout; mkdir ${1}-repo
cvs -d:local:$PWD/${1}-repo init
mkdir ${1}-repo/${1}-checkout
CVS="cvs -Q -d:local:${PWD}/${1}-repo"
$CVS co ${1}-checkout
PATH=$PATH:..
repo=${1}
cd ${1}-checkout >/dev/null
}

cvsadd() {
# Add to the repo
$CVS add ${1}
}

cvsremove() {
# Remove files from the repo
$CVS remove -f $*
}

cvsbranch() {
# Create a branch
$CVS tag ${1}_root
$CVS tag -r ${1}_root -b ${1}
$CVS up -r ${1}
}

cvsswitch() {
# Switch to branch or HEAD
$CVS up -A
if [ "$1" != HEAD ]
then
    $CVS up -r ${1}
fi
}

cvstag() {
# Create a tag
$CVS tag ${1}
}

cvsmerge() {
# Merge a branch (see https://kb.wisc.edu/middleware/page.php?id=4087)
$CVS tag merge_${1}
$CVS up -A
$CVS up -j ${1}
}

cvscommit() {
# Commit to the repo
sleep 1
$CVS commit -m "${1}"
}

emit() {
# Dump changesets from the repo
cvsps -x --fast-export -T ${1}
}

cvsdestroy() {
# Clean up
rm -fr ../${repo}-repo ../${repo}-checkout
}
