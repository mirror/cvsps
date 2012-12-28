"""
Test framework for cvsps.
"""
import sys, os, shutil, subprocess, time, filecmp

DEBUG_STEPS    = 1
DEBUG_COMMANDS = 2
DEBUG_CVS      = 3
DEBUG_CVSPS    = 4

verbose = 0

os.putenv("PATH", os.getenv("PATH") + "|..") 

def do_or_die(dcmd, legend=""):
    "Either execute a command or raise a fatal exception."
    if legend:
        legend = " "  + legend
    if verbose >= DEBUG_COMMANDS:
        sys.stdout.write("cvspstest: executing '%s'%s\n" % (dcmd, legend))
    try:
        retcode = subprocess.call(dcmd, shell=True)
        if retcode < 0:
            sys.stderr.write("cvspstest: child was terminated by signal %d.\n" % -retcode)
            sys.exit(1)
        elif retcode != 0:
            sys.stderr.write("cvspstest: child returned %d.\n" % retcode)
            sys.exit(1)
    except (OSError, IOError) as e:
        sys.stderr.write("cvspstest: xecution of %s%s failed: %s\n" % (dcmd, legend, e))
        sys.exit(1)

def capture_or_die(dcmd, legend=""):
    "Either execute a command and capture its output or die."
    if legend:
        legend = " "  + legend
    if verbose >= DEBUG_COMMANDS:
        sys.stdout.write("cvspstest: executing '%s'%s\n" % (dcmd, legend))
    try:
        return subprocess.check_output(dcmd, shell=True)
    except subprocess.CalledProcessError as e:
        if e.returncode < 0:
            sys.stderr.write("cvspstest: child was terminated by signal %d." % -e.returncode)
        elif e.returncode != 0:
            sys.stderr.write("cvspstest: child returned %d." % e.returncode)
        sys.exit(1)
    
class directory_context:
    def __init__(self, target):
        self.target = target
        self.source = None
    def __enter__(self):
        if verbose >= DEBUG_COMMANDS:
            sys.stdout.write("In %s: " % os.path.relpath(self.target))
        self.source = os.getcwd()
        if os.path.isdir(self.target):
            os.chdir(self.target)
    def __exit__(self, extype, value_unused, traceback_unused):
        os.chdir(self.source)

class CVSRepository:
    def __init__(self, name):
        self.name = name
        self.fast_export = not ("-o" in sys.argv[1:])
        self.retain = ("-n" in sys.argv[1:])
        global verbose
        verbose += sys.argv[1:].count("-v")
        self.directory = os.path.join(os.getcwd(), self.name)
        self.checkouts = []
    def do(self, *cmd):
        "Execute a CVS command in context of this repo."
        if verbose < DEBUG_CVS:
            mute = '-Q'
        else:
            mute = ""
        do_or_die("cvs %s -d:local:%s %s" % (mute,
                                             self.directory,
                                             " ".join(cmd)))
    def init(self):
        do_or_die("rm -fr {0}; mkdir {0}".format(self.name))
        self.do("init")
    def module(self, mname):
        "Create an empty module with a specified name."
        module = os.path.join(self.directory, mname)
        if verbose >= DEBUG_COMMANDS:
            sys.stdout.write("Creating module %s\n" % module)
        os.mkdir(module)
    def checkout(self, module, checkout=None):
        "Create a checkout of this repo."
        self.checkouts.append(CVSCheckout(self, module, checkout))
        return self.checkouts[-1]
    def convert(self, module, gitdir):
        "Convert a specified module.  Leave the stream dump in a log file."
        vopt = "-v " * (verbose - DEBUG_CVSPS + 1)
        do_or_die("rm -fr {0} && mkdir {0} && git init --quiet {0}".format(gitdir))
        do_or_die('cvsps {3} --root ":local:{0}" --fast-export {1} | tee {2}.log | (cd {2} >/dev/null; git fast-import --quiet --done && git checkout)'.format(self.directory, module, gitdir, vopt))
    def cleanup(self):
        "Clean up the repository checkout directories."
        if not self.retain:
            for checkout in self.checkouts:
                checkout.cleanup()

class CVSCheckout:
    def __init__(self, repo, module, checkout=None):
        self.repo = repo
        self.module = module
        self.checkout = checkout or module
        self.repo.do("co", self.module)
        if checkout:
            if os.path.exists(checkout):
                shutil.rmtree(checkout)
            os.rename(module, checkout)
        self.directory = os.path.join(os.getcwd(), self.checkout)
    def do(self, cmd, *args):
        "Execute a command in the checkout directory."
        with directory_context(self.directory):
            apply(self.repo.do, [cmd] + list(args))
    def add(self, *filenames):
        "Add a file to the version-controlled set."
        apply(self.do, ["add"] + list(filenames))
    def remove(self, *files):
        "Remove a file from the version-controlled set."
        apply(self.do, ["remove", "-f"] + list(files))
    def branch(self, branchname):
        "Create a new branch."
        self.do("tag", branchname + "_root")
        self.do("tag", "-r", branchname + "_root", "-b", branchname)
        self.do("up", "-r", branchname)
    def switch(self, branch="HEAD"):
        "Switch to an existing branch."
        self.do("up", "-A")
        if branch != "HEAD":
            self.do("up", "-r", branch)
    def tag(self, name):
        "Create a tag."
        self.do("tag", name)
    def merge(self, branchname):
        "Merge a branch to trunk."
        # See https://kb.wisc.edu/middleware/page.php?id=4087
        self.do("tag", "merge_" + branchname)
        self.do("up", "-A")
        self.do("up", "-j", branchname)
    def commit(self, message):
        "Commit changes to the repository."
        time.sleep(1)
        apply(self.do, ["commit", "-m '%s'" % message])
    def write(self, fn, content):
        "Create file content in the repository."
        if verbose >= DEBUG_COMMANDS:
            sys.stdout.write("%s <- %s" % (fn, content))
        with directory_context(self.directory):
            with open(fn, "w") as fp:
                fp.write(content)
    def append(self, fn, content):
        "Append to file content in the repository."
        if verbose >= DEBUG_COMMANDS:
            sys.stdout.write("%s <-| %s" % (fn, content))
        with directory_context(self.directory):
            with open(fn, "a") as fp:
                fp.write(content)
    def update(self, rev):
        "Update the content to the specified revision or tag."
        if rev == 'master':
            rev = "HEAD"
        self.do("up", "-kk", "-r", rev) 
    def cleanup(self):
        "Clean up the checkout directory."
        shutil.rmtree(self.directory)

def expect_same(a, b):
    "Complain if two files aren't identical"
    if not filecmp.cmp(a, b, shallow=False):
        sys.stderr.write("%s and %s are not the same.\n" % (a, b))
    
def expect_different(a, b):
    "Rejoice if two files are unexpectedly identical"
    if filecmp.cmp(a, b, shallow=False):
        sys.stderr.write("%s and %s are unexpectedly the same.\n" % (a, b))

class ConvertComparison:
    "Compare a CVS repository and its conversion for equality."
    def __init__(self, stem, module):
        self.stem = stem
        self.module = module
        self.repo = CVSRepository(stem + ".testrepo")
        self.checkout = self.repo.checkout(module, stem + ".checkout")
        self.repo.convert("module", stem + ".git")
        with directory_context(stem + ".git"):
            self.branches = [name for name in capture_or_die("git branch -l").split()]
            self.tags = [name for name in capture_or_die("git tag -l").split()]
    def cmp_branch_tree(self, legend, tag, success_expected):
        "Test to see if a tag checkout has the expected content."
        def recursive_file_gen(mydir, ignore):
            for root, dirs, files in os.walk(mydir):
                for file in files:
                    path = os.path.join(root, file)
                    if ignore not in path.split(os.sep):
                        yield path
        preamble = "%s %s %s: " % (self.stem, legend, tag)
        if tag not in self.tags and tag not in self.branches:
            if success_expected:
                sys.stderr.write(preamble + "tag or branch %s unexpectedly missing\n" % tag)
            return False
        self.checkout.update(tag)
        with directory_context(self.stem + ".git"):
            do_or_die("git checkout --quiet %s" % tag)
        cvspaths = list(recursive_file_gen(self.stem + ".checkout", ignore="CVS"))
        cvsfiles = [fn[len(self.stem+".checkout")+1:] for fn in cvspaths]
        gitpaths = list(recursive_file_gen(self.stem + ".git", ignore=".git"))
        gitfiles = [fn[len(self.stem+".git")+1:] for fn in gitpaths]
        cvsfiles.sort()
        gitfiles.sort()
        if cvsfiles != gitfiles:
            if success_expected:
                sys.stderr.write(preamble + "file manifests don't match\n")
                print >>sys.stderr, cvsfiles, gitfiles
            return False
        else:
            success = True
            for (a, b) in zip(cvspaths, gitpaths):
                if not filecmp.cmp(a, b, shallow=False):
                    success = False
                    if success_expected:
                        sys.stderr.write("%s %s %s: %s and %s are different.\n" % (self.stem, legend, tag, a, b))
                        #do_or_die("diff -u %s %s" % (a, b))
        if success:
            if not success_expected:
                sys.stderr.write(preamble + "trees unexpectedly match\n")
            elif verbose >= DEBUG_STEPS:
                sys.stderr.write(preamble + "trees matched as expected\n")
        elif not success:
            if not success_expected and verbose >= DEBUG_STEPS:
                sys.stderr.write(preamble + "trees diverged as expected\n")
        return success
    def cleanup(self):
        os.system("rm -fr {0}.git {0}.checkout".format(self.stem))

# End.
