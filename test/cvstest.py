"""
Test framework for cvsps.
"""
import sys, os, shutil, subprocess, time

DEBUG_STEPS    = 1
DEBUG_COMMANDS = 2
DEBUG_CVS      = 3

verbose = 0

os.putenv("PATH", os.getenv("PATH") + "|..") 

def do_or_die(dcmd, legend=""):
    "Either execute a command or raise a fatal exception."
    if legend:
        legend = " "  + legend
    if verbose >= DEBUG_COMMANDS:
        sys.stdout.write("Executing '%s'%s\n" % (dcmd, legend))
    try:
        retcode = subprocess.call(dcmd, shell=True)
        if retcode < 0:
            sys.stderr.write("Child was terminated by signal %d.\n" % -retcode)
            sys.exit(1)
        elif retcode != 0:
            sys.stderr.write("Child returned %d.\n" % retcode)
            sys.exit(1)
    except (OSError, IOError) as e:
        sys.stderr.write("Execution of %s%s failed: %s\n" % (dcmd, legend, e))
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
    def emit(self, timebase):
        "Report the history of the repository as seen from here."
        with directory_context(self.directory):
            if self.repo.fast_export:
                do_or_die("cvsps --fast-export -T " + timebase)
            else:
                do_or_die("cvsps")
    def cleanup(self):
        "Clean up the checkout directory."
        shutil.rmtree(self.directory)

# End.
