#!/usr/bin/env python
#
# Import CVS history into git
#
# Intended to be a near-workalike of Matthias Urlichs's Perl implementation.
#
# By Eric S. Raymond <esr@thyrsus.com>, December 2012
# May be redistributed under the license of the git project.

import sys

if sys.hexversion < 0x02060000:
    sys.stderr.write("git-cvsimport: requires Python 2.6 or later.\n")
    sys.exit(1)

import os, getopt, subprocess, tempfile

DEBUG_COMMANDS = 1

class Fatal(Exception):
    "Unrecoverable error."
    def __init__(self, msg):
        Exception.__init__(self)
        self.msg = msg

def do_or_die(dcmd, legend=""):
    "Either execute a command or raise a fatal exception."
    if legend:
        legend = " "  + legend
    if verbose >= DEBUG_COMMANDS:
        sys.stdout.write("git-cvsimport: executing '%s'%s\n" % (dcmd, legend))
    try:
        retcode = subprocess.call(dcmd, shell=True)
        if retcode < 0:
            raise Fatal("git-cvsimport: child was terminated by signal %d." % -retcode)
        elif retcode != 0:
            raise Fatal("git-cvsimport: child returned %d." % retcode)
    except (OSError, IOError) as e:
        raise Fatal("git-cvsimport: execution of %s%s failed: %s" % (dcmd, legend, e))

class cvsps:
    "Method class for cvsps back end."
    def __init__(self):
        self.opts = ""
    def set_repo(self, val):
        "Set the repository root option."
        if not val.startswith(":"):
            if not val.startswith(os.sep):
                val = os.path.abspath(val)
            val = ":local:" + val
        backend_opts += " --root '%s'" % val
    def set_fuzz(self, val):
        "Set the commit-similarity window."
        self.opts += " -z %s" % val
    def add_opts(self, val):
        "Add options to the engine command line."
        self.opts += " " + val
    def set_exclusion(self, val):
        "Set a file exclusion regexp."
        self.opts += " -n -f '%s'" % val
    def set_module(self.val):
        "Set the module to query."
        self.opts += " " + module
    def command(self):
        "Emit the command implied by all previous options."
        return "cvsps --fast-export " + self.opts

class cvs2git:
    "Method class for cvs2git back end."
    def __init__(self):
        self.opts = ""
    def set_repo(self, val):
        "Set the repository root option."
        sys.stderr.write("git-cvsimport: cvs2git must run within a repository checkout directory.\n")
        sys.exit(1)
    def set_fuzz(self, val):
        "Set the commit-similarity window."
        sys.stderr.write("git-cvsimport: fuzz setting is not supported with cvs2git.\n")
        sys.exit(1)
    def add_opts(self, val):
        "Add options to the engine command line."
        self.opts += " " + val
    def set_exclusion(self, val):
        "Set a file exclusion regexp."
        self.opts += " --exclude='%s'" % val
    def set_module(self.val):
        "Set the module to query."
        self.opts += " " + module
    def command(self):
        "Emit the command implied by all previous options."
        return "cvs2git --blobfile={0} --dumpfile={1} {2} | cat {0} {1} && rm {0} {1}".format(tempfile.mkstemp(), tempfile.mkstemp(), self.opts)

if __name__ == '__main__':
    if sys.hexversion < 0x02060000:
        sys.stderr.write("git-cvsimport: requires Python 2.6 or later.\n")
        sys.exit(1)
    (options, arguments) = getopt.getopt(sys.argv[1:], "ve:d:C:r:o:ikus:p:z:P:S:aL:A:Rh")
    verbose = 0
    root = None
    outdir = os.getcwd()
    remotize = False
    import_only = False
    underscore_to_dot = False
    slashsubst = None
    authormap = None
    revisionmap = False
    backend = cvsps()
    for (opt, val) in options:
        if opt == '-v':
            verbose += 1
        elif opt == '-e':
            for cls in (cvsps, cvs2git):
                if cls.name == val:
                    backend = cls()
                    break
            else:
                sys.stderr.write("git-cvsimport: unknown engine %s.\n" % val)
                sys.exit(1)
        elif opt == '-d':
            backend.repo_set(val)
        elif opt == '-C':
            outdir = val
        elif opt == '-r':
            remotize = True
        elif opt == '-o':
            sys.stderr.write("git-cvsimport: -o is no longer supported.\n")
            sys.exit(1)
        elif opt == '-i':
            import_only = True
        elif opt == '-k':
            sys.stderr.write("git-cvsimport: -k is permanently on.\n")
        elif opt == '-u':
            underscore_to_dot = True
        elif opt == '-s':
            slashsubst = val
        elif opt == '-p':
            backend.add_opts(val.replace(",", " "))
        elif opt == '-z':
            backend.set_fuzz(val)
        elif opt == '-P':
            sys.stderr.write("git-cvsimport: -P is no longer supported.\n")
            sys.exit(1)
        elif opt in ('-m', '-M'):
            sys.stderr.write("git-cvsimport: -m and -M are no longer supported: use reposurgeon instead.\n")
            sys.exit(1)
        elif opt == '-S':
            backend.set_exclusion(val)
        elif opt == '-a':
            sys.stderr.write("git-cvsimport: -a is no longer supported.\n")
            sys.exit(1)
        elif opt == '-L':
            sys.stderr.write("git-cvsimport: -L is no longer supported.\n")
            sys.exit(1)
        elif opt == '-A':
            backend_opts += " -A '%s'" % val
        elif opt == '-R':
            revisionmap = True	# FIXME: Not implemented
        else:
            print """\
git-cvsimport -o <branch-for-HEAD>] [-e engine] [-h] [-v] [-d <CVSROOT>]
     [-A <author-conv-file>] [-p <options-for-cvsps>]
     [-C <git_repository>] [-z <fuzz>] [-i] [-u] [-s <subst>]
     [-m] [-M <regex>] [-S <regex>] [-r <remote>] [-R] [<CVS_module>]
"""         
    backend.set_module(arguments[0])
    try:
        if outdir:
            try:
                # If the output directory does not exist, create it
                # and initialize it as a git repository.
                os.mkdir(outdir)
                do_or_die("git init " + outdir)
            except:
                # Otherwise, assume user wants incremental import.
                if not os.path.exists(os.path.join(outdir, ".git")):
                    raise Fatal("output directory is not a git repository")
        do_or_die("%s | (cd %s >/dev/null; git fast-import --quiet)" \
                  % (backend.command(), outdir))
        os.chdir(outdir)
        tagnames = capture_or_die("git tag -l")
        for tag in tags.split():
            if tag:
                changed = tag
                if underscore_to_dot:
                    changed = changed.replace("_", ".")
                if slashsubst:
                    changed = changed.replace(os.sep, slashsubst)
                if changed != tag:
                    do_or_die("git tag -f %s %s >/dev/null" % (tag, changed))
        branchnames = capture_or_die("git branch -l")
        for branch in branchnames.split():
            if branch:
                # Ugh - fragile dependency on branch -l output format
                branch = branch[2:]
                changed = branch
                if underscore_to_dot:
                    changed = changed.replace("_", ".")
                if slashsubst:
                    changed = changed.replace(os.sep, slashsubst)
                if remotize:
                    changed = os.path.join("remotes", remotize, branch)
                if changed != branch:
                    do_or_die("branch --m %s %s >/dev/null" % (branch, changed))
        # Implementation of postprocessing options go here
        if not import_only:
            do_or_die("git checkout -q")
    except Fatal, err:
        sys.stderr.write("git_cvsimport: " + err.msg + "\n")
        sys.exit(1)
    except KeyboardInterrupt:
        pass

# end
