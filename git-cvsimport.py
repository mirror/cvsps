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
    sys.stderr.write("git cvsimport: requires Python 2.6 or later.\n")
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
        sys.stdout.write("git cvsimport: executing '%s'%s\n" % (dcmd, legend))
    try:
        retcode = subprocess.call(dcmd, shell=True)
        if retcode < 0:
            raise Fatal("git cvsimport: child was terminated by signal %d." % -retcode)
        elif retcode != 0:
            raise Fatal("git cvsimport: child returned %d." % retcode)
    except (OSError, IOError) as e:
        raise Fatal("git cvsimport: execution of %s%s failed: %s" % (dcmd, legend, e))

def capture_or_die(dcmd, legend=""):
    "Either execute a command and capture its output or die."
    if legend:
        legend = " "  + legend
    if verbose >= DEBUG_COMMANDS:
        sys.stdout.write("git cvsimport: executing '%s'%s\n" % (dcmd, legend))
    try:
        return subprocess.check_output(dcmd, shell=True)
    except subprocess.CalledProcessError as e:
        if e.returncode < 0:
            sys.stderr.write("git cvsimport: child was terminated by signal %d." % -e.returncode)
        elif e.returncode != 0:
            sys.stderr.write("git cvsimport: child returned %d." % e.returncode)
        sys.exit(1)
    
class cvsps:
    "Method class for cvsps back end."
    def __init__(self):
        self.opts = ""
        self.revmap = None
    def set_repo(self, val):
        "Set the repository root option."
        if not val.startswith(":"):
            if not val.startswith(os.sep):
                val = os.path.abspath(val)
            val = ":local:" + val
        self.opts += " --root '%s'" % val
    def set_authormap(self, val):
        "Set the author-map file."
        self.opts += " -A '%s'" % val
    def set_fuzz(self, val):
        "Set the commit-similarity window."
        self.opts += " -z %s" % val
    def set_nokeywords(self):
        "Suppress CVS keyword expansion."
        self.opts += " -k"
    def add_opts(self, val):
        "Add options to the engine command line."
        self.opts += " " + val
    def set_exclusion(self, val):
        "Set a file exclusion regexp."
        self.opts += " -n -f '%s'" % val
    def set_after(self, val):
        "Set a date threshold for incremental import."
        self.opts += " -d '%s'" % val
    def set_revmap(self, val):
        "Set the file to which the engine should dump a reference map."
        self.revmap = val
        self.opts += " -R '%s'" % self.revmap
    def set_module(self, val):
        "Set the module to query."
        self.opts += " " + val
    def command(self):
        "Emit the command implied by all previous options."
        return "cvsps --fast-export " + self.opts

class cvs2git:
    "Method class for cvs2git back end."
    def __init__(self):
        self.opts = ""
    def set_authormap(self, _val):
        "Set the author-map file."
        sys.stderr.write("git cvsimport: author maping is not supported with cvs2git.\n")
        sys.exit(1)
    def set_repo(self, _val):
        "Set the repository root option."
        sys.stderr.write("git cvsimport: cvs2git must run within a repository checkout directory.\n")
        sys.exit(1)
    def set_fuzz(self, _val):
        "Set the commit-similarity window."
        sys.stderr.write("git cvsimport: fuzz setting is not supported with cvs2git.\n")
        sys.exit(1)
    def set_nokeywords(self):
        "Suppress CVS keyword expansion."
        self.opts += " --keywords-off"
    def add_opts(self, val):
        "Add options to the engine command line."
        self.opts += " " + val
    def set_exclusion(self, val):
        "Set a file exclusion regexp."
        self.opts += " --exclude='%s'" % val
    def set_after(self, _val):
        "Set a date threshold for incremental import."
        sys.stderr.write("git cvsimport: incremental import is not supported with cvs2git.\n")
    def set_revmap(self, _val):
        "Set the file to which the engine should dump a reference map."
        sys.stderr.write("git cvsimport: can't get a reference map from cvs2git.\n")
        sys.exit(1)
    def set_module(self, val):
        "Set the module to query."
        self.opts += " " + val
    def command(self):
        "Emit the command implied by all previous options."
        return "cvs2git --blobfile={0} --dumpfile={1} {2} | cat {0} {1} && rm {0} {1}".format(tempfile.mkstemp()[1], tempfile.mkstemp()[1], self.opts)

class filesource:
    "Method class for file-source back end."
    def __init__(self, filename):
        self.filename = filename
    def __complain(self, legend):
        sys.stderr.write("git cvsimport: %s with file source.\n" % legend)
        sys.exit(1)
    def set_repo(self, _val):
        "Set the repository root option."
        self.__complain("repository can't be set")
    def set_authormap(self, _val):
        "Set the author-map file."
        sys.stderr.write("git cvsimport: author maping is not supported with filesource.\n")
        sys.exit(1)
    def set_fuzz(self, _val):
        "Set the commit-similarity window."
        self.__complain("fuzz can't be set")
    def set_nokeywords(self, _val):
        "Suppress CVS keyword expansion."
        self.__complain("keyword suppression can't be set")
    def add_opts(self, _val):
        "Add options to the engine command line."
        self.__complain("other options can't be set")
    def set_exclusion(self, _val):
        "Set a file exclusion regexp."
        self.__complain("exclusions can't be set")
    def set_after(self, _val):
        "Set a date threshold for incremental import."
        pass
    def set_revmap(self, _val):
        "Set the file to which the engine should dump a reference map."
        sys.stderr.write("git cvsimport: can't get a reference map from cvs2git.\n")
        sys.exit(1)
    def set_module(self, _val):
        "Set the module to query."
        self.__complain("module can't be set")
    def command(self):
        "Emit the command implied by all previous options."
        return "cat " + self.filename

if __name__ == '__main__':
    if sys.hexversion < 0x02060000:
        sys.stderr.write("git cvsimport: requires Python 2.6 or later.\n")
        sys.exit(1)
    (options, arguments) = getopt.getopt(sys.argv[1:], "vbe:d:C:r:o:ikus:p:z:P:S:aL:A:Rh")
    verbose = 0
    bare = False
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
        elif opt == '-b':
            bare = True
        elif opt == '-e':
            for cls in (cvsps, cvs2git):
                if cls.__name__ == val:
                    backend = cls()
                    break
            else:
                sys.stderr.write("git cvsimport: unknown engine %s.\n" % val)
                sys.exit(1)
        elif opt == '-d':
            backend.set_repo(val)
        elif opt == '-C':
            outdir = val
        elif opt == '-r':
            remotize = True
        elif opt == '-o':
            sys.stderr.write("git cvsimport: -o is no longer supported.\n")
            sys.exit(1)
        elif opt == '-i':
            import_only = True
        elif opt == '-k':
            backend.set_nokeywords()
        elif opt == '-u':
            underscore_to_dot = True
        elif opt == '-s':
            slashsubst = val
        elif opt == '-p':
            backend.add_opts(val.replace(",", " "))
        elif opt == '-z':
            backend.set_fuzz(val)
        elif opt == '-P':
            backend = filesource(val)
            sys.exit(1)
        elif opt in ('-m', '-M'):
            sys.stderr.write("git cvsimport: -m and -M are no longer supported: use reposurgeon instead.\n")
            sys.exit(1)
        elif opt == '-S':
            backend.set_exclusion(val)
        elif opt == '-a':
            sys.stderr.write("git cvsimport: -a is no longer supported.\n")
            sys.exit(1)
        elif opt == '-L':
            sys.stderr.write("git cvsimport: -L is no longer supported.\n")
            sys.exit(1)
        elif opt == '-A':
            backend.set_authormap(val)
        elif opt == '-R':
            revisionmap = True
        else:
            print """\
git cvsimport [-A <author-conv-file>] [-C <git_repository>] [-b] [-d <CVSROOT>]
     [-e engine] [-h] [-i] [-k] [-m] [-M <regex>] [-p <options-for-cvsps>]
     [-P <source-file>] [-r <remote>] [-R] [-s <subst>] [-S <regex>] [-u]
     [-v] [-z <fuzz>] [<CVS_module>]
"""         
    try:
        if outdir:
            try:
                # If the output directory does not exist, create it
                # and initialize it as a git repository.
                os.mkdir(outdir)
                do_or_die("git init --quiet " + outdir)
            except OSError:
                # Otherwise, assume user wants incremental import.
                if not os.path.exists(os.path.join(outdir, ".git")):
                    raise Fatal("output directory is not a git repository")
                threshold = capture_or_die("git log -1 --format=%ct").strip()
                backend.set_after(threshold)
        if revisionmap:
            backend.set_revmap(tempfile.mkstemp()[1])
            markmap = tempfile.mkstemp()[1]
        if arguments:
            backend.set_module(arguments[0])
        gitopts = ""
        if bare:
            gitopts += " --bare"
        if revisionmap:
            gitopts += " --export-marks='%s'" % markmap
        do_or_die("%s | (cd %s >/dev/null; git fast-import --quiet %s)" \
                  % (backend.command(), outdir, gitopts))
        os.chdir(outdir)
        if underscore_to_dot or slashsubst:
            tagnames = capture_or_die("git tag -l")
            for tag in tagnames.split():
                if tag:
                    changed = tag
                    if underscore_to_dot:
                        changed = changed.replace("_", ".")
                    if slashsubst:
                        changed = changed.replace(os.sep, slashsubst)
                    if changed != tag:
                        do_or_die("git tag -f %s %s >/dev/null" % (tag, changed))
        if underscore_to_dot or slashsubst or remotize:
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
        if revisionmap:
            refd = {}
            for line in open(backend.revmap):
                if line.startswith("#"):
                    continue
                (fn, rev, mark) = line.split()
                refd[(fn, rev)] = mark
            markd = {}
            for line in open(markmap):
                if line.startswith("#"):
                    continue
                (mark, hashd) = line.split()
                markd[mark] = hashd
            cvs_revisions = "cvs-revisions"
            if not bare:
                cvs_revisions = os.path.join(".git", cvs_revisions) 
            with open(cvs_revisions, "w") as wfp:
                for ((fn, rev), val) in refd.items():
                    if val in markd:
                        wfp.write("%s %s %s\n" % (fn, rev, markd[val]))
            os.remove(markmap)
            os.remove(backend.revmap)
        if not import_only and not bare:
            do_or_die("git checkout -q")
    except Fatal, err:
        sys.stderr.write("git_cvsimport: " + err.msg + "\n")
        sys.exit(1)
    except KeyboardInterrupt:
        pass

# end
