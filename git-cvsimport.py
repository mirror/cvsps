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

import os, getopt, subprocess, tempfile, shutil


DEBUG_COMMANDS = 1
verbose = 0


class Fatal(Exception):
    "Unrecoverable error."
    def __init__(self, msg):
        Exception.__init__(self)
        self.msg = msg


def do_or_die(dcmd):
    "Either execute a command or raise a fatal exception."
    if verbose >= DEBUG_COMMANDS:
        sys.stdout.write("git cvsimport: executing '%s'\n" % ' '.join(dcmd))
    return subprocess.check_call(dcmd)


def capture_or_die(dcmd):
    "Either execute a command and capture its output or die."
    if verbose >= DEBUG_COMMANDS:
        sys.stdout.write("git cvsimport: executing '%s'\n" % ' '.join(dcmd))
    return subprocess.check_output(dcmd)


class Cvsps:
    "Method class for cvsps back end."

    def __init__(self):
        self.opts = []
        self.revmap = None

    def set_repo(self, val):
        "Set the repository root option."
        if not val.startswith(":"):
            if not val.startswith(os.sep):
                val = os.path.abspath(val)
            val = ":local:" + val
        self.opts.extend(["--root", val])

    def set_authormap(self, val):
        "Set the author-map file."
        self.opts.extend(["-A", val])

    def set_fuzz(self, val):
        "Set the commit-similarity window."
        self.opts.extend(["-z", val])

    def set_nokeywords(self):
        "Suppress CVS keyword expansion."
        self.opts.append("-k")

    def add_opts(self, options):
        "Add options to the engine command line."
        self.opts.extend(options)

    def set_exclusion(self, val):
        "Set a file exclusion regexp."
        self.opts.extend(["-n", "-f", val])

    def set_after(self, val):
        "Set a date threshold for incremental import."
        self.opts.extend(["-d", val])

    def set_revmap(self, val):
        "Set the file to which the engine should dump a reference map."
        self.revmap = val
        self.opts.extend(["-R", self.revmap])

    def set_module(self, val):
        "Set the module to query."
        self.opts.append(val)

    def run(self, fast_import):
        "Runs the command, piping data into the fast_import subprocess."
        subprocess.check_call([self.cvsps, "--fast-export"] + self.opts,
                              stdout=fast_import.stdin)


class Cvs2Git:
    "Method class for cvs2git back end."

    def __init__(self):
        self.opts = []
        self.modulepath = "."

    def set_authormap(self, _val):
        "Set the author-map file."
        raise Fatal("author maping is not supported with cvs2git.")

    def set_repo(self, _val):
        "Set the repository root option."
        raise Fatal("cvs2git must run within a repository checkout directory.")

    def set_fuzz(self, _val):
        "Set the commit-similarity window."
        raise Fatal("fuzz setting is not supported with cvs2git.")

    def set_nokeywords(self):
        "Suppress CVS keyword expansion."
        self.opts.append("--keywords-off")

    def add_opts(self, options):
        "Add options to the engine command line."
        self.opts.extend(options)

    def set_exclusion(self, val):
        "Set a file exclusion regexp."
        self.opts.append("--exclude=%s" % val)

    def set_after(self, _val):
        "Set a date threshold for incremental import."
        raise Fatal("incremental import is not supported with cvs2git.")

    def set_revmap(self, _val):
        "Set the file to which the engine should dump a reference map."
        raise Fatal("can't get a reference map from cvs2git.")

    def set_module(self, val):
        "Set the module to query."
        self.modulepath = val

    def run(self, fast_import):
        "Runs the command, piping data into the fast_import subprocess."
        blobfile = tempfile.mkstemp()[1]
        dumpfile = tempfile.mkstemp()[1]
        do_or_die(["cvs2git", "--username=git-cvsimport",
                              "--quiet", "--quiet",
                              "--blobfile=%s" % blobfile,
                              "--dumpfile=%s" % dumpfile] +
                              self.opts + [self.modulepath])
        subprocess.check_call(['cat', blobfile, dumpfile],
                              stdout=fast_import.stdin)
        os.unlink(blobfile)
        os.unlink(dumpfile)


class CvsFastExport:
    "Method class for cvs-fast-export back end."

    def __init__(self):
        self.opts = []
        self.revmap = None

    def set_repo(self, val):
        raise Fatal("cvs-fast-export must be run from within a module directory.")

    def set_authormap(self, val):
        "Set the author-map file."
        self.opts.extend(["-A", val])

    def set_fuzz(self, val):
        "Set the commit-similarity window."
        self.opts.extend(["-w", val])

    def set_nokeywords(self):
        "Suppress CVS keyword expansion."
        self.opts.append("-k")

    def add_opts(self, options):
        "Add options to the engine command line."
        self.opts.extend(options)

    def set_exclusion(self, val):
        "Set a file exclusion regexp."
        raise Fatal("exclusion is not supported with cvs-fast-export.")

    def set_after(self, val):
        "Set a date threshold for incremental import."
        raise Fatal("incremental import is not supported with cvs-fast-export.")

    def set_revmap(self, val):
        "Set the file to which the engine should dump a reference map."
        self.revmap = val
        self.opts.extend(["-R", self.revmap])

    def set_module(self, val):
        "Set the module to query."

    def run(self, fast_import):
        "Emit the command implied by all previous options."
        cmd = ["cvs-fast-export"] + self.opts
        fast_export = subprocess.Popen(cmd,
                                       stdin=subprocess.PIPE,
                                       stdout=fast_import.stdin)
        fast_import.stdin.close()
        for root, dirs, files in os.walk('.', onerror=lambda e: raise e):
            for name in files:
                if name.endswith(',v'):
                    fast_export.stdin.write('%s\n' % os.path.join(root, name))
        fast_export.stdin.close()

        returncode = fast_export.wait()
        if returncode != 0:
            raise CalledProcessError(returncode, cmd)


class FileSource:
    "Method class for file-source back end."

    def __init__(self, filename):
        self.filename = filename

    def __complain(self, legend):
        raise Fatal("%s with file source." % legend)

    def set_repo(self, _val):
        "Set the repository root option."
        self.__complain("repository can't be set")

    def set_authormap(self, _val):
        "Set the author-map file."
        raise Fatal("author mapping is not supported with filesource.")

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
        raise Fatal("can't get a reference map from cvs2git.")

    def set_module(self, _val):
        "Set the module to query."
        self.__complain("module can't be set")

    def command(self, fast_import):
        "Runs the command, piping data into the fast_import subprocess."
        subprocess.check_call(["cat", self.filename],
                              stdout=fast_import.stdin)


def main(argv):
    (options, arguments) = getopt.getopt(argv, "vbe:d:C:r:o:ikus:p:z:P:S:aL:A:Rh")
    global verbose
    bare = False
    root = None
    outdir = os.getcwd()
    remotize = False
    import_only = False
    underscore_to_dot = False
    slashsubst = None
    authormap = None
    revisionmap = False

    # Since a number of other options are passed to the backend, we need to
    # extract the backend option before handling the others.
    backend_opt = [o[1] for o in options if o[0] == 'e']
    if backend_opt:
        val = backend_opt[0]
        for cls in (Cvsps, Cvs2Git):
            if cls.__name__.lower() == val:
                backend = cls()
                break
        else:
            raise Fatal("unknown engine %s." % val)
    else:
        backend = Cvsps()

    for (opt, val) in options:
        if opt == '-v':
            verbose += 1
        elif opt == '-b':
            bare = True
        elif opt == '-e':
            # We handled the backend first, above.
            pass
        elif opt == '-d':
            backend.set_repo(val)
        elif opt == '-C':
            outdir = val
        elif opt == '-r':
            remotize = True
        elif opt == '-o':
            raise Fatal("-o is no longer supported.")
        elif opt == '-i':
            import_only = True
        elif opt == '-k':
            backend.set_nokeywords()
        elif opt == '-u':
            underscore_to_dot = True
        elif opt == '-s':
            slashsubst = val
        elif opt == '-p':
            backend.add_opts(val.split(","))
        elif opt == '-z':
            backend.set_fuzz(val)
        elif opt == '-P':
            backend = FileSource(val)
        elif opt in ('-m', '-M'):
            raise Fatal("-m and -M are no longer supported: use reposurgeon instead.")
        elif opt == '-S':
            backend.set_exclusion(val)
        elif opt == '-a':
            raise Fatal("-a is no longer supported.")
        elif opt == '-L':
            raise Fatal("-L is no longer supported.")
        elif opt == '-A':
            authormap = os.path.abspath(val)
        elif opt == '-R':
            revisionmap = True
        else:
            print """\
git cvsimport [-A <author-conv-file>] [-C <git_repository>] [-b] [-d <CVSROOT>]
     [-e engine] [-h] [-i] [-k] [-p <options-for-cvsps>] [-P <source-file>]
     [-r <remote>] [-R] [-s <subst>] [-S <regex>] [-u] [-v] [-z <fuzz>]
     [<CVS_module>]
"""
    def metadata(fn, outdir='.'):
        if bare:
            return os.path.join(outdir, fn)
        else:
            return os.path.join(outdir, ".git", fn) 
    # Ugly fallback code for people with only cvsps-2.x
    # Added January 2013 - should be removed after a decent interval.
    if backend.__class__.__name__ == "cvsps":
        try:
            subprocess.check_output("cvsps -V 2>/dev/null", shell=True)
        except subprocess.CalledProcessError as e:
            raise Fatal("cvsps 2.x is unsupported.")
    # Real mainline code begins here
    if outdir:
        try:
            # If the output directory does not exist, create it
            # and initialize it as a git repository.
            os.mkdir(outdir)
            do_or_die(["git", "init", "--quiet", outdir])
        except OSError:
            # Otherwise, assume user wants incremental import.
            if not bare and not os.path.exists(os.path.join(outdir, ".git")):
                raise Fatal("output directory is not a git repository")
            threshold = capture_or_die(["git", "log",  "-1",
                                        "--format=%ct"]).strip()
            backend.set_after(threshold)
    if revisionmap:
        backend.set_revmap(tempfile.mkstemp()[1])
        markmap = tempfile.mkstemp()[1]

    if len(arguments) > 1:
        raise Fatal('you cannot specify more than one CVS module')
    if arguments:
        backend.set_module(arguments[0])

    gitopts = []
    if bare:
        gitopts.append("--bare")
    if revisionmap:
        gitopts.append("--export-marks=%s" % markmap)
    if authormap:
        shutil.copyfile(authormap, metadata("cvs-authors", outdir))
    if os.path.exists(metadata("cvs-authors", outdir)):
        backend.set_authormap(metadata("cvs-authors", outdir))
    fast_import = subprocess.Popen(["git", "fast-import", "--quiet"] + gitopts,
                                   cwd=outdir,
                                   stdin=subprocess.PIPE)
    backend.run(fast_import)
    if fast_import.wait():
        raise Fatal("git-fast-import returned an error: %d"
                    % fast_import.returncode)

    os.chdir(outdir)
    if underscore_to_dot or slashsubst:
        tagnames = capture_or_die(["git", "for-each-ref",
                                          "--format=%(refname)",
                                          "refs/tags/"])
        for ref in tagnames.splitlines():
            # Get rid of the trailing newline and the leading "refs/tags/":
            tag = ref.strip()[10:]
            changed = tag
            if underscore_to_dot:
                changed = changed.replace("_", ".")
            if slashsubst:
                changed = changed.replace(os.sep, slashsubst)
            if changed != tag:
                do_or_die(["git", "update-ref",
                                  "refs/tags/%s" % changed,
                                  ref])
                do_or_die(["git", "update-ref", "-d", tag])
    if underscore_to_dot or slashsubst or remotize:
        branchnames = capture_or_die(["git", "for-each-ref",
                                             "--format=%(refname)",
                                             "refs/heads/"])
        for branch in branchnames.splitlines():
            # Get rid of the trailing newline and the leading "refs/heads/":
            branch = branch.strip()[11:]
            changed = branch
            if underscore_to_dot:
                changed = changed.replace("_", ".")
            if slashsubst:
                changed = changed.replace(os.sep, slashsubst)
            if remotize:
                changed = os.path.join("remotes", remotize, branch)
            if changed != branch:
                do_or_die(["git", "branch", "-m", branch, changed])
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
        with open(metadata("cvs-revisions"), "a") as wfp:
            for ((fn, rev), val) in refd.items():
                if val in markd:
                    wfp.write("%s %s %s\n" % (fn, rev, markd[val]))
        os.remove(markmap)
        os.remove(backend.revmap)
    if not import_only and not bare:
        do_or_die(["git", "checkout", "-f"])


if __name__ == '__main__':
    try:
        try:
            sys.exit(main(sys.argv[1:]))
        except subprocess.CalledProcessError as e:
            if e.returncode < 0:
                raise Fatal("child was terminated by signal %d."
                            % -e.returncode)
            else:
                raise Fatal("child returned %d." % e.returncode)
        except KeyboardInterrupt:
            pass
    except Fatal as err:
        sys.stderr.write("git cvsimport: " + err.msg + "\n")
        sys.exit(1)
