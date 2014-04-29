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


def do_or_die(*args, **kwargs):
    "Either execute a command or raise a fatal exception."
    if verbose >= DEBUG_COMMANDS:
        sys.stdout.write("git cvsimport: executing '%s'\n" % ' '.join(args[0]))
    return subprocess.check_call(*args, **kwargs)


def capture_or_die(*args, **kwargs):
    "Either execute a command and capture its output or die."
    if verbose >= DEBUG_COMMANDS:
        sys.stdout.write("git cvsimport: executing '%s'\n" % ' '.join(args[0]))
    return subprocess.check_output(*args, **kwargs)


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
        do_or_die(['cat', blobfile, dumpfile], stdout=fast_import.stdin)
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
        self.opts.extend(["-i", val])

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
        for root, dirs, files in os.walk('.', onerror=Fatal):
            for name in files:
                if name.endswith(',v'):
                    fast_export.stdin.write('%s\n' % os.path.join(root, name))
        fast_export.stdin.close()

        returncode = fast_export.wait()
        if returncode != 0:
            raise Fatal("cvs-fast-export returned an error: %d" % returncode)


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

    def run(self, fast_import):
        "Runs the command, piping data into the fast_import subprocess."
        subprocess.check_call(["cat", self.filename],
                              stdout=fast_import.stdin)


def read_repo_config(optstring):
    # Users can set default values for options in their git configuration
    # file but that is case insensitive so we map uppercase option letters
    # to a long name.
    config_longopt_map = {
        'A': 'authorsfile',
        'P': None,
        'R': 'trackrevisions',
        'S': 'ignorepaths',
    }
    options = []
    for i, c in enumerate(optstring):
        if c == ':':
            continue
        # Map the letter to a long option if applicable.
        key = config_longopt_map.get(c, c)
        cmd = ["git", "config"]
        # If the next character isn't a colon, this is a flag.
        flag = (i + 1 == len(optstring)) or (optstring[i + 1] != ':')
        if flag:
            cmd.append("--bool")
        cmd.extend(["--get", "cvsimport.%s" % key])
        try:
            result = capture_or_die(cmd).strip()
        except subprocess.CalledProcessError:
            continue
        if not flag or result != "false":
            options.append(("-%s" % c, result))
    return options


def _get_ref_times():
    """Gets a map of ref -> commit time.

    The ref is a byte string and the commit time is an integer number of
    seconds since the Unix epoch.

    """
    # We use both %(authordate) and %(*authordate) here since only one will
    # be non-empty and this lets us read the right thing for both tags and
    # branches.
    output = capture_or_die(["git", "for-each-ref",
                "--format=%(refname)%09%(authordate:raw)%(*authordate:raw)"])
    refs = {}
    for line in output.splitlines():
        ref, time = line.split(b'\t')
        # The time string may only contain ASCII characters and it's easier
        # to deal with it as a string, so decode it now.
        time = time.decode('ascii')
        time, offset = time.split(' ')
        time = int(time)
        delta = ((int(offset[1:3]) * 60) + int(offset[3:5])) * 60
        if offset[0] == '+':
            time += delta
        else:
            time -= delta
        refs[ref] = time
    return refs


def main(argv):
    optstring = "vbe:d:C:r:o:ikus:p:z:P:S:aL:A:Rh"
    (options, arguments) = getopt.getopt(argv, optstring)
    global verbose
    bare = False
    outdir = os.getcwd()
    remotize = False
    import_only = False
    underscore_to_dot = False
    slashsubst = None
    authormap = None
    revisionmap = False

    # Add the user's repository options to the beginning of the parsed option
    # list.
    options = read_repo_config(optstring) + options

    # Since a number of other options are passed to the backend, we need to
    # extract the backend option before handling the others.
    backend_opt = [o[1] for o in options if o[0] == '-e']
    if backend_opt:
        val = backend_opt[0]
        for cls in (CvsFastExport, Cvs2Git):
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
    # Real mainline code begins here
    outdir = os.path.abspath(outdir)
    if bare:
        gitdir = outdir
    else:
        gitdir = os.path.join(outdir, os.environ.get('GIT_DIR', '.git'))
    os.environ['GIT_DIR'] = gitdir

    timestamp_file = os.path.join(gitdir, "CVSIMPORT_TIMESTAMP")

    timestamp = 0
    if os.path.exists(gitdir):
        # If the git directory already exists, continue the previous import.
        try:
            with open(timestamp_file) as f:
                timestamp = int(f.read().strip())
        except IOError:
            timestamp = capture_or_die(["git", "log",
                                          "--format=%ct",
                                          "-n 1",
                                          "--all"])
        backend.set_after(str(timestamp))
    else:
        # Otherwise, initialize a new Git repository.
        cmd = ["git", "init", "--quiet"]
        if bare:
            cmd.append("--bare")
        cmd.append(outdir)
        do_or_die(cmd)
    os.chdir(outdir)

    if revisionmap:
        backend.set_revmap(tempfile.mkstemp()[1])
        markmap = tempfile.mkstemp()[1]

    if len(arguments) > 1:
        raise Fatal('you cannot specify more than one CVS module')
    if not arguments:
        try:
            module = capture_or_die(["git", "config", "--get", "cvsimport.module"])
            arguments = [module.strip()]
        except subprocess.CalledProcessError:
            pass
    if arguments:
        backend.set_module(arguments[0])

    start_refs = _get_ref_times()

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

    end_refs = _get_ref_times()

    # Calculate the time of the last commit imported from CVS by looking at
    # those refs which have changed while fast-import was running.
    for ref, time in end_refs.items():
        orig_time = start_refs.get(ref, 0)
        if orig_time != time and time > timestamp:
            timestamp = time

    with open(timestamp_file, "w") as f:
        f.write("%d\n" % timestamp)

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
        with open(backend.revmap) as f:
            for line in f:
                if line.startswith("#"):
                    continue
                (fn, rev, mark) = line.split()
                refd[(fn, rev)] = mark
        markd = {}
        with open(markmap) as f:
            for line in f:
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
