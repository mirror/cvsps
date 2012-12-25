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

import os, getopt, subprocess

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

if __name__ == '__main__':
    if sys.hexversion < 0x02060000:
        sys.stderr.write("git-cvsimport: requires Python 2.6 or later.")
        sys.exit(1)
    (options, arguments) = getopt.getopt(sys.argv[1:], "vd:C:r:o:ikus:p:z:P:S:aL:A:Rh")
    cvsps_opts = ""
    verbose = 0
    root = None
    outdir = os.getcwd()
    remotize = False
    import_only = False
    underscore_to_dot = False
    slashsubst = None
    pathselect = None
    authormap = None
    revisionmap = False
    for (opt, val) in options:
        if opt == '-v':
            verbose += 1
        elif opt == '-d':
            if not val.startswith(":"):
                if not val.startswith("/"):
                    val = os.path.abspath(val)
                val = ":local:" + val
            cvsps_opts += " --root '%s'" % val
        elif opt == '-C':
            outdir = val
        elif opt == '-r':
            remotize = True	# FIXME: Not implemented
        elif opt == '-o':
            sys.stderr.write("git-cvsimport: -o is no longer supported.\n")
            sys.exit(1)
        elif opt == '-i':
            import_only = True
        elif opt == '-k':
            sys.stderr.write("git-cvsimport: -k is permanently on.\n")
        elif opt == '-u':
            underscore_to_dot = True	# FIXME: Not implemented
        elif opt == '-s':
            slashsubst = val	# FIXME: Not implemented
        elif opt == '-p':
            cvsps_opts += val.replace(",", " ")
        elif opt == '-z':
            cvsps_opts += " -Z %s" % val
        elif opt == '-P':
            sys.stderr.write("git-cvsimport: -P is no longer supported.\n")
            sys.exit(1)
        elif opt in ('-m', '-M'):
            sys.stderr.write("git-cvsimport: -m and -M are no longer supported: use reposurgeon instead.\n")
            sys.exit(1)
        elif opt == '-S':
            pathselect = False	# FIXME: Not implemented
        elif opt == '-a':
            sys.stderr.write("git-cvsimport: -a is no longer supported.\n")
            sys.exit(1)
        elif opt == '-L':
            sys.stderr.write("git-cvsimport: -L is no longer supported.\n")
            sys.exit(1)
        elif opt == '-A':
            cvsps_opts += " -A '%s'" % val
        elif opt == '-R':
            revisionmap = True	# FIXME: Not implemented
        else:
            print """\
git-cvsimport -o <branch-for-HEAD>] [-h] [-v] [-d <CVSROOT>]
     [-A <author-conv-file>] [-p <options-for-cvsps>]
     [-C <git_repository>] [-z <fuzz>] [-i] [-u] [-s <subst>]
     [-m] [-M <regex>] [-S <regex>] [-r <remote>] [-R] [<CVS_module>]
"""         
    cvsps_opts += " " + arguments[0]
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
        do_or_die("cvsps --fast-export %s | (cd %s >/dev/null; git fast-import --quiet)" \
                  % (cvsps_opts, outdir))
        os.chdir(outdir)
        # Implementation of postprocessing options go here
        if not import_only:
            do_or_die("git checkout -q")
    except Fatal, err:
        sys.stderr.write("git_cvsimport: " + err.msg + "\n")
        sys.exit(1)
    except KeyboardInterrupt:
        pass

# end
