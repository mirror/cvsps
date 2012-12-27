/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <search.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/wait.h> /* for WEXITSTATUS - see system(3) */

#include "hash.h"
#include "list.h"
#include "text_util.h"
#include "debug.h"

#include "cvsps_types.h"
#include "cvsps.h"
#include "util.h"
#include "stats.h"
#include "cvsclient.h"
#include "list_sort.h"

#define CVS_LOG_BOUNDARY "----------------------------\n"
#define CVS_FILE_BOUNDARY "=============================================================================\n"

enum
{
    NEED_RCS_FILE,
    NEED_WORKING_FILE,
    NEED_SYMS,
    NEED_EOS,
    NEED_START_LOG,
    NEED_REVISION,
    NEED_DATE_AUTHOR_STATE,
    NEED_EOM
};

/* true globals */
struct hash_table * file_hash;
CvsServerCtx * cvsclient_ctx;
char root_path[PATH_MAX];
char repository_path[PATH_MAX];

const char * tag_flag_descr[] = {
    "",
    "**FUNKY**",
    "**INVALID**",
    "**INVALID**"
};

const char * fnk_descr[] = {
    "",
    "FNK_SHOW_SOME",
    "FNK_SHOW_ALL",
    "FNK_HIDE_ALL",
    "FNK_HIDE_SOME"
};

/* static globals */
static int ps_counter;
static void * ps_tree;
static struct hash_table * global_symbols;
static char strip_path[PATH_MAX];
static int strip_path_len;
static bool statistics;
static const char * test_log_file;
static struct hash_table * branch_heads;
static struct list_head all_patch_sets;
static struct list_head collisions;
static struct hash_table * branches;
static int dubious_branches = 0;

/* settable via options */
static int timestamp_fuzz_factor = 300;
static bool do_diff;
static const char * restrict_author;
static bool have_restrict_log;
static regex_t restrict_log;
static bool have_restrict_file;
static regex_t restrict_file;
static time_t restrict_date_start;
static time_t restrict_date_end;
static const char * restrict_branch;
static struct list_head show_patch_set_ranges;
static struct list_head authormap;
static int summary_first;
static bool fast_export;
static const char * patch_set_dir;
static const char * restrict_tag_start;
static const char * restrict_tag_end;
static int restrict_tag_ps_start;
static int restrict_tag_ps_end = INT_MAX;
static const char * diff_opts;
static int compress;
static char compress_arg[8];
static time_t regression_time;
static bool selection_sense = true;
static FILE *revfp;

static int parse_args(int, char *[]);
static int parse_rc();
static void load_from_cvs();
static void init_paths();
static CvsFile * build_file_by_name(const char *);
static CvsFile * parse_rcs_file(const char *);
static CvsFile * parse_working_file(const char *);
static CvsFileRevision * parse_revision(CvsFile * file, char * rev_str);
static void assign_pre_revision(PatchSetMember *, CvsFileRevision * rev);
static void check_print_patch_set(PatchSet *);
static void print_patch_set(PatchSet *);
static void print_fast_export(PatchSet *);
static void assign_patchset_id(PatchSet *);
static int compare_rev_strings(const char *, const char *);
static int compare_patch_sets_by_members(const PatchSet * ps1, const PatchSet * ps2);
static int compare_patch_sets(const void *, const void *);
static int compare_patch_sets_bytime_list(struct list_head *, struct list_head *);
static int compare_patch_sets_bytime(const PatchSet *, const PatchSet *);
static bool is_revision_metadata(const char *);
static bool patch_set_member_regex(PatchSet * ps, regex_t * reg);
static bool patch_set_affects_branch(PatchSet *, const char *);
static void do_cvs_diff(PatchSet *);
static PatchSet * create_patch_set();
static PatchSetRange * create_patch_set_range();
static void parse_sym(CvsFile *, char *);
static void resolve_global_symbols();
static bool revision_affects_branch(CvsFileRevision *, const char *);
static bool is_vendor_branch(const char *);
static void set_psm_initial(PatchSetMember * psm);
static int check_rev_funk(PatchSet *, CvsFileRevision *);
static CvsFileRevision * rev_follow_branch(CvsFileRevision *, const char *);
static bool before_tag(CvsFileRevision * rev, const char * tag);
static void handle_collisions();
static Branch * create_branch(const char * name) ;
static void find_branch_points(PatchSet * ps);

int main(int argc, char *argv[])
{
    struct list_head * next;

    debuglvl = DEBUG_APPERROR|DEBUG_SYSERROR|DEBUG_APPWARN;

    INIT_LIST_HEAD(&show_patch_set_ranges);
    INIT_LIST_HEAD(&authormap);

    if (parse_rc() < 0)
	exit(1);

    if (parse_args(argc, argv) < 0)
	exit(1);

    file_hash = create_hash_table(1023);
    global_symbols = create_hash_table(111);
    branch_heads = create_hash_table(1023);
    branches = create_hash_table(1023);
    INIT_LIST_HEAD(&all_patch_sets);
    INIT_LIST_HEAD(&collisions);

    /* this parses some of the CVS/ files, and initializes
     * the repository_path and other variables 
     */
    init_paths();

    if (!test_log_file)
	cvsclient_ctx = open_cvs_server(root_path, compress);

    load_from_cvs();

    //XXX
    //handle_collisions();

    list_sort(&all_patch_sets, compare_patch_sets_bytime_list);

    ps_counter = 0;
    walk_all_patch_sets(assign_patchset_id);

    handle_collisions();

    resolve_global_symbols();

    if (statistics)
	print_statistics(ps_tree);

    /* check that the '-r' symbols (if specified) were resolved */
    if (restrict_tag_start && restrict_tag_ps_start == 0 && 
	strcmp(restrict_tag_start, "#CVSPS_EPOCH") != 0)
    {
	debug(DEBUG_APPERROR, "symbol given with -r: %s: not found", restrict_tag_start);
	exit(1);
    }

    if (restrict_tag_end && restrict_tag_ps_end == INT_MAX)
    {
	debug(DEBUG_APPERROR, "symbol given with second -r: %s: not found", restrict_tag_end);
	exit(1);
    }

    for (next=all_patch_sets.next; next!=&all_patch_sets; next=next->next) {
	PatchSet * ps = list_entry(next, PatchSet, all_link);
	PatchSet * nextps = next->next ? list_entry(next->next, PatchSet, all_link) : NULL;
	if (ps->commitid == NULL
	    && (next->next == NULL || nextps == NULL || nextps->commitid == NULL))
	{
	    if (fast_export)
		debug(DEBUG_APPERROR,
		      "commitid reliable only after commit :%d%s",
		      ps->mark);
	    else
		debug(DEBUG_APPERROR,
		      "commitid reliable only after patch set %d%s",
		      ps->psid);
	}
    }

    walk_all_patch_sets(check_print_patch_set);

    if (summary_first++)
	walk_all_patch_sets(check_print_patch_set);

    if (cvsclient_ctx)
	close_cvs_server(cvsclient_ctx);

    if (fast_export) {
	fputs("done\n", stdout);
	if (dubious_branches > 1)
	    debug(DEBUG_APPWARN, "multiple vendor or anonymous branches; head content may be incorrect.");
	if (revfp)
	    fclose(revfp);
    }

    exit(0);
}

#ifdef HEIKO
void detect_and_repair_time_skew(const char *last_date, char *date, int n,
                                 PatchSetMember *psm)
{

    time_t smaller;
    time_t bigger;
    char *rev_end;

    /* if last_date does not exist do nothing */
    if (last_date[0] == '\0')
        return;

    /* TODO: repairing of branch times, skipping them for the moment */
    /* check whether rev is of the form /1.[0-9]+/ */
    if (psm->post_rev->rev[0] != '1' || psm->post_rev->rev[1] != '.')
        return;
    strtol(psm->post_rev->rev+2, &rev_end, 10);
    if (*rev_end != '\0')
        return;

    /* important: because rlog is showing revisions backwards last_date should
     * always be bigger than date */
    convert_date(&bigger, last_date);
    convert_date(&smaller, date);

    if (difftime(bigger, smaller) <= 0) {
        struct tm *ts;
        debug(DEBUG_APPWARN,"broken revision date: %s -> %s file: %s, repairing.\n",
              date, last_date, psm->file->filename);
        if (!(bigger > 0)) {
            debug(DEBUG_APPERROR, "timestamp underflow, exiting ... ");
            exit(1);
        }
        smaller = bigger - 1;
        ts = gmtime(&smaller);
        strftime(date, n, "%Y-%m-%d %H:%M:%S", ts);
    }
}
#endif

static void load_from_cvs()
{
    FILE * cvsfp = NULL;
    char buff[BUFSIZ];
    int state = NEED_RCS_FILE;
    CvsFile * file = NULL;
    PatchSetMember * psm = NULL;
    char datebuff[26];
#ifdef HEIKO
    char last_datebuff[20];
#endif
    char authbuff[AUTH_STR_MAX];
    char cidbuff[CID_STR_MAX];
    int logbufflen = LOG_STR_MAX + 1;
    char * logbuff = malloc(logbufflen);
    int loglen = 0;
    bool have_log = false;
    char date_str[64];

    if (test_log_file)
	cvsfp = fopen(test_log_file, "r");
    else if (cvsclient_ctx)
	cvsfp = cvs_rlog_open(cvsclient_ctx, repository_path, date_str);

    if (!cvsfp)
    {
	debug(DEBUG_SYSERROR, "can't get CVS log data");
	exit(1);
    }

#ifdef HEIKO
    /* initialize the last_datebuff with value indicating invalid date */
    last_datebuff[0]='\0';
#endif
    for (;;)
    {
	char * tst;
	if (cvsclient_ctx)
	    tst = cvs_rlog_fgets(buff, BUFSIZ, cvsclient_ctx);
	else
	    tst = fgets(buff, BUFSIZ, cvsfp);

	if (!tst)
	    break;

	debug(DEBUG_STATUS, "state: %d read line:%s", state, buff);

	switch(state)
	{
	case NEED_RCS_FILE:
	    if (strncmp(buff, "RCS file", 8) == 0) {
              if ((file = parse_rcs_file(buff)) != NULL)
		state = NEED_SYMS;
              else
                state = NEED_WORKING_FILE;
            }
	    break;
	case NEED_WORKING_FILE:
	    if (strncmp(buff, "Working file", 12) == 0) {
              if ((file = parse_working_file(buff)))
		state = NEED_SYMS;
              else
                state = NEED_RCS_FILE;
		break;
	    } else {
              // Working file come just after RCS file. So reset state if it was not found
              state = NEED_RCS_FILE;
            }
            break;
	case NEED_SYMS:
	    if (strncmp(buff, "symbolic names:", 15) == 0)
		state = NEED_EOS;
	    break;
	case NEED_EOS:
	    if (!isspace(buff[0]))
	    {
		/* see cvsps_types.h for commentary on have_branches */
		file->have_branches = true;
		state = NEED_START_LOG;
	    }
	    else
		parse_sym(file, buff);
	    break;
	case NEED_START_LOG:
	    if (strcmp(buff, CVS_LOG_BOUNDARY) == 0)
		state = NEED_REVISION;
	    break;
	case NEED_REVISION:
	    if (strncmp(buff, "revision", 8) == 0)
	    {
		char new_rev[REV_STR_MAX];
		CvsFileRevision * rev;

		strcpy(new_rev, buff + 9);
		chop(new_rev);

		/* 
		 * rev may already exist (think cvsps -u), in which
		 * case parse_revision is a hash lookup
		 */
		rev = parse_revision(file, new_rev);

		/* 
		 * in the simple case, we are copying rev to psm->pre_rev
		 * (psm refers to last patch set processed at this point)
		 * since generally speaking the log is reverse chronological.
		 * This breaks down slightly when branches are introduced 
		 */

		assign_pre_revision(psm, rev);

		/*
		 * if this is a new revision, it will have no post_psm associated.
		 * otherwise we are (probably?) hitting the overlap in cvsps -u 
		 */
		if (!rev->post_psm)
		{
		    psm = rev->post_psm = create_patch_set_member();
		    psm->post_rev = rev;
		    psm->file = file;
		    state = NEED_DATE_AUTHOR_STATE;
		}
		else
		{
		    /* we hit this in cvsps -u mode, we are now up-to-date
		     * w.r.t this particular file. skip all of the rest 
		     * of the info (revs and logs) until we hit the next file
		     */
		    psm = NULL;
		    state = NEED_EOM;
		}
	    }
	    break;
	case NEED_DATE_AUTHOR_STATE:
	    if (strncmp(buff, "date:", 5) == 0)
	    {
		char * p;

		strncpy(datebuff, buff + 6, sizeof(datebuff));
		datebuff[sizeof(datebuff)-1] = 0;

		strcpy(authbuff, "unknown");
		p = strstr(buff, "author: ");
		if (p)
		{
		    char * op;
		    p += 8;
		    op = strchr(p, ';');
		    if (op)
		    {
			strzncpy(authbuff, p, op - p + 1);
		    }
		}
		
		/* read the 'state' tag to see if this is a dead revision */
		p = strstr(buff, "state: ");
		if (p)
		{
		    char * op;
		    p += 7;
		    op = strchr(p, ';');
		    if (op)
			if (strncmp(p, "dead", MIN(4, op - p)) == 0)
			    psm->post_rev->dead = true;
		}

		cidbuff[0] = 0;
		p = strstr(buff, "commitid: ");
		if (p)
		{
		    char * op;
		    p += 10;
		    op = strchr(p, ';');
		    if (op)
		    {
			strzncpy(cidbuff, p, op - p + 1);
		    }
		}

		state = NEED_EOM;
	    }
	    break;
	case NEED_EOM:
	    if (strcmp(buff, CVS_LOG_BOUNDARY) == 0)
	    {
		if (psm)
		{
		    PatchSet *ps;
#ifdef HEIKO
		    detect_and_repair_time_skew(last_datebuff, 
						datebuff, sizeof(datebuff), 
						psm);
#endif
		    ps = get_patch_set(datebuff,
				       logbuff,
				       authbuff, 
				       psm->post_rev->branch,
				       cidbuff,
				       psm);
		    patch_set_add_member(ps, psm);
#ifdef HEIKO
		    /* remember last revision */
		    strncpy(last_datebuff, datebuff, 20);
		    /* just to be sure */
		    last_datebuff[19] = '\0';
#endif
		}

		logbuff[0] = 0;
		loglen = 0;
		have_log = false;
		state = NEED_REVISION;
	    }
	    else if (strcmp(buff, CVS_FILE_BOUNDARY) == 0)
	    {
		if (psm)
		{
		    PatchSet *ps;
#ifdef HEIKO
		    detect_and_repair_time_skew(last_datebuff, 
						datebuff, sizeof(datebuff),
						psm);
#endif
		    ps = get_patch_set(datebuff, 
				       logbuff, 
				       authbuff, 
				       psm->post_rev->branch,
				       cidbuff,
				       psm);
		    patch_set_add_member(ps, psm);

#ifdef HEIKO
		    /* just finished the last revision of this file,
		     * set last_datebuff to invalid */
		    last_datebuff[0]='\0';
#endif

		    assign_pre_revision(psm, NULL);
		}

		logbuff[0] = 0;
		loglen = 0;
		have_log = false;
		psm = NULL;
		file = NULL;
		state = NEED_RCS_FILE;
	    }
	    else
	    {
		/* other "blahblah: information;" messages can 
		 * follow the stuff we pay attention to
		 */
		if (have_log || !is_revision_metadata(buff))
		{
		    /* If the log buffer is full, try to reallocate more. */
		    if (loglen < logbufflen)
		    {
 			int len = strlen(buff);
 			
			if (len >= logbufflen - loglen)
 			{
			    debug(DEBUG_STATUS, "reallocating logbufflen to %d bytes for file %s", logbufflen, file->filename);
			    logbufflen += (len >= LOG_STR_MAX ? (len+1) : LOG_STR_MAX);
			    char * newlogbuff = realloc(logbuff, logbufflen);
			    if (newlogbuff == NULL)
			    {
				debug(DEBUG_SYSERROR, "could not realloc %d bytes for logbuff in load_from_cvs", logbufflen);
				exit(1);
			    }
			    logbuff = newlogbuff;
 			}

			debug(DEBUG_STATUS, "appending %s to log", buff);
			memcpy(logbuff + loglen, buff, len);
			loglen += len;
			logbuff[loglen] = 0;
			have_log = true;
		    }
		}
		else 
		{
		    debug(DEBUG_STATUS, "ignoring unhandled info %s", buff);
		}
	    }

	    break;
	}
    }

    if (state == NEED_SYMS)
    {
	debug(DEBUG_APPERROR, "Error: 'symbolic names' not found in log output.");
	exit(1);
    }

    if (state != NEED_RCS_FILE)
    {
	debug(DEBUG_APPERROR, "Error: Log file parsing error. (%d)  Use -v to debug", state);
	exit(1);
    }
    
    if (test_log_file)
    {
	fclose(cvsfp);
    }
    else if (cvsclient_ctx)
    {
	cvs_rlog_close(cvsclient_ctx);
    }
}

static int usage(const char * str1, const char * str2)
{
    if (str1)
	debug(DEBUG_APPERROR, "\nbad usage: %s %s\n", str1, str2);

    debug(DEBUG_APPERROR, "Usage: cvsps [-h] [-x] [-u] [-z <fuzz>] [-g] [-s <range>[,<range>]]  ");
    debug(DEBUG_APPERROR, "             [-a <author>] [-f <file>] [-d <date1> [-d <date2>]] ");
    debug(DEBUG_APPERROR, "             [-b <branch>]  [-l <regex>] [-n] [-r <tag> [-r <tag>]] ");
    debug(DEBUG_APPERROR, "             [-p <directory>] [-A 'authormap'] [-v] [-t] [--summary-first]");
    debug(DEBUG_APPERROR, "             [--test-log <captured cvs log file>]");
    debug(DEBUG_APPERROR, "             [--diff-opts <option string>]");
    debug(DEBUG_APPERROR, "             [--debuglvl <bitmask>] [-Z <compression>] [--root <cvsroot>]");
    debug(DEBUG_APPERROR, "             [-T] [-V] [<repository>]");
    debug(DEBUG_APPERROR, "");
    debug(DEBUG_APPERROR, "Where:");
    debug(DEBUG_APPERROR, "  -h display this informative message");
    debug(DEBUG_APPERROR, "  -z <fuzz> set the timestamp fuzz factor for identifying patch sets");
    debug(DEBUG_APPERROR, "  -g generate diffs of the selected patch sets");
    debug(DEBUG_APPERROR, "  -s <patch set>[-[<patch set>]][,<patch set>...] restrict patch sets by id");
    debug(DEBUG_APPERROR, "  -a <author> restrict output to patch sets created by author");
    debug(DEBUG_APPERROR, "  -f <file> restrict output to patch sets involving file");
    debug(DEBUG_APPERROR, "  -d <date1> -d <date2> if just one date specified, show");
    debug(DEBUG_APPERROR, "     revisions newer than date1.  If two dates specified,");
    debug(DEBUG_APPERROR, "     show revisions between two dates.");
    debug(DEBUG_APPERROR, "  -b <branch> restrict output to patch sets affecting history of branch");
    debug(DEBUG_APPERROR, "  -l <regex> restrict output to patch sets matching <regex> in log message");
    debug(DEBUG_APPERROR, "  -n negate filter sense, print all patchsetss *not* matching.");
    debug(DEBUG_APPERROR, "  -r <tag1> -r <tag2> if just one tag specified, show");
    debug(DEBUG_APPERROR, "     revisions since tag1. If two tags specified, show");
    debug(DEBUG_APPERROR, "     revisions between the two tags.");
    debug(DEBUG_APPERROR, "  -p <directory> output patch sets to individual files in <directory>");
    debug(DEBUG_APPERROR, "  -v show very verbose parsing messages");
    debug(DEBUG_APPERROR, "  -t show some brief memory usage statistics");
    debug(DEBUG_APPERROR, "  --summary-first when multiple patch sets are shown, put all summaries first");
    debug(DEBUG_APPERROR, "  --test-log <captured cvs log> supply a captured cvs log for testing");
    debug(DEBUG_APPERROR, "  --diff-opts <option string> supply special set of options to diff");
    debug(DEBUG_APPERROR, "  --debuglvl <bitmask> enable various debug channels.");
    debug(DEBUG_APPERROR, "  -Z <compression> A value 1-9 which specifies amount of compression");
    debug(DEBUG_APPERROR, "  --root <cvsroot> specify cvsroot.  overrides env. and working directory");
    debug(DEBUG_APPERROR, "  -T <date> set base date for regression testing");
    debug(DEBUG_APPERROR, "  --fast-export emit a git-style fast-import stream");
    debug(DEBUG_APPERROR, "  -V emit version and exit");
    debug(DEBUG_APPERROR, "  <repository> apply cvsps to repository. Overrides working directory");
    debug(DEBUG_APPERROR, "\ncvsps version %s\n", VERSION);

    return -1;
}

static int parse_args(int argc, char *argv[])
{
    int i = 1;
    while (i < argc)
    {
	if (strcmp(argv[i], "-z") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -z missing", "");

	    timestamp_fuzz_factor = atoi(argv[i++]);
	    continue;
	}
	
	if (strcmp(argv[i], "-g") == 0)
	{
	    do_diff = true;
	    i++;
	    continue;
	}
	
	/* leave this in place so git-cvsimport will cause graceful death */
	if (strcmp(argv[i], "-u") == 0)
	{
	    fprintf(stderr, "cvsps: -u is no longer supported.\n");
	    fprintf(stderr, "cvsps: your calling program needs to be upgraded to work with cvsps 3.x.\n");
	    exit(1);
	}

	if (strcmp(argv[i], "-s") == 0)
	{
	    PatchSetRange * range;
	    char * min_str, * max_str;

	    if (++i >= argc)
		return usage("argument to -s missing", "");

	    min_str = strtok(argv[i++], ",");
	    do
	    {
		range = create_patch_set_range();

		max_str = strrchr(min_str, '-');
		if (max_str)
		    *max_str++ = '\0';
		else
		    max_str = min_str;

		range->min_counter = atoi(min_str);

		if (*max_str)
		    range->max_counter = atoi(max_str);
		else
		    range->max_counter = INT_MAX;

		list_add(&range->link, show_patch_set_ranges.prev);
	    }
	    while ((min_str = strtok(NULL, ",")));

	    continue;
	}
	
	if (strcmp(argv[i], "-a") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -a missing", "");

	    restrict_author = argv[i++];
	    continue;
	}

	if (strcmp(argv[i], "-A") == 0)
	{
	    FILE *fp;
	    char authorline[BUFSIZ];
	    if (++i >= argc)
		return usage("argument to -A missing", "");

	    fp = fopen(argv[i++], "r");
	    if (fp == NULL) {
		fprintf(stderr, "cvsps: couldn't open specified author map.\n");
		exit(1);
	    }
	    while (fgets(authorline, sizeof(authorline), fp) != NULL)
	    {
		char *shortname, *longname, *timezone, *eq, *cp;
		MapEntry *mapentry;

		if ((eq = strchr(authorline, '=')) == NULL)
		    continue;
		shortname = authorline;
		while (isspace(*shortname))
		    ++shortname;
		if (*shortname == '#')
		    continue;
		for (cp = eq; cp >= shortname; --cp)
		    if (*cp == '=')
			continue;
		    else if (isspace(*cp))
			*cp = '\0';
		for (longname = eq + 1; isspace(*longname); ++longname)
		    continue;
		timezone = strchr(longname, '>');
		if (timezone == NULL)
		    continue;
		for (++timezone; isspace(*timezone); timezone++)
		    *timezone = '\0';
		for (cp = timezone + strlen(timezone) - 1; isspace(*cp); --cp)
		    *cp = '\0';

		mapentry = (MapEntry*)malloc(sizeof(*mapentry));
		mapentry->shortname = strdup(shortname);
		mapentry->longname = strdup(longname);
		mapentry->timezone = strdup(timezone);
		list_add(&mapentry->link, &authormap);
	    }

	    fclose(fp);
	    
	    continue;
	}

	if (strcmp(argv[i], "-R") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -R missing", "");

	    revfp = fopen(argv[i++], "w");
	    continue;
	}

	if (strcmp(argv[i], "-l") == 0)
	{
	    int err;

	    if (++i >= argc)
		return usage("argument to -l missing", "");

	    if ((err = regcomp(&restrict_log, argv[i++], REG_EXTENDED|REG_NOSUB)) != 0)
	    {
		char errbuf[256];
		regerror(err, &restrict_log, errbuf, 256);
		return usage("bad regex to -l", errbuf);
	    }

	    have_restrict_log = true;

	    continue;
	}

	if (strcmp(argv[i], "-f") == 0)
	{
	    int err;

	    if (++i >= argc)
		return usage("argument to -f missing", "");

	    if ((err = regcomp(&restrict_file, argv[i++], REG_EXTENDED|REG_NOSUB)) != 0)
	    {
		char errbuf[256];
		regerror(err, &restrict_file, errbuf, 256);
		return usage("bad regex to -f", errbuf);
	    }

	    have_restrict_file = true;

	    continue;
	}
	
	if (strcmp(argv[i], "-n") == 0)
	{
	    selection_sense = false;
	    i++;
	    continue;
	}
	
	if (strcmp(argv[i], "-d") == 0)
	{
	    time_t *pt;

	    if (++i >= argc)
		return usage("argument to -d missing", "");

	    pt = (restrict_date_start == 0) ? &restrict_date_start : &restrict_date_end;
	    convert_date(pt, argv[i++]);
	    continue;
	}

	if (strcmp(argv[i], "-T") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -T missing", "");

	    convert_date(&regression_time, argv[i++]);
	    continue;
	}

	if (strcmp(argv[i], "-r") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -r missing", "");

	    if (restrict_tag_start)
		restrict_tag_end = argv[i];
	    else
		restrict_tag_start = argv[i];

	    i++;
	    continue;
	}

	if (strcmp(argv[i], "-b") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -b missing", "");

	    restrict_branch = argv[i++];
	    /* Warn if the user tries to use TRUNK. Should eventually
	     * go away as TRUNK may be a valid branch within CVS
	     */
	    if (strcmp(restrict_branch, "TRUNK") == 0)
		debug(DEBUG_APPWARN, "WARNING: The HEAD branch of CVS is called HEAD, not TRUNK");
	    continue;
	}

	if (strcmp(argv[i], "-p") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -p missing", "");
	    
	    patch_set_dir = argv[i++];
	    continue;
	}

	if (strcmp(argv[i], "-v") == 0)
	{
	    debuglvl = ~0;
	    i++;
	    continue;
	}
	
	if (strcmp(argv[i], "-t") == 0)
	{
	    statistics = true;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "--summary-first") == 0)
	{
	    summary_first = 1;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "-h") == 0)
	    return usage(NULL, NULL);

	if (strcmp(argv[i], "--test-log") == 0)
	{
	    if (++i >= argc)
		return usage("argument to --test-log missing", "");

	    test_log_file = argv[i++];
	    continue;
	}

	if (strcmp(argv[i], "--diff-opts") == 0)
	{
	    if (++i >= argc)
		return usage("argument to --diff-opts missing", "");

	    /* allow diff_opts to be turned off by making empty string
	     * into NULL
	     */
	    if (!strlen(argv[i]))
		diff_opts = NULL;
	    else
		diff_opts = argv[i];
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "--debuglvl") == 0)
	{
	    if (++i >= argc)
		return usage("argument to --debuglvl missing", "");

	    debuglvl = atoi(argv[i++]);
	    continue;
	}

	if (strcmp(argv[i], "-Z") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -Z", "");

	    compress = atoi(argv[i++]);

	    if (compress < 0 || compress > 9)
		return usage("-Z level must be between 1 and 9 inclusive (0 disables compression)", argv[i-1]);

	    if (compress == 0)
		compress_arg[0] = 0;
	    else
		snprintf(compress_arg, 8, "-z%d", compress);
	    continue;
	}
	
	if (strcmp(argv[i], "--root") == 0)
	{
	    if (++i >= argc)
		return usage("argument to --root missing", "");

	    strcpy(root_path, argv[i++]);
	    continue;
	}

	if (strcmp(argv[i], "--fast-export") == 0)
	{
	    fast_export = true;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "-V") == 0)
	{
	    printf("cvsps: version " VERSION "\n");
	    exit(0);
	}

	if (argv[i][0] == '-')
	    return usage("invalid argument", argv[i]);
	
	strcpy(repository_path, argv[i++]);
    }

    if (fast_export && test_log_file)
    {
	fprintf(stderr, "cvsps: --fast-export and --test-log are not compatible.\n");
	exit(1);
    }

    if (do_diff && test_log_file)
    {
	fprintf(stderr, "cvsps: -g and --test-log are not compatible.\n");
	exit(1);
    }

    return 0;
}

static int parse_rc()
{
    char rcfile[PATH_MAX];
    FILE * fp;
    /* coverity[tainted_data] */
    snprintf(rcfile, PATH_MAX, "%s/cvspsrc", get_cvsps_dir());
    if ((fp = fopen(rcfile, "r")))
    {
	char buff[BUFSIZ];
	while (fgets(buff, BUFSIZ, fp))
	{
	    char * argv[3], *p;
	    int argc = 2;

	    chop(buff);

	    argv[0] = "garbage";

	    p = strchr(buff, ' ');
	    if (p)
	    {
		*p++ = '\0';
		argv[2] = xstrdup(p);
		argc = 3;
	    }

	    argv[1] = xstrdup(buff);

	    if (parse_args(argc, argv) < 0)
		return -1;
	}
	fclose(fp);
    }

    return 0;
}

static void init_paths()
{
    FILE * fp;
    char * p;
    int len;

    /* Determine the CVSROOT. Precedence:
     * 1) command line
     * 2) checkout directory
     * 3) top level of repository
     * 4) module directory just beneath a repository root.
     * 5) environment variable CVSROOT
     */
    if (!root_path[0])
    {
	/* Are we in a working directory? */
	if ((fp = fopen("CVS/Root", "r")) != NULL)
	{
	    if (fgets(root_path, PATH_MAX, fp) == NULL)
	    {
		debug(DEBUG_APPERROR, "Error reading CVSROOT");
		exit(1);
	    }
	    
	    fclose(fp);
	    
	    /* chop the lf and optional trailing '/' */
	    len = strlen(root_path) - 1;
	    root_path[len] = 0;
	    if (root_path[len - 1] == '/')
		root_path[--len] = 0;
	}
	else
	{
	    struct stat st;

	    debug(DEBUG_STATUS, "Can't open CVS/Root");

	    /* 
	     * We're not in a working directory; are we in a repository root?
	     * If so, monkey up a local path to access it.
	     */
	    if (stat("CVSROOT", &st) == 0 && S_ISDIR(st.st_mode)) {
		strcpy(root_path, ":local:");
		if (getcwd(root_path + strlen(root_path),
			   sizeof(root_path) - strlen(root_path) - 1) == NULL)
		{
		    debug(DEBUG_APPERROR, "cannot get working directory");
		    exit(1);
		}
	    }
	    /*
	     * We might be in a module directory just below a repository root.
	     * The right thing to do in this case is also clear.
	     */
	    else if (stat("../CVSROOT", &st) == 0 && S_ISDIR(st.st_mode)) {
		char *sl;
		strcpy(root_path, ":local:");
		if (getcwd(root_path + strlen(root_path),
			   sizeof(root_path) - strlen(root_path) - 1) == NULL)
		{
		    debug(DEBUG_APPERROR, "cannot get working directory");
		    exit(1);
		}
		sl = strrchr(root_path, '/');
		*sl++ = '\0';
		if (repository_path[0])
		{
		    memmove(repository_path + strlen(sl) + 1, 
			    repository_path,
			    strlen(repository_path) + 1); 
		    repository_path[strlen(sl)] = '/';
		}
		strcpy(repository_path, sl);
	    }
	    else 
	    {
		const char * e = getenv("CVSROOT");

		if (e)
		    strcpy(root_path, e);
		else
		{
		    debug(DEBUG_APPERROR, "cannot determine CVSROOT");
		    exit(1);
		}
	    }
	}
    }

    /* Determine the repository path, precedence:
     * 1) command line
     * 2) working directory
     * Note that one of the root-directory cases above prepends to this path.
     */
      
    if (!repository_path[0])
    {
	if ((fp = fopen("CVS/Repository", "r")) == NULL)
	{
	    debug(DEBUG_SYSERROR, "Can't open CVS/Repository");
	    exit(1);
	}
	
	if (fgets(repository_path, PATH_MAX, fp) == NULL)
	{
	    debug(DEBUG_APPERROR, "Error reading repository path");
	    exit(1);
	}
	
	chop(repository_path);
	fclose(fp);
    }

    /* get the path portion of the root */
    p = strrchr(root_path, ':');

    if (!p)
	p = root_path;
    else 
	p++;

    /* some CVS have the CVSROOT string as part of the repository
     * string (initial substring).  remove it.
     */
    len = strlen(p);

    if (strncmp(p, repository_path, len) == 0)
    {
	int rlen = strlen(repository_path + len + 1);
	memmove(repository_path, repository_path + len + 1, rlen + 1);
    }

    /* the 'strip_path' will be used whenever the CVS server gives us a
     * path to an 'rcs file'.  the strip_path portion of these paths is
     * stripped off, leaving us with the working file.
     *
     * NOTE: because of some bizarre 'feature' in cvs, when 'rlog' is
     * used (instead of log) it gives the 'real' RCS file path, which
     * can be different from the 'nominal' repository path because of
     * symlinks in the server and the like.  See also the
     * 'parse_rcs_file' routine
     *
     * When you've checked out the root, rather than a specific
     * module, repository_path is . but we should use only p without
     * anything added for path stripping.
     */
    if (!strcmp(repository_path,".")) {
	strip_path_len = snprintf(strip_path, PATH_MAX, "%s/", p);
    } else {
	strip_path_len = snprintf(strip_path, PATH_MAX, "%s/%s/", p, repository_path);
    }


    if (strip_path_len < 0 || strip_path_len >= PATH_MAX)
    {
	debug(DEBUG_APPERROR, "strip_path overflow");
	exit(1);
    }

    if (strip_path_len > 3 && !strcmp(strip_path + strip_path_len - 3, "/./"))
    {
	debug(DEBUG_STATUS, "pruning /./ off end of strip_path");
	strip_path_len -= 2;
	strip_path[strip_path_len] = '\0';
    }

    debug(DEBUG_STATUS, "strip_path: %s", strip_path);
}

static CvsFile * parse_rcs_file(const char * buff)
{
    char fn[PATH_MAX];
    size_t len = strlen(buff + 10);
    char * p;

    /* once a single file has been parsed ok we set this */
    static bool path_ok;

    /* chop the ",v" string and the "LF" */
    len -= 3;
    memcpy(fn, buff + 10, len);
    fn[len] = 0;
    if (strncmp(fn, strip_path, strip_path_len) != 0)
    {
	/* if the very first file fails the strip path,
	 * then maybe we need to try for an alternate.
	 * this will happen if symlinks are being used
	 * on the server.  our best guess is to look
	 * for the final occurance of the repository
	 * path in the filename and use that.  it should work
	 * except in the case where:
	 * 1) the project has no files in the top-level directory
	 * 2) the project has a directory with the same name as the project
	 * 3) that directory sorts alphabetically before any other directory
	 * in which case, you are scr**ed
	 */
	if (!path_ok)
	{
	    char * p = fn, *lastp = NULL;

	    while ((p = strstr(p, repository_path)))
		lastp = p++;

	    if (lastp)
	    {
		size_t len = strlen(repository_path);
		memcpy(strip_path, fn, lastp - fn + len + 1);
		strip_path_len = lastp - fn + len + 1;
		strip_path[strip_path_len] = 0;
		debug(DEBUG_APPWARN, "NOTICE: used alternate strip path %s", strip_path);
		goto ok;
	    }
	}


	/* Windows CVS server may use two path separators: / for files
	 * and \ for subdirectories. */
	if (strncmp(fn, strip_path, strip_path_len-1) == 0 &&
	    (fn[strip_path_len-1] == '\\' ||
	     fn[strip_path_len-1] == '/')) {
		goto ok;
	}

	/* FIXME: a subdirectory may have a different Repository path
	 * than its parent.  we'll fail the above test since strip_path
	 * is global for the entire checked out tree (recursively).
	 *
	 * For now just ignore such files
	 */
	debug(DEBUG_APPWARN, "WARNING: file %s doesn't match strip_path %s. ignoring",
	      fn, strip_path);
	return NULL;
    }

 ok:
    if(len <= strip_path_len)
    {
        debug(DEBUG_APPWARN, "WARNING: file %s doesn't match strip_path %s. ignoring",
	      fn, strip_path);
        return NULL;
    }
    /* remove from beginning the 'strip_path' string */
    len -= strip_path_len;
    path_ok = true;

    memmove(fn, fn + strip_path_len, len);
    fn[len] = 0;

    /* check if file is in the 'Attic/' and remove it */
    if ((p = strrchr(fn, '/')) &&
	p - fn >= 5 && strncmp(p - 5, "Attic", 5) == 0)
    {
	memmove(p - 5, p + 1, len - (p - fn + 1));
	len -= 6;
	fn[len] = 0;
    }

    debug(DEBUG_STATUS, "stripped filename %s", fn);

    return build_file_by_name(fn);
}

static CvsFile * parse_working_file(const char * buff)
{
    char fn[PATH_MAX];
    int len = strlen(buff + 14);

    /* chop the "LF" */
    len -= 1;
    memcpy(fn, buff + 14, len);
    fn[len] = 0;

    debug(DEBUG_STATUS, "working filename %s", fn);

    return build_file_by_name(fn);
}

static CvsFile * build_file_by_name(const char * fn)
{
    CvsFile * retval;

    retval = (CvsFile*)get_hash_object(file_hash, fn);

    if (!retval)
    {
	if ((retval = create_cvsfile()))
	{
	    retval->filename = xstrdup(fn);
	    put_hash_object_ex(file_hash, retval->filename, retval, HT_NO_KEYCOPY, NULL, NULL);
	}
	else
	{
	    debug(DEBUG_SYSERROR, "malloc failed");
	    exit(1);
	}

	debug(DEBUG_STATUS, "new file: %s", retval->filename);
    }
    else
    {
	debug(DEBUG_STATUS, "existing file: %s", retval->filename);
    }

    return retval;
}

PatchSet * get_patch_set(const char * dte, const char * log, const char * author, const char * branch, const char *commitid, PatchSetMember * psm)
{
    PatchSet * retval = NULL, **find = NULL;

    if (!(retval = create_patch_set()))
    {
	debug(DEBUG_SYSERROR, "malloc failed for PatchSet");
	return NULL;
    }

    convert_date(&retval->date, dte);
    retval->author = get_string(author);
    retval->commitid = get_string(commitid);
    retval->descr = xstrdup(log);
    retval->branch = get_string(branch);
    
    /* we are looking for a patchset suitable for holding this member.
     * this means two things:
     * 1) a patchset already containing an entry for the file is no good
     * 2) for two patchsets with same exact date/time, if they reference 
     *    the same file, we can properly order them.  this primarily solves
     *    the 'cvs import' problem and may not have general usefulness
     *    because it would only work if the first member we consider is
     *    present in the existing ps.
     */
    if (psm)
	list_add(&psm->link, retval->members.prev);

    find = (PatchSet**)tsearch(retval, &ps_tree, compare_patch_sets);

    if (psm)
	list_del(&psm->link);

    if (*find != retval)
    {
	debug(DEBUG_STATUS, "found existing patch set");

	free(retval->descr);

	/* keep the minimum date of any member as the 'actual' date */
	if (retval->date < (*find)->date)
	    (*find)->date = retval->date;

	/* expand the min_date/max_date window to help finding other members .
	 * open the window by an extra margin determined by the fuzz factor 
	 */
	if (retval->date - timestamp_fuzz_factor < (*find)->min_date)
	{
	    (*find)->min_date = retval->date - timestamp_fuzz_factor;
	    //debug(DEBUG_APPWARN, "WARNING: non-increasing dates in encountered patchset members");
	}
	else if (retval->date + timestamp_fuzz_factor > (*find)->max_date)
	    (*find)->max_date = retval->date + timestamp_fuzz_factor;

	free(retval);
	retval = *find;
    }
    else
    {
	debug(DEBUG_STATUS, "new patch set!");
	debug(DEBUG_STATUS, "%s %s %s %s", retval->author, retval->descr, retval->commitid, dte);

	retval->min_date = retval->date - timestamp_fuzz_factor;
	retval->max_date = retval->date + timestamp_fuzz_factor;

	list_add(&retval->all_link, &all_patch_sets);
    }


    return retval;
}

static bool get_branch_ext(char * buff, const char * rev, int * leaf)
{
    char * p;
    int len = strlen(rev);

    /* allow get_branch(buff, buff) without destroying contents */
    memmove(buff, rev, len);
    buff[len] = 0;

    p = strrchr(buff, '.');
    if (!p)
	return false;
    *p++ = 0;

    if (leaf)
	*leaf = atoi(p);

    return true;
}

static int get_branch(char * buff, const char * rev)
/* return true if rev is a non-trunk branch */
{
    return get_branch_ext(buff, rev, NULL);
}

/* 
 * the goal if this function is to determine what revision to assign to
 * the psm->pre_rev field.  usually, the log file is strictly 
 * reverse chronological, so rev is direct ancestor to psm, 
 * 
 * This all breaks down at branch points however
 */

static void assign_pre_revision(PatchSetMember * psm, CvsFileRevision * rev)
{
    char pre[REV_STR_MAX], post[REV_STR_MAX];

    if (!psm)
	return;
    
    if (!rev)
    {
	/* if psm was last rev. for file, it's either an 
	 * INITIAL, or first rev of a branch.  to test if it's 
	 * the first rev of a branch, do get_branch twice - 
	 * this should be the bp.
	 */
	if (get_branch(post, psm->post_rev->rev) && 
	    get_branch(pre, post))
	{
	    psm->pre_rev = file_get_revision(psm->file, pre);
	    list_add(&psm->post_rev->link, &psm->pre_rev->branch_children);
	}
	else
	{
	    set_psm_initial(psm);
	}
	return;
    }

    /* 
     * is this canditate for 'pre' on the same branch as our 'post'? 
     * this is the normal case
     */
    if (!get_branch(pre, rev->rev))
    {
	debug(DEBUG_APPERROR, "get_branch malformed input (1)");
	return;
    }

    if (!get_branch(post, psm->post_rev->rev))
    {
	debug(DEBUG_APPERROR, "get_branch malformed input (2)");
	return;
    }

    if (strcmp(pre, post) == 0)
    {
	psm->pre_rev = rev;
	rev->pre_psm = psm;
	return;
    }
    
    /* branches don't match. new_psm must be head of branch,
     * so psm is oldest rev. on branch. or oldest
     * revision overall.  if former, derive predecessor.  
     * use get_branch to chop another rev. off of string.
     *
     * FIXME:
     * There's also a weird case.  it's possible to just re-number
     * a revision to any future revision. i.e. rev 1.9 becomes 2.0
     * It's not widely used.  In those cases of discontinuity,
     * we end up stamping the predecessor as 'INITIAL' incorrectly
     *
     */
    if (!get_branch(pre, post))
    {
	set_psm_initial(psm);
	return;
    }
    
    psm->pre_rev = file_get_revision(psm->file, pre);
    list_add(&psm->post_rev->link, &psm->pre_rev->branch_children);
}

static bool visible(PatchSet * ps)
/* should we display this patch set? */
{
    /* the funk_factor overrides the restrict_tag_start and end */
    if (ps->funk_factor == FNK_SHOW_SOME || ps->funk_factor == FNK_SHOW_ALL)
	goto ok;

    if (ps->funk_factor == FNK_HIDE_ALL)
	return false;

    if (ps->psid <= restrict_tag_ps_start)
    {
	if (ps->psid == restrict_tag_ps_start)
	    debug(DEBUG_STATUS, "PatchSet %d matches tag %s.", ps->psid, restrict_tag_start);
	
	return false;
    }
    
    if (ps->psid > restrict_tag_ps_end)
	return false;

 ok:
    if (restrict_date_start > 0 &&
	(ps->date < restrict_date_start ||
	 (restrict_date_end > 0 && ps->date > restrict_date_end)))
	return false;

    if (restrict_author && strcmp(restrict_author, ps->author) != 0)
	return false;

    if (have_restrict_log && regexec(&restrict_log, ps->descr, 0, NULL, 0) != 0)
	return false;

    if (have_restrict_file && !patch_set_member_regex(ps, &restrict_file))
	return false;

    if (restrict_branch && !patch_set_affects_branch(ps, restrict_branch))
	return false;
    
    if (!list_empty(&show_patch_set_ranges))
    {
	struct list_head * next = show_patch_set_ranges.next;
	
	while (next != &show_patch_set_ranges)
	{
	    PatchSetRange *range = list_entry(next, PatchSetRange, link);
	    if (range->min_counter <= ps->psid &&
		ps->psid <= range->max_counter)
	    {
		break;
	    }
	    next = next->next;
	}
	
	if (next == &show_patch_set_ranges)
	    return false;
    }

    return true;
}

static void check_print_patch_set(PatchSet * ps)
{
    if (ps->psid < 0)
	return;

    if (visible(ps) != selection_sense)
	return;

    if (patch_set_dir)
    {
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%d.patch", patch_set_dir, ps->psid);

	fflush(stdout);
	close(1);
	if (open(path, O_WRONLY|O_TRUNC|O_CREAT, 0666) < 0)
	{
	    debug(DEBUG_SYSERROR, "can't open patch file %s", path);
	    exit(1);
	}

	fprintf(stderr, "Directing PatchSet %d to file %s\n", ps->psid, path);
    }

    /*
     * If the summary_first option is in effect, there will be 
     * two passes through the tree.  the first with summary_first == 1
     * the second with summary_first == 2.  if the option is not
     * in effect, there will be one pass with summary_first == 0
     *
     * When the -s option is in effect, the show_patch_set_ranges
     * list will be non-empty.
     *
     * In fast-export mode, the do_diff and summary_first options 
     * are ignored.
     */
    if (fast_export)
	print_fast_export(ps);
    else if (summary_first <= 1)
	print_patch_set(ps);
    if (do_diff && summary_first != 1)
	do_cvs_diff(ps);

    fflush(stdout);
}

static void print_patch_set(PatchSet * ps)
{
    struct tm *tm;
    struct list_head * next, * tagl;
    const char * funk = "";

    tm = localtime(&ps->date);
    
    funk = fnk_descr[ps->funk_factor];

    /* this '---...' is different from the 28 hyphens that separate cvs log output */
    printf("---------------------\n");
    printf("PatchSet %d %s\n", ps->psid, funk);
    printf("Date: %d/%02d/%02d %02d:%02d:%02d\n", 
	   1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday, 
	   tm->tm_hour, tm->tm_min, tm->tm_sec);
    printf("Author: %s\n", ps->author);
    printf("Branch: %s\n", ps->branch);
    if (ps->ancestor_branch)
	printf("Ancestor branch: %s\n", ps->ancestor_branch);
    printf("Tags:");
    for (tagl = ps->tags.next; tagl != &ps->tags; tagl = tagl->next)
    {
	TagName* tag = list_entry (tagl, TagName, link);

	printf(" %s %s%s", tag->name, tag_flag_descr[tag->flags],
	       (tagl->next == &ps->tags) ? "" : ",");
    }
    printf("\n");
    printf("Branches: ");
    for (next = ps->branches.next; next != &ps->branches; next = next->next) {
	Branch * branch = list_entry(next, Branch, link);
	if (next != ps->branches.next)
	    printf(",");
	printf("%s", branch->name);
    }
    printf("\n");
    printf("Log:\n%s\n", ps->descr);
    printf("Members: \n");

    next = ps->members.next;
    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	if (ps->funk_factor == FNK_SHOW_SOME && psm->bad_funk)
	    funk = "(BEFORE START TAG)";
	else if (ps->funk_factor == FNK_HIDE_SOME && !psm->bad_funk)
	    funk = "(AFTER END TAG)";
	else
	    funk = "";

	printf("\t%s:%s->%s%s %s\n", 
	       psm->file->filename, 
	       psm->pre_rev ? psm->pre_rev->rev : "INITIAL", 
	       psm->post_rev->rev, 
	       psm->post_rev->dead ? "(DEAD)": "",
	       funk);

	next = next->next;
    }

    printf("\n");
}

#define SUFFIX(a, s)	(strcmp(a + strlen(a) - strlen(s), s) == 0) 

static char *fast_export_sanitize(char *name, char *sanitized, int sanlength)
{
    char *sp, *tp;

#define BADCHARS	"~^:\\*?[]"
    memset(tp = sanitized, '\0', sanlength);
    for (sp = name; *sp; sp++) {
	if (!isgraph(*sp) || strchr(BADCHARS, *sp) == NULL) {
	    *tp++ = *sp;
	    if (SUFFIX(sanitized,"@{")||SUFFIX(sanitized,"..")) {
		fprintf(stderr, 
			"Tag or branch name %s is ill-formed.\n", 
			name);
		exit(1);
	    }
	}
    }
    if (strlen(sanitized) == 0) {
	fprintf(stderr, 
		"Tag or branch name %s was empty after sanitization.\n", 
		name);
	exit(1);
    }

    return sanitized;
}

static void print_fast_export(PatchSet * ps)
{
    struct tm *tm;
    struct list_head * next, * tagl, * mapl;
    static int mark = 0;
    char *tf = tmpnam(NULL);	/* ugly necessity */
    struct stat st;
    int basemark = mark;
    int c;
    int ancestor_mark = 0;
    char sanitized_branch[strlen(ps->branch)+1];
    char *match, *tz;
 
    struct branch_head {
	char *name;
	int mark;
	struct branch_head *prev;
    };
    static struct branch_head *heads = NULL;
    struct branch_head *tip = NULL;

    for (tip = heads; tip; tip = tip->prev) 
	if (strcmp(tip->name, ps->branch) == 0) {
	    ancestor_mark = tip->mark;
	    break;
	}
    if (tip == NULL) {
	/* we're at a branch division */
	tip = malloc(sizeof(struct branch_head));
	tip->mark = 0;
	tip->name = ps->branch;
	tip->prev = heads;
	heads = tip;

	/* look for the branch join */
	for (next = all_patch_sets.next; next != &all_patch_sets; next = next->next) {
	    struct list_head * child_iter;

	    PatchSet * as = list_entry(next, PatchSet, all_link);

	    /* walk the branches looking for the join */
	    for (child_iter = as->branches.next; child_iter != &as->branches; child_iter = child_iter->next) {
		Branch * branch = list_entry(child_iter, Branch, link);
		if (strcmp(ps->branch, branch->name) == 0) {
		    ancestor_mark = as->mark;
		    break;
		}
	    }
	}
    }

    /* we need to be able to fake dates for regression testing */
    if (regression_time == 0)
	tm = localtime(&ps->date);
    else
    {
	time_t clock_tick = regression_time + ps->psid;
	tm = localtime(&clock_tick);
    }

    next = ps->members.next;
    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);

	if (!psm->post_rev->dead) 
	{
	    FILE *ofp = fopen(tf, "w");
	    FILE *cfp;

	    if (ofp == NULL)
	    {
		fprintf(stderr, "CVS direct retrieval of %s failed.\n",
			psm->file->filename);
		exit(1);
	    }

	    debug(DEBUG_APPMSG2, "retrieving %s for %s at :%d", 
		  psm->post_rev->rev,
		  psm->file->filename, 
		  mark+1);
	    cvs_rupdate(cvsclient_ctx,
			repository_path,
			psm->file->filename,
			psm->post_rev->rev, ofp);

	    /* coverity[toctou] */
	    if (stat(tf, &st) != 0)
	    {
		fprintf(stderr, "stat(2) of %s:%s copy failed.\n",
			psm->file->filename, psm->post_rev->rev);
		exit(1);
	    }

	    printf("blob\nmark :%d\ndata %zd\n", ++mark, st.st_size);
	    if ((cfp = fopen(tf, "r")) == NULL)
	    {
		fprintf(stderr, "blobfile open of  %s:%s failed.\n",
			psm->file->filename, psm->post_rev->rev);
		exit(1);
	    }
	    while ((c = fgetc(cfp)) != EOF)
		putchar(c);
	    (void)fclose(cfp);
	    putchar('\n');

	    if (revfp)
		fprintf(revfp, "%s %s :%d\n",
			psm->file->filename,
			psm->post_rev->rev,
			mark);
	}

	next = next->next;
    }

    match = NULL;
    tz = "+0000";
    for (mapl = authormap.next; mapl != &authormap; mapl = mapl->next)
    {
	MapEntry* mapentry = list_entry (mapl, MapEntry, link);
	if (strcmp(mapentry->shortname, ps->author) == 0)
	{
	    match = mapentry->longname;
	    if (mapentry->timezone[0])
		tz = mapentry->timezone;
	}
    }

    /* map HEAD branch to master, leave others unchanged */
    printf("commit refs/heads/%s\n", 
	   strcmp("HEAD", ps->branch) ? fast_export_sanitize(ps->branch, sanitized_branch, sizeof(sanitized_branch)) : "master");
    printf("mark :%d\n", ++mark);
    if (match != NULL)
	printf("committer %s", match);
    else
	printf("committer %s <%s>", ps->author, ps->author);
    printf(" %zd %s\n", mktime(tm) - tm->tm_gmtoff, tz);
    printf("data %zd\n%s\n", strlen(ps->descr), ps->descr); 
    if (ancestor_mark)
	printf("from :%d\n", ancestor_mark);
    ps->mark = tip->mark = mark;

    next = ps->members.next;
    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);

	/* 
	 * .cvsignore files have a gloobing syntax that is upward-compatible
	 * with git's, 
	 */
	if (SUFFIX(psm->file->filename, ".cvsignore")) {
	    char *end = psm->file->filename + strlen(psm->file->filename);
	    end[-9] = 'g';
	    end[-8] = 'i';
	    end[-7] = 't';
	}

	if (psm->post_rev->dead)
	    printf("D 100644 %s\n", psm->file->filename);
	else if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
	    printf("M 100755 :%d %s\n", ++basemark, psm->file->filename);
	else
	    printf("M 100644 :%d %s\n", ++basemark, psm->file->filename);

	next = next->next;
    }
    printf("\n");

    for (tagl = ps->tags.next; tagl != &ps->tags; tagl = tagl->next)
    {
	TagName* tag = list_entry (tagl, TagName, link);
	char sanitized_tag[strlen(tag->name) + 1];

	/* might be this patchset has tags pointing to it */
	printf("reset refs/tags/%s\nfrom :%d\n\n", 
	       fast_export_sanitize(tag->name, sanitized_tag, sizeof(sanitized_tag)), ps->mark);
    }

    unlink(tf);
}

/* walk all the patchsets to assign monotonic psid, 
 * and to establish  branch ancestry
 */
static void assign_patchset_id(PatchSet * ps)
{
    /*
     * Ignore the 'BRANCH ADD' patchsets 
     */
    if (!ps->branch_add)
    {
	ps_counter++;
	ps->psid = ps_counter;

	find_branch_points(ps);
    }
    else
    {
	ps->psid = -1;
    }
}

static int compare_rev_strings(const char * cr1, const char * cr2)
{
    char r1[REV_STR_MAX];
    char r2[REV_STR_MAX];
    char *s1 = r1, *s2 = r2;
    char *p1, *p2;
    int n1, n2;

    strcpy(s1, cr1);
    strcpy(s2, cr2);

    for (;;) 
    {
	p1 = strchr(s1, '.');
	p2 = strchr(s2, '.');

	if (p1) *p1++ = 0;
	if (p2) *p2++ = 0;
	
	n1 = atoi(s1);
	n2 = atoi(s2);
	
	if (n1 < n2)
	    return -1;
	if (n1 > n2)
	    return 1;

	if (!p1 && p2)
	    return -1;
	if (p1 && !p2)
	    return 1;
	if (!p1 && !p2)
	    return 0;

	s1 = p1;
	s2 = p2;
    }
}

static int compare_patch_sets_by_members(const PatchSet * ps1, const PatchSet * ps2)
{
    struct list_head * i;

    for (i = ps1->members.next; i != &ps1->members; i = i->next)
    {
	PatchSetMember * psm1 = list_entry(i, PatchSetMember, link);
	struct list_head * j;

	for (j = ps2->members.next; j != &ps2->members; j = j->next)
	{
	    PatchSetMember * psm2 = list_entry(j, PatchSetMember, link);
	    if (psm1->file == psm2->file) 
	    {
		int ret = compare_rev_strings(psm1->post_rev->rev, psm2->post_rev->rev);
		//debug(DEBUG_APPWARN, "file: %s comparing %s %s = %d", psm1->file->filename, psm1->post_rev->rev, psm2->post_rev->rev, ret);
		return ret;
	    }
	}
    }
    
    return 0;
}

static int compare_patch_sets(const void * v_ps1, const void * v_ps2)
{
    const PatchSet * ps1 = (const PatchSet *)v_ps1;
    const PatchSet * ps2 = (const PatchSet *)v_ps2;
    long diff;
    int ret;
    time_t d, min, max;

    /* We order by (author, descr, branch, commitid, members, date), but because
     * of the fuzz factor we treat times within a certain distance as
     * equal IFF the author and descr match.
     */

    ret = compare_patch_sets_by_members(ps1, ps2);
    if (ret)
	return ret;

    ret = strcmp(ps1->author, ps2->author);
    if (ret)
	    return ret;

    ret = strcmp(ps1->descr, ps2->descr);
    if (ret)
	    return ret;

    ret = strcmp(ps1->branch, ps2->branch);
    if (ret)
	return ret;

    ret = strcmp(ps1->commitid, ps2->commitid);
    if (ret)
	return ret;

    /* 
     * one of ps1 or ps2 is new.  the other should have the min_date
     * and max_date set to a window opened by the fuzz_factor
     */
    if (ps1->min_date == 0)
    {
	d = ps1->date;
	min = ps2->min_date;
	max = ps2->max_date;
    } 
    else if (ps2->min_date == 0)
    {
	d = ps2->date;
	min = ps1->min_date;
	max = ps1->max_date;
    }
    else
    {
	debug(DEBUG_APPERROR, "how can we have both patchsets pre-existing?");
	exit(1);
    }

    if (min < d && d < max)
	return 0;

    diff = ps1->date - ps2->date;

    return (diff < 0) ? -1 : 1;
}

static int compare_patch_sets_bytime_list(struct list_head * l1, struct list_head * l2)
{
    const PatchSet *ps1 = list_entry(l1, PatchSet, all_link);
    const PatchSet *ps2 = list_entry(l2, PatchSet, all_link);
    return compare_patch_sets_bytime(ps1, ps2);
}

static int compare_patch_sets_bytime(const PatchSet * ps1, const PatchSet * ps2)
{
    long diff;
    int ret;

    /* When doing a time-ordering of patchsets, we don't need to
     * fuzzy-match the time.  We've already done fuzzy-matching so we
     * know that insertions are unique at this point.
     */

    diff = ps1->date - ps2->date;
    if (diff)
	return (diff < 0) ? -1 : 1;

    ret = compare_patch_sets_by_members(ps1, ps2);
    if (ret)
	return ret;

    ret = strcmp(ps1->author, ps2->author);
    if (ret)
	return ret;

    ret = strcmp(ps1->descr, ps2->descr);
    if (ret)
	return ret;

    ret = strcmp(ps1->branch, ps2->branch);
    if (ret)
	return ret;

    ret = strcmp(ps1->commitid, ps2->commitid);
    return ret;
}


static bool is_revision_metadata(const char * buff)
{
    char * p1, *p2;
    int len;

    if (!(p1 = strchr(buff, ':')))
	return 0;

    p2 = strchr(buff, ' ');
    
    if (p2 && p2 < p1)
	return false;

    len = strlen(buff);

    /* lines have LF at end */
    if (len > 1 && buff[len - 2] == ';')
	return true;

    return false;
}

static bool patch_set_member_regex(PatchSet * ps, regex_t * reg)
{
    struct list_head * next = ps->members.next;

    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	
	if (regexec(&restrict_file, psm->file->filename, 0, NULL, 0) == 0)
	    return true;

	next = next->next;
    }

    return false;
}

static bool patch_set_affects_branch(PatchSet * ps, const char * branch)
{
    struct list_head * next;

    for (next = ps->members.next; next != &ps->members; next = next->next)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);

	/*
	 * slight hack. if -r is specified, and this patchset
	 * is 'before' the tag, but is FNK_SHOW_SOME, only
	 * check if the 'after tag' revisions affect
	 * the branch.  this is especially important when
	 * the tag is a branch point.
	 */
	if (ps->funk_factor == FNK_SHOW_SOME && psm->bad_funk)
	    continue;

	if (revision_affects_branch(psm->post_rev, branch))
	    return true;
    }

    return false;
}

static void do_cvs_diff(PatchSet * ps)
{
    struct list_head * next;
    const char * dopts;
    char use_rep_path[PATH_MAX];
    char esc_use_rep_path[PATH_MAX];

    fflush(stdout);
    fflush(stderr);

    if (diff_opts == NULL) 
    {
	dopts = "-u";
	sprintf(use_rep_path, "%s/", repository_path);
	/* the rep_path may contain characters that the shell will barf on */
	escape_filename(esc_use_rep_path, PATH_MAX, use_rep_path);
    }
    else
    {
	dopts = diff_opts;
	use_rep_path[0] = 0;
	esc_use_rep_path[0] = 0;
    }

    for (next = ps->members.next; next != &ps->members; next = next->next)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	char esc_file[PATH_MAX];

	/* the filename may contain characters that the shell will barf on */
	escape_filename(esc_file, PATH_MAX, psm->file->filename);

	/*
	 * Check the patchset funk. We may not want to diff this
	 * particular file
	 */
	if (ps->funk_factor == FNK_SHOW_SOME && psm->bad_funk)
	{
	    printf("Index: %s\n", psm->file->filename);
	    printf("===================================================================\n");
	    printf("*** Member not diffed, before start tag\n");
	    continue;
	}
	else if (ps->funk_factor == FNK_HIDE_SOME && !psm->bad_funk)
	{
	    printf("Index: %s\n", psm->file->filename);
	    printf("===================================================================\n");
	    printf("*** Member not diffed, after end tag\n");
	    continue;
	}

	/* 
	 * When creating diffs for INITIAL or DEAD revisions, we have
	 * to use 'cvs co' or 'cvs update' to get the file, because
	 * cvs won't generate these diffs.  The problem is that this
	 * must be piped to diff, and so the resulting diff doesn't
	 * contain the filename anywhere! (diff between - and
	 * /dev/null).  sed is used to replace the '-' with the
	 * filename.
	 *
	 * It's possible for pre_rev to be a 'dead' revision. This
	 * happens when a file is added on a branch. post_rev will be
	 * dead dead for remove
	 */
	if (!psm->pre_rev || psm->pre_rev->dead || psm->post_rev->dead)
	{
	    bool cr;
	    const char * rev;
	    char cmdbuff[BUFSIZ];
	    FILE *fp;

	    if (!psm->pre_rev || psm->pre_rev->dead)
	    {
		cr = true;
		rev = psm->post_rev->rev;
	    }
	    else
	    {
		cr = false;
		rev = psm->pre_rev->rev;
	    }

	    snprintf(cmdbuff, BUFSIZ, "diff %s %s /dev/null %s | sed -e '%s s|^\\([+-][+-][+-]\\) -|\\1 %s/%s|g'",
		     dopts, cr?"":"-", cr?"-":"", cr?"2":"1", repository_path, psm->file->filename);

	    /* debug(DEBUG_TCP, "cmdbuff: %s", cmdbuff); */

	    if (!(fp = popen(cmdbuff, "w")))
	    {
		debug(DEBUG_APPERROR, "cvsclient: popen for diff failed: %s", cmdbuff);
		exit(1);
	    }

	    cvs_rupdate(cvsclient_ctx, 
			repository_path, psm->file->filename, rev, fp);
	    pclose(fp);
	}
	else
	    cvs_diff(cvsclient_ctx, 
		     repository_path, 
		     psm->file->filename, 
		     psm->pre_rev->rev, 
		     psm->post_rev->rev,
		     dopts);

    }
}

static CvsFileRevision * parse_revision(CvsFile * file, char * rev_str)
{
    char * p;

    /* The "revision" log line can include extra information 
     * including who is locking the file --- strip that out.
     */
    
    p = rev_str;
    while (isdigit(*p) || *p == '.')
	    p++;
    *p = 0;

    return cvs_file_add_revision(file, rev_str);
}

CvsFileRevision * cvs_file_add_revision(CvsFile * file, const char * rev_str)
{
    CvsFileRevision * rev;

    if (!(rev = (CvsFileRevision*)get_hash_object(file->revisions, rev_str)))
    {
	rev = (CvsFileRevision*)calloc(1, sizeof(*rev));
	rev->rev = get_string(rev_str);
	rev->file = file;
	rev->branch = NULL;
	rev->present = false;
	rev->pre_psm = NULL;
	rev->post_psm = NULL;
	INIT_LIST_HEAD(&rev->branch_children);
	INIT_LIST_HEAD(&rev->tags);
	
	put_hash_object_ex(file->revisions, rev->rev, rev, HT_NO_KEYCOPY, NULL, NULL);

	debug(DEBUG_STATUS, "added revision %s to file %s", rev_str, file->filename);
    }
    else
    {
	debug(DEBUG_STATUS, "found revision %s to file %s", rev_str, file->filename);
    }

    /* 
     * note: we are guaranteed to get here at least once with
     * 'have_branches' == true.  we may pass through once before this,
     * because of symbolic tags, then once always when processing the
     * actual revision logs
     *
     * rev->branch will always be set to something, maybe "HEAD"
     */
    if (!rev->branch && file->have_branches)
    {
	char branch_str[REV_STR_MAX];

	/* in the cvs cvs repository (ccvs) there are tagged versions
	 * that don't exist.  let's mark every 'known to exist' 
	 * version
	 */
	rev->present = true;

	/* determine the branch this revision was committed on */
	if (!get_branch(branch_str, rev->rev))
	{
	    debug(DEBUG_APPERROR, "invalid rev format %s", rev->rev);
	    exit(1);
	}
	
	rev->branch = (char*)get_hash_object(file->branches, branch_str);
	
	/* if there's no branch and it's not on the trunk, blab */
	if (!rev->branch)
	{
	    if (get_branch(branch_str, branch_str))
	    {
		debug(DEBUG_APPMSG2, 
		      "revision %s of file %s on unnamed branch at %s", 
		      rev->rev, rev->file->filename, branch_str);
		rev->branch = "#CVSPS_NO_BRANCH";
		/* this is just to suppress a warning on re-import */
		cvs_file_add_branch(rev->file, rev->rev, rev->branch,
				    is_vendor_branch(rev->rev));
		/*
		 * This triggers a warning about a the broken case
		 * in the t9601 case. I haven't figured it out yet,
		 * but we can at least warn when it might happen.
		 */
		dubious_branches++;

	    }
	    else
	    {
		rev->branch = "HEAD";
	    }
	}

	debug(DEBUG_STATUS, "revision %s of file %s on branch %s", rev->rev, rev->file->filename, rev->branch);
    }

    return rev;
}

CvsFile * create_cvsfile()
{
    CvsFile * f = (CvsFile*)calloc(1, sizeof(*f));
    if (!f)
	return NULL;

    f->revisions = create_hash_table(53);
    f->branches = create_hash_table(13);
    f->branches_sym = create_hash_table(13);
    f->symbols = create_hash_table(253);
    f->have_branches = false;

    if (!f->revisions || !f->branches || !f->branches_sym)
    {
	if (f->branches)
	    destroy_hash_table(f->branches, NULL);
	if (f->revisions)
	    destroy_hash_table(f->revisions, NULL);
	free(f);
	return NULL;
    }
   
    return f;
}

static PatchSet * create_patch_set()
{
    PatchSet * ps = (PatchSet*)calloc(1, sizeof(*ps));;
    
    if (ps)
    {
	INIT_LIST_HEAD(&ps->members);
	INIT_LIST_HEAD(&ps->branches);
	INIT_LIST_HEAD(&ps->tags);
	ps->psid = -1;
	ps->date = 0;
	ps->min_date = 0;
	ps->max_date = 0;
	ps->descr = NULL;
	ps->author = NULL;
	ps->branch_add = false;
	ps->commitid = "";
	ps->funk_factor = 0;
	ps->ancestor_branch = NULL;
	CLEAR_LIST_NODE(&ps->collision_link);
    }

    return ps;
}

PatchSetMember * create_patch_set_member()
{
    PatchSetMember * psm = (PatchSetMember*)calloc(1, sizeof(*psm));
    psm->pre_rev = NULL;
    psm->post_rev = NULL;
    psm->ps = NULL;
    psm->file = NULL;
    psm->bad_funk = false;
    return psm;
}

static PatchSetRange * create_patch_set_range()
{
    PatchSetRange * psr = (PatchSetRange*)calloc(1, sizeof(*psr));
    return psr;
}

CvsFileRevision * file_get_revision(CvsFile * file, const char * r)
{
    CvsFileRevision * rev;

    if (strcmp(r, "INITIAL") == 0)
	return NULL;

    rev = (CvsFileRevision*)get_hash_object(file->revisions, r);
    
    if (!rev)
    {
	debug(DEBUG_APPERROR, "request for non-existent rev %s in file %s", r, file->filename);
	exit(1);
    }

    return rev;
}

/*
 * Parse lines in the format:
 * 
 * <white space>tag_name: <rev>;
 *
 * Handles both regular tags (these go into the symbols hash)
 * and magic-branch-tags (second to last node of revision is 0)
 * which go into branches and branches_sym hashes.  Magic-branch
 * format is hidden in CVS everwhere except the 'cvs log' output.
 */

static void parse_sym(CvsFile * file, char * sym)
{
    char * tag = sym, *eot;
    int leaf, final_branch = -1;
    char rev[REV_STR_MAX];
    char rev2[REV_STR_MAX];
    
    while (*tag && isspace(*tag))
	tag++;

    if (!*tag)
	return;

    eot = strchr(tag, ':');
    
    if (!eot)
	return;

    *eot = 0;
    eot += 2;
    
    if (!get_branch_ext(rev, eot, &leaf))
    {
	if (strcmp(tag, "TRUNK") == 0)
	{
	    debug(DEBUG_STATUS, "ignoring the TRUNK branch/tag");
	    return;
	}
	debug(DEBUG_APPERROR, "malformed revision");
	exit(1);
    }

    /* 
     * get_branch_ext will leave final_branch alone
     * if there aren't enough '.' in string 
     */
    get_branch_ext(rev2, rev, &final_branch);

    if (final_branch == 0)
    {
	snprintf(rev, REV_STR_MAX, "%s.%d", rev2, leaf);
	debug(DEBUG_STATUS, "got sym: %s for %s", tag, rev);
	
	cvs_file_add_branch(file, rev, tag, false);
    }
    else
    {
	strcpy(rev, eot);
	chop(rev);

	/* see cvs manual: what is this vendor tag? */
	if (is_vendor_branch(rev))
	    cvs_file_add_branch(file, rev, tag, true);
	else
	    cvs_file_add_symbol(file, rev, tag);
    }
}

void cvs_file_add_symbol(CvsFile * file, const char * rev_str, const char * p_tag_str)
{
    CvsFileRevision * rev;
    GlobalSymbol * sym;
    Tag * tag;

    /* get a permanent storage string */
    char * tag_str = get_string(p_tag_str);

    debug(DEBUG_STATUS, "adding symbol to file: %s %s->%s", file->filename, tag_str, rev_str);
    rev = cvs_file_add_revision(file, rev_str);
    put_hash_object_ex(file->symbols, tag_str, rev, HT_NO_KEYCOPY, NULL, NULL);
    
    /*
     * check the global_symbols
     */
    sym = (GlobalSymbol*)get_hash_object(global_symbols, tag_str);
    if (!sym)
    {
	sym = (GlobalSymbol*)malloc(sizeof(*sym));
	sym->tag = tag_str;
	sym->ps = NULL;
	INIT_LIST_HEAD(&sym->tags);

	put_hash_object_ex(global_symbols, sym->tag, sym, HT_NO_KEYCOPY, NULL, NULL);
    }

    tag = (Tag*)malloc(sizeof(*tag));
    tag->tag = tag_str;
    tag->rev = rev;
    tag->sym = sym;
    list_add(&tag->global_link, &sym->tags);
    list_add(&tag->rev_link, &rev->tags);
}

char * cvs_file_add_branch(CvsFile * file,
			   const char * rev, 
			   const char * tag,
			   bool vendor_branch)
{
    char * new_tag;
    char * new_rev;

    if (get_hash_object(file->branches, rev))
    {
	debug(DEBUG_STATUS, "attempt to add existing branch %s:%s to %s", 
	      rev, tag, file->filename);
	return NULL;
    }

    /* get permanent storage for the strings */
    new_tag = get_string(tag);
    new_rev = get_string(rev); 

    put_hash_object_ex(file->branches, new_rev, new_tag, HT_NO_KEYCOPY, NULL, NULL);
    put_hash_object_ex(file->branches_sym, new_tag, new_rev, HT_NO_KEYCOPY, NULL, NULL);
    
    if (get_hash_object(branches, tag) == NULL) {
	debug(DEBUG_STATUS, "adding new branch to branches hash: %s", tag);
	Branch * branch = create_branch(tag);
	branch->vendor_branch = vendor_branch;
	if (vendor_branch)
	    dubious_branches += 1;
	put_hash_object_ex(branches, new_tag, branch, HT_NO_KEYCOPY, NULL, NULL);
    }
    

    return new_tag;
}

/*
 * Resolve each global symbol to a PatchSet.  This is
 * not necessarily doable, because tagging isn't 
 * necessarily done to the project as a whole, and
 * it's possible that no tag is valid for all files 
 * at a single point in time.  We check for that
 * case though.
 *
 * Implementation: the most recent PatchSet containing
 * a revision (post_rev) tagged by the symbol is considered
 * the 'tagged' PatchSet.
 */

static void resolve_global_symbols()
{
    struct hash_entry * he_sym;

    reset_hash_iterator(global_symbols);
    while ((he_sym = next_hash_entry(global_symbols)))
    {
	GlobalSymbol * sym = (GlobalSymbol*)he_sym->he_obj;
	PatchSet * ps;
	TagName * tagname;
	struct list_head * next;

	debug(DEBUG_STATUS, "resolving global symbol %s", sym->tag);

	/*
	 * First pass, determine the most recent PatchSet with a 
	 * revision tagged with the symbolic tag.  This is 'the'
	 * patchset with the tag
	 */

	for (next = sym->tags.next; next != &sym->tags; next = next->next)
	{
	    Tag * tag = list_entry(next, Tag, global_link);
	    CvsFileRevision * rev = tag->rev;

	    /* FIXME:test for rev->post_psm from DEBIAN. not sure how
	     * this could happen */
	    if (!rev->present || !rev->post_psm)
	    {
		struct list_head *tmp = next->prev;
		debug(DEBUG_APPERROR, "revision %s of file %s is tagged but not present",
		      rev->rev, rev->file->filename);
		/* FIXME: memleak */
		list_del(next);
		next = tmp;
		continue;
	    }

	    ps = rev->post_psm->ps;

	    if (!sym->ps || ps->date > sym->ps->date)
		sym->ps = ps;
	}
	
	/* convenience variable */
	ps = sym->ps;

	if (!ps)
	{
	    debug(DEBUG_APPERROR, "no patchset for tag %s", sym->tag);
	    return;
	}

	tagname = (TagName*)malloc(sizeof(TagName));
	tagname->name = sym->tag;
	tagname->flags = 0;
	list_add(&tagname->link, &ps->tags);


	/* check if this ps is one of the '-r' patchsets */
	if (restrict_tag_start && strcmp(restrict_tag_start, sym->tag) == 0)
	    restrict_tag_ps_start = ps->psid;

	/* the second -r implies -b */
	if (restrict_tag_end && strcmp(restrict_tag_end, sym->tag) == 0)
	{
	    restrict_tag_ps_end = ps->psid;

	    if (restrict_branch)
	    {
		if (strcmp(ps->branch, restrict_branch) != 0)
		{
		    debug(DEBUG_APPWARN,
			  "WARNING: -b option and second -r have conflicting branches: %s %s", 
			  restrict_branch, ps->branch);
		}
	    }
	    else
	    {
		debug(DEBUG_APPWARN, "NOTICE: implicit branch restriction set to %s", ps->branch);
		restrict_branch = ps->branch;
	    }
	}

	/* 
	 * Second pass. 
	 * check if this is an invalid patchset, 
	 * check which members are invalid.  determine
	 * the funk factor etc.
	 */
	for (next = sym->tags.next; next != &sym->tags; next = next->next)
	{
	    Tag * tag = list_entry(next, Tag, global_link);
	    CvsFileRevision * rev = tag->rev;
	    CvsFileRevision * next_rev = rev_follow_branch(rev, ps->branch);
	    
	    if (!next_rev)
		continue;
		
	    /*
	     * we want the 'tagged revision' to be valid until after
	     * the date of the 'tagged patchset' or else there's something
	     * funky going on
	     */
	    if (next_rev->post_psm->ps->date < ps->date)
	    {
		int flag = check_rev_funk(ps, next_rev);
		debug(DEBUG_STATUS, "file %s revision %s tag %s: TAG VIOLATION %s",
		      rev->file->filename, rev->rev, sym->tag, tag_flag_descr[flag]);
		/* FIXME: using tags.next is somewhat kludgy */
		list_entry(ps->tags.next, TagName, link)->flags |= flag;
	    }
	}
    }
}

static bool revision_affects_branch(CvsFileRevision * rev, const char * branch)
{
    /* special case the branch called 'HEAD' */
    if (strcmp(branch, "HEAD") == 0)
    {
	/* look for only one '.' in rev */
	char * p = strchr(rev->rev, '.');
	if (p && !strchr(p + 1, '.'))
	    return true;
    }
    else
    {
	char * branch_rev = (char*)get_hash_object(rev->file->branches_sym, branch);
	
	if (branch_rev)
	{
	    char post_rev[REV_STR_MAX];
	    char branch[REV_STR_MAX];
	    int file_leaf, branch_leaf;
	    
	    strcpy(branch, branch_rev);
	    
	    /* first get the branch the file rev is on */
	    if (get_branch_ext(post_rev, rev->rev, &file_leaf))
	    {
		branch_leaf = file_leaf;
		
		/* check against branch and all branch ancestor branches */
		do 
		{
		    debug(DEBUG_STATUS, "check %s against %s for %s", branch, post_rev, rev->file->filename);
		    if (strcmp(branch, post_rev) == 0)
			return (file_leaf <= branch_leaf);
		}
		while(get_branch_ext(branch, branch, &branch_leaf));
	    }
	}
    }

    return false;
}

static int count_dots(const char * p)
{
    int dots = 0;

    while (*p)
	if (*p++ == '.')
	    dots++;

    return dots;
}

/*
 * When importing vendor sources, (apparently people do this)
 * the code is added on a 'vendor' branch, which, for some reason
 * doesn't use the magic-branch-tag format.  Try to detect that now
 */
static bool is_vendor_branch(const char * rev)
{
    return !(count_dots(rev)&1);
}

void patch_set_add_member(PatchSet * ps, PatchSetMember * psm)
{
    /* check if a member for the same file already exists, if so
     * put this PatchSet on the collisions list 
     */
    struct list_head * next;
    for (next = ps->members.next; next != &ps->members; next = next->next) 
    {
	PatchSetMember * m = list_entry(next, PatchSetMember, link);
	if (m->file == psm->file) {
		int order = compare_rev_strings(psm->post_rev->rev, m->post_rev->rev);

		/*
		 * Same revision too? Add it to the collision list
		 * if it isn't already.
		 */
		if (!order) {
			if (ps->collision_link.next == NULL)
				list_add(&ps->collision_link, &collisions);
			return;
		}

		/*
		 * If this is an older revision than the one we already have
		 * in this patchset, just ignore it
		 */
		if (order < 0)
			return;

		/*
		 * This is a newer one, remove the old one
		 */
		list_del(&m->link);
	}
    }

    psm->ps = ps;
    list_add(&psm->link, ps->members.prev);
}

static void set_psm_initial(PatchSetMember * psm)
{
    psm->pre_rev = NULL;
    if (psm->post_rev->dead)
    {
	/* 
	 * We expect a 'file xyz initially added on branch abc' here.
	 * There can be several such members in a given patchset,
	 * since cvs only includes the file basename in the log message.
	 */
	psm->ps->branch_add = true;
    }
}

/* 
 * look at all revisions starting at rev and going forward until 
 * ps->date and see whether they are invalid or just funky.
 */
static int check_rev_funk(PatchSet * ps, CvsFileRevision * rev)
{
    struct list_head * tag;

    int retval = TAG_FUNKY;

    for (tag = ps->tags.next; tag != &ps->tags; tag = tag->next)
    {
        char* tagname = list_entry (&tag, TagName, link)->name;

	while (rev)
	{
	    PatchSet * next_ps = rev->post_psm->ps;
	    struct list_head * next;

	    if (next_ps->date > ps->date)
		break;

	    debug(DEBUG_STATUS, "ps->date %d next_ps->date %d rev->rev %s rev->branch %s", 
		  ps->date, next_ps->date, rev->rev, rev->branch);

	    /*
	     * If the tagname is one of the two possible '-r' tags
	     * then the funkyness is even more important.
	     *
	     * In the restrict_tag_start case, this next_ps is chronologically
	     * before ps, but tagwise after, so set the funk_factor so it will
	     * be included.
	     *
	     * The restrict_tag_end case is similar, but backwards.
	     *
	     * Start assuming the HIDE/SHOW_ALL case, we will determine
	     * below if we have a split ps case 
	     */
	    if (restrict_tag_start && strcmp(tagname, restrict_tag_start) == 0)
		next_ps->funk_factor = FNK_SHOW_ALL;
	    if (restrict_tag_end && strcmp(tagname, restrict_tag_end) == 0)
		next_ps->funk_factor = FNK_HIDE_ALL;

	    /*
	     * if all of the other members of this patchset are also 'after' the tag
	     * then this is a 'funky' patchset w.r.t. the tag.  however, if some are
	     * before then the patchset is 'invalid' w.r.t. the tag, and we mark
	     * the members individually with 'bad_funk' ,if this tag is the
	     * '-r' tag.  Then we can actually split the diff on this patchset
	     */
	    for (next = next_ps->members.next; next != &next_ps->members; next = next->next)
	    {
		PatchSetMember * psm = list_entry(next, PatchSetMember, link);
		if (before_tag(psm->post_rev, tagname))
		{
		    retval = TAG_INVALID;
		    /* only set bad_funk for one of the -r tags */
		    if (next_ps->funk_factor)
		    {
			psm->bad_funk = true;
			next_ps->funk_factor = 
			    (next_ps->funk_factor == FNK_SHOW_ALL) ? FNK_SHOW_SOME : FNK_HIDE_SOME;
		    }
		    debug(DEBUG_APPWARN,
			  "WARNING: Invalid PatchSet %d, Tag %s:\n"
			  "    %s:%s=after, %s:%s=before. Treated as 'before'", 
			  next_ps->psid, tagname, 
			  rev->file->filename, rev->rev, 
			  psm->post_rev->file->filename, psm->post_rev->rev);
		}
	    }

	    rev = rev_follow_branch(rev, ps->branch);
	}
    }

    return retval;
}

/* determine if the revision is before the tag */
static bool before_tag(CvsFileRevision * rev, const char * tag)
{
    CvsFileRevision * tagged_rev = (CvsFileRevision*)get_hash_object(rev->file->symbols, tag);
    bool retval = false;

    if (tagged_rev && tagged_rev->branch == NULL)
        debug(DEBUG_APPWARN, "WARNING: Branch == NULL for: %s %s %s %s %d",
	      rev->file->filename, tag, rev->rev, tagged_rev->rev, retval);

    if (tagged_rev && tagged_rev->branch != NULL &&
	revision_affects_branch(rev, tagged_rev->branch) && 
	rev->post_psm->ps->date <= tagged_rev->post_psm->ps->date)
	retval = true;

    debug(DEBUG_STATUS, "before_tag: %s %s %s %s %d", 
	  rev->file->filename, tag, rev->rev, tagged_rev ? tagged_rev->rev : "N/A", retval);

    return retval;
}

/* get the next revision from this one following branch if possible */
/* FIXME: not sure if this needs to follow branches leading up to branches? */
static CvsFileRevision * rev_follow_branch(CvsFileRevision * rev, const char * branch)
{
    struct list_head * next;

    /* check for 'main line of inheritance' */
    if (strcmp(rev->branch, branch) == 0)
	return rev->pre_psm ? rev->pre_psm->post_rev : NULL;

    /* look down branches */
    for (next = rev->branch_children.next; next != &rev->branch_children; next = next->next)
    {
	CvsFileRevision * next_rev = list_entry(next, CvsFileRevision, link);
	//debug(DEBUG_STATUS, "SCANNING BRANCH CHILDREN: %s %s", next_rev->branch, branch);
	if (strcmp(next_rev->branch, branch) == 0)
	    return next_rev;
    }
    
    return NULL;
}

static void handle_collisions()
{
    struct list_head *next;
    for (next = collisions.next; next != &collisions; next = next->next) 
    {
	PatchSet * ps = list_entry(next, PatchSet, collision_link);
	printf("PatchSet %d has collisions\n", ps->psid);
    }
}

void walk_all_patch_sets(void (*action)(PatchSet *))
{
    struct list_head * next;;
    for (next = all_patch_sets.next; next != &all_patch_sets; next = next->next) {
	PatchSet * ps = list_entry(next, PatchSet, all_link);
	action(ps);
    }
}

static Branch * create_branch(const char * name) 
{
    Branch * branch = (Branch*)calloc(1, sizeof(*branch));
    branch->name = get_string(name);
    branch->ps = NULL;
    CLEAR_LIST_NODE(&branch->link);
    return branch;
}

static void find_branch_points(PatchSet * ps)
{
    struct list_head * next;
    
    /*
     * for each member, check if the post-rev has any branch children.
     * if so, the branch point for that branch cannot be earlier than this 
     * PatchSet, so just assign here for now.  It'll get pushed ahead
     * bit by bit until it falls into the right place.
     */
    for (next = ps->members.next; next != &ps->members; next = next->next) 
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	CvsFileRevision * rev = psm->post_rev;
	struct list_head * child_iter;

	for (child_iter = rev->branch_children.next; child_iter != &rev->branch_children; child_iter = child_iter->next) {
	    CvsFileRevision * branch_child = list_entry(child_iter, CvsFileRevision, link);
	    Branch * branch = get_hash_object(branches, branch_child->branch);
	    if (branch == NULL) {
		debug(DEBUG_APPERROR, "branch %s not found in global branch hash", branch_child->branch);
		return;
	    }
	    
	    if (branch->ps != NULL) {
		list_del(&branch->link);
	    }

	    branch->ps = ps;
	    list_add(&branch->link, ps->branches.prev);
	}
    }
	
}
