#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <search.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>
#include <cbtcommon/hash.h>
#include <cbtcommon/list.h>
#include <cbtcommon/text_util.h>
#include <cbtcommon/debug.h>
#include <cbtcommon/rcsid.h>

RCSID("$Id: cvsps.c,v 4.31 2003/02/24 18:49:33 david Exp $");

#define LOG_STR_MAX 8192
#define AUTH_STR_MAX 64
#define REV_STR_MAX 64
#define CACHE_DESCR_BOUNDARY "-=-END CVSPS DESCR-=-\n"
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

enum
{
    NEED_FILE,
    NEED_SYMS,
    NEED_EOS,
    NEED_START_LOG,
    NEED_REVISION,
    NEED_DATE_AUTHOR_STATE,
    NEED_EOM
};

typedef struct _CvsFile CvsFile;
typedef struct _PatchSet PatchSet;
typedef struct _PatchSetMember PatchSetMember;
typedef struct _PatchSetRange PatchSetRange;
typedef struct _CvsFileRevision CvsFileRevision;

struct _CvsFileRevision
{
    char * rev;
    int dead;
    CvsFile * file;
    /*
     * A revision can be part of man PatchSets because it may
     * be the branch point of many branches (as a pre_rev).  
     * It should, however, be the 'post_rev' of only one 
     * PatchSetMember, which is kept here.
     */
    PatchSetMember * psm;
};

struct _CvsFile
{
    char *filename;
    struct hash_table * revisions;
    struct hash_table * branches;     /* branch to branch_sym map */
    struct hash_table * branches_sym; /* branch_sym to branch map */
};

struct _PatchSet
{
    time_t date;
    char *descr;
    char *author;
    struct list_head members;
};

struct _PatchSetMember
{
    CvsFileRevision * pre_rev;
    CvsFileRevision * post_rev;
    PatchSet * ps;
    CvsFile * file;
    struct list_head link;
};

struct _PatchSetRange
{
    int min_counter;
    int max_counter;
    struct list_head link;
};

static int ps_counter;
static struct hash_table * file_hash;
static void * ps_tree, * ps_tree_bytime;
static void * string_tree;

static int timestamp_fuzz_factor = 300;
static const char * restrict_author;
static const char * restrict_file;
static time_t restrict_date_start;
static time_t restrict_date_end;
static const char * restrict_branch;
static struct list_head show_patch_set_ranges;
static char strip_path[PATH_MAX];
static int strip_path_len;
static time_t cache_date;
static FILE * cache_fp;
static int update_cache;
static int ignore_cache;
static int statistics;
static const char * norc = "";

static void parse_args(int, char *[]);
static void load_from_cvs();
static void init_strip_path();
static CvsFile * parse_file(const char *);
static PatchSet * get_patch_set(const char *, const char *, const char *);
static void assign_pre_revision(PatchSetMember *, CvsFileRevision * rev);
static void check_print_patch_set(PatchSet *);
static void print_patch_set(PatchSet *);
static void show_ps_tree_node(const void *, const VISIT, const int);
static int compare_patch_sets(const void *, const void *);
static int compare_patch_sets_bytime(const void *, const void *);
static void convert_date(time_t *, const char *);
static int is_revision_metadata(const char *);
static int patch_set_contains_member(PatchSet *, const char *);
static int patch_set_affects_branch(PatchSet *, const char *);
static void do_cvs_diff(PatchSet *);
static void strzncpy(char *, const char *, int);
static void write_cache();
static CvsFileRevision * cvs_file_add_revision(CvsFile *, char *);
static void write_tree_node_to_cache(const void *, const VISIT, const int);
static void dump_patch_set(FILE *, PatchSet *);
static int read_cache();
static CvsFile * create_cvsfile();
static PatchSet * create_patchset();
static PatchSetMember * create_patchset_member();
static PatchSetRange * create_patchset_range();
static void parse_cache_revision(PatchSetMember *, const char *);
static CvsFileRevision * file_get_revision(CvsFile *, const char *);
static void parse_sym(CvsFile *, char *);
static char * cvs_file_add_branch(CvsFile *, const char *, const char *);
static void print_statistics(void);

char *xstrdup(char const *str)
{
    char *ret;
    assert(str);
    ret = strdup(str);
    if (!ret)
    {
	debug(DEBUG_ERROR, "strdup failed");
	exit(1);
    }

    return ret;
}

typedef int (*compare_func)(const void *, const void *);

char *get_string(char const *str)
{
    char ** res = (char **)tfind(str, &string_tree, (compare_func)strcmp);
    if (!res)
    {
	char *key = xstrdup(str);
	res = (char **)tsearch(key, &string_tree, (compare_func)strcmp);
	*res = key;
    }

    return *res;
}

int main(int argc, char *argv[])
{
    debuglvl = DEBUG_APPERROR|DEBUG_SYSERROR;

    INIT_LIST_HEAD(&show_patch_set_ranges);

    parse_args(argc, argv);
    file_hash = create_hash_table(1023);

    if (!ignore_cache)
    {
	int save_fuzz_factor = timestamp_fuzz_factor;

	/* the timestamp fuzz should only be in effect when loading from
	 * CVS, not re-fuzzed when loading from cache.  This is a hack
	 * working around bad use of global variables
	 */

	timestamp_fuzz_factor = 0;

	if (read_cache() < 0)
	    update_cache = 1;

	timestamp_fuzz_factor = save_fuzz_factor;
    }
    
    if (update_cache)
    {
	load_from_cvs();
	write_cache();
    }

    if (statistics)
    {
	printf("Statistics:\n");
	print_statistics();
    }

    ps_counter = 0;
    twalk(ps_tree_bytime, show_ps_tree_node);
    exit(0);
}

static void load_from_cvs()
{
    FILE * cvsfp;
    char buff[BUFSIZ];
    int state = NEED_FILE;
    CvsFile * file = NULL;
    PatchSetMember * psm = NULL;
    char datebuff[20];
    char authbuff[AUTH_STR_MAX];
    char logbuff[LOG_STR_MAX];
    int loglen = 0;
    int have_log = 0;
    char cmd[BUFSIZ];
    char date_str[64];

    init_strip_path();

    if (cache_date != 0)
    {
	struct tm * tm = gmtime(&cache_date);
	strftime(date_str, 64, "%b %d, %Y %H:%M:%S GMT", tm);

	/* this command asks for logs using two different date
	 * arguments, separated by ';' (see man rlog).  The first
	 * gets all revisions more recent than date, the second 
	 * gets a single revision no later than date, which combined
	 * get us all revisions that have occurred since last update
	 * and overlaps what we had before by exactly one revision,
	 * which is necessary to fill in the pre_rev stuff for a 
	 * PatchSetMember
	 */
	snprintf(cmd, BUFSIZ, "cvs %s log -d '%s<;%s'", norc, date_str, date_str);
    }
    else
    {
	snprintf(cmd, BUFSIZ, "cvs %s log", norc);
    }
    
    debug(DEBUG_STATUS, "******* USING CMD %s", cmd);

    cache_date = time(NULL);
    cvsfp = popen(cmd, "r");

    if (!cvsfp)
    {
	debug(DEBUG_SYSERROR, "can't open cvs pipe using command %s", cmd);
	exit(1);
    }
    
    while(fgets(buff, BUFSIZ, cvsfp))
    {
	debug(DEBUG_STATUS, "state: %d read line:%s", state, buff);

	switch(state)
	{
	case NEED_FILE:
	    if (strncmp(buff, "RCS file", 8) == 0 && (file = parse_file(buff)))
		state = NEED_SYMS;
	    break;
	case NEED_SYMS:
	    if (strncmp(buff, "symbolic names:", 15) == 0)
		state = NEED_EOS;
	    break;
	case NEED_EOS:
	    if (!isspace(buff[0]))
		state = NEED_START_LOG;
	    else
		parse_sym(file, buff);
	    break;
	case NEED_START_LOG:
	    if (strncmp(buff, "--------", 8) == 0)
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
		 * case cvs_file_add_revision is a hash lookup
		 */
		rev = cvs_file_add_revision(file, new_rev);

		/* 
		 * in the simple case, we are copying rev to psm->pre_rev
		 * (psm refers to last patch set processed at this point)
		 * since generally speaking the log is reverse chronological.
		 * This breaks down slightly when branches are introduced 
		 */

		assign_pre_revision(psm, rev);

		/*
		 * if this is a new revision, it will have no psm associated.
		 * otherwise we are (probably?) hitting the overlap in cvsps -u 
		 */
		if (!rev->psm)
		{
		    psm = rev->psm = create_patchset_member();
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

		strncpy(datebuff, buff + 6, 19);
		datebuff[19] = 0;

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
			    psm->post_rev->dead = 1;
		}

		state = NEED_EOM;
	    }
	    break;
	case NEED_EOM:
	    if (strncmp(buff, "--------", 8) == 0)
	    {
		if (psm)
		{
		    psm->ps = get_patch_set(datebuff, logbuff, authbuff);
		    list_add(&psm->link, psm->ps->members.prev);
		}

		logbuff[0] = 0;
		loglen = 0;
		have_log = 0;
		state = NEED_REVISION;
	    }
	    else if (strncmp(buff, "========", 8) == 0)
	    {
		if (psm)
		{
		    psm->ps = get_patch_set(datebuff, logbuff, authbuff);
		    list_add(&psm->link, psm->ps->members.prev);
		    assign_pre_revision(psm, NULL);
		}

		logbuff[0] = 0;
		loglen = 0;
		have_log = 0;
		psm = NULL;
		file = NULL;
		state = NEED_FILE;
	    }
	    else
	    {
		/* other "blahblah: information;" messages can 
		 * follow the stuff we pay attention to
		 */
		if (have_log || !is_revision_metadata(buff))
		{
		    int len;

		    debug(DEBUG_STATUS, "appending %s to log", buff);
		    len = MIN(LOG_STR_MAX - loglen, strlen(buff));
		    memcpy(logbuff + loglen, buff, len);
		    loglen += len;
		    logbuff[loglen] = 0;
		    have_log = 1;
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
	debug(DEBUG_APPERROR, "       Perhaps you should try running with --norc");
	exit(1);
    }

    if (state != NEED_FILE)
    {
	debug(DEBUG_APPERROR, "Error: Log file parsing error.  Use -v to debug");
	exit(1);
    }
    
    pclose(cvsfp);
}

static void usage(const char * str1, const char * str2)
{
    if (str1)
	debug(DEBUG_APPERROR, "\nbad usage: %s %s\n", str1, str2);

    debug(DEBUG_APPERROR, "Usage: cvsps [-x] [-u] [-z <fuzz>] [-s <patchset>] [-a <author>] ");
    debug(DEBUG_APPERROR, "             [-f <file>] [-d <date1> [-d <date2>]] [-b <branch>]");
    debug(DEBUG_APPERROR, "             [-v] [-h]");
    debug(DEBUG_APPERROR, "");
    debug(DEBUG_APPERROR, "Where:");
    debug(DEBUG_APPERROR, "  -x ignore (and rebuild) CVS/cvsps.cache file");
    debug(DEBUG_APPERROR, "  -u update CVS/cvsps.cache file");
    debug(DEBUG_APPERROR, "  -z <fuzz> set the timestamp fuzz factor for identifying patch sets");
    debug(DEBUG_APPERROR, "  -s <patchset> generate a diff for a given patchset");
    debug(DEBUG_APPERROR, "  -a <author> restrict output to patchsets created by author");
    debug(DEBUG_APPERROR, "  -f <file> restrict output to patchsets involving file");
    debug(DEBUG_APPERROR, "  -d <date1> -d <date2> if just one date specified, show");
    debug(DEBUG_APPERROR, "     revisions newer than date1.  If two dates specified,");
    debug(DEBUG_APPERROR, "     show revisions between two dates.");
    debug(DEBUG_APPERROR, "  -b <branch> restrict output to patchsets affecting history of branch");
    debug(DEBUG_APPERROR, "  -v show verbose parsing messages");
    debug(DEBUG_APPERROR, "  -t show some brief memory usage statistics");
    debug(DEBUG_APPERROR, "  --norc when invoking cvs, ignore the .cvsrc file");
    debug(DEBUG_APPERROR, "  -h display this informative message");
    debug(DEBUG_APPERROR, "\ncvsps version %s\n", VERSION);

    exit(1);
}

static void parse_args(int argc, char *argv[])
{
    int i = 1;
    while (i < argc)
    {
	if (strcmp(argv[i], "-z") == 0)
	{
	    if (++i >= argc)
		usage("argument to -z missing", "");

	    timestamp_fuzz_factor = atoi(argv[i++]);
	    continue;
	}
	
	if (strcmp(argv[i], "-s") == 0)
	{
	    PatchSetRange * range;
	    char * min_str, * max_str;

	    if (++i >= argc)
		usage("argument to -s missing", "");

	    min_str = strtok(argv[i++], ",");
	    do
	    {
		range = create_patchset_range();

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
		usage("argument to -a missing", "");

	    restrict_author = argv[i++];
	    continue;
	}
	
	if (strcmp(argv[i], "-f") == 0)
	{
	    if (++i >= argc)
		usage("argument to -f missing", "");

	    restrict_file = argv[i++];
	    continue;
	}
	
	if (strcmp(argv[i], "-d") == 0)
	{
	    time_t *pt;

	    if (++i >= argc)
		usage("argument to -d missing", "");

	    pt = (restrict_date_start == 0) ? &restrict_date_start : &restrict_date_end;
	    convert_date(pt, argv[i++]);
	    continue;
	}

	if (strcmp(argv[i], "-u") == 0)
	{
	    update_cache = 1;
	    i++;
	    continue;
	}
	
	if (strcmp(argv[i], "-x") == 0)
	{
	    ignore_cache = 1;
	    update_cache = 1;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "-b") == 0)
	{
	    if (++i >= argc)
		usage("argument to -b missing", "");

	    restrict_branch = argv[i++];
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
	    statistics = 1;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "-h") == 0)
	    usage(NULL, NULL);

	if (strcmp(argv[i], "--norc") == 0)
	{
	    norc = "-f";
	    i++;
	    continue;
	}

	usage("invalid argument", argv[i]);
    }
}

static void init_strip_path()
{
    FILE * fp;
    char root_buff[PATH_MAX], rep_buff[PATH_MAX], *p;
    int len;

    if (!(fp = fopen("CVS/Root", "r")))
    {
	debug(DEBUG_SYSERROR, "Can't open CVS/Root");
	exit(1);
    }
    
    if (!fgets(root_buff, PATH_MAX, fp))
    {
	debug(DEBUG_APPERROR, "Error reading CVSROOT");
	exit(1);
    }

    fclose(fp);
	
    p = strrchr(root_buff, ':');

    if (!p)
	p = root_buff;
    else 
	p++;

    len = strlen(root_buff) - 1;
    root_buff[len] = 0;
    if (root_buff[len - 1] == '/')
	root_buff[--len] = 0;

    if (!(fp = fopen("CVS/Repository", "r")))
    {
	debug(DEBUG_SYSERROR, "Can't open CVS/Repository");
	exit(1);
    }

    if (!fgets(rep_buff, PATH_MAX, fp))
    {
	debug(DEBUG_APPERROR, "Error reading repository path");
	exit(1);
    }
    
    rep_buff[strlen(rep_buff) - 1] = 0;

    /* some CVS have the CVSROOT string as part of the repository
     * string (initial substring).  handle that case.
     */
    if (strncmp(p, rep_buff, strlen(p)) == 0)
        strip_path_len = snprintf(strip_path, PATH_MAX, "%s/", rep_buff);
    else
        strip_path_len = snprintf(strip_path, PATH_MAX, "%s/%s/", p, rep_buff);

    if (strip_path_len < 0)
    {
	debug(DEBUG_APPERROR, "strip_path overflow");
	exit(1);
    }

    debug(DEBUG_STATUS, "strip_path: %s", strip_path);
}

static CvsFile * parse_file(const char * buff)
{
    CvsFile * retval;
    char fn[PATH_MAX];
    int len = strlen(buff + 10);
    char * p;
    
    /* chop the ",v" string and the "LF" */
    len -= 3;
    memcpy(fn, buff + 10, len);
    fn[len] = 0;
    
    if (strncmp(fn, strip_path, strip_path_len) != 0)
    {
	/* FIXME: a subdirectory may have a different Repository path
	 * than it's parent.  we'll fail the above test since strip_path
	 * is global for the entire checked out tree (recursively).
	 *
	 * For now just ignore such files
	 */
	debug(DEBUG_APPERROR, "*** file %s doesn't match strip_path %s. ignoring", 
	      fn, strip_path);
	return NULL;
    }

    /* remove from beginning the 'strip_path' string */
    len -= strip_path_len;
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

    retval = (CvsFile*)get_hash_object(file_hash, fn);

    if (!retval)
    {
	if ((retval = create_cvsfile()))
	{
	    retval->filename = xstrdup(fn);
	    put_hash_object(file_hash, retval->filename, retval);
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

static PatchSet * get_patch_set(const char * dte, const char * log, const char * author)
{
    PatchSet * retval = NULL, **find = NULL;
    
    if (!(retval = create_patchset()))
    {
	debug(DEBUG_SYSERROR, "malloc failed for PatchSet");
	return NULL;
    }

    convert_date(&retval->date, dte);
    retval->author = get_string(author);
    retval->descr = xstrdup(log);

    find = (PatchSet**)tsearch(retval, &ps_tree, compare_patch_sets);

    if (*find != retval)
    {
	debug(DEBUG_STATUS, "found existing patch set");
	free(retval->descr);
	free(retval);
	retval = *find;
    }
    else
    {
	debug(DEBUG_STATUS, "new patch set!");
	debug(DEBUG_STATUS, "%s %s %s", retval->author, retval->descr, dte);
	if (tsearch(retval, &ps_tree_bytime, compare_patch_sets_bytime) == retval)
		abort();
    }

    return retval;
}

static int get_branch_ext(char * buff, const char * rev, int * leaf)
{
    char * p;
    int len = strlen(rev);
    
    /* allow get_branch(buff, buff) without destroying contents */
    memmove(buff, rev, len);
    buff[len] = 0;

    p = strrchr(buff, '.');
    if (!p)
	return 0;
    *p++ = 0;

    if (leaf)
	*leaf = atoi(p);

    return 1;
}

static int get_branch(char * buff, const char * rev)
{
    return get_branch_ext(buff, rev, NULL);
}

/* the goal if this function is to determine what revision to assign to
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
	 * INITIAL, or head of a branch.  to test if it's 
	 * the head of a branch, do get_branch twice. 
	 */
	if (get_branch(post, psm->post_rev->rev) && 
	    get_branch(pre, post))
	    psm->pre_rev = file_get_revision(psm->file, pre);
	else
	    psm->pre_rev = NULL;
	return;
    }

    /* is this canditate for 'pre' on the same branch as our 'post' ? */
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
	psm->pre_rev = NULL;
	return;
    }
    
    psm->pre_rev = file_get_revision(psm->file, pre);
}

static void check_print_patch_set(PatchSet * ps)
{
    if (restrict_date_start > 0 && 
	(ps->date < restrict_date_start ||
	 (restrict_date_end > 0 && ps->date > restrict_date_end)))
	return;
    
    if (restrict_author && strcmp(restrict_author, ps->author) != 0)
	return;

    if (restrict_file && !patch_set_contains_member(ps, restrict_file))
	return;

    if (restrict_branch && !patch_set_affects_branch(ps, restrict_branch))
	return;
    
    print_patch_set(ps);
}

static void print_patch_set(PatchSet * ps)
{
    struct tm * tm;
    struct list_head * next;

    tm = localtime(&ps->date);
    next = ps->members.next;
    
    printf("---------------------\n");
    printf("PatchSet %d\n", ps_counter);
    printf("Date: %d/%02d/%02d %02d:%02d:%02d\n", 
	   1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday, 
	   tm->tm_hour, tm->tm_min, tm->tm_sec);
    printf("Author: %s\n", ps->author);
    printf("Log:\n%s\n", ps->descr);
    printf("Members: \n");
    
    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	char branch[REV_STR_MAX + 2], *tag;

	if (get_branch(branch, psm->post_rev->rev) && 
	    (tag = (char*)get_hash_object(psm->file->branches, branch)))
	    snprintf(branch, REV_STR_MAX + 2, "[%s]", tag);
	else
	    branch[0] = 0;

	printf("\t%s:%s->%s%s %s\n", 
	       psm->file->filename, 
	       psm->pre_rev ? psm->pre_rev->rev : "INITIAL", 
	       psm->post_rev->rev, 
	       psm->post_rev->dead ? "(DEAD)": "", 
	       branch);
	next = next->next;
    }
    
    printf("\n");
}

static void show_ps_tree_node(const void * nodep, const VISIT which, const int depth)
{
    PatchSet * ps;

    switch(which)
    {
    case postorder:
    case leaf:
	ps = *(PatchSet**)nodep;
	ps_counter++;

	if (!list_empty(&show_patch_set_ranges))
	{
	    struct list_head * next = show_patch_set_ranges.next;

	    while (next != &show_patch_set_ranges)
	    {
		PatchSetRange *range = list_entry(next, PatchSetRange, link);
		if (range->min_counter <= ps_counter &&
		    ps_counter <= range->max_counter)
		{
			print_patch_set(ps);
			do_cvs_diff(ps);
		}
		next = next->next;
	    }
	}
	else
	{
	    check_print_patch_set(ps);
	}
	break;

    default:
	break;
    }
}

static int compare_patch_sets(const void * v_ps1, const void * v_ps2)
{
    const PatchSet * ps1 = (const PatchSet *)v_ps1;
    const PatchSet * ps2 = (const PatchSet *)v_ps2;
    long diff;
    int ret;

    /* We order by (author, descr, date), but because of the fuzz factor
     * we treat times within a certain distance as equal IFF the author
     * and descr match.  If we allow the fuzz, but then the author or
     * descr don't match, return the date diff (if any) in order to get
     * the ordering right.
     */

    ret = strcmp(ps1->author, ps2->author);
    if (ret)
	    return ret;

    ret = strcmp(ps1->descr, ps2->descr);
    if (ret)
	    return ret;

    diff = ps1->date - ps2->date;

    if (labs(diff) > timestamp_fuzz_factor)
	return (diff < 0) ? -1 : 1;
    return 0;
}

static int compare_patch_sets_bytime(const void * v_ps1, const void * v_ps2)
{
    const PatchSet * ps1 = (const PatchSet *)v_ps1;
    const PatchSet * ps2 = (const PatchSet *)v_ps2;
    long diff;
    int ret;

    /* When doing a time-ordering of patchsets, we don't need to
     * fuzzy-match the time.  We've already done fuzzy-matching so we
     * know that insertions are unique at this point.
     */

    diff = ps1->date - ps2->date;
    if (diff)
	return (diff < 0) ? -1 : 1;

    ret = strcmp(ps1->author, ps2->author);
    if (ret)
	return ret;

    ret = strcmp(ps1->descr, ps2->descr);
    return ret;
}

static void convert_date(time_t * t, const char * dte)
{
    /* HACK: this routine parses two formats,
     * 1) 'cvslog' format YYYY/MM/DD HH:MM:SS
     * 2) time_t formatted as %d
     */
       
    if (strchr(dte, '/'))
    {
	struct tm tm;
	
	memset(&tm, 0, sizeof(tm));
	sscanf(dte, "%d/%d/%d %d:%d:%d", 
	       &tm.tm_year, &tm.tm_mon, &tm.tm_mday, 
	       &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
	
	tm.tm_year -= 1900;
	tm.tm_mon--;
	
	*t = mktime(&tm);
    }
    else
    {
	*t = atoi(dte);
    }
}

static int is_revision_metadata(const char * buff)
{
    char * p1, *p2;
    int len;

    if (!(p1 = strchr(buff, ':')))
	return 0;

    p2 = strchr(buff, ' ');
    
    if (p2 && p2 < p1)
	return 0;

    len = strlen(buff);

    /* lines have LF at end */
    if (len > 1 && buff[len - 2] == ';')
	return 1;

    return 0;
}

static int patch_set_contains_member(PatchSet * ps, const char * file)
{
    struct list_head * next = ps->members.next;

    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	
	if (strstr(psm->file->filename, file))
	    return 1;

	next = next->next;
    }

    return 0;
}

static int patch_set_affects_branch(PatchSet * ps, const char * branch)
{
    struct list_head * next = ps->members.next;

    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);

	/* special case the branch called 'TRUNK' */
	if (strcmp(branch, "TRUNK") == 0)
	{
	    /* look for only one '.' in rev */
	    char * p = strchr(psm->post_rev->rev, '.');
	    if (p && !strchr(p + 1, '.'))
		return 1;
	}
	else
	{
	    char * branch_rev = (char*)get_hash_object(psm->file->branches_sym, branch);
	    
	    if (branch_rev)
	    {
		char post_rev[REV_STR_MAX];
		char branch[REV_STR_MAX];
		int file_leaf, branch_leaf;
		
		strcpy(branch, branch_rev);
		
		/* first get the branch the file rev is on */
		if (get_branch_ext(post_rev, psm->post_rev->rev, &file_leaf))
		{
		    branch_leaf = file_leaf;
		    
		    /* check against branch and all branch ancestor branches */
		    do 
		    {
			debug(DEBUG_STATUS, "check %s against %s for %s", branch, post_rev, psm->file->filename);
			if (strcmp(branch, post_rev) == 0)
			    return (file_leaf <= branch_leaf);
		    }
		    while(get_branch_ext(branch, branch, &branch_leaf));
		}
	    }
	}
	next = next->next;
    }

    return 0;
}

static void do_cvs_diff(PatchSet * ps)
{
    struct list_head * next = ps->members.next;

    fflush(stdout);
    fflush(stderr);

    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	char cmdbuff[PATH_MAX * 2+1];
	cmdbuff[PATH_MAX*2] = 0;

	/*
	 * It's possible for pre_rev to be a 'dead' revision.
	 * this happens when a file is added on a branch
	 */
	if (!psm->pre_rev || psm->pre_rev->dead)
	{
	    snprintf(cmdbuff, PATH_MAX * 2, "cvs %s update -p -r %s %s | diff -u /dev/null - | sed -e '1 s|^--- /dev/null|--- %s|g' -e '2 s|^+++ -|+++ %s|g'",
		     norc, psm->post_rev->rev, psm->file->filename, psm->file->filename, psm->file->filename);
	}
	else if (psm->post_rev->dead)
	{
	    snprintf(cmdbuff, PATH_MAX * 2, "cvs %s update -p -r %s %s | diff -u - /dev/null | sed -e '1 s|^--- -|--- %s|g' -e '2 s|^+++ /dev/null|+++ %s|g'",
		     norc, psm->pre_rev->rev, psm->file->filename, psm->file->filename, psm->file->filename);
	    
	}
	else
	{
	    snprintf(cmdbuff, PATH_MAX * 2, "cvs %s diff -u -r %s -r %s %s",
		     norc, psm->pre_rev->rev, psm->post_rev->rev, psm->file->filename);
	}

	system(cmdbuff);

	next = next->next;
    }
}

static void strzncpy(char * dst, const char * src, int n)
{
    strncpy(dst, src, n);
    dst[n - 1] = 0;
}

static void write_cache()
{
    struct hash_entry * file_iter;

    ps_counter = 0;

    if ((cache_fp = fopen("CVS/cvsps.cache", "w")) == NULL)
    {
	debug(DEBUG_SYSERROR, "can't open CVS/cvsps.cache for write");
	return;
    }

    fprintf(cache_fp, "cache date: %d\n", (int)cache_date);

    reset_hash_iterator(file_hash);

    while ((file_iter = next_hash_entry(file_hash)))
    {
	CvsFile * file = (CvsFile*)file_iter->he_obj;
	struct hash_entry * rev_iter;

	fprintf(cache_fp, "file: %s\n", file->filename);
	reset_hash_iterator(file->revisions);
	
	while ((rev_iter = next_hash_entry(file->revisions)))
	{
	    CvsFileRevision * rev = (CvsFileRevision*)rev_iter->he_obj;
	    fprintf(cache_fp, "%s\n", rev->rev);
	}

	fprintf(cache_fp, "branches:\n");
	reset_hash_iterator(file->branches);
	
	while ((rev_iter = next_hash_entry(file->branches)))
	{
	    char * rev = (char *)rev_iter->he_key;
	    char * tag = (char *)rev_iter->he_obj;
	    fprintf(cache_fp, "%s: %s\n", rev, tag);
	}

	fprintf(cache_fp, "\n");

	
    }

    fprintf(cache_fp, "\n");
    twalk(ps_tree_bytime, write_tree_node_to_cache);
    fclose(cache_fp);
    cache_fp = NULL;
}

static CvsFileRevision * cvs_file_add_revision(CvsFile * file, char * rev_str)
{
    CvsFileRevision * rev;
    char * p;

    /* The "revision" log line can include extra information 
     * including who is locking the file --- strip that out.
     */
    
    p = rev_str;
    while (isdigit(*p) || *p == '.')
	    p++;
    *p = 0;

    if (!(rev = (CvsFileRevision*)get_hash_object(file->revisions, rev_str)))
    {
	rev = (CvsFileRevision*)calloc(1, sizeof(*rev));
	rev->rev = get_string(rev_str);
	rev->file = file;
	put_hash_object(file->revisions, rev_str, rev);

	debug(DEBUG_STATUS, "added revision %s to file %s", rev_str, file->filename);
    }
    else
    {
	debug(DEBUG_STATUS, "found revision %s to file %s", rev_str, file->filename);
    }

    return rev;
}

static void write_tree_node_to_cache(const void * nodep, const VISIT which, const int depth)
{
    PatchSet * ps;

    switch(which)
    {
    case postorder:
    case leaf:
	ps = *(PatchSet**)nodep;
	dump_patch_set(cache_fp, ps);
	break;

    default:
	break;
    }
}

static void dump_patch_set(FILE * fp, PatchSet * ps)
{
    struct list_head * next = ps->members.next;

    ps_counter++;
    fprintf(fp, "patchset: %d\n", ps_counter);
    fprintf(fp, "date: %d\n", (int)ps->date);
    fprintf(fp, "author: %s\n", ps->author);
    fprintf(fp, "descr:\n%s", ps->descr); /* descr is guaranteed to end with LF */
    fprintf(fp, CACHE_DESCR_BOUNDARY);
    fprintf(fp, "members:\n");

    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	fprintf(fp, "file: %s; pre_rev: %s; post_rev: %s; dead: %d\n", 
		psm->file->filename, 
		psm->pre_rev ? psm->pre_rev->rev : "INITIAL", psm->post_rev->rev, psm->post_rev->dead);
	next = next->next;
    }

    fprintf(fp, "\n");
}

enum
{
    CACHE_NEED_FILE,
    CACHE_NEED_REV,
    CACHE_NEED_BRANCHES,
    CACHE_NEED_PS,
    CACHE_NEED_PS_DATE,
    CACHE_NEED_PS_AUTHOR,
    CACHE_NEED_PS_DESCR,
    CACHE_NEED_PS_EOD,
    CACHE_NEED_PS_MEMBERS,
    CACHE_NEED_PS_EOM
};

static int read_cache()
{
    FILE * fp;
    char buff[BUFSIZ];
    int state = CACHE_NEED_FILE;
    CvsFile * f = NULL;
    PatchSet * ps = NULL;
    char datebuff[20] = "";
    char authbuff[AUTH_STR_MAX] = "";
    char logbuff[LOG_STR_MAX] = "";

    if (!(fp = fopen("CVS/cvsps.cache", "r")))
	return -1;

    /* first line is date cache was created, format "cache date: %d\n" */
    if (!fgets(buff, BUFSIZ, fp) || strncmp(buff, "cache date:", 11))
    {
	debug(DEBUG_APPERROR, "bad CVS/cvsps.cache file");
	return -1;
    }

    cache_date = atoi(buff + 12);
    debug(DEBUG_STATUS, "read cache_date %d", (int)cache_date);

    while (fgets(buff, BUFSIZ, fp))
    {
	int len = strlen(buff);

	switch(state)
	{
	case CACHE_NEED_FILE:
	    if (strncmp(buff, "file:", 5) == 0)
	    {
		len -= 6;
		f = create_cvsfile();
		f->filename = xstrdup(buff + 6);
		f->filename[len-1] = 0; /* Remove the \n at the end of line */
		debug(DEBUG_STATUS, "read cache filename '%s'", f->filename);
		put_hash_object(file_hash, f->filename, f);
		state = CACHE_NEED_REV;
	    }
	    else
	    {
		state = CACHE_NEED_PS;
	    }
	    break;
	case CACHE_NEED_REV:
	    if (isdigit(buff[0]))
	    {
		buff[len-1] = 0;
		cvs_file_add_revision(f, buff);
	    }
	    else
	    {
		state = CACHE_NEED_BRANCHES;
	    }
	    break;
	case CACHE_NEED_BRANCHES:
	    if (buff[0] != '\n')
	    {
		char * tag;

		tag = strchr(buff, ':');
		if (tag)
		{
		    *tag = 0;
		    tag += 2;
		    buff[len - 1] = 0;
		    cvs_file_add_branch(f, buff, tag);
		}
	    }
	    else
	    {
		state = CACHE_NEED_FILE;
	    }
	    break;
	case CACHE_NEED_PS:
	    if (strncmp(buff, "patchset:", 9) == 0)
		state = CACHE_NEED_PS_DATE;
	    break;
	case CACHE_NEED_PS_DATE:
	    if (strncmp(buff, "date:", 5) == 0)
	    {
		/* remove prefix "date: " and LF from len */
		len -= 6;
		strzncpy(datebuff, buff + 6, MIN(len, sizeof(datebuff)));
		state = CACHE_NEED_PS_AUTHOR;
	    }
	    break;
	case CACHE_NEED_PS_AUTHOR:
	    if (strncmp(buff, "author:", 7) == 0)
	    {
		/* remove prefix "author: " and LF from len */
		len -= 8;
		strzncpy(authbuff, buff + 8, MIN(len, AUTH_STR_MAX));
		state = CACHE_NEED_PS_DESCR;
	    }
	    break;
	case CACHE_NEED_PS_DESCR:
	    if (strncmp(buff, "descr:", 6) == 0)
		state = CACHE_NEED_PS_EOD;
	    break;
	case CACHE_NEED_PS_EOD:
	    if (strcmp(buff, CACHE_DESCR_BOUNDARY) == 0)
	    {
		debug(DEBUG_STATUS, "patch set %s %s %s", datebuff, authbuff, logbuff);
		ps = get_patch_set(datebuff, logbuff, authbuff);
		state = CACHE_NEED_PS_MEMBERS;
	    }
	    else
	    {
		/* Make sure we have enough in the buffer */
		if (strlen(logbuff)+strlen(buff)<LOG_STR_MAX)
		    strcat(logbuff, buff);
	    }
	    break;
	case CACHE_NEED_PS_MEMBERS:
	    if (strncmp(buff, "members:", 8) == 0)
		state = CACHE_NEED_PS_EOM;
	    break;
	case CACHE_NEED_PS_EOM:
	    if (buff[0] == '\n')
	    {
		datebuff[0] = 0;
		authbuff[0] = 0;
		logbuff[0] = 0;
		state = CACHE_NEED_PS;
	    }
	    else
	    {
		PatchSetMember * psm = create_patchset_member();
		parse_cache_revision(psm, buff);
		psm->ps = ps;
		list_add(&psm->link, psm->ps->members.prev);
	    }
	    break;
	}
    }

    return 0;
}

static CvsFile * create_cvsfile()
{
    CvsFile * f = (CvsFile*)calloc(1, sizeof(*f));
    if (!f)
	return NULL;

    f->revisions = create_hash_table(1);
    f->branches = create_hash_table(1);
    f->branches_sym = create_hash_table(1);

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

static PatchSet * create_patchset()
{
    PatchSet * ps = (PatchSet*)calloc(1, sizeof(*ps));;
    
    if (ps)
	INIT_LIST_HEAD(&ps->members);

    return ps;
}

static PatchSetMember * create_patchset_member()
{
    PatchSetMember * psm = (PatchSetMember*)calloc(1, sizeof(*psm));
    psm->pre_rev = NULL;
    psm->post_rev = NULL;
    psm->file = NULL;
    return psm;
}

static PatchSetRange * create_patchset_range()
{
    PatchSetRange * psr = (PatchSetRange*)calloc(1, sizeof(*psr));
    return psr;
}

static void parse_cache_revision(PatchSetMember * psm, const char * buff)
{
    /* The format used to generate is:
     * "file: %s; pre_rev: %s; post_rev: %s; dead: %d\n"
     */
    const char *s, *p;
    char fn[PATH_MAX];
    char pre[REV_STR_MAX];
    char post[REV_STR_MAX];
    
    s = buff + 6;
    p = strchr(buff, ';');
    strzncpy(fn, s,  p - s + 1);
    
    psm->file = (CvsFile*)get_hash_object(file_hash, fn);

    if (!psm->file)
    {
	debug(DEBUG_APPERROR, "file %s not found in hash", fn);
	return;
    }

    s = p + 11;
    p = strchr(s, ';');
    strzncpy(pre, s, p - s + 1);

    s = p + 12;
    p = strchr(s, ';');
    strzncpy(post, s, p - s + 1);

    psm->pre_rev = file_get_revision(psm->file, pre);
    psm->post_rev = file_get_revision(psm->file, post);
    psm->post_rev->dead = atoi(p + 8);
    psm->post_rev->psm = psm;
}

static CvsFileRevision * file_get_revision(CvsFile * file, const char * r)
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

static void parse_sym(CvsFile * file, char * sym)
{
    char * tag = sym, *eot;
    int leaf, final_branch;
    char rev[REV_STR_MAX];
    char rev2[REV_STR_MAX];
    
    /* this routine looks for and parses lines formatted as:
     * <white space>tag_name: <rev>;
     * where rev is a sequence of integers separated by '.'
     * AND where the second to last number is a 0.  This is
     * the 'magic-branch-tag' format used internally to CVS
     * and made visible in the 'cvs log' command.
     */

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
	return;

    if (!get_branch_ext(rev2, rev, &final_branch))
	return;
    
    if (final_branch != 0)
	return;

    snprintf(rev, REV_STR_MAX, "%s.%d", rev2, leaf);
    debug(DEBUG_STATUS, "got sym: %s for %s", tag, rev);

    cvs_file_add_branch(file, rev, tag);
}

static char * cvs_file_add_branch(CvsFile * file, const char * rev, const char * tag)
{
    char * new_tag;
    char * new_rev;

    if (get_hash_object(file->branches, rev))
    {
	debug(DEBUG_STATUS, "attempt to add existing branch %s:%s to %s", 
	      rev, tag, file->filename);
	return NULL;
    }

    new_tag = get_string(tag);
    new_rev = get_string(rev);
    put_hash_object(file->branches, new_rev, new_tag);
    put_hash_object(file->branches_sym, new_tag, new_rev);
    
    return new_tag;
}

static void count_hash(struct hash_table *hash, unsigned int *total, 
	unsigned int *max_val)
{
    int counter = 0;
    struct hash_entry *fh;
    
    reset_hash_iterator(hash);
    while ((fh = next_hash_entry(hash)))
	counter++;

    *total += counter;
    *max_val= MAX(*max_val, counter);
}

static unsigned int num_patchsets = 0;
static unsigned int num_ps_member = 0, max_ps_member_in_ps = 0;
static unsigned int num_authors = 0, max_author_len = 0, total_author_len = 0;
static unsigned int max_descr_len = 0, total_descr_len = 0;
struct hash_table *author_hash;

static void stat_ps_tree_node(const void * nodep, const VISIT which, const int depth)
{
    int desc_len;
    PatchSet * ps;
    struct list_head * next;
    int counter;

    /* Make sure we have it if we do statistics */
    if (!author_hash)
	author_hash = create_hash_table(1023);

    switch(which)
    {
    case postorder:
    case leaf:
	ps = *(PatchSet**)nodep;
	num_patchsets++;

	/* Author statistics */
	if (!put_hash_object(author_hash, ps->author, ps->author))
	{
	    int len = strlen(ps->author);
	    num_authors++;
	    max_author_len = MAX(max_author_len, len);
	    total_author_len += len;
	}

	/* Log message statistics */
	desc_len = strlen(ps->descr);
	max_descr_len = MAX(max_descr_len, desc_len);
	total_descr_len += desc_len;
	
	/* PatchSet member statistics */
	counter = 0;
	next = ps->members.next;
	while (next != &ps->members)
	{
	    counter++;
	    next = next->next;
	}

	num_ps_member += counter;
	max_ps_member_in_ps = MAX(max_ps_member_in_ps, counter);
	break;

    default:
	break;
    }
}

static void print_statistics(void)
{
    /* Statistics data */
    unsigned int num_files = 0, max_file_len = 0, total_file_len = 0;
    unsigned int total_revisions = 0, max_revisions_for_file = 0;
    unsigned int total_branches = 0, max_branches_for_file = 0;
    unsigned int total_branches_sym = 0, max_branches_sym_for_file = 0;

    /* Other vars */
    struct hash_entry *he;
   
    fflush(stdout);

    /* Gather file statistics */
    reset_hash_iterator(file_hash);
    while ((he=next_hash_entry(file_hash)))
    {
	int len = strlen(he->he_key);
	CvsFile *file = (CvsFile *)he->he_obj;
	
	num_files++;
	max_file_len = MAX(max_file_len, len);
	total_file_len += len;

	count_hash(file->revisions, &total_revisions, &max_revisions_for_file);
	count_hash(file->branches, &total_branches, &max_branches_for_file);
	count_hash(file->branches_sym, &total_branches_sym,
	    &max_branches_sym_for_file);
    }

    /* Print file statistics */
    printf("Num files: %d\nMax filename len: %d, Average filename len: %.2f\n",
	    num_files, max_file_len, (float)total_file_len/num_files);

    printf("Max revisions for file: %d, Average revisions for file: %.2f\n",
	  max_revisions_for_file, (float)total_revisions/num_files);
    printf("Max branches for file: %d, Average branches for file: %.2f\n",
	  max_branches_for_file, (float)total_branches/num_files);
    printf("Max branches_sym for file: %d, Average branches_sym for file: %.2f\n",
	  max_branches_sym_for_file, (float)total_branches_sym/num_files);

    /* Gather patchset statistics */
    twalk(ps_tree, stat_ps_tree_node);

    /* Print patchset statistics */
    printf("Num patchsets: %d\n", num_patchsets);
    printf("Max PS members in PS: %d\nAverage PS members in PS: %.2f\n",
	    max_ps_member_in_ps, (float)num_ps_member/num_patchsets);
    printf("Num authors: %d, Max author len: %d, Avg. author len: %.2f\n", 
	    num_authors, max_author_len, (float)total_author_len/num_authors);
    printf("Max desc len: %d, Avg. desc len: %.2f\n",
	    max_descr_len, (float)total_descr_len/num_patchsets);
}

