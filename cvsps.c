#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <search.h>
#include <time.h>
#include <common/hash.h>
#include <common/list.h>
#include <common/text_util.h>
#include <common/debug.h>

#define LOG_STR_MAX 8192
#define AUTH_STR_MAX 64
#define REV_STR_MAX 64
#define min(a, b) ((a) < (b) ? (a) : (b))

enum
{
    NEED_FILE,
    NEED_START_LOG,
    NEED_REVISION,
    NEED_DATE_AUTHOR_STATE,
    NEED_EOM
};

typedef struct _CvsFile
{
    char filename[PATH_MAX];
    struct list_head patch_sets;
} CvsFile;

typedef struct _PatchSet
{
    time_t date;
    char author[AUTH_STR_MAX];
    char descr[LOG_STR_MAX];
    struct list_head members;
} PatchSet;

typedef struct _PatchSetMember
{
    char pre_rev[REV_STR_MAX];
    char post_rev[REV_STR_MAX];
    PatchSet * cp;
    CvsFile * file;
    int dead_revision;
    struct list_head file_link;
    struct list_head patch_set_link;
} PatchSetMember;

static int ps_counter;
static struct hash_table * file_hash;
static void * ps_tree;
static int timestamp_fuzz_factor = 300;
static const char * restrict_author;
static const char * restrict_file;
static time_t restrict_date_start;
static time_t restrict_date_end;
static int show_patch_set;
static char strip_path[PATH_MAX];
static int strip_path_len;

static void parse_args(int, char *[]);
static void init_strip_path();
static CvsFile * parse_file(const char *);
static PatchSetMember * parse_revision(const char *);
static PatchSet * get_patch_set(const char *, const char *, const char *);
static void assign_pre_revision(PatchSetMember *, PatchSetMember *);
static void check_print_patch_set(PatchSet *);
static void print_patch_set(PatchSet *);
static void show_ps_tree_node(const void *, const VISIT, const int);
static int compare_patch_sets(const void *, const void *);
static void convert_date(time_t *, const char *);
static int is_revision_metadata(const char *);
static int patch_set_contains_member(PatchSet *, const char *);
static void do_cvs_diff(PatchSet *);
static void strzncpy(char *, const char *, int);

int main(int argc, char *argv[])
{
    FILE * cvsfp;
    char buff[BUFSIZ];
    int state = NEED_FILE;
    CvsFile * file = NULL;
    PatchSetMember * psm = NULL, * last_psm = NULL;
    char datebuff[20];
    char authbuff[AUTH_STR_MAX];
    char logbuff[LOG_STR_MAX];
    int loglen = 0;
    int have_log = 0;
    
    parse_args(argc, argv);
    file_hash = create_hash_table(1023);
    ps_tree = NULL;
    init_strip_path();

    cvsfp = popen("cvs log", "r");

    if (!cvsfp)
    {
	perror("can't open cvs pipe\n");
	exit(1);
    }
    
    while(fgets(buff, BUFSIZ, cvsfp))
    {
	//debug(DEBUG_STATUS, "state: %d read line:%s", state, buff);

	switch(state)
	{
	case NEED_FILE:
	    if (strncmp(buff, "RCS file", 8) == 0)
	    {
		file = parse_file(buff);
		state = NEED_START_LOG;
	    }
	    break;
	case NEED_START_LOG:
	    if (strncmp(buff, "--------", 8) == 0)
		state = NEED_REVISION;
	    break;
	case NEED_REVISION:
	    if (strncmp(buff, "revision", 8) == 0)
	    {
		psm = parse_revision(buff);
		psm->file = file;

		/* in the simple case, we are copying psm->post_rev to last_psm->pre_rev
		 * since generally speaking the log is reverse chronological.
		 * This breaks down slightly when branches are introduced 
		 */
		assign_pre_revision(last_psm, psm);
		last_psm = psm;
		list_add(&psm->file_link, file->patch_sets.prev);
		state = NEED_DATE_AUTHOR_STATE;
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
			strncpy(authbuff, p, op - p);
			authbuff[op - p] = 0;
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
			if (strncmp(p, "dead", min(4, op - p)) == 0)
			    psm->dead_revision = 1;
		}

		state = NEED_EOM;
	    }
	    break;
	case NEED_EOM:
	    if (strncmp(buff, "--------", 8) == 0)
	    {
		psm->cp = get_patch_set(datebuff, logbuff, authbuff);
		list_add(&psm->patch_set_link, &psm->cp->members);
		logbuff[0] = 0;
		loglen = 0;
		psm = NULL;
		state = NEED_REVISION;
		have_log = 0;
	    }
	    else if (strncmp(buff, "========", 8) == 0)
	    {
		psm->cp = get_patch_set(datebuff, logbuff, authbuff);
		list_add(&psm->patch_set_link, &psm->cp->members);
		logbuff[0] = 0;
		loglen = 0;
		assign_pre_revision(last_psm, NULL);
		psm = NULL;
		last_psm = NULL;
		file = NULL;
		state = NEED_FILE;
		have_log = 0;
	    }
	    else
	    {
		/* other "blahblah: information;" messages can 
		 * follow the stuff we pay attention to
		 */
		if (have_log || !is_revision_metadata(buff))
		{
		    int len;
		    
		    len = min(LOG_STR_MAX - loglen, strlen(buff));
		    memcpy(logbuff + loglen, buff, len);
		    loglen += len;
		    logbuff[loglen - 1] = 0;

		    have_log = 1;
		}
		else 
		{
		    debug(DEBUG_STATUS, "ignoring unneeded info %s", buff);
		}
	    }

	    break;
	}
    }

    pclose(cvsfp);
    twalk(ps_tree, show_ps_tree_node);

    exit(0);
}

static void usage(const char * str1, const char * str2)
{
    debug(DEBUG_APPERROR, "\nbad usage: %s %s\n", str1, str2);
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
	    if (++i >= argc)
		usage("argument to -s missing", "");

	    show_patch_set = atoi(argv[i++]);
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

    retval = (CvsFile*)get_hash_object(file_hash, buff + 10);

    if (!retval)
    {
	if ((retval = (CvsFile*)malloc(sizeof(*retval))))
	{
	    int len = strlen(buff + 10);
	    char * p;
	    
	    /* chop the ",v" string and the "LF" */
	    len -= 3;
	    memcpy(retval->filename, buff + 10, len);
	    retval->filename[len] = 0;
	    
	    if (strncmp(retval->filename, strip_path, strip_path_len) != 0)
	    {
		debug(DEBUG_APPERROR, "filename %s doesn't match strip_path %s", 
		      retval->filename, strip_path);
		exit(1);
	    }

	    /* remove from beginning the 'strip_path' string */
	    len -= strip_path_len;
	    memmove(retval->filename, retval->filename + strip_path_len, len);
	    retval->filename[len] = 0;

	    /* check if file is in the 'Attic/' and remove it */
	    if ((p = strrchr(retval->filename, '/')) && 
		p - retval->filename >= 5 && strncmp(p - 5, "Attic", 5) == 0)
	    {
		memmove(p - 5, p + 1, len - (p - retval->filename + 1));
		len -= 6;
		retval->filename[len] = 0;
	    }

	    INIT_LIST_HEAD(&retval->patch_sets);
	    put_hash_object(file_hash, retval->filename, retval);
	}
    }

    debug(DEBUG_STATUS, "new file: %s", retval->filename);

    return retval;
}

static PatchSetMember * parse_revision(const char * buff)
{
    PatchSetMember * retval = (PatchSetMember*)malloc(sizeof(*retval));

    //FIXME: what about pre_rev?
    strcpy(retval->pre_rev, "UNKNOWN");
    strzncpy(retval->post_rev, buff + 9, REV_STR_MAX);
    chop(retval->post_rev);
    retval->cp = NULL;
    retval->dead_revision = 0;

    debug(DEBUG_STATUS, "new rev: %s", retval->post_rev);

    return retval;
}

static PatchSet * get_patch_set(const char * dte, const char * log, const char * author)
{
    PatchSet * retval = NULL, **find = NULL;
    
    if (!(retval = (PatchSet*)malloc(sizeof(*retval))))
    {
	debug(DEBUG_SYSERROR, "malloc failed for PatchSet");
	return NULL;
    }

    convert_date(&retval->date, dte);
    strzncpy(retval->author, author, AUTH_STR_MAX);
    strzncpy(retval->descr, log, LOG_STR_MAX);
    INIT_LIST_HEAD(&retval->members);

    find = (PatchSet**)tsearch(retval, &ps_tree, compare_patch_sets);

    if (*find != retval)
    {
	debug(DEBUG_STATUS, "found existing patch set");
	free(retval);
	retval = *find;
    }
    else
    {
	debug(DEBUG_STATUS, "new patch set!");
	debug(DEBUG_STATUS, "%s %s %s", retval->author, retval->descr, dte);
    }

    return retval;
}

static int get_branch(char * buff, const char * rev)
{
    char * p;
    strcpy(buff, rev);
    p = strrchr(buff, '.');
    if (!p)
	return 0;
    *p = 0;
    return 1;
}

static void assign_pre_revision(PatchSetMember * last_psm, PatchSetMember * psm)
{
    char pre[REV_STR_MAX], post[REV_STR_MAX];

    if (!last_psm)
	return;
    
    if (!psm)
    {
	/* if last_psm was last rev. for file, it's either an 
	 * INITIAL, or head of a branch.  to test if it's 
	 * the head of a branch, do get_branch twice
	 */
	if (get_branch(post, last_psm->post_rev) && 
	    get_branch(pre, post))
	    strcpy(last_psm->pre_rev, pre);
	else
	    strcpy(last_psm->pre_rev, "INITIAL");
	return;
    }

    /* are the two revisions on the same branch? */
    if (!get_branch(pre, psm->post_rev))
	return;

    if (!get_branch(post, last_psm->post_rev))
	return;

    if (strcmp(pre, post) == 0)
    {
	strcpy(last_psm->pre_rev, psm->post_rev);
	return;
    }
    
    /* branches don't match. psm must be head of branch,
     * so last_psm is first rev. on branch. or first
     * revision overall.  if former, derive predecessor.  
     * use get_branch to chop another rev. off of string.
     */
    if (!get_branch(pre, post))
    {
	strcpy(last_psm->pre_rev, "INITIAL");
	return;
    }
    
    strcpy(last_psm->pre_rev, pre);
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
    printf("Log:\n%s", ps->descr);
    printf("Members: \n");
    
    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, patch_set_link);
	printf("\t%s:%s->%s%s\n", psm->file->filename, psm->pre_rev, psm->post_rev, psm->dead_revision ? "(DEAD)": "");
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

	if (show_patch_set > 0)
	{
	    if (ps_counter == show_patch_set)
	    {
		print_patch_set(ps);
		do_cvs_diff(ps);
		exit(0);
	    }
	    break;
	}

	check_print_patch_set(ps);

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

    diff = ps1->date - ps2->date;

    if (labs(diff) > timestamp_fuzz_factor)
	return (diff < 0) ? -1 : 1;

    ret = strcmp(ps1->author, ps2->author);

    if (ret)
	return ret;

    return strcmp(ps1->descr, ps2->descr);
}

static void convert_date(time_t * t, const char * dte)
{
    struct tm tm;
    int ret;
    
    memset(&tm, 0, sizeof(tm));
    ret = sscanf(dte, "%d/%d/%d %d:%d:%d", 
	   &tm.tm_year, &tm.tm_mon, &tm.tm_mday, 
	   &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    
    tm.tm_year -= 1900;
    tm.tm_mon--;

    *t = mktime(&tm);
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
	PatchSetMember * psm = list_entry(next, PatchSetMember, patch_set_link);
	
	if (strstr(psm->file->filename, file))
	    return 1;

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
	PatchSetMember * psm = list_entry(next, PatchSetMember, patch_set_link);
	char cmdbuff[PATH_MAX * 2];

	if (strcmp(psm->pre_rev, "INITIAL") == 0)
	{
	    snprintf(cmdbuff, PATH_MAX * 2, "cvs update -p -r %s %s | diff -u /dev/null - | sed -e '1 s|^--- /dev/null|--- %s|g' -e '2 s|^+++ -|+++ %s|g'",
		     psm->post_rev, psm->file->filename, psm->file->filename, psm->file->filename);
	}
	else if (psm->dead_revision)
	{
	    snprintf(cmdbuff, PATH_MAX * 2, "cvs update -p -r %s %s | diff -u - /dev/null | sed -e '1 s|^--- -|--- %s|g' -e '2 s|^+++ /dev/null|+++ %s|g'",
		     psm->pre_rev, psm->file->filename, psm->file->filename, psm->file->filename);
	    
	}
	else
	{
	    snprintf(cmdbuff, PATH_MAX * 2, "cvs diff -u -r %s -r %s %s",
		     psm->pre_rev, psm->post_rev, psm->file->filename);
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
