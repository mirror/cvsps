#include <stdio.h>
#include <search.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include <cbtcommon/hash.h>
#include <cbtcommon/debug.h>

#include "cache.h"
#include "cvsps_types.h"
#include "cvsps.h"
#include "util.h"

#define CACHE_DESCR_BOUNDARY "-=-END CVSPS DESCR-=-\n"

/* the tree walk pretty much requries use of globals :-( */
static FILE * cache_fp;
static int ps_counter;

static void write_tree_node_to_cache(const void *, const VISIT, const int);
static void parse_cache_revision(PatchSetMember *, const char *);
static void dump_patch_set(FILE *, PatchSet *);

static FILE *cache_open(char const *mode)
{
    char root[PATH_MAX];
    char repository[PATH_MAX];
    char *prefix, *tmp1, *tmp2;
    char fname[PATH_MAX];
    FILE * fp;

    /* Get the prefix */
    prefix = get_cvsrc_dir();
    if (!prefix)
	return NULL;
    
    /* Generate the full path */
    tmp1 = readfile("CVS/Root", root, sizeof(root));
    tmp2 = readfile("CVS/Repository", repository, sizeof(repository));
    if (!tmp1 || !tmp2)
	return NULL;

    strrep(root, '/', '#');
    strrep(repository, '/', '#');

    snprintf(fname, PATH_MAX, "%s/%s#%s", prefix, root, repository);
    
    if (!(fp = fopen(fname, mode)) && *mode == 'r')
    {
	if ((fp = fopen("CVS/cvsps.cache", mode)))
	{
	    fprintf(stderr, "\n");
	    fprintf(stderr, "****WARNING**** Obsolete CVS/cvsps.cache file found.\n");
	    fprintf(stderr, "                New file will be re-written in ~/%s/\n", CVSPS_PREFIX);
	    fprintf(stderr, "                Old file will be ignored.\n");
	    fprintf(stderr, "                Please manually remove.\n");
	    fprintf(stderr, "                Continuing in 5 seconds.\n");
	    sleep(5);
	    fclose(fp);
	    fp = NULL;
	}
    }

    return fp;
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
    CACHE_NEED_PS_BRANCH,
    CACHE_NEED_PS_DESCR,
    CACHE_NEED_PS_EOD,
    CACHE_NEED_PS_MEMBERS,
    CACHE_NEED_PS_EOM
};

time_t read_cache()
{
    FILE * fp;
    char buff[BUFSIZ];
    int state = CACHE_NEED_FILE;
    CvsFile * f = NULL;
    PatchSet * ps = NULL;
    char datebuff[20] = "";
    char authbuff[AUTH_STR_MAX] = "";
    char branchbuff[AUTH_STR_MAX] = "";
    char logbuff[LOG_STR_MAX] = "";
    time_t cache_date;

    if (!(fp = cache_open("r")))
	return -1;

    /* first line is date cache was created, format "cache date: %d\n" */
    if (!fgets(buff, BUFSIZ, fp) || strncmp(buff, "cache date:", 11))
    {
	debug(DEBUG_APPERROR, "bad cvsps.cache file");
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
		state = CACHE_NEED_PS_BRANCH;
	    }
	    break;
	case CACHE_NEED_PS_BRANCH:
	    if (strncmp(buff, "branch:", 7) == 0)
	    {
		/* remove prefix "branch: " and LF from len */
		len -= 8;
		strzncpy(branchbuff, buff + 8, MIN(len, AUTH_STR_MAX));
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
		debug(DEBUG_STATUS, "patch set %s %s %s %s", datebuff, authbuff, logbuff, branchbuff);
		ps = get_patch_set(datebuff, logbuff, authbuff, branchbuff);
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

    return cache_date;
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
    psm->post_rev->post_psm = psm;
}

void write_cache(time_t cache_date, void * ps_tree_bytime)
{
    struct hash_entry * file_iter;

    ps_counter = 0;

    if ((cache_fp = cache_open("w")) == NULL)
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

