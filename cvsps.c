#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <common/hash.h>
#include <common/list.h>
#include <common/text_util.h>
#include <common/debug.h>

#define CVS_LOG_MAX 8192

enum
{
    NEED_FILE,
    NEED_START_LOG,
    NEED_REVISION,
    NEED_DATE_AND_AUTHOR,
    NEED_EOM
};

typedef struct _CvsFile
{
    char filename[PATH_MAX];
    struct list_head patch_sets;
} CvsFile;

typedef struct _PatchSet
{
    char id[16];
    char date[20];
    char author[64];
    char descr[CVS_LOG_MAX];
    struct list_head members;
} PatchSet;

typedef struct _PatchSetMember
{
    char pre_rev[16];
    char post_rev[16];
    PatchSet * cp;
    CvsFile * file;
    struct list_head file_link;
    struct list_head patch_set_link;
} PatchSetMember;

static int ps_counter;
static struct hash_table * file_hash;
static struct hash_table * ps_hash;

static CvsFile * parse_file(const char *);
static PatchSetMember * parse_revision(const char *);
static PatchSet * get_patch_set(const char *, const char *, const char *);

int main()
{
    FILE * cvsfp;
    char buff[BUFSIZ];
    int state = NEED_FILE;
    struct hash_entry * he;
    CvsFile * file = NULL;
    PatchSetMember * psm = NULL;
    char datebuff[20];
    char authbuff[64];
    char logbuff[CVS_LOG_MAX];
    
    //chdir("../pricing_engine");

    file_hash = create_hash_table(1023);
    ps_hash = create_hash_table(1023);

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
		state++;
	    }
	    break;
	case NEED_START_LOG:
	    if (strncmp(buff, "--------", 8) == 0)
		state++;
	    break;
	case NEED_REVISION:
	    if (strncmp(buff, "revision", 8) == 0)
	    {
		psm = parse_revision(buff);
		psm->file = file;
		list_add(&psm->file_link, file->patch_sets.prev);
		state++;
	    }
	    break;
	case NEED_DATE_AND_AUTHOR:
	    if (strncmp(buff, "date:", 5) == 0)
	    {
		char * p;
		strncpy(datebuff, buff + 6, 19);
		datebuff[19] = 0;
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
		
		state++;
	    }
	    break;
	case NEED_EOM:
	    if (strncmp(buff, "--------", 8) == 0)
	    {
		psm->cp = get_patch_set(datebuff, logbuff, authbuff);
		list_add(&psm->patch_set_link, &psm->cp->members);
		datebuff[0] = 0;
		logbuff[0] = 0;
		psm = NULL;
		state = NEED_REVISION;
	    }
	    else if (strncmp(buff, "========", 8) == 0)
	    {
		psm->cp = get_patch_set(datebuff, logbuff, authbuff);
		datebuff[0] = 0;
		logbuff[0] = 0;
		psm = NULL;
		file = NULL;
		state = NEED_FILE;
	    }
	    else
	    {
		strcat(logbuff, buff);
	    }

	    break;
	}
    }

    pclose(cvsfp);

    reset_hash_iterator(ps_hash);
    while((he = next_hash_entry(ps_hash)))
    {
	PatchSet * ps = (PatchSet*)he->he_obj;
	struct list_head * next = ps->members.next;

	printf("---------------------\n");
	printf("PatchSet %s\n", ps->id);
	printf("Date: %s\n", ps->date);
	printf("Author: %s\n", ps->author);
	printf("Log:\n%s", ps->descr);
	printf("Members: ");

	while (next != &ps->members)
	{
	    PatchSetMember * psm = list_entry(next, PatchSetMember, patch_set_link);
	    printf("%s:%s ", psm->file->filename, psm->post_rev);
	    next = next->next;
	}
	
	printf("\n");
    }

    exit(0);
}

static CvsFile * parse_file(const char * buff)
{
    CvsFile * retval;

    retval = (CvsFile*)get_hash_object(file_hash, buff + 10);

    if (!retval)
    {
	if ((retval = (CvsFile*)malloc(sizeof(*retval))))
	{
	    strcpy(retval->filename, buff + 10);
	    chop(retval->filename);
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
    strcpy(retval->post_rev, buff + 9);
    chop(retval->post_rev);
    retval->cp = NULL;

    debug(DEBUG_STATUS, "new rev: %s", retval->post_rev);

    return retval;
}

static PatchSet * get_patch_set(const char * dte, const char * log, const char * author)
{
    char key[CVS_LOG_MAX + 20];
    PatchSet * retval;

    /* just date and author are key.  how could one person commit twice in same second... */
    strcpy(key, dte);
    strcat(key, author);

    //debug(DEBUG_STATUS, "cp key: %s", key);

    retval = (PatchSet*)get_hash_object(ps_hash, key);

    if (!retval)
    {
	if ((retval = (PatchSet*)malloc(sizeof(*retval))))
	{
	    sprintf(retval->id, "%d", ps_counter++);
	    strcpy(retval->date, dte);
	    strcpy(retval->descr, log);
	    strcpy(retval->author, author);
	    INIT_LIST_HEAD(&retval->members);

	    put_hash_object(ps_hash, key, retval);
	}
	debug(DEBUG_STATUS, "new PatchSet: %s", retval->id);
    }
    else
    {
	debug(DEBUG_STATUS, "found existing PatchSet %s", retval->id);
    }

    return retval;
}
