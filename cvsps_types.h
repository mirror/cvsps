#ifndef CVSPS_TYPES_H
#define CVSPS_TYPES_H

#define LOG_STR_MAX 8192
#define AUTH_STR_MAX 64
#define REV_STR_MAX 64
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

typedef struct _CvsFile CvsFile;
typedef struct _PatchSet PatchSet;
typedef struct _PatchSetMember PatchSetMember;
typedef struct _PatchSetRange PatchSetRange;
typedef struct _CvsFileRevision CvsFileRevision;
typedef struct _GlobalSymbol GlobalSymbol;
typedef struct _Tag Tag;

struct _CvsFileRevision
{
    char * rev;
    int dead;
    CvsFile * file;
    char * branch;
    /*
     * A revision can be part of man PatchSets because it may
     * be the branch point of many branches (as a pre_rev).  
     * It should, however, be the 'post_rev' of only one 
     * PatchSetMember.  The 'main line of inheritence' is
     * kept in pre_psm, and all 'branch revisions' are kept
     * in a list.
     */
    PatchSetMember * pre_psm;
    PatchSetMember * post_psm;
    struct list_head branch_children;
    
    /* 
     * for linking this 'branch head' into the parent revision list
     */
    struct list_head link;

    /*
     * A list of all Tag structures tagging this revision
     */
    struct list_head tags;
};

struct _CvsFile
{
    char *filename;
    struct hash_table * revisions;    /* rev_str to revision [CvsFileRevision*] */
    struct hash_table * branches;     /* branch to branch_sym map [char*]       */
    struct hash_table * branches_sym; /* branch_sym to branch map [char*]       */
    struct hash_table * symbols;      /* tag to revision [CvsFileRevision*]     */
    /* 
     * this is a hack. when we initially create entries in the symbol hash
     * we don't have the branch info, so the CvsFileRevisions get created 
     * with the branch attribute NULL.  Later we need to resolve these.
     */
    int have_branches;
};

struct _PatchSet
{
    time_t date;
    char *descr;
    char *author;
    char *tag;
    int valid_tag;
    char *branch;
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

struct _GlobalSymbol
{
    char * tag;
    PatchSet * ps;
    struct list_head tags;
};

struct _Tag
{
    GlobalSymbol * sym;
    CvsFileRevision * rev;
    char * tag;
    struct list_head global_link;
    struct list_head rev_link;
};

#endif /* CVSPS_TYPES_H */
