#ifndef CVSPS_H
#define CVSPS_H

extern struct hash_table * file_hash;

CvsFile * create_cvsfile();
char *xstrdup(char const *);
CvsFileRevision * cvs_file_add_revision(CvsFile *, char *);
char * cvs_file_add_branch(CvsFile *, const char *, const char *);
void strzncpy(char * dst, const char * src, int n);
PatchSet * get_patch_set(const char *, const char *, const char *, const char *);
PatchSetMember * create_patchset_member();
CvsFileRevision * file_get_revision(CvsFile *, const char *);

#endif /* CVSPS_H */
