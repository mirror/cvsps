#ifndef CVS_DIRECT_H
#define CVS_DIRECT_H

typedef struct _CvsServerCtx CvsServerCtx;

CvsServerCtx * open_cvs_server(char * root);
void close_cvs_server(CvsServerCtx*);
void cvs_rdiff(CvsServerCtx *, const char *, const char *, const char *, const char *, const char *);

#endif /* CVS_DIRECT_H */
