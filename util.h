#ifndef UTIL_H
#define UTIL_H

#define CVSPS_PREFIX ".cvsps"

char *xstrdup(char const *);
void strzncpy(char * dst, const char * src, int n);
char *readfile(char const *filename, char *buf, size_t size);
char *strrep(char *s, char find, char replace);
char *get_cvsrc_dir();
char *get_string(char const *str);

#endif /* UTIL_H */
