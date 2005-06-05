#ifndef UTIL_H
#define UTIL_H

#define CVSPS_PREFIX ".cvsps"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

char *xstrdup(char const *);
void strzncpy(char * dst, const char * src, int n);
char *readfile(char const *filename, char *buf, size_t size);
char *strrep(char *s, char find, char replace);
char *get_cvsps_dir();
char *get_string(char const *str);
void convert_date(time_t *, const char *);
void timing_start();
void timing_stop(const char *);
int my_system(const char *);
int escape_filename(char *, int, const char *);
void strcpy_a(char * dst, const char * src, int n);

#endif /* UTIL_H */
