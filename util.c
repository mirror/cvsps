#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <search.h>
#include <time.h>
#include <sys/stat.h>

#include <cbtcommon/debug.h>

#include "util.h"

typedef int (*compare_func)(const void *, const void *);

static void * string_tree;

char *readfile(char const *filename, char *buf, size_t size)
{
    FILE *fp;
    char *ptr;
    size_t len;

    fp = fopen(filename, "r");
    if (!fp)
	return NULL;

    ptr = fgets(buf, size, fp);
    fclose(fp);

    if (!ptr)
	return NULL;

    len = strlen(buf);
    if (buf[len-1] == '\n')
	buf[len-1] = '\0';
    
    return buf;
}

char *strrep(char *s, char find, char replace)
{
    char * p = s;
    while (*p)
    {
	if (*p == find)
	    *p = replace;
	p++;
    }

    return s;
}

char *get_cvsrc_dir()
{
    struct stat sbuf;
    static char prefix[PATH_MAX];
    const char * home;

    if (!(home = getenv("HOME")))
    {
	debug(DEBUG_APPERROR, "HOME environment variable not set");
	exit(1);
    }

    if (snprintf(prefix, PATH_MAX, "%s/%s", home, CVSPS_PREFIX) >= PATH_MAX)
    {
	debug(DEBUG_APPERROR, "prefix buffer overflow");
	exit(1);
    }

    /* Make sure the prefix directory exists */
    if (stat(prefix, &sbuf) < 0)
    {
	int ret;
	ret = mkdir(prefix, 0777);
	if (ret < 0)
	{
	    debug(DEBUG_SYSERROR, "Cannot create the cvsps directory '%s'", CVSPS_PREFIX);
	    exit(1);
	}
    }
    else
    {
	if (!(S_ISDIR(sbuf.st_mode)))
	    debug(DEBUG_APPERROR, "cvsps directory '%s' is not a directory!", CVSPS_PREFIX);
    }

    return prefix;
}

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

void strzncpy(char * dst, const char * src, int n)
{
    strncpy(dst, src, n);
    dst[n - 1] = 0;
}

char *get_string(char const *str)
{
    char ** res;

    if (!str)
	return NULL;
    
    res = (char **)tfind(str, &string_tree, (compare_func)strcmp);
    if (!res)
    {
	char *key = xstrdup(str);
	res = (char **)tsearch(key, &string_tree, (compare_func)strcmp);
	*res = key;
    }

    return *res;
}

void convert_date(time_t * t, const char * dte)
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
