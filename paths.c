#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <search.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/wait.h> /* for WEXITSTATUS - see system(3) */

#include "hash.h"
#include "list.h"
#include "debug.h"

#include "cvsps_types.h"
#include "cvsps.h"
#include "util.h"
#include "stats.h"
#include "cvsclient.h"
#include "list_sort.h"

int init_paths(char *root_path, char *repository_path, char *strip_path)
{
    FILE * fp;
    char * p;
    int len;
    int strip_path_len;

    /* Determine the CVSROOT. Precedence:
     * 1) command line
     * 2) checkout directory
     * 3) top level of repository
     * 4) module directory just beneath a repository root.
     * 5) environment variable CVSROOT
     */
    if (!root_path[0])
    {
	/* Are we in a working directory? */
	if ((fp = fopen("CVS/Root", "r")) != NULL)
	{
	    if (fgets(root_path, PATH_MAX, fp) == NULL)
	    {
		debug(DEBUG_APPERROR, "Error reading CVSROOT");
		exit(1);
	    }
	    
	    fclose(fp);
	    
	    /* chop the lf and optional trailing '/' */
	    len = strlen(root_path) - 1;
	    root_path[len] = 0;
	    if (root_path[len - 1] == '/')
		root_path[--len] = 0;
	}
	else
	{
	    struct stat st;

	    debug(DEBUG_STATUS, "Can't open CVS/Root");

	    /* 
	     * We're not in a working directory; are we in a repository root?
	     * If so, monkey up a local path to access it.
	     */
	    if (stat("CVSROOT", &st) == 0 && S_ISDIR(st.st_mode)) {
		strcpy(root_path, ":local:");
		if (getcwd(root_path + strlen(root_path),
			   sizeof(root_path) - strlen(root_path) - 1) == NULL)
		{
		    debug(DEBUG_APPERROR, "cannot get working directory");
		    exit(1);
		}
	    }
	    /*
	     * We might be in a module directory just below a repository root.
	     * The right thing to do in this case is also clear.
	     */
	    else if (stat("../CVSROOT", &st) == 0 && S_ISDIR(st.st_mode)) {
		char *sl;
		strcpy(root_path, ":local:");
		if (getcwd(root_path + strlen(root_path),
			   sizeof(root_path) - strlen(root_path) - 1) == NULL)
		{
		    debug(DEBUG_APPERROR, "cannot get working directory");
		    exit(1);
		}
		sl = strrchr(root_path, '/');
		*sl++ = '\0';
		if (repository_path[0])
		{
		    memmove(repository_path + strlen(sl) + 1, 
			    repository_path,
			    strlen(repository_path) + 1); 
		    repository_path[strlen(sl)] = '/';
		}
		strcpy(repository_path, sl);
	    }
	    else 
	    {
		const char * e = getenv("CVSROOT");

		if (e)
		    strcpy(root_path, e);
		else
		{
		    debug(DEBUG_APPERROR, "cannot determine CVSROOT");
		    exit(1);
		}
	    }
	}
    }

    /* Determine the repository path, precedence:
     * 1) command line
     * 2) working directory
     * Note that one of the root-directory cases above prepends to this path.
     */
      
    if (!repository_path[0])
    {
	if ((fp = fopen("CVS/Repository", "r")) == NULL)
	{
	    debug(DEBUG_SYSERROR, "repository path is missing or unreadable");
	    exit(1);
	}
	
	if (fgets(repository_path, PATH_MAX, fp) == NULL)
	{
	    debug(DEBUG_APPERROR, "error reading repository path");
	    exit(1);
	}
	
	chop(repository_path);
	fclose(fp);
    }

    /* get the path portion of the root */
    p = strrchr(root_path, ':');

    if (!p)
	p = root_path;
    else 
	p++;

    /* some CVS have the CVSROOT string as part of the repository
     * string (initial substring).  remove it.
     */
    len = strlen(p);

    if (strncmp(p, repository_path, len) == 0)
    {
	int rlen = strlen(repository_path + len + 1);
	memmove(repository_path, repository_path + len + 1, rlen + 1);
    }

    /* the 'strip_path' will be used whenever the CVS server gives us a
     * path to an 'rcs file'.  the strip_path portion of these paths is
     * stripped off, leaving us with the working file.
     *
     * NOTE: because of some bizarre 'feature' in cvs, when 'rlog' is
     * used (instead of log) it gives the 'real' RCS file path, which
     * can be different from the 'nominal' repository path because of
     * symlinks in the server and the like.  See also the
     * 'parse_rcs_file' routine
     *
     * When you've checked out the root, rather than a specific
     * module, repository_path is . but we should use only p without
     * anything added for path stripping.
     */
    if (!strcmp(repository_path,".")) {
	strip_path_len = snprintf(strip_path, PATH_MAX, "%s/", p);
    } else {
	strip_path_len = snprintf(strip_path, PATH_MAX, "%s/%s/", p, repository_path);
    }


    if (strip_path_len < 0 || strip_path_len >= PATH_MAX)
    {
	debug(DEBUG_APPERROR, "strip_path overflow");
	exit(1);
    }

    if (strip_path_len > 3 && !strcmp(strip_path + strip_path_len - 3, "/./"))
    {
	debug(DEBUG_PARSE, "pruning /./ off end of strip_path");
	strip_path_len -= 2;
	strip_path[strip_path_len] = '\0';
    }

    debug(DEBUG_PARSE, "strip_path: %s", strip_path);

    return strip_path_len;
}

// end
