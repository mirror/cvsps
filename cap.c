#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cbtcommon/debug.h>
#include <cbtcommon/text_util.h>

#include "cap.h"

static char client_version[BUFSIZ];
static char server_version[BUFSIZ];

static int check_cvs_version(int, int, int);
static int check_version_string(const char *, int, int, int);

int cvs_check_cap(int cap)
{
    int ret;

    switch(cap)
    {
    case CAP_HAVE_RLOG:
	if (!(ret = check_cvs_version(1,11,1)))
	{
	    debug(DEBUG_APPERROR, "\n"
		  "Your CVS client version [%s]\n"
		  "and/or server version [%s]\n"
		  "are too old to properly support the rlog command. \n"
		  "This command was introduced in 1.11.1.  Cvsps\n"
		  "will use log instead, but PatchSet numbering\n"
		  "may become unstable due to pruned empty\n"
		  "directories.\n", client_version, server_version);
	}
	break;
		  
    default:
	debug(DEBUG_APPERROR, "unknown cvs capability check %d", cap);
	exit(1);
    }

    return ret;
}

int check_cvs_version(int req_major, int req_minor, int req_extra)
{
    if (!client_version[0])
    {
	FILE * cvsfp;

	if (!(cvsfp = popen("cvs version", "r")))
	{
	    debug(DEBUG_APPERROR, "cannot popen cvs version. exiting");
	    exit(1);
	}
	
	if (!fgets(client_version, BUFSIZ, cvsfp))
	{
	    debug(DEBUG_APPERROR, "malformed CVS version: no data");
	    exit(1);
	}

	chop(client_version);
	
	if (strncmp(client_version, "Client", 6) == 0)
	{
	    if (!fgets(server_version, BUFSIZ, cvsfp))
	    {
		debug(DEBUG_APPERROR, "malformed CVS version: no server data");
		exit(1);
	    }
	    chop(server_version);
	}
	else
	{
	    server_version[0] = 0;
	}

	pclose(cvsfp);
    }

    return (check_version_string(client_version, req_major, req_minor, req_extra) &&
	    (!server_version[0] || check_version_string(server_version, req_major, req_minor, req_extra)));
}

int check_version_string(const char * str, int req_major, int req_minor, int req_extra)
{
    char * p;
    int major, minor, extra;

    p = strstr(client_version, "(CVS) ");
    if (!p)
    {
	debug(DEBUG_APPERROR, "malformed CVS version: %s", client_version);
	exit(1);
    }

    p += 6;
    sscanf(p, "%d.%d.%d", &major, &minor, &extra);

    return (major > req_major || 
	    (major == req_major && minor > req_minor) ||
	    (major == req_major && minor == req_minor && extra >= req_extra));
}
