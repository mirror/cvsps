#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <stdarg.h>
#include <cbtcommon/debug.h>
#include <cbtcommon/text_util.h>
#include <cbtcommon/tcpsocket.h>
#include <cbtcommon/sio.h>
#include "cvs_direct.h"

#define RD_BUFF_SIZE 4096

struct _CvsServerCtx 
{
    int fd;
    char read_buff[RD_BUFF_SIZE];
    int read_pos;
};

static void get_cvspass(char *, const char *);
static void send_string(CvsServerCtx *, const char *, ...);
static int read_response(CvsServerCtx *, const char *);

CvsServerCtx * open_cvs_server(char * p_root)
{
    CvsServerCtx * ctx = (CvsServerCtx*)malloc(sizeof(*ctx));
    char root[PATH_MAX];
    char * p = root, *tok, *tok2;
    char user[BUFSIZ];
    char server[BUFSIZ];
    char pass[BUFSIZ];
    char port[8];
    char fake_root[PATH_MAX];

    if (!ctx)
	return NULL;

    strcpy(root, p_root);

    tok = strsep(&p, ":");
    debug(DEBUG_APPERROR, "1st token '%s'", tok);

    tok = strsep(&p, ":");
    debug(DEBUG_APPERROR, "2nd token '%s'", tok);

    tok = strsep(&p, ":");
    debug(DEBUG_APPERROR, "3rd token '%s'", tok);

    tok2 = strsep(&tok, "@");
    strcpy(user, tok2);
    strcpy(server, tok);

    tok = strsep(&p, ":");
    if (!p)
    {
	strcpy(port, "2401");
    }
    else
    {
	strcpy(port, tok);
	tok = strsep(&p, ":");
    }

    snprintf(fake_root, PATH_MAX, ":pserver:%s@%s:%s%s", user, server, port, tok);
    get_cvspass(pass, fake_root);

    debug(DEBUG_APPERROR, "user:%s server:%s port:%s pass:%s", user, server, port, pass);

    if ((ctx->fd = tcp_create_socket(REUSE_ADDR)) < 0)
    {
	free(ctx);
	return NULL;
    }

    if (tcp_connect(ctx->fd, server, atoi(port)) < 0)
    {
	free(ctx);
	return NULL;
    }
    
    ctx->read_pos = RD_BUFF_SIZE;


    send_string(ctx, "BEGIN AUTH REQUEST\n");
    send_string(ctx, "%s\n", tok);
    send_string(ctx, "%s\n", user);
    send_string(ctx, "%s\n", pass);
    send_string(ctx, "END AUTH REQUEST\n");
    send_string(ctx, "Root %s\n", tok);

    if (!read_response(ctx, "I LOVE YOU"))
    {
	debug(DEBUG_APPERROR, "cvs server auth failed");
	exit(1);
    }

    return ctx;
}

void close_cvs_server(CvsServerCtx * ctx)
{
    if (ctx->fd)
    {
	debug(DEBUG_APPERROR, "closing cvs server connection %d", ctx->fd);
	close(ctx->fd);
    }
    free(ctx);
}

static void get_cvspass(char * pass, const char * root)
{
    char cvspass[PATH_MAX];
    const char * home;
    FILE * fp;

    pass[0] = 0;

    if (!(home = getenv("HOME")))
    {
	debug(DEBUG_APPERROR, "HOME environment variable not set");
	exit(1);
    }

    if (snprintf(cvspass, PATH_MAX, "%s/.cvspass", home) >= PATH_MAX)
    {
	debug(DEBUG_APPERROR, "prefix buffer overflow");
	exit(1);
    }
    
    if ((fp = fopen(cvspass, "r")))
    {
	char buff[BUFSIZ];
	int len = strlen(root);

	while (fgets(buff, BUFSIZ, fp))
	{
	    if (strncmp(buff, "/1 ", 3) != 0)
		continue;

	    if (strncmp(buff + 3, root, len) == 0)
	    {
		strcpy(pass, buff + 3 + len + 1);
		chop(pass);
		break;
	    }
		
	}
	fclose(fp);
    }

    if (!pass[0])
	pass[0] = 'A';
}

static void send_string(CvsServerCtx * ctx, const char * str, ...)
{
    int len;
    char buff[BUFSIZ];
    va_list ap;
    va_start(ap, str);

    len = vsnprintf(buff, BUFSIZ, str, ap);

    if (writen(ctx->fd, buff, len)  != len)
    {
	debug(DEBUG_APPERROR, "bad write return");
	exit(1);
    }
    debug(DEBUG_APPERROR, "string: '%s' sent", buff);
}

static int read_line(CvsServerCtx * ctx, char * p)
{
    /* FIXME: more than 1 char at a time */
    int len = 0;
    while (1)
    {
	if (read(ctx->fd, p, 1) != 1)
	    return -1;

	if (*p == '\n')
	{
	    *p = 0;
	    break;
	}
	p++;
	len++;
    }

    return len;
}

static int read_response(CvsServerCtx * ctx, const char * str)
{
    /* FIXME: more than 1 char at a time */
    char resp[BUFSIZ];
    read_line(ctx, resp);
    debug(DEBUG_APPERROR, "response '%s' read", resp);
    return (strcmp(resp, str) == 0);
}

void cvs_rdiff(CvsServerCtx * ctx, 
	       const char * rep, const char * file, 
	       const char * rev1, const char * rev2, const char * opts)
{
    char line[BUFSIZ];

    send_string(ctx, "Argument -u\n");
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev1);
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev2);
    send_string(ctx, "Argument %s%s\n", rep, file);
    send_string(ctx, "rdiff\n");

    while (1)
    {
	read_line(ctx, line);
	if (line[0] == 'M')
	{
	    printf("%s\n", line + 2);
	}
	else
	{
	    break;
	}
    }

    fflush(stdout);
}
