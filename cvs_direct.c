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
    int read_fd;
    int write_fd;
    char repository[PATH_MAX];

    /* buffered reads from descriptor */
    char read_buff[RD_BUFF_SIZE];
    char * head;
    char * tail;
};

static void get_cvspass(char *, const char *);
static void send_string(CvsServerCtx *, const char *, ...);
static int read_response(CvsServerCtx *, const char *);

static CvsServerCtx * open_ctx_pserver(CvsServerCtx *, const char *);
static CvsServerCtx * open_ctx_forked(CvsServerCtx *, const char *);

CvsServerCtx * open_cvs_server(char * p_root)
{
    CvsServerCtx * ctx = (CvsServerCtx*)malloc(sizeof(*ctx));
    char root[PATH_MAX];
    char * p = root, *tok;

    if (!ctx)
	return NULL;

    ctx->head = ctx->tail = ctx->read_buff;
    ctx->read_fd = ctx->write_fd = -1;

    strcpy(root, p_root);

    tok = strsep(&p, ":");

    /* if root string looks like :pserver:... then the first token will be empty */
    if (strlen(tok) == 0)
    {
	char * method = strsep(&p, ":");
	if (strcmp(method, "pserver") == 0)
	{
	    ctx = open_ctx_pserver(ctx, p);
	}
	else if (strstr(method, "local:ext:fork:server"))
	{
	    /* handle all of these via fork, even local */
	    ctx = open_ctx_forked(ctx, p);
	}
	else
	{
	    debug(DEBUG_APPERROR, "cvs_direct: unsupported cvs access method: %s", method);
	    free(ctx);
	    ctx = NULL;
	}
    }
    else
    {
	ctx = open_ctx_forked(ctx, p_root);
    }

    if (ctx)
	send_string(ctx, "Root %s\n", ctx->repository);

    return ctx;
}

static CvsServerCtx * open_ctx_pserver(CvsServerCtx * ctx, const char * p_root)
{
    char root[PATH_MAX];
    char full_root[PATH_MAX];
    char * p = root, *tok, *tok2;
    char user[BUFSIZ];
    char server[BUFSIZ];
    char pass[BUFSIZ];
    char port[8];

    strcpy(root, p_root);

    tok = strsep(&p, ":");
    if (strlen(tok) == 0 || !p)
    {
	debug(DEBUG_APPERROR, "parse error on third token");
	goto out_free_err;
    }

    tok2 = strsep(&tok, "@");
    if (!strlen(tok2) || (!tok || !strlen(tok)))
    {
	debug(DEBUG_APPERROR, "parse error on user@server in pserver");
	goto out_free_err;
    }

    strcpy(user, tok2);
    strcpy(server, tok);
    
    if (*p != '/')
    {
	tok = strchr(p, '/');
	if (!tok)
	{
	    debug(DEBUG_APPERROR, "parse error: expecting / in root");
	    goto out_free_err;
	}
	
	memset(port, 0, sizeof(port));
	memcpy(port, p, tok - p);

	p = tok;
    }
    else
    {
	strcpy(port, "2401");
    }

    /* the line from .cvspass is fully qualified, so rebuild */
    snprintf(full_root, PATH_MAX, ":pserver:%s@%s:%s%s", user, server, port, p);
    get_cvspass(pass, full_root);

    debug(DEBUG_TCP, "user:%s server:%s port:%s pass:%s full_root:%s", user, server, port, pass, full_root);

    if ((ctx->read_fd = tcp_create_socket(REUSE_ADDR)) < 0)
	goto out_free_err;

    ctx->write_fd = ctx->read_fd;

    if (tcp_connect(ctx->read_fd, server, atoi(port)) < 0)
	goto out_close_err;
    
    send_string(ctx, "BEGIN AUTH REQUEST\n");
    send_string(ctx, "%s\n", p);
    send_string(ctx, "%s\n", user);
    send_string(ctx, "%s\n", pass);
    send_string(ctx, "END AUTH REQUEST\n");

    if (!read_response(ctx, "I LOVE YOU"))
	goto out_close_err;

    strcpy(ctx->repository, p);

    return ctx;

 out_close_err:
    close(ctx->read_fd);
 out_free_err:
    free(ctx);
    return NULL;
}

static CvsServerCtx * open_ctx_forked(CvsServerCtx * ctx, const char * p_root)
{
    char root[PATH_MAX];
    char * p = root, *tok, *tok2, *rep;
    char execcmd[PATH_MAX];
    int to_cvs[2];
    int from_cvs[2];
    pid_t pid;
    const char * cvs_server = getenv("CVS_SERVER");

    if (!cvs_server)
	cvs_server = "cvs";

    strcpy(root, p_root);

    /* if there's a ':', it's remote */
    tok = strsep(&p, ":");

    if (p)
    {
	const char * cvs_rsh = getenv("CVS_RSH");

	if (!cvs_rsh)
	    cvs_rsh = "rsh";

	tok2 = strsep(&tok, "@");

	if (tok)
	    snprintf(execcmd, PATH_MAX, "%s -l %s %s %s server", cvs_rsh, tok2, tok, cvs_server);
	else
	    snprintf(execcmd, PATH_MAX, "%s %s %s server", cvs_rsh, tok2, cvs_server);

	rep = p;
    }
    else
    {
	snprintf(execcmd, PATH_MAX, "%s server", cvs_server);
	rep = tok;
    }

    if (pipe(to_cvs) < 0)
    {
	debug(DEBUG_SYSERROR, "cvs_direct: failed to create pipe to_cvs");
	goto out_free_err;
    }

    if (pipe(from_cvs) < 0)
    {
	debug(DEBUG_SYSERROR, "cvs_direct: failed to create pipe from_cvs");
	goto out_close_err;
    }

    debug(DEBUG_TCP, "forked cmdline: %s", execcmd);

    if ((pid = fork()) < 0)
    {
	debug(DEBUG_SYSERROR, "cvs_direct: can't fork");
	goto out_close2_err;
    }
    else if (pid == 0) /* child */
    {
	char * argp[4];
	argp[0] = "sh";
	argp[1] = "-c";
	argp[2] = execcmd;
	argp[3] = NULL;

	close(to_cvs[1]);
	close(from_cvs[0]);
	
	close(0);
	dup(to_cvs[0]);
	close(1);
	dup(from_cvs[1]);

	execv("/bin/sh",argp);

	debug(DEBUG_APPERROR, "cvs_direct: fatal: shouldn't be reached");
	exit(1);
    }

    close(to_cvs[0]);
    close(from_cvs[1]);
    ctx->read_fd = from_cvs[0];
    ctx->write_fd = to_cvs[1];

    strcpy(ctx->repository, rep);

    return ctx;

 out_close2_err:
    close(from_cvs[0]);
    close(from_cvs[1]);
 out_close_err:
    close(to_cvs[0]);
    close(to_cvs[1]);
 out_free_err:
    free(ctx);
    return NULL;
}

void close_cvs_server(CvsServerCtx * ctx)
{
    if (ctx->read_fd >= 0)
    {
	debug(DEBUG_TCP, "cvs_direct: closing cvs server connection %d", ctx->read_fd);
	close(ctx->read_fd);
    }

    if (ctx->write_fd >= 0 && ctx->write_fd != ctx->read_fd)
    {
	debug(DEBUG_TCP, "cvs_direct: closing cvs server connection %d", ctx->write_fd);
	close(ctx->write_fd);
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
	    /* FIXME: what does /1 mean? */
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
    if (len >= BUFSIZ)
    {
	debug(DEBUG_APPERROR, "cvs_direct: command send string overflow");
	exit(1);
    }

    if (writen(ctx->write_fd, buff, len)  != len)
    {
	debug(DEBUG_SYSERROR, "cvs_direct: can't send command");
	exit(1);
    }

    debug(DEBUG_TCP, "string: '%s' sent", buff);
}

static int refill_buffer(CvsServerCtx * ctx)
{
    int len = ctx->read_buff + RD_BUFF_SIZE - ctx->tail;
    if (len == 0)
    {
	ctx->head = ctx->read_buff;
	len = RD_BUFF_SIZE;
    }

    len = read(ctx->read_fd, ctx->head, len);
    ctx->tail = (len <= 0) ? ctx->head : ctx->head + len;

    return len;
}

static int read_line(CvsServerCtx * ctx, char * p)
{
    int len = 0;
    while (1)
    {
	if (ctx->head == ctx->tail)
	    if (refill_buffer(ctx) <= 0)
		return -1;

	*p = *ctx->head++;

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

    if (read_line(ctx, resp) < 0)
	return 0;

    debug(DEBUG_TCP, "response '%s' read", resp);

    return (strcmp(resp, str) == 0);
}

static void ctx_to_fp(CvsServerCtx * ctx, FILE * fp)
{
    char line[BUFSIZ];

    while (1)
    {
	read_line(ctx, line);
	if (line[0] == 'M')
	    fprintf(fp, "%s\n", line + 2);
	else if (strncmp(line, "ok", 2) == 0 || strncmp(line, "error", 5) == 0)
	    break;
    }

    fflush(fp);
}

void cvs_rdiff(CvsServerCtx * ctx, 
	       const char * rep, const char * file, 
	       const char * rev1, const char * rev2, const char * opts)
{
    send_string(ctx, "Argument -u\n");
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev1);
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev2);
    send_string(ctx, "Argument %s%s\n", rep, file);
    send_string(ctx, "rdiff\n");

    ctx_to_fp(ctx, stdout);
}

void cvs_rupdate(CvsServerCtx * ctx, const char * rep, const char * file, const char * rev, int create, const char * opts)
{
    FILE * fp;
    char cmdbuff[BUFSIZ];
    
    snprintf(cmdbuff, BUFSIZ, "diff %s %s /dev/null %s | sed -e '%s s|^+++ -|+++ %s%s|g'",
	     opts, create?"":"-", create?"-":"", create?"2":"1", rep, file);

    debug(DEBUG_TCP, "cmdbuff: %s", cmdbuff);

    if (!(fp = popen(cmdbuff, "w")))
    {
	debug(DEBUG_APPERROR, "cvs_direct: popen for diff failed: %s", cmdbuff);
	exit(1);
    }

    send_string(ctx, "Argument -p\n");
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev);
    send_string(ctx, "Argument %s%s\n", rep, file);
    send_string(ctx, "co\n");

    ctx_to_fp(ctx, fp);

    pclose(fp);
}
