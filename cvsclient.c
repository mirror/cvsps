/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <zlib.h>
#include <sys/socket.h>
#include <cbtcommon/debug.h>
#include <cbtcommon/text_util.h>
#include <cbtcommon/tcpsocket.h>
#include <cbtcommon/sio.h>

#include "cvsclient.h"
#include "util.h"

#define RD_BUFF_SIZE 4096

struct _CvsServerCtx 
{
    int read_fd;
    int write_fd;
    char root[PATH_MAX];

    bool is_pserver;

    /* buffered reads from descriptor */
    char read_buff[RD_BUFF_SIZE];
    char * head;
    char * tail;

    bool compressed;
    z_stream zout;
    z_stream zin;

    /* when reading compressed data, the compressed data buffer */
    unsigned char zread_buff[RD_BUFF_SIZE];
};

static void get_cvspass(char *, const char *, int len);
static void send_string(CvsServerCtx *, const char *, ...);
static int read_response(CvsServerCtx *, const char *);
static void ctx_to_fp(CvsServerCtx * ctx, FILE * fp);
static int read_line(CvsServerCtx * ctx, char * p, int len);

static CvsServerCtx * open_ctx_pserver(CvsServerCtx *, const char *);
static CvsServerCtx * open_ctx_forked(CvsServerCtx *, const char *);

CvsServerCtx * open_cvs_server(char * p_root, int compress)
{
    CvsServerCtx * ctx = (CvsServerCtx*)malloc(sizeof(*ctx));
    char root[PATH_MAX];
    char * p = root, *tok;

    if (!ctx)
	return NULL;

    ctx->head = ctx->tail = ctx->read_buff;
    ctx->read_fd = ctx->write_fd = -1;
    ctx->compressed = false;
    ctx->is_pserver = false;

    if (compress)
    {
	memset(&ctx->zout, 0, sizeof(z_stream));
	memset(&ctx->zin, 0, sizeof(z_stream));
	
	/* 
	 * to 'prime' the reads, make it look like there was output
	 * room available (i.e. we have processed all pending compressed 
	 * data
	 */
	ctx->zin.avail_out = 1;
	
	if (deflateInit(&ctx->zout, compress) != Z_OK)
	{
	    free(ctx);
	    return NULL;
	}
	
	if (inflateInit(&ctx->zin) != Z_OK)
	{
	    deflateEnd(&ctx->zout);
	    free(ctx);
	    return NULL;
	}
    }

    strcpy_a(root, p_root, PATH_MAX);

    tok = strsep(&p, ":");

    /* if root string looks like :pserver:... then the first token will be empty */
    if (strlen(tok) == 0)
    {
	char * method = strsep(&p, ":");
	if (strcmp(method, "pserver") == 0)
	{
	    ctx = open_ctx_pserver(ctx, p);
	}
	else if (strstr("local:ext:fork:server", method))
	{
	    /* handle all of these via fork, even local */
	    ctx = open_ctx_forked(ctx, p);
	}
	else
	{
	    debug(DEBUG_APPERROR, "cvsclient: unsupported cvs access method: %s", method);
	    free(ctx);
	    ctx = NULL;
	}
    }
    else
    {
	ctx = open_ctx_forked(ctx, p_root);
    }

    if (ctx)
    {
	char buff[BUFSIZ];

	send_string(ctx, "Root %s\n", ctx->root);

	/* this is taken from 1.11.1p1 trace - but with Mbinary removed. we can't handle it (yet!) */
	send_string(ctx, "Valid-responses ok error Valid-requests Checked-in New-entry Checksum Copy-file Updated Created Update-existing Merged Patched Rcs-diff Mode Mod-time Removed Remove-entry Set-static-directory Clear-static-directory Set-sticky Clear-sticky Template Set-checkin-prog Set-update-prog Notified Module-expansion Wrapper-rcsOption M E F\n", ctx->root);

	send_string(ctx, "valid-requests\n");

	/* check for the commands we will issue */
	read_line(ctx, buff, BUFSIZ);
	if (strncmp(buff, "Valid-requests", 14) != 0)
	{
	    debug(DEBUG_APPERROR, "cvsclient: bad response to valid-requests command");
	    close_cvs_server(ctx);
	    return NULL;
	}

	if (!strstr(buff, " version") ||
	    !strstr(buff, " rlog") ||
	    !strstr(buff, " diff") ||
	    !strstr(buff, " co"))
	{
	    debug(DEBUG_APPERROR, "cvsclient: cvs server too old for cvsclient");
	    close_cvs_server(ctx);
	    return NULL;
	}
	
	read_line(ctx, buff, BUFSIZ);
	if (strcmp(buff, "ok") != 0)
	{
	    debug(DEBUG_APPERROR, "cvsclient: bad ok trailer to valid-requests command");
	    close_cvs_server(ctx);
	    return NULL;
	}

	/* this is myterious but 'mandatory' */
	send_string(ctx, "UseUnchanged\n");

	if (compress)
	{
	    send_string(ctx, "Gzip-stream %d\n", compress);
	    ctx->compressed = true;
	}

	debug(DEBUG_APPMSG2, "cvsclient: initialized to CVSROOT %s", ctx->root);
    }

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

    strcpy_a(root, p_root, PATH_MAX);

    /* parse initial "user@server" portion of p. */
    tok = strsep(&p, "@");
    tok2 = p;
    p += strcspn(p, ":/"); /* server part ends at first ':' or '/'. */
    if (!tok || !tok2 || !strlen(tok) || 0 >= (p - tok2))
    {
	debug(DEBUG_APPERROR, "parse error on user@server in pserver");
	goto out_free_err;
    }

    strcpy(user, tok);
    memcpy(server, tok2, p - tok2);
    server[p - tok2] = '\0';

    /* p now points to ':' or '/' following server part. */
    tok = strchr(p, '/'); /* find start of path */
    if (!tok)
    {
	debug(DEBUG_APPERROR, "parse error: expecting / in root");
	goto out_free_err;
    }

    if (*p == ':') /* port number specified. Ends at tok. */
    {
	p++;
	memcpy(port, p, tok - p);
	port[tok - p] = '\0';
    }
    else
    {
	strcpy(port, "2401");
    }

    /* Make p point to path component, starting with '/'. */
    p = tok;

    /* the line from .cvspass is fully qualified, so rebuild */
    snprintf(full_root, PATH_MAX, ":pserver:%s@%s:%s%s", user, server, port, p);
    get_cvspass(pass, full_root, BUFSIZ);

    debug(DEBUG_TCP, "user:%s server:%s port:%s pass:%s full_root:%s", user, server, port, pass, full_root);

    if ((ctx->read_fd = tcp_create_socket(REUSE_ADDR)) < 0)
	goto out_free_err;

    ctx->write_fd = dup(ctx->read_fd);
    if (ctx->write_fd < 0)
	goto out_close_err;

    if (tcp_connect(ctx->read_fd, server, atoi(port)) < 0)
	goto out_close_err;
    
    send_string(ctx, "BEGIN AUTH REQUEST\n");
    send_string(ctx, "%s\n", p);
    send_string(ctx, "%s\n", user);
    send_string(ctx, "%s\n", pass);
    send_string(ctx, "END AUTH REQUEST\n");

    if (!read_response(ctx, "I LOVE YOU"))
	goto out_close_err;

    strcpy_a(ctx->root, p, PATH_MAX);
    ctx->is_pserver = true;

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
    char * p = root, *tok, *rep;
    char execcmd[PATH_MAX];
    int to_cvs[2];
    int from_cvs[2];
    pid_t pid;
    const char * cvs_server = getenv("CVS_SERVER");

    if (!cvs_server)
	cvs_server = "cvs";

    strcpy_a(root, p_root, PATH_MAX);

    /* if there's a ':', it's remote */
    tok = strsep(&p, ":");

    if (p)
    {
	char * tok2;
	/* coverity[tainted_data] */
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
	debug(DEBUG_SYSERROR, "cvsclient: failed to create pipe to_cvs");
	goto out_free_err;
    }

    if (pipe(from_cvs) < 0)
    {
	debug(DEBUG_SYSERROR, "cvsclient: failed to create pipe from_cvs");
	goto out_close_err;
    }

    debug(DEBUG_TCP, "forked cmdline: %s", execcmd);

    if ((pid = fork()) < 0)
    {
	debug(DEBUG_SYSERROR, "cvsclient: can't fork");
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
	if (dup(to_cvs[0]) < 0) {
	    debug(DEBUG_APPERROR, "cvsclient: dup of input failed");
	    exit(1);
	}
	close(1);
	if (dup(from_cvs[1]) < 0) {
	    debug(DEBUG_APPERROR, "cvsclient: dup of output failed");
	    exit(1);
	}

	execv("/bin/sh",argp);

	debug(DEBUG_APPERROR, "cvsclient: fatal: shouldn't be reached");
	exit(1);
    }

    close(to_cvs[0]);
    close(from_cvs[1]);
    ctx->read_fd = from_cvs[0];
    ctx->write_fd = to_cvs[1];

    strcpy_a(ctx->root, rep, PATH_MAX);

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
    /* FIXME: some sort of flushing should be done for non-compressed case */

    if (ctx->compressed)
    {
	int ret, len;
	char buff[BUFSIZ];

	/* 
	 * there shouldn't be anything left, but we do want
	 * to send an 'end of stream' marker, (if such a thing
	 * actually exists..)
	 */
	do
	{
	    ctx->zout.next_out = (unsigned char *)buff;
	    ctx->zout.avail_out = BUFSIZ;
	    ret = deflate(&ctx->zout, Z_FINISH);

	    if ((ret == Z_OK || ret == Z_STREAM_END) && ctx->zout.avail_out != BUFSIZ)
	    {
		len = BUFSIZ - ctx->zout.avail_out;
		if (writen(ctx->write_fd, buff, len) != len)
		    debug(DEBUG_APPERROR, "cvsclient: zout: error writing final state");
		    
		//hexdump(buff, len, "cvsclient: zout: sending unsent data");
	    }
	} while (ret == Z_OK);

	if ((ret = deflateEnd(&ctx->zout)) != Z_OK)
	    debug(DEBUG_APPERROR, "cvsclient: zout: deflateEnd error: %s: %s", 
		  (ret == Z_STREAM_ERROR) ? "Z_STREAM_ERROR":"Z_DATA_ERROR", ctx->zout.msg);
    }
    
    /* we're done writing now */
    debug(DEBUG_TCP, "cvsclient: closing cvs server write connection %d", ctx->write_fd);
    close(ctx->write_fd);

    /* 
     * if this is pserver, then read_fd is a bi-directional socket.
     * we want to shutdown the write side, just to make sure the 
     * server get's eof
     */
    if (ctx->is_pserver)
    {
	debug(DEBUG_TCP, "cvsclient: shutdown on read socket");
	if (shutdown(ctx->read_fd, SHUT_WR) < 0)
	    debug(DEBUG_SYSERROR, "cvsclient: error with shutdown on pserver socket");
    }

    if (ctx->compressed)
    {
	int ret = Z_OK, len, eof = 0;
	unsigned char buff[BUFSIZ];

	/* read to the 'eof'/'eos' marker.  there are two states we 
	 * track, looking for Z_STREAM_END (application level EOS)
	 * and EOF on socket.  Both should happen at the same time,
	 * but we need to do the read first, the first time through
	 * the loop, but we want to do one read after getting Z_STREAM_END
	 * too.  so this loop has really ugly exit conditions.
	 */
	for(;;)
	{
	    /*
	     * if there's nothing in the avail_in, and we
	     * inflated everything last pass (avail_out != 0)
	     * then slurp some more from the descriptor, 
	     * if we get EOF, exit the loop
	     */
	    if (ctx->zin.avail_in == 0 && ctx->zin.avail_out != 0)
	    {
		debug(DEBUG_TCP, "cvsclient: doing final slurp");
		len = read(ctx->read_fd, ctx->zread_buff, RD_BUFF_SIZE);
		debug(DEBUG_TCP, "cvsclient: did final slurp: %d", len);

		if (len <= 0)
		{
		    eof = 1;
		    break;
		}

		/* put the data into the inflate input stream */
		ctx->zin.next_in = ctx->zread_buff;
		ctx->zin.avail_in = len;
	    }

	    /* 
	     * if the last time through we got Z_STREAM_END, and we 
	     * get back here, it means we should've gotten EOF but
	     * didn't
	     */
	    if (ret == Z_STREAM_END)
		break;

	    ctx->zin.next_out = buff;
	    ctx->zin.avail_out = BUFSIZ;

	    ret = inflate(&ctx->zin, Z_SYNC_FLUSH);
	    len = BUFSIZ - ctx->zin.avail_out;
	    
	    if (ret == Z_BUF_ERROR)
		debug(DEBUG_APPERROR, "Z_BUF_ERROR");

	    if (ret == Z_OK && len == 0)
		debug(DEBUG_TCP, "cvsclient: no data out of inflate");

	    if (ret == Z_STREAM_END)
		debug(DEBUG_TCP, "cvsclient: got Z_STREAM_END");

	    if ((ret == Z_OK || ret == Z_STREAM_END) && len > 0)
		hexdump((char *)buff, BUFSIZ - ctx->zin.avail_out, "cvsclient: zin: unread data at close");
	}

	if (ret != Z_STREAM_END)
	    debug(DEBUG_APPERROR, "cvsclient: zin: Z_STREAM_END not encountered (premature EOF?)");

	if (eof == 0)
	    debug(DEBUG_APPERROR, "cvsclient: zin: EOF not encountered (premature Z_STREAM_END?)");

	if ((ret = inflateEnd(&ctx->zin)) != Z_OK)
	    debug(DEBUG_APPERROR, "cvsclient: zin: inflateEnd error: %s: %s", 
		  (ret == Z_STREAM_ERROR) ? "Z_STREAM_ERROR":"Z_DATA_ERROR", ctx->zin.msg ? ctx->zin.msg : "");
    }

    debug(DEBUG_TCP, "cvsclient: closing cvs server read connection %d", ctx->read_fd);
    close(ctx->read_fd);

    free(ctx);
}

static void get_cvspass(char * pass, const char * root, int passbuflen)
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
		strcpy_a(pass, buff + 3 + len + 1, passbuflen);
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
    unsigned char buff[BUFSIZ];
    va_list ap;

    va_start(ap, str);
    len = vsnprintf((char *)buff, BUFSIZ, str, ap);
    va_end(ap);

    if (len >= BUFSIZ)
    {
	debug(DEBUG_APPERROR, "cvsclient: command send string overflow");
	exit(1);
    }

    if (ctx->compressed)
    {
	unsigned char zbuff[BUFSIZ];

	if  (ctx->zout.avail_in != 0)
	{
	    debug(DEBUG_APPERROR, "cvsclient: zout: last output command not flushed");
	    exit(1);
	}

	ctx->zout.next_in = buff;
	ctx->zout.avail_in = len;
	ctx->zout.avail_out = 0;

	while (ctx->zout.avail_in > 0 || ctx->zout.avail_out == 0)
	{
	    int ret;

	    ctx->zout.next_out = zbuff;
	    ctx->zout.avail_out = BUFSIZ;
	    
	    /* FIXME: for the arguments before a command, flushing is counterproductive */
	    ret = deflate(&ctx->zout, Z_SYNC_FLUSH);
	    
	    if (ret == Z_OK)
	    {
		len = BUFSIZ - ctx->zout.avail_out;
		
		if (writen(ctx->write_fd, zbuff, len) != len)
		{
		    debug(DEBUG_SYSERROR, "cvsclient: zout: can't write");
		    exit(1);
		}
	    }
	    else
	    {
		debug(DEBUG_APPERROR, "cvsclient: zout: error %d %s", ret, ctx->zout.msg);
	    }
	}
    }
    else
    {
	if (writen(ctx->write_fd, buff, len)  != len)
	{
	    debug(DEBUG_SYSERROR, "cvsclient: can't send command");
	    exit(1);
	}
    }

    debug(DEBUG_TCP, "string: '%s' sent", buff);
}

static int refill_buffer(CvsServerCtx * ctx)
{
    int len;

    if (ctx->head != ctx->tail)
    {
	debug(DEBUG_APPERROR, "cvsclient: refill_buffer called on non-empty buffer");
	exit(1);
    }

    ctx->head = ctx->read_buff;
    len = RD_BUFF_SIZE;
	
    if (ctx->compressed)
    {
	int zlen, ret;

	/* if there was leftover buffer room, it's time to slurp more data */
	do 
	{
	    if (ctx->zin.avail_out > 0)
	    {
		if (ctx->zin.avail_in != 0)
		{
		    debug(DEBUG_APPERROR, "cvsclient: zin: expect 0 avail_in");
		    exit(1);
		}
		zlen = read(ctx->read_fd, ctx->zread_buff, RD_BUFF_SIZE);
		ctx->zin.next_in = ctx->zread_buff;
		ctx->zin.avail_in = zlen;
	    }
	    
	    ctx->zin.next_out = (unsigned char *)ctx->head;
	    ctx->zin.avail_out = len;
	    
	    /* FIXME: we don't always need Z_SYNC_FLUSH, do we? */
	    ret = inflate(&ctx->zin, Z_SYNC_FLUSH);
	}
	while (ctx->zin.avail_out == len);

	if (ret == Z_OK)
	{
	    ctx->tail = ctx->head + (len - ctx->zin.avail_out);
	}
	else
	{
	    debug(DEBUG_APPERROR, "cvsclient: zin: error %d %s", ret, ctx->zin.msg);
	    exit(1);
	}
    }
    else
    {
	len = read(ctx->read_fd, ctx->head, len);
	ctx->tail = (len <= 0) ? ctx->head : ctx->head + len;
    }

    return len;
}

static int read_line(CvsServerCtx * ctx, char * p, int maxlen)
{
    int len = 0;

    if (maxlen <= 0)
	return -1;

    while (1)
    {
	if (ctx->head == ctx->tail)
	    if (refill_buffer(ctx) <= 0)
		return -1;

	/* break out without advancing head if buffer is exhausted */
	if (maxlen == 1 || (*p = *ctx->head++) == '\n')
	{
	    *p = 0;
	    break;
	}

	p++;
	len++;
	maxlen--;
    }

    return len;
}

static int read_response(CvsServerCtx * ctx, const char * str)
{
    /* FIXME: more than 1 char at a time */
    char resp[BUFSIZ];

    if (read_line(ctx, resp, BUFSIZ) < 0)
	return 0;

    debug(DEBUG_TCP, "response '%s' read", resp);

    return (strcmp(resp, str) == 0);
}

static void ctx_to_fp(CvsServerCtx * ctx, FILE * fp)
{
    char line[BUFSIZ];

    while (1)
    {
	read_line(ctx, line, BUFSIZ);
	debug(DEBUG_TCP, "ctx_to_fp: %s", line);
	if (memcmp(line, "M ", 2) == 0)
	{
	    if (fp)
		fprintf(fp, "%s\n", line + 2);
	}
	else if (memcmp(line, "E ", 2) == 0)
	{
	    debug(DEBUG_TCP, "%s", line + 2);
	}
	else if (strncmp(line, "ok", 2) == 0 || strncmp(line, "error", 5) == 0)
	{
	    break;
	}
    }

    if (fp)
	fflush(fp);
}

void cvs_rdiff(CvsServerCtx * ctx, 
	       const char * rep, const char * file, 
	       const char * rev1, const char * rev2)
{
    /* NOTE: opts are ignored for rdiff, '-u' is always used */

    send_string(ctx, "Argument -u\n");
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev1);
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev2);
    send_string(ctx, "Argument %s%s\n", rep, file);
    send_string(ctx, "rdiff\n");

    ctx_to_fp(ctx, stdout);
}

void cvs_rupdate(CvsServerCtx * ctx, const char * rep, const char * file, const char * rev, FILE *fp)
{
    send_string(ctx, "Argument -kk\n");
    send_string(ctx, "Argument -p\n");
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev);
    send_string(ctx, "Argument %s/%s\n", rep, file);
    send_string(ctx, "co\n");

    ctx_to_fp(ctx, fp);
}

static bool parse_patch_arg(char * arg, char ** str)
{
    char *tok, *tok2 = "";
    tok = strsep(str, " ");
    if (!tok)
	return false;

    if (*tok != '-')
    {
	debug(DEBUG_APPERROR, "diff_opts parse error: no '-' starting argument: %s", *str);
	return false;
    }
    
    /* if it's not 'long format' argument, we can process it efficiently */
    if (tok[1] == '-')
    {
	debug(DEBUG_APPERROR, "diff_opts parse_error: long format args not supported");
	return false;
    }

    /* see if command wants two args and they're separated by ' ' */
    if (tok[2] == 0 && strchr("BdDFgiorVxYz", tok[1]))
    {
	tok2 = strsep(str, " ");
	if (!tok2)
	{
	    debug(DEBUG_APPERROR, "diff_opts parse_error: argument %s requires two arguments", tok);
	    return false;
	}
    }
    
    snprintf(arg, 32, "%s%s", tok, tok2);
    return true;
}

void cvs_diff(CvsServerCtx * ctx, 
	       const char * rep, const char * file, 
	       const char * rev1, const char * rev2, const char * opts)
{
    char argstr[BUFSIZ], *p = argstr;
    char arg[32];
    char file_buff[PATH_MAX], *basename;

    strzncpy(argstr, opts, BUFSIZ);
    while (parse_patch_arg(arg, &p))
	send_string(ctx, "Argument %s\n", arg);

    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev1);
    send_string(ctx, "Argument -r\n");
    send_string(ctx, "Argument %s\n", rev2);

    /* 
     * we need to separate the 'basename' of file in order to 
     * generate the Directory directive(s)
     */
    strzncpy(file_buff, file, PATH_MAX);
    if ((basename = strrchr(file_buff, '/')))
    {
	*basename = 0;
	send_string(ctx, "Directory %s/%s\n", rep, file_buff);
	send_string(ctx, "%s/%s/%s\n", ctx->root, rep, file_buff);
    }
    else
    {
	send_string(ctx, "Directory %s\n", rep, file_buff);
	send_string(ctx, "%s/%s\n", ctx->root, rep);
    }

    send_string(ctx, "Directory .\n");
    send_string(ctx, "%s\n", ctx->root);
    send_string(ctx, "Argument %s/%s\n", rep, file);
    send_string(ctx, "diff\n");

    ctx_to_fp(ctx, stdout);
}

/*
 * FIXME: the design of this sucks.  It was originally designed to fork a subprocess
 * which read the cvs response and send it back through a pipe the main process,
 * which fdopen(3)ed the other end, and just used regular fgets.  This however
 * didn't work because the reads of compressed data in the child process altered
 * the compression state, and there was no way to resynchronize that state with
 * the parent process.  We could use threads...
 */
FILE * cvs_rlog_open(CvsServerCtx * ctx, const char * rep, const char * date_str)
{
    /* note: use of the date_str is handled in a non-standard, cvsps specific way */
    if (date_str && date_str[0])
    {
	send_string(ctx, "Argument -d\n", rep);
	send_string(ctx, "Argument %s<1 Jan 2038 05:00:00 -0000\n", date_str);
	send_string(ctx, "Argument -d\n", rep);
	send_string(ctx, "Argument %s\n", date_str);
    }

    send_string(ctx, "Argument %s\n", rep);
    send_string(ctx, "rlog\n");

    /*
     * FIXME: is it possible to create a 'fake' FILE * whose 'refill'
     * function is below?
     */
    return (FILE*)ctx;
}

char * cvs_rlog_fgets(char * buff, int buflen, CvsServerCtx * ctx)
{
    char lbuff[BUFSIZ];
    int len;

    len = read_line(ctx, lbuff, BUFSIZ);
    debug(DEBUG_TCP, "cvsclient: rlog: read %s", lbuff);

    if (memcmp(lbuff, "M ", 2) == 0)
    {
	memcpy(buff, lbuff + 2, len - 2);
	buff[len - 2 ] = '\n';
	buff[len - 1 ] = 0;
    }
    else if (memcmp(lbuff, "E ", 2) == 0)
    {
	debug(DEBUG_TCP, "%s", lbuff + 2);
    }
    else if (strcmp(lbuff, "ok") == 0 || strncmp(lbuff, "error", 5) == 0)
    {
	debug(DEBUG_TCP, "cvsclient: rlog: got command completion");
	return NULL;
    }

    return buff;
}

void cvs_rlog_close(CvsServerCtx * ctx)
{
}

void cvs_version(CvsServerCtx * ctx, char * client_version, char * server_version, int cvlen, int svlen)
{
    char lbuff[BUFSIZ];
    strcpy_a(client_version, "Client: Concurrent Versions System (CVS) 99.99.99 (client/server) cvs-direct", cvlen);
    send_string(ctx, "version\n");
    read_line(ctx, lbuff, BUFSIZ);
    if (memcmp(lbuff, "M ", 2) == 0)
	snprintf(server_version, svlen, "Server: %s", lbuff + 2);
    else
	debug(DEBUG_APPERROR, "cvsclient: didn't read version: %s", lbuff);
    
    read_line(ctx, lbuff, BUFSIZ);
    if (strstr(lbuff,"CVSACL")!=NULL) {
	read_line(ctx, lbuff, BUFSIZ);
    }
    if (strcmp(lbuff, "ok") != 0)
	debug(DEBUG_APPERROR, "cvsclient: protocol error reading version");

    debug(DEBUG_TCP, "cvsclient: client version %s", client_version);
    debug(DEBUG_TCP, "cvsclient: server version %s", server_version);
}
