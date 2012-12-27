/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include <stdarg.h>
#ifndef MACINTOSH
#include <sys/types.h>
#endif

#include "inline.h"

#define DEBUG_NUM_FACILITIES  32 /* should be 64 on 64bit CPU... */
#define DEBUG_SYSERROR  0x0001  /* same as DEBUG_ERROR, but here for clarity */
#define DEBUG_ERROR     0x0001
#define DEBUG_APPERROR  0x0002
#define DEBUG_APPWARN   0x0004
#define DEBUG_RETRIEVAL	0x0010
#define DEBUG_STATUS    0x0020
#define DEBUG_TCP       0x0040
#define DEBUG_PARSE	0x0080

#ifdef __cplusplus
extern "C" 
{
#endif

extern unsigned int debuglvl;

void hexdump( const char *ptr, int size, const char *fmt, ... );
void vdebug(int dtype, const char *fmt, va_list);
void vmdebug(int dtype, const char *fmt, va_list);
void to_hex( char* dest, const char* src, size_t n );
void debug_set_error_file(FILE *);
void debug_set_error_facility(int mask, FILE *);

static INLINE void debug(unsigned int dtype, const char *fmt, ...)
{
    va_list ap;
    
    if (!(debuglvl & dtype))
	return;
    
    va_start(ap, fmt);
    vdebug(dtype, fmt, ap);
    va_end(ap);
}

static INLINE void mdebug(unsigned int dtype, const char *fmt, ...)
{
    va_list ap;
    
    if (!(debuglvl & dtype))
	return;
    
    va_start(ap, fmt);
    vmdebug(dtype, fmt, ap);
    va_end(ap);
}

#ifdef __cplusplus
}
#endif


#endif /* DEBUG_H */
