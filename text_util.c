/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

/**
 * Copyright (c) 1998 Cobite, Inc. All Rights Reserved.
 * @author Karl LaRocca
 * @created Fri Nov  6 14:33:29 1998
 * @version $Revision: 1.9 $$Date: 2001/10/25 18:36:11 $
 */
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "text_util.h"

char* 
chop( char* src )
{
  char* p = src + strlen(src) - 1;

  while( p >= src )
  {
    if ( *p == '\n' || *p == '\r' )
    {
      *p-- = 0;
    } 

    else
    {
      break;
    }
  }

  return( src );
}


