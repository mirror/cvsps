/*
 * Copyright 2013 Sergei Trofimovich
 * See COPYING file for license information 
 */

#ifndef COMPILER_H
#define COMPILER_H

/* gcc specific extension. does nothing on other compilers */
#if defined(__GNUC__)
#    define GCCISM(x) x
#else
#    define GCCISM(x)
#endif /* __GNUC__ */

#endif /* COMPILER_H */
