#ifndef LIST_SORT_H
#define LIST_SORT_H

#include <cbtcommon/list.h>

void list_sort(struct list_head *, int (*)(struct list_head *, struct list_head *));

#endif /* LIST_SORT_H */
