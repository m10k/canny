/*
 * Canny - A simple CAN-over-IP gateway
 * Copyright (C) 2016 Matthias Kruk
 *
 * Canny is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * Canny is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with canny; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __ARRAY_H
#define __ARRAY_H

#include <pthread.h>

typedef struct array array_t;

struct array {
	int		a_size;
	int		a_used;
	int		a_next;
	void	**a_data;

	pthread_mutex_t a_lock;
};

#define ARRAY_DIRTY_MARK	((void*)0x1)

#define	ARRAY_FOREACH(arr,type,elem,what)	if(pthread_mutex_lock(&((arr)->a_lock)) == 0) { \
												int __iter_##elem; \
												for(__iter_##elem = 0; __iter_##elem < (arr)->a_size; __iter_##elem++) { \
													type *elem = (type*)(arr)->a_data[__iter_##elem]; \
													if((void*)elem > ARRAY_DIRTY_MARK) \
														what \
												} \
												assert(pthread_mutex_unlock(&((arr)->a_lock)) == 0); \
											}

array_t*	array_alloc(void);
void		array_free(array_t*);

int			array_insert(array_t*, const void*);
int			array_remove(array_t*, const void*);

void*		array_get_nth(array_t*, int);
int			array_get_length(array_t*);

void		array_foreach(array_t*, void(*)(void*));
void		array_foreach2(array_t*, void(*)(void*, void*), void*);
void*		array_find(array_t*, int(*)(void*,void*), void*);
array_t*    array_dup(array_t*);

void		array_debug(array_t*);

#endif /* __ARRAY_H */
