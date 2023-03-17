/*
 * Canny - A simple CAN-over-IP gateway
 * Copyright (C) 2016-2023 Matthias Kruk
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

#include <config.h>
#include <array.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>

#define ARRAY_INIT_SIZE 16
#define ARRAY_INC_SHIFT 1
#define ARRAY_DEC_SHIFT 1

static size_t _array_increase(array_t *this)
{
	size_t nsize, nsize_raw;
	void **ndata;

	assert(this);

	nsize = this->a_size << ARRAY_INC_SHIFT;
	nsize_raw = nsize * sizeof(void*);
	ndata = malloc(nsize_raw);

	if(ndata) {
		memset(ndata, 0, nsize_raw);
		memcpy(ndata, this->a_data, this->a_size * sizeof(void*));
		free(this->a_data);
		this->a_next = this->a_size;
		this->a_size = nsize;
		this->a_data = ndata;

		return(nsize);
	}
	return(0);
}

static size_t _array_decrease(array_t *this)
{
	size_t nsize, nsize_raw;
	void **ndata;

	assert(this);
	assert((this->a_size >> ARRAY_DEC_SHIFT) >= this->a_used);

	nsize = this->a_size >> ARRAY_DEC_SHIFT;
	nsize_raw = nsize * sizeof(void*);
	ndata = malloc(nsize_raw);

	if(ndata) {
		int i, n;

		memset(ndata, 0, nsize_raw);

		for(i = 0, n = 0; i < this->a_size && n < this->a_used; i++) {
			if(this->a_data[i] > ARRAY_DIRTY_MARK) {
				ndata[n] = this->a_data[i];
				n++;
			}
		}
		free(this->a_data);

		this->a_data = ndata;
		this->a_size = nsize;
		this->a_next = this->a_used;

		return(nsize);
	}
	return(0);
}

/**
 * Allocate a new array
 * @return a pointer to the new array, or NULL in case of an error
 */
array_t* array_alloc(void)
{
	array_t *a;

	if((a = malloc(sizeof(*a)))) {
		memset(a, 0, sizeof(*a));
		a->a_used = 0;
		a->a_next = 0;
		a->a_size = ARRAY_INIT_SIZE;
		a->a_data = malloc(ARRAY_INIT_SIZE * sizeof(void*));
		assert(pthread_mutex_init(&(a->a_lock), NULL) == 0);

		if(!a->a_data) {
			pthread_mutex_destroy(&(a->a_lock));
			free(a);
			a = NULL;
		} else {
			memset(a->a_data, 0, ARRAY_INIT_SIZE * sizeof(void*));
		}
	}
	return(a);
}

/**
 * Free the memory occupied by an array
 * @param this the array to be freed
 * @return void
 */
void array_free(array_t *this)
{
	assert(this);
	assert(pthread_mutex_lock(&(this->a_lock)) == 0);

	/* FIXME: We never unlock it - might cause deadlocks */

	if(this->a_data) {
		free(this->a_data);
	}
	free(this);

	return;
}

/**
 * Return the number of elements in the array
 * @param this the array
 * @return the number of elements in the array
 */
int array_get_length(array_t *this)
{
	int len;

	assert(this);

	assert(pthread_mutex_lock(&(this->a_lock)) == 0);
	len = this->a_used;
	assert(pthread_mutex_unlock(&(this->a_lock)) == 0);

	return(len);
}

/**
 * Insert an element into the array
 * @param this the array to insert the element into
 * @param ptr the element to be inserted
 * @return a non-negative value on success, or a negative value in case of an error
 */
int array_insert(array_t *this, const void *ptr)
{
	int i;

	assert(this != NULL);
	assert(ptr != NULL);
	assert(ptr != ARRAY_DIRTY_MARK);

	assert(pthread_mutex_lock(&(this->a_lock)) == 0);

	if(this->a_used == this->a_size) {
		assert(_array_increase(this));
	}

	i = this->a_next;
	do {
		if(this->a_data[i] <= ARRAY_DIRTY_MARK) {
			this->a_data[i] = (void*)ptr;
			this->a_used++;
			this->a_next = (i + 1) % this->a_size;
			assert(pthread_mutex_unlock(&(this->a_lock)) == 0);
			return(i);
		}
		i = (i + 1) % this->a_size;
	} while(i != this->a_next);

	assert(pthread_mutex_unlock(&(this->a_lock)) == 0);
	return(-1);
}

/**
 * Remove an element from an array
 * @param this the array to remove from
 * @param ptr the element to be removed
 * @return a non-negative value on success, or a negative value of the element was not found
 */
int array_remove(array_t *this, const void *ptr)
{
	int i;

	assert(this);
	assert(ptr);
	assert(ptr != ARRAY_DIRTY_MARK);

	assert(pthread_mutex_lock(&(this->a_lock)) == 0);

	for(i = 0; i < this->a_size; i++) {
		if(this->a_data[i] == ptr) {
			this->a_data[i] = ARRAY_DIRTY_MARK;
			this->a_used--;
			this->a_next = i;

			if(this->a_size > ARRAY_INIT_SIZE && (this->a_size >> ARRAY_DEC_SHIFT) > this->a_used) {
				_array_decrease(this);
			}

			assert(pthread_mutex_unlock(&(this->a_lock)) == 0);
			return(i);
		}
	}
	assert(pthread_mutex_unlock(&(this->a_lock)) == 0);
	return(-1);
}

/**
 * Call a function for each of the elements of an array
 * @param this the array
 * @param func the function to call for each element
 * @return void
 */
void array_foreach(array_t *this, void (*func)(void*))
{
	int i, d;

	assert(this);
	assert(func);

	assert(pthread_mutex_lock(&(this->a_lock)) == 0);

	for(i = 0, d = 0; i < this->a_size && d < this->a_used; i++) {
		if(this->a_data[i] > ARRAY_DIRTY_MARK) {
			func(this->a_data[i]);
			d++;
		}
	}

	assert(pthread_mutex_unlock(&(this->a_lock)) == 0);
	return;
}

/**
 * Call a function for each of the elements of an array and pass an additional argument
 * @param this the array
 * @param func the function to call for each element
 * @param data the value to pass as the second argument to the function
 * @return void
 */
void array_foreach2(array_t *this, void (*func)(void*, void*), void *data)
{
	int i, d;

	assert(this);
	assert(func);

	assert(pthread_mutex_lock(&(this->a_lock)) == 0);

	for(i = 0, d = 0; i < this->a_size && d < this->a_used; i++) {
		if(this->a_data[i] > ARRAY_DIRTY_MARK) {
			func(this->a_data[i], data);
			d++;
		}
	}

	assert(pthread_mutex_unlock(&(this->a_lock)) == 0);
	return;
}

/**
 * Get the nth element of an array
 * @param this the array
 * @param n the index into the array
 * @return a pointer to the nth element in the array, or NULL if n is outside the array bounds
 */
void* array_get_nth(array_t *this, int n)
{
	int i;
	void *ptr;

	assert(this);
	assert(n < this->a_used);

	ptr = NULL;

	assert(pthread_mutex_lock(&(this->a_lock)) == 0);

	for(i = 0; i < this->a_size; i++) {
		if(this->a_data[i] > ARRAY_DIRTY_MARK) {
			if(n--) {
				continue;
			}
			ptr = this->a_data[i];
			break;
		}
	}

	assert(pthread_mutex_unlock(&(this->a_lock)) == 0);
	return(ptr);
}

/**
 * Find an element in an array, using a caller-specified comparator
 * @param this the array to iterate over
 * @param cmp a pointer to the comparator function
 * @param arg the second argument to the comparator function
 * @return a pointer to the located element, or NULL if no element could be found
 */
void* array_find(array_t *this, int (*cmp)(void*, void*), void *arg)
{
	int i, d;
	void *ptr;

	assert(this);
	assert(cmp);
	assert(arg);

	assert(pthread_mutex_lock(&(this->a_lock)) == 0);

	for(i = 0, d = 0; i < this->a_size && d < this->a_used; i++) {
		ptr = this->a_data[i];

		if(ptr > ARRAY_DIRTY_MARK) {
			if(cmp(ptr, arg) == 0) {
				assert(pthread_mutex_unlock(&(this->a_lock)) == 0);
				return(ptr);
			}
			d++;
		}
	}

	assert(pthread_mutex_unlock(&(this->a_lock)) == 0);
	return(NULL);
}

/**
 * Duplicate an array
 * @param this the array to duplicate
 * @return a pointer to the newly created array, or NULL if an error occurred
 */
array_t* array_dup(array_t *this)
{
	array_t *a;

	assert(this);

	if((a = array_alloc())) {
		ARRAY_FOREACH(this, void, elem, {
			array_insert(a, elem);
		});
	}

	return(a);
}
