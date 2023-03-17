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

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include "log.h"

static int verbosity = LOG_WARN;

int log_increase_verbosity(int inc)
{
	verbosity += inc;

	if (verbosity > LOG_DEBUG) {
		verbosity = LOG_DEBUG;
	}
	if (verbosity < LOG_ERROR) {
		verbosity = LOG_ERROR;
	}

	return verbosity;
}

int make_timestamp(char *dst, size_t dst_size)
{
	time_t now;
	struct tm curtime;

	now = time(NULL);
	if (!localtime_r(&now, &curtime)) {
		return -errno;
	}

	return strftime(dst, dst_size, "%Y-%m-%d %H:%M:%S%z", &curtime);
}

void log_write(int level, const char *prefix, const char *fmt, ...)
{
	char timestamp[32];
	va_list args;

	if (level > verbosity) {
		return;
	}

	if (make_timestamp(timestamp, sizeof(timestamp)) < 0) {
		return;
	}

	fprintf(stderr, "%s %s ", timestamp, prefix);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}
