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

#ifndef LOG_H
#define LOG_H

#define LOG_ERROR 0
#define LOG_WARN  1
#define LOG_INFO  2
#define LOG_DEBUG 3

#define log_info(fmt, ...)  log_write(LOG_INFO,  "[INF]", fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  log_write(LOG_WARN,  "[WRN]", fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log_write(LOG_ERROR, "[ERR]", fmt, ##__VA_ARGS__)
#define log_perror(msg)     log_error("%s: %s\n", msg, strerror(errno))

int  log_increase_verbosity(int inc);
void log_write(int level, const char *prefix, const char *fmt, ...);

#endif /* LOG_H */
