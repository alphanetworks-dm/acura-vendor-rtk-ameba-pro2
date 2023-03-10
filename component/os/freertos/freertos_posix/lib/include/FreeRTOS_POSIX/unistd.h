/*
 * Amazon FreeRTOS+POSIX V1.0.3
 * Copyright (C) 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/**
 * @file unistd.h
 * @brief Standard symbolic constants and types
 *
 * http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/unistd.h.html
 */

#ifndef _FREERTOS_POSIX_UNISTD_H_
#define _FREERTOS_POSIX_UNISTD_H_

#include "FreeRTOS_POSIX/sys/types.h"

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Suspend execution for an interval of time.
 *
 * http://pubs.opengroup.org/onlinepubs/9699919799/functions/sleep.html
 */
unsigned sleep( unsigned seconds );

/**
 * @brief Suspend execution for microsecond intervals.
 *
 * This is a useful, non-POSIX function.
 * @param[in] usec The number of microseconds to suspend execution.
 *
 * @return 0 always. This function does not specify any failure conditions.
 */
int usleep( useconds_t usec );

#if defined (__ICCARM__)
char *strerror_r(int errnum, char *buffer, size_t n);

void bzero(char *s, int n);
#endif /* defined (__ICCARM__) */

// ESSENTAIL2 START --- VFS wrapper support access function
#ifndef F_OK
#define F_OK            0       /* test for existence of file */
#define X_OK            0x01    /* test for execute or search permission */
#define W_OK            0x02    /* test for write permission */
#define R_OK            0x04    /* test for read permission */
#endif
int access(const char *pathname, int mode);
// ESSENTIAL2 END

#ifdef __cplusplus
}
#endif
#endif /* ifndef _FREERTOS_POSIX_UNISTD_H_ */
