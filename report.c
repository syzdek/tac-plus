/* 
   Copyright (c) 1995-2000 by Cisco systems, Inc.

   Permission to use, copy, modify, and distribute modified and
   unmodified copies of this software for any purpose and without fee is
   hereby granted, provided that (a) this copyright and permission notice
   appear on all copies of the software and supporting documentation, (b)
   the name of Cisco Systems, Inc. not be used in advertising or
   publicity pertaining to distribution of the program without specific
   prior permission, and (c) notice be given in supporting documentation
   that use, modification, copying and distribution is by permission of
   Cisco Systems, Inc.

   Cisco Systems, Inc. makes no representations about the suitability
   of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
   IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
   WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
   FITNESS FOR A PARTICULAR PURPOSE.
*/

#include "tac_plus.h"
#include <stdio.h>

#ifdef AIX
#include <sys/types.h>
#else
#include <time.h>
#endif

#ifdef __STDC__
#include <stdarg.h>		/* ANSI C, variable length args */
#else
#include <varargs.h>		/* has 'vararg' definitions */
#endif

FILE *ostream = NULL;

char *logfile = LOGFILE_DEFAULT;

/* report:
 *
 * This routine reports errors and such via stderr and syslog() if
 * appopriate.  It just helps avoid a lot of if-else in the code.
 *
 * LOG_DEBUG messages are ignored unless debugging is on.
 * All other priorities are always logged to syslog.
 */

#ifdef __STDC__
void
report(int priority, char *fmt,...)
#else
/* VARARGS2 */
void
report(priority, fmt, va_alist)
int priority;
char *fmt;
va_dcl				/* no terminating semi-colon */
#endif
{
    char msg[255];		/* temporary string */
    char *fp, *bufp, *charp;
    int len, m, i, n;
    char digits[16];
    va_list ap;

#ifdef __STDC__
    va_start(ap, fmt);
#else
    va_start(ap);
#endif

    /* ensure that msg is never overwritten */
    n = 255;
    fp = fmt;
    len = 0;
    msg[n-1] = '\0';
    bufp = msg;

    while (*fp) {

	if (*fp != '%') {
	    if ((len+1) >= n) {
		break;
	    }
	    *bufp++ = *fp++;
	    len++;
	    continue;
	}

	/* seen a '%' */
	fp++;

	switch (*fp) {

	case 's':
	    fp++;
	    charp = va_arg(ap, char *);
	    m = strlen(charp);
	    break;

	case 'u':
	    fp++;
	    i = va_arg(ap, uint);
	    sprintf(digits, "%u", i);
	    m = strlen(digits);
	    charp = digits;
	    break;
	case 'x':
	    fp++;
	    i = va_arg(ap, uint);
	    sprintf(digits, "%x", i);
	    m = strlen(digits);
	    charp = digits;
	    break;
	case 'd':
	    fp++;
	    i = va_arg(ap, int);
	    sprintf(digits, "%d", i);
	    m = strlen(digits);
	    charp = digits;
	    break;
	}
	    
	if ((len + m + 1) >= n) {
	    break;
	}

	memcpy(bufp, charp, m);
	bufp += m;
	len += m;
	continue;
    }

    msg[len] = '\0';

    /* check we never overwrote the end of the buffer */
    if (msg[n-1]) {
	abort();
    }

    va_end(ap);


    if (console) {
	extern int errno;
	
	if (!ostream)
	    ostream = fopen("/dev/console", "w");

	if (ostream) {
	    if (priority == LOG_ERR)
		fprintf(ostream, "Error ");
	    fprintf(ostream, "%s\n", msg);
	}
	else 
	    syslog(LOG_ERR, "Cannot open /dev/console errno=%d", errno);
    }

    if (debug) {
	int logfd;

	logfd = open(logfile, O_CREAT | O_WRONLY | O_APPEND, 0666);
	if (logfd >= 0) {
	    char buf[512];
	    time_t t = time(NULL);
	    char *ct = ctime(&t);

	    ct[24] = '\0';
	    tac_lockfd(logfile, logfd);
	    sprintf(buf, "%s [%d]: ", ct, getpid());
	    write(logfd, buf, strlen(buf));
	    if (priority == LOG_ERR)
		write(logfd, "Error ", 6);
	    write(logfd, msg, strlen(msg));
	    write(logfd, "\n", 1);
	    close(logfd);
	}
    }

    if (single) {
	fprintf(stderr, "%s\n", msg);
    }

    if (priority == LOG_DEBUG)
	return;

    if (priority == LOG_ERR)
	syslog(priority, "Error %s", msg);
    else
	syslog(priority, "%s", msg);
}

/* format a hex dump for syslog */
void
report_hex(priority, p, len)
u_char *p;
int len;
{
    char buf[256];
    char digit[10];
    int buflen;
    int i;
    
    if (len <= 0)
	return;

    buf[0] = '\0';
    buflen = 0;
    for (i = 0; i < len && i < 255; i++, p++) {

	sprintf(digit, "0x%x ", *p);
	strcat(buf, digit);
	buflen += strlen(digit);

	if (buflen > 75) {
	    report(priority, "%s", buf);
	    buf[0] = '\0';
	    buflen = 0;
	}
    }

    if (buf[0]) {
	report(priority, "%s", buf);
    }
}


/* format a non-null terminated string for syslog */
void
report_string(priority, p, len)
u_char *p;
int len;
{
    char buf[256];
    char *bufp = buf;
    int i;

    if (len <= 0)
	return;

    for (i = 0; i < len && i < 255; i++) {
	if (32 <= *p && *p <= 126) {
	    *bufp++ = *p++;
	} else {
	    sprintf(bufp, " 0x%x ", *p);
	    bufp += strlen(bufp);
	    p++;
	}
    }
    *bufp = '\0';
    report(priority, "%s", buf);
}

void
regerror(s)
char *s;
{
    report(LOG_ERR, "in regular expression %s", s);
}

