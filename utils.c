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

#ifdef STDLIB_MALLOC

#include <stdlib.h>

#else /* !STDLIB_MALLOC */

#include <malloc.h>

#endif /* STDLIB_MALLOC */

char *
tac_malloc(size)
int size;
{
    char *p;

    /* some mallocs don't like requests for zero length */
    if (size == 0) {
	size++;
    }

    p = (char *) malloc(size);

    if (p == NULL) {
	report(LOG_ERR, "malloc %d failure", size);
	tac_exit(1);
    }
    return (p);
}

char *
tac_realloc(ptr, size)
char *ptr;
int size;
{
    char *p;

    if (ptr == NULL) {
	/* realloc(0, size) is not portable */
	p = tac_malloc(size);
    } else {
	p = (char *)realloc(ptr, size);
    }

    if (p == NULL) {
	report(LOG_ERR, "realloc %d failure", size);
	tac_exit(1);
    }
    return (p);
}

tac_exit(status)
int status;
{
    if (debug & DEBUG_FORK_FLAG)
	report(LOG_DEBUG, "exit status=%d", status);
    exit(status);
}

char *
tac_strdup(p)
char *p;
{
    char *n = strdup(p);

    if (n == NULL) {
	report(LOG_ERR, "strdup allocation failure");
	tac_exit(1);
    }
    return (n);
}

char *
tac_make_string(p, len)
u_char *p;
int len;
{
    char *string;
    int new_len = len;

    /* 
     * Add space for a null terminator if needed. Also, no telling
     * what various mallocs will do when asked for a length of zero.
     */
    if (len == 0 || p[len - 1])
	new_len++;

    string = (char *) tac_malloc(new_len);

    bzero(string, new_len);
    bcopy(p, string, len);
    return (string);
}

/* return a pointer to the end of substring in string, or NULL. Substring 
   must begin at start of string.
*/
char *
tac_find_substring(substring, string)
char *substring, *string;
{
    int len;

    if (!(substring && string)) {
	return(NULL);
    }

    len = strlen(substring);

    if (len > (int) strlen(string)) {
	return(NULL);
    }
	
    if (strncmp(substring, string, len)) {
	/* no match */
	return(NULL);
    }
    return(string + len);
}

#ifdef NEED_BZERO
int
bzero(p, len)
    register char *p;
    int len;
{
    register int n;

    if (len <= 0) {
	return;
    }
    for (n=0; n < len; n++) {
	p[n] = 0;
    }
}

int
bcopy(s1, s2, len)
    register char *s1, *s2;
    int len;
{
    register int n;

    if ((n = len) <= 0)
	return;
    do
	*s2++ = *s1++;
    while (--n);
}

int 
bcmp(s1,s2,n)
    char *s1,*s2;
    int n;
{     
    while (n-- > 0) {
	if (*s1++ != *s2++) {
	    return(1);
	}
    }
    return 0;
}
#endif /* NEED_BZERO */

/* Lock a file descriptor using fcntl. Returns 1 on successfully
   acquiring the lock. The lock disappears when we close the file.

   Note that if the locked file is on an NFS-mounted partition, you
   are at the mercy of SUN's lockd, which is probably a bad idea 
*/

int
tac_lockfd (filename, lockfd)
char *filename;
int lockfd;
{
    int tries;
    struct flock flock;
    int status;

    flock.l_type   = F_WRLCK;
    flock.l_whence = SEEK_SET; /* relative to bof */
    flock.l_start  = 0L; /* from offset zero */
    flock.l_len    = 0L; /* lock to eof */

    if (debug & DEBUG_LOCK_FLAG) {
	syslog(LOG_ERR, "Attempting to lock %s fd %d", filename, lockfd);
    }

    for (tries = 0; tries < 10; tries++) {
	errno = 0;
	status = fcntl(lockfd, F_SETLK, &flock);
	if (status == -1) {
	    if (errno == EACCES || errno == EAGAIN) {
		sleep(1);
		continue;
	    } else {
		syslog(LOG_ERR, "fcntl lock error status %d on %s %d %s", 
		       status, filename, lockfd, sys_errlist[errno]);
		return(0);
	    }
	}
	/* successful lock */
	break;
    }

    if (errno != 0) {
	syslog(LOG_ERR, "Cannot lock %s fd %d in %d tries %s", 
	       filename, lockfd, tries+1, sys_errlist[errno]);

	/* who is hogging this lock */
	flock.l_type   = F_WRLCK;
	flock.l_whence = SEEK_SET; /* relative to bof */
	flock.l_start  = 0L; /* from offset zero */
	flock.l_len    = 0L; /* lock to eof */
#ifdef HAS_FLOCK_SYSID
	flock.l_sysid  = 0L;
#endif
	flock.l_pid    = 0;

	status = fcntl(lockfd, F_GETLK, &flock);
	if ((status == -1) || (flock.l_type == F_UNLCK)) {
	    syslog(LOG_ERR, "Cannot determine %s lockholder status=%d type=%d",
		   filename, status, flock.l_type);
	    return(0);
	}

	if (debug & DEBUG_LOCK_FLAG) {
	    syslog(LOG_ERR, "Lock on %s is being held by sys=%u pid=%d",
		   filename, 
#ifdef HAS_FLOCK_SYSID
		   flock.l_sysid, 
#else
		   0,
#endif
		   flock.l_pid);
	}
	return(0);
    }

    if (debug & DEBUG_LOCK_FLAG) {
	syslog(LOG_ERR, "Successfully locked %s fd %d after %d tries", 
	       filename, lockfd, tries+1);
    }
    return(1);
}

/* Unlock a file descriptor using fcntl. Returns 1 on successfully
   releasing a lock. The lock dies when we close the file.

   Note that if the locked file is on an NFS-mounted partition, you
   are at the mercy of SUN's lockd, which is probably a bad idea 
*/

int
tac_unlockfd (filename,lockfd)
char *filename;
int lockfd;
{
    struct flock flock;
    int status;

    flock.l_type   = F_WRLCK;
    flock.l_whence = SEEK_SET; /* relative to bof */
    flock.l_start  = 0L; /* from offset zero */
    flock.l_len    = 0L; /* lock to eof */

    if (debug & DEBUG_LOCK_FLAG) {
	syslog(LOG_ERR, "Attempting to unlock %s fd %d", filename, lockfd);
    }

    status = fcntl(lockfd, F_UNLCK, &flock);
    if (status == -1) {
	syslog(LOG_ERR, "fcntl unlock error status %d on %s %d %s", 
	       status, filename, lockfd, sys_errlist[errno]);
	return(1);
    }

    if (debug & DEBUG_LOCK_FLAG) {
	syslog(LOG_ERR, "Successfully unlocked %s fd %d", 
	       filename, lockfd);
    }
    return(0);
}
