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

static int acctfd = 0;

/* Make a acct entry into the accounting file for accounting. 
   Return 1 on error  */

static int
acct_write(string)
    char *string;
{
    if (write(acctfd, string, strlen(string)) != strlen(string)) {
	report(LOG_ERR, "%s: couldn't write acct file %s %s",
	       session.peer,
	       session.acctfile, sys_errlist[errno]);
	return(1);
    }
    
    if (debug & DEBUG_ACCT_FLAG)
	report(LOG_DEBUG, "'%s'", string);

    return(0);
}

/* Write a string or "unknown" into the accounting file.
   Return 1 on error  */
static int
acct_write_field(string)
    char *string;
{
    if (string && string[0]) {
	if (acct_write(string))
	    return(1);
    } else {
	if (acct_write("unknown"))
	    return(1);
    }
    return(0);
}

int
do_acct(rec)
struct acct_rec *rec;
{
    int i, errors;
    time_t t = time(NULL);
    char *ct = ctime(&t);

    ct[24] = '\0';

    if (!acctfd) {
	acctfd = open(session.acctfile, O_CREAT | O_WRONLY | O_APPEND, 0666);
	if (acctfd < 0) {
	    report(LOG_ERR, "Can't open acct file %s -- %s",
		   session.acctfile, sys_errlist[errno]);
	    return(1);
	}
    }
    if (!tac_lockfd(session.acctfile, acctfd)) {
	rec->admin_msg = tac_strdup("Cannot lock log file");
	report(LOG_ERR, "%s: Cannot lock %s", 
	       session.peer, session.acctfile);
	return(1);
    }

    errors = 0;

    errors += acct_write(ct);
    errors += acct_write("\t");

    errors += acct_write_field(rec->identity->NAS_name);
    errors += acct_write("\t");

    errors += acct_write_field(rec->identity->username);
    errors += acct_write("\t");

    errors += acct_write_field(rec->identity->NAS_port);
    errors += acct_write("\t");

    errors += acct_write_field(rec->identity->NAC_address);
    errors += acct_write("\t");

    switch(rec->acct_type) {
    case ACCT_TYPE_UPDATE:
	errors += acct_write("update\t");
	break;
    case ACCT_TYPE_START:
	errors += acct_write("start\t");
	break;
    case ACCT_TYPE_STOP:
	errors += acct_write("stop\t");
	break;
    default:
	errors += acct_write("unknown\t");
	break;
    }

    for (i=0; i < rec->num_args; i++) {
	errors += acct_write(rec->args[i]);
	if (i < (rec->num_args-1)) 
	    errors += acct_write("\t");
    }
    errors += acct_write("\n");

    close(acctfd);
    acctfd = 0;

    if (errors) {
	return(1);
    }
    return (0);
}

int
wtmp_entry (line, name, host, utime)
    char *line, *name, *host;
    time_t utime;
{
    struct utmp entry;

    if (!wtmpfile) {
	return(1);
    }

    bzero(&entry, sizeof entry);

    if (strlen(line) < sizeof entry.ut_line)
	strcpy(entry.ut_line, line);
    else bcopy(line, entry.ut_line, sizeof entry.ut_line);

    if (strlen(name) < sizeof entry.ut_name)
	strcpy(entry.ut_name, name);
    else bcopy(name, entry.ut_name, sizeof entry.ut_name);

#ifndef SOLARIS
    if (strlen(host) < sizeof entry.ut_host)
	strcpy(entry.ut_host, host);
    else bcopy(host, entry.ut_host, sizeof entry.ut_host);
#endif
    entry.ut_time = utime;

    wtmpfd = open(wtmpfile, O_CREAT | O_WRONLY | O_APPEND | O_SYNC, 0666);	
    if (wtmpfd < 0) {
	report(LOG_ERR, "Can't open wtmp file %s -- %s",
	       wtmpfile, sys_errlist[errno]);
	return(1);
    }

    if (!tac_lockfd(wtmpfile, wtmpfd)) {
	report(LOG_ERR, "%s: Cannot lock %s", session.peer, wtmpfile);
	return(1);
    }

    if (write(wtmpfd, &entry, sizeof entry) != (sizeof entry)) {
	report(LOG_ERR, "%s: couldn't write wtmp file %s %s",
	       session.peer, wtmpfile, sys_errlist[errno]);
	return(1);
    } 

    close(wtmpfd);

    if (debug & DEBUG_ACCT_FLAG) {
	report(LOG_DEBUG, "wtmp: %s, %s %s %d", line, name, host, utime);
    }
    
    return(0);
}

char *
find_attr_value (attr, args, cnt)
    char *attr, **args;
    int cnt;
{
    int i;

    for (i=0; i < cnt; i++) {
	if (!strncmp(attr, args[i], strlen(attr))) {
	    char *ptr;

	    for (ptr = args[i]; ptr && *ptr; ptr++) {
		if ((*ptr == '*') || (*ptr == '=')) {
		    return(ptr+1);
		}
	    }
	    return(NULL);
	}
    }
    return(NULL);
}

int
do_wtmp(rec)
    struct acct_rec *rec;
{
    time_t now = time(NULL);
    char *service;
    char *elapsed_time, *start_time;
    time_t start_utime = 0, stop_utime = 0, elapsed_utime = 0;
    

    switch(rec->acct_type) {
    case ACCT_TYPE_START:
    case ACCT_TYPE_STOP:
	break;

    case ACCT_TYPE_UPDATE:
    default:
	return(0);
    }

    service = find_attr_value("service", rec->args, rec->num_args);

    if (!service) {
	/* An error */
	return(1);
    }

    if (STREQ(service, "system")) {
	if (rec->acct_type == ACCT_TYPE_START) {
	    /* A reload */
	    wtmp_entry("~", "", session.peer, now);
	}
	return(0);
    }
	
    if (rec->acct_type != ACCT_TYPE_STOP) {
	return(0);
    }

    /* 
     * Since xtacacs logged start records containing the peer address
     * for a connection, we have to generate them from T+ stop records.
     * Might as well do this for exec records too.
     */
    
    elapsed_time = find_attr_value("elapsed_time", rec->args, rec->num_args);

    if (elapsed_time) {
	elapsed_utime = strtol(elapsed_time, NULL, 10);
    }

    start_time = find_attr_value("start_time", rec->args, rec->num_args);

    /* 
     * Use the start_time if there is one. If not (e.g. the NAS may
     * not know the time), assume the stop time is now, and calculate
     * the rest
     */

    if (start_time) {
	start_utime = strtol(start_time, NULL, 10);
	stop_utime  = start_utime + elapsed_utime;
    } else {
	start_utime = now - elapsed_utime;
	stop_utime  = now;
    }	

    if (STREQ(service, "slip") || STREQ(service, "ppp")) {
	char *dest_addr = find_attr_value("addr", rec->args, rec->num_args);

	/* The start record */
	wtmp_entry(rec->identity->NAS_port,
		   rec->identity->username,
		   dest_addr,
		   start_utime);

	/* The stop record */
	wtmp_entry(rec->identity->NAS_port,
		   "",
		   dest_addr,
		   stop_utime);
	return(0);
    }

    if (STREQ(service, "shell")) {
	/* Start */
	wtmp_entry(rec->identity->NAS_port,
		   rec->identity->username,
		   session.peer,
		   start_utime);

	/* Stop */
	wtmp_entry(rec->identity->NAS_port,
		   "",
		   session.peer,
		   stop_utime);
	return(0);
    }
    return(0);
}
