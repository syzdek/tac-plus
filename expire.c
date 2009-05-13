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
#include "expire.h"

/*
 * check a date for expiry. If the field specifies
 * a shell return PW_OK
 *
 * Return PW_OK if not expired
 * Return PW_EXPIRING if expiry is coming soon
 * Return PW_EXPIRED  if already expired
 */

#define SEC_IN_DAY (24*60*60)
#define WARNING_PERIOD 14

static char *monthname[] = {"JAN", "FEB", "MAR", "APR", "MAY", "JUN",
"JUL", "AUG", "SEP", "OCT", "NOV", "DEC"};
static long days_ere_month[] = {0, 31, 59, 90, 120, 151,
181, 212, 243, 273, 304, 334};

int
check_expiration(date)
char *date;
{
    long day, month, year, leaps, now, expiration, warning;
    char monthstr[10];
    int i;

    monthstr[0] = '\0';

    /* If no date or a shell, let it pass.  (Backward compatibility.) */
    if (!date || (strlen(date) == 0) || (*date == '/'))
	return (PW_OK);

    /* Parse date string.  Fail it upon error. */
    if (sscanf(date, "%s %d %d", monthstr, &day, &year) != 3)
	return (PW_EXPIRED);

    for(i=0; i < 3; i++) {
	monthstr[i] = toupper(monthstr[i]);
    }

    /* Compute the expiration date in days. */
    for (month = 0; month < 12; month++)
	if (strncmp(monthstr, monthname[month], 3) == 0)
	    break;

    if (month > 11)
	return (PW_EXPIRED);

    leaps = (year - 1969) / 4 + (((year % 4) == 0) && (month > 2));
    expiration = (((year - 1970) * 365) + days_ere_month[month] + (day - 1) + leaps);
    warning = expiration - WARNING_PERIOD;

    /* Get the current time (to the day) */
    now = time(NULL) / SEC_IN_DAY;

    if (now > expiration)
	return (PW_EXPIRED);

    if (now > warning)
	return (PW_EXPIRING);

    return (PW_OK);
}
