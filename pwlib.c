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

#ifdef SHADOW_PASSWORDS
#include <shadow.h>
#endif

/* Generic password verification routines for des, file and cleartext
   passwords */

static int passwd_file_verify();

/* Adjust data->status depending on whether a user has expired or not */

void
set_expiration_status(exp_date, data)
char *exp_date;
struct authen_data *data;
{
    int expired;

    /* if the status is anything except pass, there's no point proceeding */
    if (data->status != TAC_PLUS_AUTHEN_STATUS_PASS) {
	return;
    }

    /* Check the expiration date, if any. If NULL, this check will return
     * PW_OK */
    expired = check_expiration(exp_date);

    switch (expired) {
    case PW_OK:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password has not expired %s", 
		   exp_date ? exp_date : "<no expiry date set>");

	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	return;

    case PW_EXPIRING:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password will expire soon %s", 
		   exp_date ? exp_date : "<no expiry date set>");
	if (data->server_msg)
	    free(data->server_msg);
	data->server_msg = tac_strdup("Password will expire soon");
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	return;

    case PW_EXPIRED:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password has expired %s", 
		   exp_date ? exp_date : "<no expiry date set>");
	if (data->server_msg)
	    free(data->server_msg);
	data->server_msg = tac_strdup("Password has expired");
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;

    default:
	report(LOG_ERR, "%s: Bogus return value %d from check_expiration", 
	       session.peer, expired);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
}

/* Verify that this user/password is valid.  Works only for cleartext,
   file and des passwords.
   
   Return 1 if password is valid */

int
verify(name, passwd, data, recurse)
char *name, *passwd;
struct authen_data *data;
int recurse;
{
    char *exp_date;
    char *cfg_passwd;
    char *p;

    if (data->type == TAC_PLUS_AUTHEN_TYPE_PAP) {
	cfg_passwd = cfg_get_pap_secret(name, recurse);
    } else {
	cfg_passwd = cfg_get_login_secret(name, recurse);
    }

    /* If there is no login or pap password for this user, see if there is 
       a global password for her that we can use */

    if (!cfg_passwd) {
	cfg_passwd = cfg_get_global_secret(name, recurse);
    }

    /* If we still have no password for this user (or no user for that
       matter) but the default authentication = file <file> statement
       has been issued, attempt to use this password file */

    if (!cfg_passwd) {
	char *file = cfg_get_authen_default();
	if (file) {
	    return (passwd_file_verify(name, passwd, data, file));
	}

	/* otherwise, we fail */
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return (0);
    }

    /* We have a configured password. Deal with it depending on its
       type */

    p = tac_find_substring("cleartext ", cfg_passwd);
    if (p) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "verify daemon %s == NAS %s", p, passwd);

	if (strcmp(passwd, p)) {
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Password is incorrect"); 
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Password is correct"); 
	}

	exp_date = cfg_get_expires(name, recurse);
	set_expiration_status(exp_date, data);
	return (data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("des ", cfg_passwd);
    if (p) {
	/* try to verify this des password */
	if (!des_verify(passwd, p)) {
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return (0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	}

	exp_date = cfg_get_expires(name, recurse);
	set_expiration_status(exp_date, data);
	return (data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("file ", cfg_passwd);
    if (p) {
	return (passwd_file_verify(name, passwd, data, p));
    }

    /* Oops. No idea what kind of password this is. This should never
       happen as the parser should never create such passwords. */

    report(LOG_ERR, "%s: Error cannot identify password type %s for %s",
	   session.peer, 
	   cfg_passwd && cfg_passwd[0] ? cfg_passwd : "<NULL>", 
	   name ? name : "<unknown>");

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    return (0);
}

/* verify that this user/password is valid per /etc/passwd.
   Return 0 if invalid. */
static int
etc_passwd_file_verify(user, supplied_passwd, data)
char *user, *supplied_passwd;
struct authen_data *data;
{
    struct passwd *pw;
    char *exp_date;
    char *cfg_passwd;
#ifdef SHADOW_PASSWORDS
    char buf[12];
#endif /* SHADOW_PASSWORDS */

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    setpwent();
    pw = getpwnam(user);
    endpwent();

    if (pw == NULL) {
	/* no entry exists */
	return (0);
    }

    if (*pw->pw_passwd == '\0' ||
	supplied_passwd == NULL ||
	*supplied_passwd == '\0') {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return (0);
    }
    cfg_passwd = pw->pw_passwd;
    exp_date = pw->pw_shell;

#ifdef SHADOW_PASSWORDS
    if (STREQ(pw->pw_passwd, "x")) {
	struct spwd *spwd = getspnam(user);

	if (!spwd) {
	    if (debug & DEBUG_PASSWD_FLAG) {
		report(LOG_DEBUG, "No entry for %s in shadow file", user);
	    }
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return (0);
	}
	if (debug & DEBUG_PASSWD_FLAG) {
	    report(LOG_DEBUG, "Found entry for %s in shadow file", user);
	}
	cfg_passwd = spwd->sp_pwdp;

	/* 
	 * Sigh. The Solaris shadow password file contains its own
	 * expiry date as the number of days after the epoch
	 * (January 1, 1970) when the password expires.
	 * Convert this to ascii so that the traditional tacacs
	 * password expiration routines work correctly. 
	 */

	if (spwd->sp_expire > 0) {
	    long secs = spwd->sp_expire * 24 * 60 * 60;
	    char *p = ctime(&secs);
	    bcopy(p+4, buf, 7);
	    bcopy(p+20, buf+7, 4);
	    buf[11] = '\0';
	    exp_date = buf;
	}
    }
#endif /* SHADOW_PASSWORDS */

    /* try to verify the password */
    if (!des_verify(supplied_passwd, cfg_passwd)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return (0);
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

    /* password ok. Check expiry field */
    set_expiration_status(exp_date, data);

    return (data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
}

/* verify that this user/password is valid per a passwd(5) style
   database. Return 0 if invalid. */

static int
passwd_file_verify(user, supplied_passwd, data, filename)
char *user, *supplied_passwd;
struct authen_data *data;
char *filename;
{
    struct passwd *pw;
    char *exp_date;
    char *cfg_passwd;

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    if (filename && STREQ(filename, "/etc/passwd")) {
	return(etc_passwd_file_verify(user, supplied_passwd, data));
    }

    /* an alternate filename */
    if (!(access(filename, R_OK) == 0)) {
	report(LOG_ERR, "%s %s: Cannot access %s for user %s -- %s",
	       session.peer, session.port, filename, user, sys_errlist[errno]);
	return (0);
    }

    pw = tac_passwd_lookup(user, filename);

    if (pw == NULL)
	/* no entry exists */
	return (0);

    if (*pw->pw_passwd == '\0' ||
	supplied_passwd == NULL ||
	*supplied_passwd == '\0') {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return (0);
    }
    cfg_passwd = pw->pw_passwd;
    exp_date = pw->pw_shell;

    /* try to verify the password */
    if (!des_verify(supplied_passwd, cfg_passwd)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return (0);
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

    /* password ok. Check expiry field */
    set_expiration_status(exp_date, data);
    return (data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
}

/*
 * verify a provided password against a des encrypted one
 * return 1 if verified, 0 otherwise.
 */

int
des_verify(users_passwd, encrypted_passwd)
char *users_passwd, *encrypted_passwd;
{
    char *ep;

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "verify %s %s", users_passwd, encrypted_passwd);

    if (users_passwd == NULL ||
	*users_passwd == '\0' ||
	encrypted_passwd == NULL ||
	*encrypted_passwd == '\0') {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "verify returns 0");
	return (0);
    }

    ep = (char *) crypt(users_passwd, encrypted_passwd);

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "%s encrypts to %s", users_passwd, ep);

    if (strcmp(ep, encrypted_passwd) == 0) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password is correct");
	return (1);
    }

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "Password is incorrect");

    return (0);
}
