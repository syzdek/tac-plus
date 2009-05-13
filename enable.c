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

/* internal state variables */
#define STATE_AUTHEN_START   0	/* no requests issued */
#define STATE_AUTHEN_GETUSER 1	/* username has been requested */
#define STATE_AUTHEN_GETPASS 2	/* password has been requested */

struct private_data {
    char password[MAX_PASSWD_LEN + 1];
    int state;
};

static void
enable(passwd, data)
char *passwd;
struct authen_data *data;
{
    int level = data->NAS_id->priv_lvl;

    /* sanity check */
    if (level < TAC_PLUS_PRIV_LVL_MIN || level > TAC_PLUS_PRIV_LVL_MAX) {
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	data->server_msg = tac_strdup("Invalid privilege level in packet");
	report(LOG_ERR, "%s level=%d %s", session.peer, level, data->server_msg);
	return;
    }
    /* 0 <= level <= 14: look for $enab<n>$ and verify */
    if (level < TAC_PLUS_PRIV_LVL_MAX) {
	char buf[11];

	sprintf(buf, "$enab%d$", level);
	if (!verify(buf, passwd, data, TAC_PLUS_NORECURSE))
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }

    /* 2). level=15. Try $enab15$ or $enable$ (for backwards
       compatibility) and verify */

    if (verify("$enable$", passwd, data, TAC_PLUS_NORECURSE) ||
	verify("$enab15$", passwd, data, TAC_PLUS_NORECURSE)) {
	return;
    }

    /* return fail */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    return;
}


/*
 * Tacacs enable authentication function. Wants an enable
 * password, and tries to verify it.
 *
 * Choose_authen will ensure that we already have a username before this
 * gets called.
 *
 * We will query for a password and keep it in the method_data.
 *
 * Any strings returned via pointers in authen_data must come from the
 * heap. They will get freed by the caller.
 *
 * Return 0 if data->status is valid, otherwise 1
 */

int
enable_fn(data)
struct authen_data *data;
{
    char *passwd;
    struct private_data *p;
    int pwlen;

    p = (struct private_data *) data->method_data;

    /* An abort has been received. Clean up and return */
    if (data->flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
	if (data->method_data)
	    free(data->method_data);
	data->method_data = NULL;
	return (1);
    }
    /* Initialise method_data if first time through */
    if (!p) {
	p = (struct private_data *) tac_malloc(sizeof(struct private_data));
	bzero(p, sizeof(struct private_data));
	data->method_data = p;
	p->state = STATE_AUTHEN_START;
    }

    /* As we're enabling, we don't need a username, but do we have a
       password? */

    passwd = p->password;

    if (!passwd[0]) {

	/* No password. Either we need to ask for one and expect to get
	 * called again, or we asked but nothing came back, which is fatal */

	switch (p->state) {
	case STATE_AUTHEN_GETPASS:
	    /* We already asked for a password. This should be the
               reply */
	    if (data->client_msg) {
		pwlen = MIN((int)strlen(data->client_msg), MAX_PASSWD_LEN);
	    } else {
		pwlen = 0;
	    }
	    strncpy(passwd, data->client_msg, pwlen);
	    passwd[pwlen] = '\0';
	    break;

	default:
	    /* Request a password */
	    data->flags = TAC_PLUS_AUTHEN_FLAG_NOECHO;
	    data->server_msg = tac_strdup("Password: ");
	    data->status = TAC_PLUS_AUTHEN_STATUS_GETPASS;
	    p->state = STATE_AUTHEN_GETPASS;
	    return (0);
	}
    }

    /* We have a password. Try validating */

    /* Assume the worst */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    switch (data->service) {
    case TAC_PLUS_AUTHEN_SVC_ENABLE:
	enable(passwd, data);
	if (debug) {
	    char *name = data->NAS_id->username;

	    report(LOG_INFO, "enable query for '%s' %s from %s %s",
		   name && name[0] ? name : "unknown",
		   data->NAS_id->NAS_port && data->NAS_id->NAS_port[0] ?
		       data->NAS_id->NAS_port : "unknown",
		   session.peer, 
		   (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		   "accepted" : "rejected");
	}
	break;
    default:
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	report(LOG_ERR, "%s: Bogus service value %d from packet", 
	       session.peer, data->service);
	break;
    }

    if (data->method_data)
	free(data->method_data);
    data->method_data = NULL;

    switch (data->status) {
    case TAC_PLUS_AUTHEN_STATUS_ERROR:
    case TAC_PLUS_AUTHEN_STATUS_FAIL:
    case TAC_PLUS_AUTHEN_STATUS_PASS:
	return (0);
    default:
	report(LOG_ERR, "%s: authenticate_fn can't set status %d",
	       session.peer, data->status);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return (1);
    }
}
