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

/*
 *  Come here when we receive an Start Accounting packet
 */

void account();

void
accounting(pak)
u_char *pak;
{
    struct acct *acct_pak;
    u_char *p;
    HDR *hdr;
    u_char *read_packet();
    int i, len;

    if (debug & DEBUG_ACCT_FLAG)
	report(LOG_DEBUG, "Start accounting request");

    hdr = (HDR *) pak;
    acct_pak = (struct acct *) (pak + TAC_PLUS_HDR_SIZE);

    /* Do some sanity checking on the packet */

    /* arg counts start here */
    p = pak + TAC_PLUS_HDR_SIZE + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;

    /* Length checks */
    len = TAC_ACCT_REQ_FIXED_FIELDS_SIZE;
    len += acct_pak->user_len + acct_pak->port_len + 
	acct_pak->rem_addr_len + acct_pak->arg_cnt;
    for (i = 0; i < (int)acct_pak->arg_cnt; i++) {
	len += p[i];
    }

    if (len != ntohl(hdr->datalength)) {
	send_error_reply(TAC_PLUS_ACCT, NULL);
	return;
    }

    account(pak);

    free(pak);
}

void
account(pak)
u_char *pak;
{
    struct acct *acct_pak;
    u_char *p, *argsizep;
    struct acct_rec rec;
    struct identity identity;
    char **cmd_argp;
    int i, errors, status;

    acct_pak = (struct acct *) (pak + TAC_PLUS_HDR_SIZE);

    /* Fill out accounting record structure */
    bzero(&rec, sizeof(struct acct_rec));

    if (acct_pak->flags & TAC_PLUS_ACCT_FLAG_WATCHDOG)
	rec.acct_type = ACCT_TYPE_UPDATE;
    if (acct_pak->flags & TAC_PLUS_ACCT_FLAG_START)
	rec.acct_type = ACCT_TYPE_START;
    if (acct_pak->flags & TAC_PLUS_ACCT_FLAG_STOP)
	rec.acct_type = ACCT_TYPE_STOP;

    rec.authen_method  = acct_pak->authen_method;
    rec.authen_type    = acct_pak->authen_type;
    rec.authen_service = acct_pak->authen_service;

    /* start of variable length data is here */
    p = pak + TAC_PLUS_HDR_SIZE + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;

    /* skip arg cnts */
    p += acct_pak->arg_cnt;

    /* zero out identity struct */
    bzero(&identity, sizeof(struct identity));

    identity.username = tac_make_string(p, (int)acct_pak->user_len);
    p += acct_pak->user_len;

    identity.NAS_name = tac_strdup(session.peer);

    identity.NAS_port = tac_make_string(p, (int)acct_pak->port_len);
    p += acct_pak->port_len;
    if (acct_pak->port_len <= 0) {
	strcpy(session.port, "unknown-port");
    } else {
	strcpy(session.port, identity.NAS_port);
    }

    identity.NAC_address = tac_make_string(p, (int)acct_pak->rem_addr_len);
    p += acct_pak->rem_addr_len;

    identity.priv_lvl = acct_pak->priv_lvl;

    rec.identity = &identity;

    /* Now process cmd args */
    argsizep = pak + TAC_PLUS_HDR_SIZE + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;

    cmd_argp = (char **) tac_malloc(acct_pak->arg_cnt * sizeof(char *));

    for (i = 0; i < (int)acct_pak->arg_cnt; i++) {
	cmd_argp[i] = tac_make_string(p, *argsizep);
	p += *argsizep++;
    }

    rec.args = cmd_argp;
    rec.num_args = acct_pak->arg_cnt;

#ifdef MAXSESS
    /*
     * Tally for MAXSESS counting
     */
    loguser(&rec);
#endif

    /*
     * Do accounting.
     */
    if (wtmpfile) {
	errors = do_wtmp(&rec);
    } else {
	errors = do_acct(&rec);
    }

    if (errors) {
	status = TAC_PLUS_ACCT_STATUS_ERROR;
    } else {
	status = TAC_PLUS_ACCT_STATUS_SUCCESS;
    }
    send_acct_reply(status, rec.msg, rec.admin_msg);

    free(identity.username);
    free(identity.NAS_name);
    free(identity.NAS_port);
    free(identity.NAC_address);

    for (i = 0; i < (int)acct_pak->arg_cnt; i++) {
	free(cmd_argp[i]);
    }    
    free(cmd_argp);
    
    if (rec.msg)
	free(rec.msg);
    if (rec.admin_msg)
	free(rec.admin_msg);
}
