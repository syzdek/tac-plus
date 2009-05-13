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

/* Everything to do with reading and writing packets */

/* send an accounting response packet */
send_acct_reply(status, msg, data)
    u_char status;
    char *msg, *data;
{
    u_char *pak, *p;
    HDR *hdr;
    int len;
    struct acct_reply *reply;
    int msg_len, data_len;

    msg_len = msg ? strlen(msg) : 0;
    data_len = data ? strlen(data) : 0;

    len = TAC_PLUS_HDR_SIZE + TAC_ACCT_REPLY_FIXED_FIELDS_SIZE + msg_len + data_len;

    pak = (u_char *) tac_malloc(len);
    reply = (struct acct_reply *) (pak + TAC_PLUS_HDR_SIZE);
    hdr = (HDR *) pak;

    bzero(pak, len);

    hdr->version = TAC_PLUS_VER_0;
    hdr->type = TAC_PLUS_ACCT;
    hdr->seq_no = ++session.seq_no;
    hdr->encryption = TAC_PLUS_CLEAR;
    hdr->session_id = htonl(session.session_id);
    hdr->datalength = htonl(len - TAC_PLUS_HDR_SIZE);

    reply->status = status;
    reply->msg_len  = msg_len;
    reply->data_len = data_len;

    p = pak + TAC_PLUS_HDR_SIZE + TAC_ACCT_REPLY_FIXED_FIELDS_SIZE;
    bcopy(msg, p, msg_len);
    p += msg_len;

    bcopy(data, p, data_len);

    if (debug & DEBUG_PACKET_FLAG) {
	report(LOG_DEBUG, "Writing %s size=%d",
	       summarise_outgoing_packet_type(pak), len);
	dump_tacacs_pak(pak);
    }

    reply->msg_len = ntohs(reply->msg_len);
    reply->data_len = ntohs(reply->data_len);

    write_packet(pak);
    free(pak);
}

/* send an authorization reply packet */
send_author_reply(status, msg, data, arg_cnt, args)
u_char status;
char *msg;
char *data;
int arg_cnt;
char **args;
{
    u_char *pak, *p;
    HDR *hdr;
    struct author_reply *reply;
    int msg_len;
    int len;
    int data_len;
    int i;

    data_len = (data ? strlen(data) : 0);
    msg_len  = (msg  ? strlen(msg)  : 0);

    /* start calculating final packet size */
    len = TAC_PLUS_HDR_SIZE + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE + msg_len +
	data_len;

    for (i=0; i < arg_cnt; i++) {
	/* space for the arg and its length */
	len += strlen(args[i]) + 1;
    }

    pak = (u_char *) tac_malloc(len);

    bzero(pak, len);

    hdr = (HDR *) pak;

    reply = (struct author_reply *) (pak + TAC_PLUS_HDR_SIZE);

    hdr->version = TAC_PLUS_VER_0;
    hdr->type = TAC_PLUS_AUTHOR;
    hdr->seq_no = ++session.seq_no;
    hdr->encryption = TAC_PLUS_CLEAR;
    hdr->session_id = htonl(session.session_id);
    hdr->datalength = htonl(len - TAC_PLUS_HDR_SIZE);

    reply->status   = status;
    reply->msg_len  = msg_len;
    reply->data_len = data_len;
    reply->arg_cnt  = arg_cnt;

    p = pak + TAC_PLUS_HDR_SIZE + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE;

    /* place arg sizes into packet  */
    for (i=0; i < arg_cnt; i++) {
	*p++ = strlen(args[i]);
    }

    bcopy(msg, p, msg_len);
    p += msg_len;

    bcopy(data, p, data_len);
    p += data_len;

    /* copy arg bodies into packet */
    for (i=0; i < arg_cnt; i++) {
	int arglen = strlen(args[i]);

	bcopy(args[i], p, arglen);
	p += arglen;
    }

    if (debug & DEBUG_PACKET_FLAG) {
	report(LOG_DEBUG, "Writing %s size=%d",
	       summarise_outgoing_packet_type(pak), len);
	dump_tacacs_pak(pak); 
    }
    
    reply->msg_len  = htons(reply->msg_len);
    reply->data_len = htons(reply->data_len);

    write_packet(pak);
    free(pak);
}


/* Send an authentication reply packet indicating an error has
   occurred. msg is a null terminated character string */

send_authen_error(msg)
char *msg;
{
    char buf[255];

    sprintf(buf, "%s %s: %s", session.peer, session.port, msg);
    report(LOG_ERR, buf);
    send_authen_reply(TAC_PLUS_AUTHEN_STATUS_ERROR,
		      buf,
		      strlen(buf),
		      NULL,
		      0,
		      0);
}

/* create and send an authentication reply packet from tacacs+ to a NAS */

send_authen_reply(status, msg, msg_len, data, data_len, flags)
int status;
char *msg;
u_short msg_len;
char *data;
u_short data_len;
u_char flags;
{
    u_char *pak, *p;
    HDR *hdr;
    struct authen_reply *reply;

    int len = TAC_PLUS_HDR_SIZE + TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE + msg_len + data_len;

    pak = (u_char *) tac_malloc(len);
    bzero(pak, len);

    hdr = (HDR *) pak;
    reply = (struct authen_reply *) (pak + TAC_PLUS_HDR_SIZE);

    hdr->version = session.version;
    hdr->type = TAC_PLUS_AUTHEN;
    hdr->seq_no = ++session.seq_no;
    hdr->encryption = TAC_PLUS_CLEAR;
    hdr->session_id = htonl(session.session_id);
    hdr->datalength = htonl(TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE + msg_len + data_len);

    reply->status = status;
    reply->msg_len = msg_len;
    reply->data_len = data_len;
    reply->flags = flags;

    p = pak + TAC_PLUS_HDR_SIZE + TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE;

    bcopy(msg, p, msg_len);
    p += msg_len;
    bcopy(data, p, data_len);

    if (debug & DEBUG_PACKET_FLAG) {
	report(LOG_DEBUG, "Writing %s size=%d",
	       summarise_outgoing_packet_type(pak), len);
	dump_tacacs_pak(pak);
    }

    reply->msg_len = htons(reply->msg_len);
    reply->data_len = htons(reply->data_len);

    write_packet(pak);
    free(pak);
}


/* read an authentication GETDATA packet from a NAS. Return 0 on failure */
u_char *
get_authen_continue()
{
    HDR *hdr;
    u_char *pak, *read_packet();
    struct authen_cont *cont;
    char msg[255];

    pak = read_packet();
    if (!pak)
	return(NULL);
    hdr = (HDR *) pak;
    cont = (struct authen_cont *) (pak + TAC_PLUS_HDR_SIZE);

    if ((hdr->type != TAC_PLUS_AUTHEN) || (hdr->seq_no <= 1)) {
	sprintf(msg,
	  "%s: Bad packet type=%d/seq no=%d when expecting authentication cont",
		session.peer, hdr->type, hdr->seq_no);
	report(LOG_ERR, msg);
	send_authen_error(msg);
	return(NULL);
    }

    cont->user_msg_len  = ntohs(cont->user_msg_len);
    cont->user_data_len = ntohs(cont->user_data_len);

    if (TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + 
	cont->user_msg_len + 
	cont->user_data_len !=
	ntohl(hdr->datalength)) {
	char *m = "Illegally sized authentication cont packet";
	report(LOG_ERR, "%s: %s", session.peer, m);
	send_authen_error(m);
	return(NULL);
    }

    if (debug & DEBUG_PACKET_FLAG)
	dump_nas_pak(pak);

    return (pak);
}

/* Read n bytes from descriptor fd into array ptr with timeout t
 * seconds. Note the timeout is applied to each read, not for the
 * overall operation.
 *
 * Return -1 on error, eof or timeout. Otherwise return number of
 * bytes read. */

int
sockread(fd, ptr, nbytes, timeout)
int fd;
u_char *ptr;
int nbytes;
int timeout;
{
    int nleft, nread;
    fd_set readfds, exceptfds;
    struct timeval tout;

    tout.tv_sec = timeout;
    tout.tv_usec = 0;

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    FD_ZERO(&exceptfds);
    FD_SET(fd, &exceptfds);

    nleft = nbytes;

    while (nleft > 0) {
	int status = select(fd + 1, &readfds, (fd_set *) NULL, 
			    &exceptfds, &tout);

	if (status == 0) {
	    report(LOG_DEBUG, "%s: timeout reading fd %d", session.peer, fd);
	    return(-1);
	}
	if (status < 0) {
	    if (errno == EINTR)
		continue;
	    report(LOG_DEBUG, "%s: error in select %s fd %d", 
		   session.peer, sys_errlist[errno], fd);
	    return (-1);
	}
	if (FD_ISSET(fd, &exceptfds)) {
	    report(LOG_DEBUG, "%s: exception on fd %d",
		   session.peer, fd);
	    return (-1);
	}
	if (!FD_ISSET(fd, &readfds)) {
	    report(LOG_DEBUG, "%s: spurious return from select",
		   session.peer);
	    continue;
	}
    again:
	nread = read(fd, ptr, nleft);

	if (nread < 0) {
	    if (errno == EINTR)
		goto again;
	    report(LOG_DEBUG, "%s %s: error reading fd %d nread=%d %s", 
		   session.peer, session.port, fd, nread, sys_errlist[errno]);
	    return (-1);	/* error */

	} else if (nread == 0) {
	    report(LOG_DEBUG, "%s %s: fd %d eof (connection closed)", 
		   session.peer, session.port, fd);
	    return (-1);	/* eof */
	}
	nleft -= nread;
	if (nleft) 
	    ptr += nread;
    }
    return (nbytes - nleft);
}

/* Write n bytes to descriptor fd from array ptr with timeout t
 * seconds. Note the timeout is applied to each write, not for the
 * overall operation.
 *
 * Return -1 on error, eof or timeout. Otherwise return number of
 * bytes written. */

int
sockwrite(fd, ptr, bytes, timeout)
int fd;
u_char *ptr;
int bytes;
int timeout;
{
    int remaining, sent;
    fd_set writefds, exceptfds;
    struct timeval tout;

    sent = 0;

    tout.tv_sec = timeout;
    tout.tv_usec = 0;

    FD_ZERO(&writefds);
    FD_SET(fd, &writefds);

    FD_ZERO(&exceptfds);
    FD_SET(fd, &exceptfds);

    remaining = bytes;

    while (remaining > 0) {
	int status = select(fd + 1, (fd_set *) NULL, 
			    &writefds, &exceptfds, &tout);

	if (status == 0) {
	    report(LOG_DEBUG, "%s: timeout writing to fd %d", 
		   session.peer, fd);
	    return (-1);
	}
	if (status < 0) {
	    report(LOG_DEBUG, "%s: error in select fd %d", 
		   session.peer, fd);
	    return (-1);
	}
	if (FD_ISSET(fd, &exceptfds)) {
	    report(LOG_DEBUG, "%s: exception on fd %d",
		   session.peer, fd);
	    return (sent);	/* error */
	}

	if (!FD_ISSET(fd, &writefds)) {
	    report(LOG_DEBUG, "%s: spurious return from select",
		   session.peer);
	    continue;
	}
	sent = write(fd, ptr, remaining);

	if (sent <= 0) {
	    report(LOG_DEBUG, "%s: error writing fd %d sent=%d", 
		   session.peer, fd, sent);
	    return (sent);	/* error */
	}
	remaining -= sent;
	ptr += sent;
    }
    return (bytes - remaining);
}

/* read a packet from the wire, and decrypt it. Increment the global
 seq_no return NULL on failure */

u_char *
read_packet()
{
    HDR hdr;
    u_char *pkt, *data;
    int len;

    if (debug & DEBUG_PACKET_FLAG)
	report(LOG_DEBUG, "Waiting for packet");

    /* read a packet header */
    len = sockread(session.sock, (u_char *) & hdr, TAC_PLUS_HDR_SIZE, TAC_PLUS_READ_TIMEOUT);
    if (len != TAC_PLUS_HDR_SIZE) {
	report(LOG_DEBUG, "Read %d bytes from %s %s, expecting %d", 
	       len, session.peer, session.port, TAC_PLUS_HDR_SIZE);
	return(NULL);
    }

    if ((hdr.version & TAC_PLUS_MAJOR_VER_MASK) != TAC_PLUS_MAJOR_VER) {
	report(LOG_ERR, 
	       "%s: Illegal major version specified: found %d wanted %d\n",
	       session.peer, hdr.version, TAC_PLUS_MAJOR_VER);
	return(NULL);
    }

    /* get memory for the packet */
    len = TAC_PLUS_HDR_SIZE + ntohl(hdr.datalength);
    if ((ntohl(hdr.datalength) & ~0xffffUL) ||
       (len < TAC_PLUS_HDR_SIZE) || (len > 0x10000)) {
       report(LOG_ERR, "%s: Illegal data size: %lu\n",
              session.peer, ntohl(hdr.datalength));
       return(NULL);
    }
    pkt = (u_char *) tac_malloc(len);

    /* initialise the packet */
    bcopy(&hdr, pkt, TAC_PLUS_HDR_SIZE);

    /* the data start here */
    data = pkt + TAC_PLUS_HDR_SIZE;

    /* read the rest of the packet data */
    if (sockread(session.sock, data, ntohl(hdr.datalength), 
		 TAC_PLUS_READ_TIMEOUT) !=
	ntohl(hdr.datalength)) {
	report(LOG_ERR, "%s: start_session: bad socket read", session.peer);
	return (NULL);
    }
    session.seq_no++;		/* should now equal that of incoming packet */
    session.last_exch = time(NULL);

    if (session.seq_no != hdr.seq_no) {
	report(LOG_ERR, "%s: Illegal session seq # %d != packet seq # %d",
	       session.peer,
	       session.seq_no, hdr.seq_no);
	return (NULL);
    }

    /* decrypt the data portion */
    if (md5_xor((HDR *)pkt, data, session.key)) {
	report(LOG_ERR, "%s: start_session error decrypting data",
	       session.peer);
	return (NULL);
    }

    if (debug & DEBUG_PACKET_FLAG)
	report(LOG_DEBUG, "Read %s size=%d",
	       summarise_incoming_packet_type(pkt), len);

    session.version = hdr.version;

    return (pkt);
}

/* write a packet to the wire, encrypting it */
write_packet(pak)
u_char *pak;
{
    HDR *hdr = (HDR *) pak;
    u_char *data;
    int len;

    len = TAC_PLUS_HDR_SIZE + ntohl(hdr->datalength);

    /* the data start here */
    data = pak + TAC_PLUS_HDR_SIZE;

    /* encrypt the data portion */
    if (md5_xor((HDR *)pak, data, session.key)) {
	report(LOG_ERR, "%s: write_packet: error encrypting data", session.peer);
	return (-1);
    }

    if (sockwrite(session.sock, pak, len, TAC_PLUS_WRITE_TIMEOUT) != len) {
	return (-1);
    }
    session.last_exch = time(NULL);
    return (0);
}

send_error_reply(type, msg)
int type;
char *msg;
{
    switch (type) {
    case TAC_PLUS_AUTHEN:
	send_authen_error(msg);
	return;

    case TAC_PLUS_AUTHOR:
	send_author_reply(AUTHOR_STATUS_ERROR, msg, NULL, 0, NULL);
	return;

    case TAC_PLUS_ACCT:
	send_acct_reply(TAC_PLUS_ACCT_STATUS_ERROR, msg, NULL);
	return;

    default:
	report(LOG_ERR, "Illegal type %d for send_error_reply", type);
	return;
    }
}
