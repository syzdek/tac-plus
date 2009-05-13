/*
 * tac_plus.c
 *
 * TACACS_PLUS daemon suitable for using on Un*x systems.
 *
 * October 1994, Lol Grant
 *
 * Copyright (c) 1994-2000 by Cisco systems, Inc.
 *
 * Permission to use, copy, modify, and distribute modified and
 * unmodified copies of this software for any purpose and without fee is
 * hereby granted, provided that (a) this copyright and permission notice
 * appear on all copies of the software and supporting documentation, (b)
 * the name of Cisco Systems, Inc. not be used in advertising or
 * publicity pertaining to distribution of the program without specific
 * prior permission, and (c) notice be given in supporting documentation
 * that use, modification, copying and distribution is by permission of
 * Cisco Systems, Inc.

 * Cisco Systems, Inc. makes no representations about the suitability
 * of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
 * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.
*/

#include "tac_plus.h"
#include "sys/wait.h"
#include "signal.h"

static int standalone  = 1; /* running standalone (1) or under inetd (0) */
static int initialised = 0; /* data structures have been allocated */
int sendauth_only      = 0; /* don't respond to sendpass requests */
int debug              = 0; /* debugging flags */
int port               = 0; /* port we're listening on */
int console            = 0; /* write all syslog messages to console */
int parse_only         = 0; /* exit after verbose parsing */
int single             = 0; /* single thread (for debugging) */
int wtmpfd	       = 0; /* for wtmp file logging */
char *wtmpfile         = NULL;

struct timeval started_at;

struct session session;     /* session data */

static char pidfilebuf[75]; /* holds current name of the pidfile */

void start_session();

#ifndef REAPCHILD
static
#ifdef VOIDSIG
void 
#else
int
#endif /* VOIDSIG */
reapchild()
{
#ifdef UNIONWAIT
    union wait status;
#else
    int status;
#endif
    int pid;

    for (;;) {
	pid = wait3(&status, WNOHANG, 0);
	if (pid <= 0)
	    return;
	if (debug & DEBUG_FORK_FLAG)
	    report(LOG_DEBUG, "%d reaped", pid);
    }
}
#endif /* REAPCHILD */

static void
die(signum)
int signum;
{
    report(LOG_INFO, "Received signal %d, shutting down", signum);
    unlink(pidfilebuf);
    tac_exit(0);
}

static void
init()
{
    if (initialised)
	cfg_clean_config();    

    report(LOG_INFO, "Reading config");

    session.acctfile = tac_strdup("/var/tmp/acctfile");
    
    if (!session.cfgfile) {
	report(LOG_ERR, "no config file specified");
	tac_exit(1);
    }
    
    /* read the config file */
    if (cfg_read_config(session.cfgfile)) {
	report(LOG_ERR, "Parsing %s", session.cfgfile);
	tac_exit(1);
    }

    initialised++;

    report(LOG_INFO, "Version %s Initialized %d", VERSION, initialised);

}

static void
handler(signum)
int signum;
{
    report(LOG_INFO, "Received signal %d", signum);
    init();
#ifdef REARMSIGNAL
    signal(SIGUSR1, handler);
    signal(SIGHUP, handler);
#endif REARMSIGNAL
}

/*
 * Return a socket bound to an appropriate port number/address. Exits
 * the program on failure */

get_socket()
{
    int s;
    struct sockaddr_in sin;
    struct servent *sp;
    int on = 1;

    bzero((char *) &sin, sizeof(sin));

    if (port) {
	sin.sin_port = htons(port);
    } else {
	sp = getservbyname("tacacs", "tcp");
	if (sp)
	    sin.sin_port = sp->s_port;
	else {
	    report(LOG_ERR, "Cannot find socket port");
	    tac_exit(1);
	}
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);

    if (s < 0) {
	console++;
	report(LOG_ERR, "get_socket: socket: %s", sys_errlist[errno]);
	tac_exit(1);
    }
#ifdef SO_REUSEADDR
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &on,
		       sizeof(on)) < 0)
	    perror("setsockopt - SO_REUSEADDR");
#endif				/* SO_REUSEADDR */

    if (bind(s, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
	console++;
	report(LOG_ERR, "get_socket: bind %d %s",
	       ntohs(sin.sin_port),
	       sys_errlist[errno]);
	tac_exit(1);
    }
    return (s);
}

static void
open_logfile()
{
#ifdef LOG_LOCAL6
    openlog("tac_plus", LOG_PID, LOG_LOCAL6);
#else
    openlog("tac_plus", LOG_PID);
#endif
    setlogmask(LOG_UPTO(LOG_DEBUG));
}

/*
 * main
 *
 * We will eventually be called from inetd or via the rc scripts directly
 * Parse arguments and act appropiately.
 */

main(argc, argv)
int argc;
char **argv;
{
    extern char *optarg;
    int childpid;
    int c;
    int s;
    FILE *fp;
    int lookup_peer = 0;

    debug = 0;			/* no debugging */
    standalone = 1;			/* standalone */
    single = 0;			/* single threaded */

    /* initialise global session data */
    bzero(&session, sizeof(session));
    session.peer = tac_strdup("unknown");

    open_logfile();

#ifdef TAC_PLUS_PORT
    port = TAC_PLUS_PORT;
#endif

    if (argc <= 1) {
	fprintf(stderr, "Usage: tac_plus -C <configuration file>\n");
	fprintf(stderr, "\t[ -t ] [ -P ] [ -g ] [ -p <port> ]\n");
	fprintf(stderr, "\t[ -d <debug level> ] [ -i ] [ -v ] [ -s ]\n");
	fprintf(stderr, "\t[ -l logfile ]");
#ifdef MAXSESS
	fprintf(stderr, " [ -w whologfile ]");
#endif
	fprintf(stderr, "\n");
	tac_exit(1);
    }

    while ((c = getopt(argc, argv, "td:C:ip:PgvsLl:w:u:")) != EOF)
	switch (c) {
	case 'L':		/* lookup peer names via DNS */
	    lookup_peer++;
	    break;
	case 's':		/* don't respond to sendpass */
	    sendauth_only++;
	    break;
	case 'v':		/* print version and exit */
	    version();
	    tac_exit(1);
	case 't':
	    console++;		/* log to console too */
	    break;
	case 'P':		/* Parse config file only */
	    parse_only++;
	    break;
	case 'g':		/* single threaded */
	    single++;
	    break;
	case 'p':		/* port */
	    port = atoi(optarg);
	    break;
	case 'd':		/* debug */
	    debug = atoi(optarg);
	    break;
	case 'C':		/* config file name */
	    session.cfgfile = tac_strdup(optarg);
	    break;
	case 'i':		/* stand-alone */
	    standalone = 0;
	    break;
	case 'l':		/* logfile */
	    logfile = tac_strdup(optarg);
	    break;
#ifdef MAXSESS
	case 'w':		/* wholog file */
	    wholog = tac_strdup(optarg);
	    break;
#endif
	case 'u':
	    wtmpfile = tac_strdup(optarg);
	    break;

	default:
	    fprintf(stderr, "%s: bad switch %c\n", argv[0], c);
	    tac_exit(1);
	}

    if (geteuid() != 0) {
	fprintf(stderr, "Warning, not running as uid 0\n");
	fprintf(stderr, "Tac_plus is usually run as root\n");
    }

    parser_init();

    init();

    signal(SIGUSR1, handler);
    signal(SIGHUP, handler);
    signal(SIGTERM, die);
    signal(SIGPIPE, SIG_IGN);

    if (parse_only)
	tac_exit(0);

    if (debug)
	report(LOG_DEBUG, "tac_plus server %s starting", VERSION);

    if (!standalone) {
	/* running under inetd */
	struct sockaddr_in name;
	int name_len;
	int on = 1;

	name_len = sizeof(name);

	session.sock = 0;
	if (getpeername(session.sock, (struct sockaddr *) &name, &name_len)) {
	    report(LOG_ERR, "getpeername failure %s", sys_errlist[errno]);
	} else {
	    struct hostent *hp;
	    hp = gethostbyaddr((char *) &name.sin_addr.s_addr,
			       sizeof(name.sin_addr.s_addr), AF_INET);
	    if (session.peer) {
		free(session.peer);
	    }
	    session.peer = tac_strdup(hp ? hp->h_name : 
				  (char *) inet_ntoa(name.sin_addr));
	}
#ifdef FIONBIO
	if (ioctl(session.sock, FIONBIO, &on) < 0) {
	    report(LOG_ERR, "ioctl(FIONBIO) %s", sys_errlist[errno]);
	    tac_exit(1);
	}
#endif
	start_session();
	tac_exit(0);
    }

    if (!single) {
	/* Running standalone. Background ourselves, let go of controlling tty */

#ifdef SIGTTOU
	signal(SIGTTOU, SIG_IGN);
#endif
#ifdef SIGTTIN
	signal(SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif
	
	signal(SIGHUP, SIG_IGN);
    
	if ((childpid = fork()) < 0)
	    report(LOG_ERR, "Can't fork first child");
	else if (childpid > 0)
	    exit(0);		/* parent */

	if (debug)
	    report(LOG_DEBUG, "Backgrounded");

#ifndef REAPCHILD

#ifdef LINUX
	if (setpgrp() == -1)
#else /* LINUX */
	if (setpgrp(0, getpid()) == -1)
#endif /* LINUX */
	    report(LOG_ERR, "Can't change process group");
	
	c = open("/dev/tty", O_RDWR);
	if (c >= 0) {
	    ioctl(c, TIOCNOTTY, (char *) 0);
	    (void) close(c);
	}
	signal(SIGCHLD, reapchild);

#else /* REAPCHILD */

	if (setpgrp() == 1)
	    report(LOG_ERR, "Can't change process group");

	signal(SIGHUP, SIG_IGN);

	if ((childpid = fork()) < 0)
	    report(LOG_ERR, "Can't fork second child");
	else if (childpid > 0)
	    exit(0);
    
	if (debug & DEBUG_FORK_FLAG)
	    report(LOG_DEBUG, "Forked grandchild");

	signal(SIGCHLD, SIG_IGN);

#endif /* REAPCHILD */

	closelog(); /* some systems require this */

	for (c = 0; c < getdtablesize(); c++)
	    (void) close(c);

	/* make sure we can still log to syslog now we've closed everything */
	open_logfile();

    } /* ! single threaded */
    
    ostream = NULL;
    /* chdir("/"); */
    umask(0);
    errno = 0;

    s = get_socket();

#ifndef SOMAXCONN
#define SOMAXCONN 5
#endif

    if (listen(s, SOMAXCONN) < 0) {
	console++;
	report(LOG_ERR, "listen: %s", sys_errlist[errno]);
	tac_exit(1);
    }

    if (port == TAC_PLUS_PORT) {
	strcpy(pidfilebuf, TAC_PLUS_PIDFILE);
    } else {
	sprintf(pidfilebuf, "%s.%d", TAC_PLUS_PIDFILE, port);
    }

    /* write process id to pidfile */
    if ((fp = fopen(pidfilebuf, "w")) != NULL) {
	fprintf(fp, "%d\n", getpid());
	fclose(fp);
    } else 
	report(LOG_ERR, "Cannot write pid to %s %s", 
	       pidfilebuf, sys_errlist[errno]);

#ifdef TAC_PLUS_GROUPID
    if (setgid(TAC_PLUS_GROUPID))
	report(LOG_ERR, "Cannot set group id to %d %s", 
	       TAC_PLUS_GROUPID, sys_errlist[errno]);
#endif

#ifdef TAC_PLUS_USERID
    if (setuid(TAC_PLUS_USERID)) 
	report(LOG_ERR, "Cannot set user id to %d %s", 
	       TAC_PLUS_USERID, sys_errlist[errno]);
#endif

#ifdef MAXSESS
    maxsess_loginit();
#endif /* MAXSESS */

    report(LOG_DEBUG, "uid=%d euid=%d gid=%d egid=%d s=%d",
	   getuid(), geteuid(), getgid(), getegid(), s);

    for (;;) {
	int pid;
	struct sockaddr_in from;
	int from_len;
	int newsockfd;
	struct hostent *hp = NULL;

	bzero((char *) &from, sizeof(from));
	from_len = sizeof(from);

	newsockfd = accept(s, (struct sockaddr *) &from, &from_len);

	if (newsockfd < 0) {
	    if (errno == EINTR)
		continue;

	    report(LOG_ERR, "accept: %s", sys_errlist[errno]);
	    continue;
	}

	if (lookup_peer) {
	    hp = gethostbyaddr((char *) &from.sin_addr.s_addr,
			       sizeof(from.sin_addr.s_addr), AF_INET);
	}

	if (session.peer) {
	    free(session.peer);
	}
	session.peer = tac_strdup(hp ? hp->h_name : 
				  (char *) inet_ntoa(from.sin_addr));

	if (debug & DEBUG_PACKET_FLAG)
	    report(LOG_DEBUG, "session request from %s sock=%d", 
		   session.peer, newsockfd);

	if (!single) {
	    pid = fork();

	    if (pid < 0) {
		report(LOG_ERR, "fork error");
		tac_exit(1);
	    }
	} else {
	    pid = 0;
	}

	if (pid == 0) {
	    /* child */
	    if (!single)
		close(s);
	    session.sock = newsockfd;
	    start_session();
	    shutdown(session.sock, 2);
	    close(session.sock);
	    if (!single)
		tac_exit(0);
	} else {
	    if (debug & DEBUG_FORK_FLAG)
		report(LOG_DEBUG, "forked %d", pid);
	    /* parent */
	    close(newsockfd);
	}
    }
}

#ifdef GETDTABLESIZE
int 
getdtablesize()
{
    return(_NFILE);
}
#endif /* GETDTABLESIZE */

/* Make sure version number is kosher. Return 0 if it is */
int
bad_version_check(pak)
u_char *pak;
{
    HDR *hdr = (HDR *) pak;
    
    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	/* 
	 * Let authen routines take care of more sophisticated version
	 * checking as its now a bit involved. 
	 */
	return(0);

    case TAC_PLUS_AUTHOR:
    case TAC_PLUS_ACCT:
	if (hdr->version != TAC_PLUS_VER_0) {
	    send_error_reply(hdr->type, "Illegal packet version");
	    return(1);
	}
	return(0);

    default:
	return(1);
    }
}

/*
 * Determine the packet type, read the rest of the packet data,
 * decrypt it and call the appropriate service routine.
 *
 */

void
start_session()
{
    u_char *pak, *read_packet();
    HDR *hdr;
    void authen();

    session.seq_no = 0;
    session.aborted = 0;
    session.version = 0;

    pak = read_packet();
    if (!pak) {
	return;
    }

    if (debug & DEBUG_PACKET_FLAG) {
	report(LOG_DEBUG, "validation request from %s", session.peer);
	dump_nas_pak(pak);
    }
    hdr = (HDR *) pak;

    session.session_id = ntohl(hdr->session_id);

    /* Do some version checking */
    if (bad_version_check(pak)) {
	free(pak);
	return;
    }

    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	authen(pak);
	free(pak);
	return;

    case TAC_PLUS_AUTHOR:
	author(pak);
	free(pak);
	return;

    case TAC_PLUS_ACCT:
	accounting(pak);
	return;

    default:
	/* Note: can't send error reply if type is unknown */
	report(LOG_ERR, "Illegal type %d in received packet", hdr->type);
	free(pak);
	return;
    }
}

version()
{
    fprintf(stdout, "tac_plus version %s\n", VERSION);
#ifdef AIX
    fprintf(stdout,"AIX\n");
#endif
#ifdef ARAP_DES
    fprintf(stdout,"ARAP_DES\n");
#endif
#ifdef BSDI
    fprintf(stdout,"BSDI\n");
#endif
#ifdef CONST_SYSERRLIST
    fprintf(stdout,"CONST_SYSERRLIST\n");
#endif
#ifdef DEBUG
    fprintf(stdout,"DEBUG\n");
#endif
#ifdef DES_DEBUG
    fprintf(stdout,"DES_DEBUG\n");
#endif
#ifdef FIONBIO
    fprintf(stdout,"FIONBIO\n");
#endif
#ifdef FREEBSD
    fprintf(stdout,"FREEBSD\n");
#endif
#ifdef GETDTABLESIZE
    fprintf(stdout,"GETDTABLESIZE\n");
#endif
#ifdef HPUX
    fprintf(stdout,"HPUX\n");
#endif
#ifdef LINUX
    fprintf(stdout,"LINUX\n");
#endif
#ifdef LITTLE_ENDIAN
    fprintf(stdout,"LITTLE_ENDIAN\n");
#endif
#ifdef LOG_LOCAL6
    fprintf(stdout,"LOG_LOCAL6\n");
#endif
#ifdef MAXSESS
    fprintf(stdout,"MAXSESS\n");
#endif
#ifdef MIPS
    fprintf(stdout,"MIPS\n");
#endif
#ifdef NEED_BZERO
    fprintf(stdout,"NEED_BZERO\n");
#endif
#ifdef NETBSD
    fprintf(stdout,"NETBSD\n");
#endif
#ifdef NO_PWAGE
    fprintf(stdout,"NO_PWAGE\n");
#endif
#ifdef REAPCHILD
    fprintf(stdout,"REAPCHILD\n");
#endif
#ifdef REARMSIGNAL
    fprintf(stdout,"REARMSIGNAL\n");
#endif
#ifdef SHADOW_PASSWORDS
    fprintf(stdout,"SHADOW_PASSWORDS\n");
#endif
#ifdef SIGTSTP
    fprintf(stdout,"SIGTSTP\n");
#endif
#ifdef SIGTTIN
    fprintf(stdout,"SIGTTIN\n");
#endif
#ifdef SIGTTOU
    fprintf(stdout,"SIGTTOU\n");
#endif
#ifdef SKEY
    fprintf(stdout,"SKEY\n");
#endif
#ifdef SOLARIS
    fprintf(stdout,"SOLARIS\n");
#endif
#ifdef SO_REUSEADDR
    fprintf(stdout,"SO_REUSEADDR\n");
#endif
#ifdef STDLIB_MALLOC
    fprintf(stdout,"STDLIB_MALLOC\n");
#endif
#ifdef STRCSPN
    fprintf(stdout,"STRCSPN\n");
#endif
#ifdef SYSLOG_IN_SYS
    fprintf(stdout,"SYSLOG_IN_SYS\n");
#endif
#ifdef SYSV
    fprintf(stdout,"SYSV\n");
#endif
#ifdef TAC_PLUS_GROUPID
    fprintf(stdout,"TAC_PLUS_GROUPID\n");
#endif
#ifdef TAC_PLUS_PORT
    fprintf(stdout,"TAC_PLUS_PORT\n");
#endif
#ifdef TAC_PLUS_USERID
    fprintf(stdout,"TAC_PLUS_USERID\n");
#endif
#ifdef TRACE
    fprintf(stdout,"TRACE\n");
#endif
#ifdef UNIONWAIT
    fprintf(stdout,"UNIONWAIT\n");
#endif
#ifdef VOIDSIG
    fprintf(stdout,"VOIDSIG\n");
#endif
#ifdef _BSD1
    fprintf(stdout,"_BSD1\n");
#endif
#ifdef _BSD_INCLUDES
    fprintf(stdout,"_BSD_INCLUDES\n");
#endif
#ifdef __STDC__
    fprintf(stdout,"__STDC__\n");
#endif
}
