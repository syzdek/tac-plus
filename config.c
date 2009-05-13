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
#include <errno.h>
#include "regexp.h"

/*
   <config>         := <decl>*

   <decl>           := <top_level_decl> | <user_decl>

   <top_level_decl> := <authen_default> |
                       accounting file = <string>
                       default authorization = permit |
                       key = <string>

   <authen_default> := default authentication = file <filename>

   <permission>     := permit | deny

   <filename>       := <string>

   <password>       := <string>

   <user_decl>      := user = <string> {
                        [ default service = [ permit | deny ] ]
                        <user_attr>*
                        <svc>*
                   }

   <password_spec>  := file <filename> | 
		       skey | 
		       cleartext <password> | 
		       des <password> |
		       nopassword

   <user_attr>      :=   name     = <string> |
                         login    = <password_spec> |
        	         member   = <string> |
        	         expires  = <string> |
                	 arap     = cleartext <string> |
	                 chap     = cleartext <string> |
#ifdef MSCHAP
	                 ms-chap  = cleartext <string> |
#endif
	                 pap      = cleartext <string> |
	                 pap      = des <string> |
	                 opap     = cleartext <string> |
	                 global   = cleartext <string> |
        	         msg      = <string>
			 before authorization = <string> |
			 after authorization = <string>

   <svc>            := <svc_auth> | <cmd_auth>

   <cmd_auth>       := cmd = <string> {
                        <cmd-match>*
                    }

   <cmd-match>      := <permission> <string>

   <svc_auth>       := service = ( exec | arap | slip | ppp protocol = <string> {
                        [ default attribute = permit ]
                        <attr_value_pair>*
                    }

   <attr_value_pair> := [ optional ] <string> = <string>

*/

static char sym_buf[MAX_INPUT_LINE_LEN];	/* parse buffer */
static int sym_pos=0;           /* current place in sym_buf */
static int sym_ch;		/* current parse character */
static int sym_code;		/* parser output */
static int sym_line = 1;	/* current line number for parsing */
static FILE *cf = NULL;		/* config file pointer */
static int sym_error = 0;	/* a parsing error has occurred */
static int no_user_dflt = 0;	/* default if user doesn't exist */
static char *authen_default = NULL;	/* top level authentication default */
static char *nopasswd_str = "nopassword";

/* A host definition structure. Currently unused, but when we start
   configuring host-specific information e.g. per-host keys, this is
   where it should be kept.

   The first 2 fields (name and hash) are used by the hash table
   routines to hash this structure into a table.  Do not (re)move them */

struct host {
    char *name;			/* host name */
    void *hash;			/* hash table next pointer */
    int line;			/* line number defined on */
};

/* A user or group definition

   The first 2 fields (name and hash) are used by the hash table
   routines to hash this structure into a table.  Move them at your
   peril */

struct user {
    char *name;			/* username */
    void *hash;			/* hash table next pointer */
    int line;			/* line number defined on */
    long flags;			/* flags field */

#define FLAG_ISUSER  1		/* this structure represents a user */
#define FLAG_ISGROUP 2		/* this structure represents a group */
#define FLAG_SEEN    4		/* for circular definition detection */

    char *full_name;		/* users full name */
    char *login;		/* Login password */
    int nopasswd;               /* user requires no password */
    char *global;		/* password to use if none set */
    char *member;		/* group we are a member of */
    char *expires;		/* expiration date */
    char *arap;			/* our arap secret */
    char *pap;			/* our pap secret */
    char *opap;			/* our outbound pap secret */
    char *chap;			/* our chap secret */
#ifdef MSCHAP
    char *mschap;		/* our mschap secret */
#endif /* MSCHAP */
    char *msg;			/* a message for this user */
    char *before_author;	/* command to run before authorization */
    char *after_author;		/* command to run after authorization */
    int svc_dflt;		/* default authorization behaviour for svc or
				 * cmd */
    NODE *svcs;			/* pointer to svc nodes */
#ifdef MAXSESS
    int maxsess;		/* Max sessions/user */
#endif /* MAXSESS */
};

typedef struct user USER;

/* Only the first 2 fields (name and hash) are used by the hash table
   routines to hashh structures into a table.
*/

union hash {
    struct user u;
    struct host h;
};

typedef union hash HASH;

void *grouptable[HASH_TAB_SIZE];/* Table of group declarations */
void *usertable[HASH_TAB_SIZE];	/* Table of user declarations */

/* void *hosttable[HASH_TAB_SIZE];	Table of host declarations */


static void
 sym_get();


#ifdef __STDC__
#include <stdarg.h>		/* ANSI C, variable length args */
static void
parse_error(char *fmt,...)
#else
#include <varargs.h>		/* has 'vararg' definitions */
/* VARARGS2 */
static void
parse_error(fmt, va_alist)
char *fmt;

va_dcl				/* no terminating semi-colon */
#endif
{
    char msg[256];		/* temporary string */
    va_list ap;

#ifdef __STDC__
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    vsprintf(msg, fmt, ap);
    va_end(ap);

    report(LOG_ERR, "%s", msg);
    fprintf(stderr, "Error: %s\n", msg);
    tac_exit(1);
}

char *
cfg_nodestring(type)
    int type;
{
    switch (type) {
    default:
	return ("unknown node type");
    case N_arg:
	return ("N_arg");
    case N_optarg:
	return ("N_optarg");
    case N_svc:
	return ("N_svc");
    case N_svc_exec:
	return ("N_svc_exec");
    case N_svc_slip:
	return ("N_svc_slip");
    case N_svc_ppp:
	return ("N_svc_ppp");
    case N_svc_arap:
	return ("N_svc_arap");
    case N_svc_cmd:
	return ("N_svc_cmd");
    case N_permit:
	return ("N_permit");
    case N_deny:
	return ("N_deny");
    }
}

static void
free_attrs(node)
NODE *node;
{
    NODE *next;

    while (node) {
	switch (node->type) {
	case N_optarg:
	case N_arg:
	    if (debug & DEBUG_CLEAN_FLAG)
		report(LOG_DEBUG, "free_cmd_match %s %s",
		       cfg_nodestring(node->type),
		       node->value);
	    break;
	default:
	    report(LOG_ERR, "Illegal node type %s for free_attrs", 
		   cfg_nodestring(node->type));
	    return;
	}

	free(node->value);
	next = node->next;
	free(node);
	node = next;
    }
}

static void
free_cmd_matches(node)
NODE *node;
{
    NODE *next;

    while (node) {
	if (debug & DEBUG_CLEAN_FLAG)
	    report(LOG_DEBUG, "free_cmd_match %s %s",
		   cfg_nodestring(node->type),
		   node->value);

	free(node->value);	/* text */
	free(node->value1);	/* regexp compiled text */
	next = node->next;
	free(node);
	node = next;
    }
}

static void
free_svcs(node)
NODE *node;
{
    NODE *next;

    while (node) {

	switch (node->type) {
	case N_svc_cmd:
	    if (debug & DEBUG_CLEAN_FLAG)
		report(LOG_DEBUG, "free %s %s",
		       cfg_nodestring(node->type), node->value);
	    free(node->value);	/* cmd name */
	    free_cmd_matches(node->value1);
	    next = node->next;
	    free(node);
	    node = next;
	    continue;

	case N_svc:
	case N_svc_ppp:
	    free(node->value1);
	    /* FALL-THROUGH */
	case N_svc_exec:
	case N_svc_arap:
	case N_svc_slip:
	    if (debug & DEBUG_CLEAN_FLAG)
		report(LOG_DEBUG, "free %s", cfg_nodestring(node->type));
	    free_attrs(node->value);
	    next = node->next;
	    free(node);
	    node = next;
	    continue;

	default:
	    report(LOG_ERR, "Illegal node type %d for free_svcs", node->type);
	    return;
	}
    }
}

static void
free_userstruct(user)
USER *user;
{
    if (debug & DEBUG_CLEAN_FLAG)
	report(LOG_DEBUG, "free %s %s",
	       (user->flags & FLAG_ISUSER) ? "user" : "group",
	       user->name);

    if (user->name)
	free(user->name);
    if (user->full_name)
	free(user->full_name);
    if (user->login)
	free(user->login);
    if (user->member)
	free(user->member);
    if (user->expires)
	free(user->expires);
    if (user->arap)
	free(user->arap);
    if (user->chap)
	free(user->chap);
#ifdef MSCHAP
    if (user->mschap)
	free(user->mschap);
#endif /* MSCHAP */
    if (user->pap)
	free(user->pap);
    if (user->opap)
	free(user->opap);
    if (user->global)
	free(user->global);
    if (user->msg)
	free(user->msg);
    if (user->before_author)
	free(user->before_author);
    if (user->after_author)
	free(user->after_author);
    free_svcs(user->svcs);
}

/*
 * Exported routines
 */

/* Free all allocated structures preparatory to re-reading the config file */
void
cfg_clean_config()
{
    int i;
    USER *entry, *next;

    if (authen_default) {
	free(authen_default);
	authen_default = NULL;
    }

    if (session.key) {
	free(session.key);
	session.key = NULL;
    }

    if (session.acctfile) {
	free(session.acctfile);
	session.acctfile = NULL;
    }

    /* clean the hosttable -- currently a no-op */

    /* the grouptable */
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	entry = (USER *) grouptable[i];
	while (entry) {
	    next = entry->hash;
	    free_userstruct(entry);
	    free(entry);
	    entry = next;
	}
	grouptable[i] = NULL;
    }

    /* the usertable */
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	entry = (USER *) usertable[i];
	while (entry) {
	    next = entry->hash;
	    free_userstruct(entry);
	    free(entry);
	    entry = next;
	}
	usertable[i] = NULL;
    }
}

static int
parse_permission()
{
    int symbol = sym_code;

    if (sym_code != S_permit && sym_code != S_deny) {
	parse_error("expecting permit or deny but found '%s' on line %d",
		    sym_buf, sym_line);
	return (0);
    }
    sym_get();

    return (symbol);
}

static int
parse(symbol)
int symbol;

{
    if (sym_code != symbol) {
	parse_error("expecting '%s' but found '%s' on line %d",
		    (symbol == S_string ? "string" : codestring(symbol)),
		    sym_buf, sym_line);
	return (1);
    }
    sym_get();
    return (0);
}

static int
parse_opt_svc_default()
{
    if (sym_code != S_default) {
	return (0);
    }

    parse(S_default);
    parse(S_svc);
    parse(S_separator);
    if (sym_code == S_permit) {
	parse(S_permit);
	return (S_permit);
    }
    parse(S_deny);
    return (S_deny);
}

static int
parse_opt_attr_default()
{
    if (sym_code != S_default)
	return (S_deny);

    parse(S_default);
    parse(S_attr);
    parse(S_separator);
    parse(S_permit);
    return (S_permit);
}

/*
static void
parse_host()
{
}
*/

static int parse_user();

static void
 rch();

/*
   Parse lines in the config file, creating data structures
   Return 1 on error, otherwise 0 */

static int
parse_decls()
{
    no_user_dflt = 0; /* default if user doesn't exist */

    sym_code = 0;
    rch();

    bzero(grouptable, sizeof(grouptable));
    bzero(usertable, sizeof(usertable));
    /* bzero(hosttable, sizeof(hosttable)); */

    sym_get();

    /* Top level of parser */
    while (1) {

	switch (sym_code) {
	case S_eof:
	    return (0);

	case S_accounting:
	    sym_get();
	    parse(S_file);
	    parse(S_separator);
	    if (session.acctfile) 
		free(session.acctfile);
	    session.acctfile = tac_strdup(sym_buf);
	    sym_get();
	    continue;

	case S_default:
	    sym_get();
	    switch (sym_code) {
	    default:
		parse_error(
	        "Expecting default authorization/authentication on lines %d",
			    sym_line);
		return (1);

	    case S_authentication:
		if (authen_default) {
		    parse_error(
		    "Multiply defined authentication default on line %d",
				sym_line);
		    return (1);
		}
		parse(S_authentication);
		parse(S_separator);
		parse(S_file);
		authen_default = tac_strdup(sym_buf);
		sym_get();
		continue;

	    case S_authorization:
		parse(S_authorization);
		parse(S_separator);
		parse(S_permit);
		no_user_dflt = S_permit;
		report(LOG_INFO, 
		       "default authorization = permit is now deprecated. Please use user = DEFAULT instead");
		continue;
	    }

	case S_key:
	    /* Process a key declaration. */
	    sym_get();
	    parse(S_separator);
	    if (session.key) {
		parse_error("multiply defined key on lines %d and %d",
			    session.keyline, sym_line);
		return (1);
	    }
	    session.key = tac_strdup(sym_buf);
	    session.keyline = sym_line;
	    sym_get();
	    continue;

	case S_user:
	case S_group:
	    parse_user();
	    continue;

	    /* case S_host: parse_host(); continue; */

	default:
	    parse_error("Unrecognised token %s on line %d", sym_buf, sym_line);
	    return (1);
	}
    }
}

static NODE *parse_svcs();

/* Assign a value to a field. Issue an error message and return 1 if
   it's already been assigned. This is a macro because I was sick of
   repeating the same code fragment over and over */

#define ASSIGN(field) \
sym_get(); parse(S_separator); if (field) { \
	parse_error("Duplicate value for %s %s and %s on line %d", \
		    codestring(sym_code), field, sym_buf, sym_line); \
        tac_exit(1); \
    } \
    field = tac_strdup(sym_buf);

static int
parse_user()
{
    USER *n;
    int isuser;
    USER *user = (USER *) tac_malloc(sizeof(USER));
    int save_sym;
    char **fieldp;
    char buf[MAX_INPUT_LINE_LEN];

    bzero(user, sizeof(USER));

    isuser = (sym_code == S_user);

    sym_get();
    parse(S_separator);
    user->name = tac_strdup(sym_buf);
    user->line = sym_line;

    if (isuser) {
	user->flags |= FLAG_ISUSER;
	n = hash_add_entry(usertable, (void *) user);
    } else {
	user->flags |= FLAG_ISGROUP;
	n = hash_add_entry(grouptable, (void *) user);
    }

    if (n) {
	parse_error("multiply defined %s %s on lines %d and %d",
		    isuser ? "user" : "group",
		    user->name, n->line, sym_line);
	return (1);
    }
    sym_get();
    parse(S_openbra);

    /* Is the default deny for svcs or cmds to be overridden? */
    user->svc_dflt = parse_opt_svc_default();

    while (1) {
	switch (sym_code) {
	case S_eof:
	    return (0);

	case S_before:
	    sym_get();
	    parse(S_authorization);
	    if (user->before_author)
		free(user->before_author);
	    user->before_author = tac_strdup(sym_buf);
	    sym_get();
	    continue;

	case S_after:
	    sym_get();
	    parse(S_authorization);
	    if (user->after_author)
		free(user->after_author);
	    user->after_author = tac_strdup(sym_buf);
	    sym_get();
	    continue;

	case S_svc:
	case S_cmd:
	    
	    if (user->svcs) {   
		/* 
		 * Already parsed some services/commands. Thanks to Gabor Kiss
		 * who found this bug.
		 */
		NODE *p;
		for (p=user->svcs; p->next; p=p->next) 
		    /* NULL STMT */;
		p->next = parse_svcs();
	    } else {
		user->svcs = parse_svcs();
	    }
	    continue;

	case S_login:
	    if (user->login) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			    codestring(sym_code), user->login,
			    sym_buf, sym_line);
		tac_exit(1);
	    }
	    sym_get();
	    parse(S_separator);
	    switch(sym_code) {

	    case S_skey:
		user->login = tac_strdup(sym_buf);
		break;

	    case S_nopasswd:
		/* set to dummy string, so that we detect a duplicate
		 * password definition attempt
		 */
		user->login = tac_strdup(nopasswd_str);
		user->nopasswd = 1;
		break;
		
	    case S_file:
	    case S_cleartext:
	    case S_des:
		sprintf(buf, "%s ", sym_buf);
		sym_get();
		strcat(buf, sym_buf);
		user->login = tac_strdup(buf);
		break;

	    default:
		parse_error(
 "expecting 'file', 'cleartext', 'nopassword', 'skey', or 'des' keyword after 'login =' on line %d", 
			    sym_line);
	    }
	    sym_get();
	    continue;

	case S_pap:
	    if (user->pap) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			    codestring(sym_code), user->pap,
			    sym_buf, sym_line);
		tac_exit(1);
	    }
	    sym_get();
	    parse(S_separator);
	    switch(sym_code) {

	    case S_cleartext:
	    case S_des:
		sprintf(buf, "%s ", sym_buf);
		sym_get();
		strcat(buf, sym_buf);
		user->pap = tac_strdup(buf);
		break;

	    default:
		parse_error(
 "expecting 'cleartext', or 'des' keyword after 'pap =' on line %d", 
 sym_line);
	    }
	    sym_get();
	    continue;

	case S_name:
	    ASSIGN(user->full_name);
	    sym_get();
	    continue;

	case S_member:
	    ASSIGN(user->member);
	    sym_get();
	    continue;

	case S_expires:
	    ASSIGN(user->expires);
	    sym_get();
	    continue;

	case S_message:
	    ASSIGN(user->msg);
	    sym_get();
	    continue;

	case S_arap:
	case S_chap:
#ifdef MSCHAP
	case S_mschap:
#endif /* MSCHAP */
	case S_opap:
	case S_global:
	    save_sym = sym_code;
	    sym_get(); 
	    parse(S_separator); 
	    sprintf(buf, "%s ", sym_buf);
	    parse(S_cleartext);
	    strcat(buf, sym_buf);

	    if (save_sym == S_arap)
		fieldp = &user->arap;
	    if (save_sym == S_chap)
		fieldp = &user->chap;
#ifdef MSCHAP
	    if (save_sym == S_mschap)
		fieldp = &user->mschap;
#endif /* MSCHAP */
	    if (save_sym == S_pap)
		fieldp = &user->pap;
	    if (save_sym == S_opap)
		fieldp = &user->opap;
	    if (save_sym == S_global)
		fieldp = &user->global;

	    if (*fieldp) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			    codestring(save_sym), *fieldp, sym_buf, sym_line);
		tac_exit(1);
	    }
	    *fieldp = tac_strdup(buf);
	    sym_get();
	    continue;

	case S_closebra:
	    parse(S_closebra);
	    return (0);

#ifdef MAXSESS
	case S_maxsess:
	    sym_get(); 
	    parse(S_separator);
	    if (sscanf(sym_buf, "%d", &user->maxsess) != 1) {
		parse_error("expecting integer, found '%s' on line %d",
		    sym_buf, sym_line);
	    }
	    sym_get();
	    continue;
#endif /* MAXSESS */

	default:
	    if (STREQ(sym_buf, "password")) {
		fprintf(stderr,
			"\npassword = <string> is obsolete. Use login = des <string>\n");
	    }
	    parse_error("Unrecognised keyword %s for user on line %d",
			sym_buf, sym_line);

	    return (0);
	}
    }
}

static NODE *parse_attrs();
static NODE *parse_cmd_matches();

static NODE *
parse_svcs()
{
    NODE *result;

    switch (sym_code) {
    default:
	return (NULL);
    case S_svc:
    case S_cmd:
	break;
    }

    result = (NODE *) tac_malloc(sizeof(NODE));

    bzero(result, sizeof(NODE));
    result->line = sym_line;

    /* cmd declaration */
    if (sym_code == S_cmd) {
	parse(S_cmd);
	parse(S_separator);
	result->value = tac_strdup(sym_buf);

	sym_get();
	parse(S_openbra);

	result->value1 = parse_cmd_matches();
	result->type = N_svc_cmd;

	parse(S_closebra);
	result->next = parse_svcs();
	return (result);
    }

    /* svc declaration */
    parse(S_svc);
    parse(S_separator);
    switch (sym_code) {
    default:
	parse_error("expecting service type but found %s on line %d",
		    sym_buf, sym_line);
	return (NULL);

    case S_string:
	result->type = N_svc;
	/* should perhaps check that this is an allowable service name */
	result->value1 = tac_strdup(sym_buf);
	break;
    case S_exec:
	result->type = N_svc_exec;
	break;
    case S_arap:
	result->type = N_svc_arap;
	break;
    case S_slip:
	result->type = N_svc_slip;
	break;
    case S_ppp:
	result->type = N_svc_ppp;
	parse(S_ppp);
	parse(S_protocol);
	parse(S_separator);
	/* Should perhaps check that this is a known PPP protocol name */
	result->value1 = tac_strdup(sym_buf);
	break;
    }
    sym_get();
    parse(S_openbra);
    result->dflt = parse_opt_attr_default();
    result->value = parse_attrs();
    parse(S_closebra);
    result->next = parse_svcs();
    return (result);
}

/*  <cmd-match>	 := <permission> <string> */

static NODE *
parse_cmd_matches()
{
    NODE *result;

    if (sym_code != S_permit && sym_code != S_deny) {
	return (NULL);
    }
    result = (NODE *) tac_malloc(sizeof(NODE));

    bzero(result, sizeof(NODE));
    result->line = sym_line;

    result->type = (parse_permission() == S_permit) ? N_permit : N_deny;
    result->value = tac_strdup(sym_buf);

    result->value1 = (void *) regcomp(result->value);
    if (!result->value1) {
	report(LOG_ERR, "in regular expression %s on line %d",
	       sym_buf, sym_line);
	tac_exit(1);
    }
    sym_get();

    result->next = parse_cmd_matches();

    return (result);
}

static NODE *
parse_attrs()
{
    NODE *result;
    char buf[MAX_INPUT_LINE_LEN];
    int optional = 0;

    if (sym_code == S_closebra) {
	return (NULL);
    }
    result = (NODE *) tac_malloc(sizeof(NODE));

    bzero(result, sizeof(NODE));
    result->line = sym_line;

    if (sym_code == S_optional) {
	optional++;
	sym_get();
    }
    result->type = optional ? N_optarg : N_arg;

    strcpy(buf, sym_buf);
    parse(S_string);
    strcat(buf, sym_buf);
    parse(S_separator);
    strcat(buf, sym_buf);
    parse(S_string);

    result->value = tac_strdup(buf);
    result->next = parse_attrs();
    return (result);
}


static void
 getsym();

static void
sym_get()
{
    getsym();

    if (debug & DEBUG_PARSE_FLAG) {
	report(LOG_DEBUG, "line=%d sym=%s code=%d buf='%s'",
	       sym_line, codestring(sym_code), sym_code, sym_buf);
    }
}

static char *
sym_buf_add(c)
char c;
{
    if (sym_pos >= MAX_INPUT_LINE_LEN) {
	sym_buf[MAX_INPUT_LINE_LEN-1] = '\0';
	if (debug & DEBUG_PARSE_FLAG) {
	    report(LOG_DEBUG, "line too long: line=%d sym=%s code=%d buf='%s'",
		   sym_line, codestring(sym_code), sym_code, sym_buf);
	}
	return(NULL);
    }

    sym_buf[sym_pos++] = c;
    return(sym_buf);
}
    
static void
getsym()
{

next:
    switch (sym_ch) {

    case EOF:
	sym_code = S_eof;
	return;

    case '\n':
	sym_line++;
	rch();
	goto next;

    case '\t':
    case ' ':
	while (sym_ch == ' ' || sym_ch == '\t')
	    rch();
	goto next;

    case '=':
	strcpy(sym_buf, "=");
	sym_code = S_separator;
	rch();
	return;

    case '{':
	strcpy(sym_buf, "{");
	sym_code = S_openbra;
	rch();
	return;

    case '}':
	strcpy(sym_buf, "}");
	sym_code = S_closebra;
	rch();
	return;

    case '#':
	while ((sym_ch != '\n') && (sym_ch != EOF))
	    rch();
	goto next;

    case '"':
	rch();
	sym_pos = 0;
	while (1) {

	    if (sym_ch == '"') {
		break;
	    }

	    /* backslash-double-quote is supported inside strings */
	    /* also allow \n */
	    if (sym_ch == '\\') {
		rch();
		switch (sym_ch) {
		case 'n':
		    /* preserve the slash for \n */
		    if (!sym_buf_add('\\')) {
			sym_code = S_unknown;
			rch();
			return;
		    }
		    
		    /* fall through */
		case '"':
		    if (!sym_buf_add(sym_ch)) {
			sym_code = S_unknown;
			rch();
			return;
		    }
		    rch();
		    continue;
		default:
		    sym_code = S_unknown;
		    rch();
		    return;
		}
	    }
	    if (!sym_buf_add(sym_ch)) {
		sym_code = S_unknown;
		rch();
		return;
	    }
	    rch();
	}
	rch();

	if (!sym_buf_add('\0')) {
	    sym_code = S_unknown;
	    rch();
	    return;
	}
	sym_code = S_string;
	return;

    default:
	sym_pos = 0;
	while (sym_ch != '\t' && sym_ch != ' ' && sym_ch != '='
	       && sym_ch != '\n') {

	    if (!sym_buf_add(sym_ch)) {
		sym_code = S_unknown;
		rch();
		return;
	    }
	    rch();
	}

	if (!sym_buf_add('\0')) {
	    sym_code = S_unknown;
	    rch();
	    return;
	}
	sym_code = keycode(sym_buf);
	if (sym_code == S_unknown)
	    sym_code = S_string;
	return;
    }
}

static void
rch()
{
    if (sym_error) {
	sym_ch = EOF;
	return;
    }
    sym_ch = getc(cf);

    if (parse_only && sym_ch != EOF)
	fprintf(stderr, "%c", sym_ch);
}


/* For a user or group, find the value of a field. Does not recurse. */
VALUE
get_value(user, field)
USER *user;
int field;
{
    VALUE v;

    v.intval = 0;

    if (!user) {
	parse_error("get_value: illegal user");
	return (v);
    }
    switch (field) {

    case S_name:
	v.pval = user->name;
	break;

    case S_login:
	v.pval = user->login;
	break;

    case S_global:
	v.pval = user->global;
	break;

    case S_member:
	v.pval = user->member;
	break;

    case S_expires:
	v.pval = user->expires;
	break;

    case S_arap:
	v.pval = user->arap;
	break;

    case S_chap:
	v.pval = user->chap;
	break;

#ifdef MSCHAP
    case S_mschap:
	v.pval = user->mschap;
	break;
#endif /* MSCHAP */

    case S_pap:
	v.pval = user->pap;
	break;

    case S_opap:
	v.pval = user->opap;
	break;

    case S_message:
	v.pval = user->msg;
	break;

    case S_svc:
	v.pval = user->svcs;
	break;

    case S_before:
	v.pval = user->before_author;
	break;

    case S_after:
	v.pval = user->after_author;
	break;

    case S_svc_dflt:
	v.intval = user->svc_dflt;
	break;

#ifdef MAXSESS
    case S_maxsess:
	v.intval = user->maxsess;
	break;
#endif 

    case S_nopasswd:
	v.intval = user->nopasswd;
	break;
	
    default:
	report(LOG_ERR, "get_value: unknown field %d", field);
	break;
    }
    return (v);
}

/* For each user, check she doesn't circularly reference a
   group. Return 1 if it does */
static int
circularity_check()
{
    USER *user, *entry, *group;
    USER **users = (USER **) hash_get_entries(usertable);
    USER **groups = (USER **) hash_get_entries(grouptable);
    USER **p, **q;

    /* users */
    for (p = users; *p; p++) {
	user = *p;

	if (debug & DEBUG_PARSE_FLAG)
	    report(LOG_DEBUG, "circularity_check: user=%s", user->name);

	/* Initialise all groups "seen" flags to zero */
	for (q = groups; *q; q++) {
	    group = *q;
	    group->flags &= ~FLAG_SEEN;
	}

	entry = user;

	while (entry) {
	    /* check groups we are a member of */
	    char *groupname = entry->member;

	    if (debug & DEBUG_PARSE_FLAG)
		report(LOG_DEBUG, "\tmember of group %s",
		       groupname ? groupname : "<none>");


	    /* if not a member of any groups, go on to next user */
	    if (!groupname)
		break;

	    group = (USER *) hash_lookup(grouptable, groupname);
	    if (!group) {
		report(LOG_ERR, "%s=%s, group %s does not exist",
		       (entry->flags & FLAG_ISUSER) ? "user" : "group",
		       entry->name, groupname);
		free(users);
		free(groups);
		return (1);
	    }
	    if (group->flags & FLAG_SEEN) {
		report(LOG_ERR, "recursively defined groups");

		/* print all seen "groups" */
		for (q = groups; *q; q++) {
		    group = *q;
		    if (group->flags & FLAG_SEEN)
			report(LOG_ERR, "%s", group->name);
		}
		free(users);
		free(groups);
		return (1);
	    }
	    group->flags |= FLAG_SEEN;	/* mark group as seen */
	    entry = group;
	}
    }
    free(users);
    free(groups);
    return (0);
}


/* Return a value for a group or user (isuser says if
   this name is a group or a user name).

   If no value exists, and recurse is true, also check groups we are a
   member of, recursively.

   Returns void * because it can return a string or a node pointer
   (should really return a union pointer).
*/
static VALUE
cfg_get_value(name, isuser, attr, recurse)
char *name;
int isuser, attr, recurse;
{
    USER *user, *group;
    VALUE value;

    value.pval = NULL;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_value: name=%s isuser=%d attr=%s rec=%d",
	       name, isuser, codestring(attr), recurse);

    /* find the user/group entry */

    user = (USER *) hash_lookup(isuser ? usertable : grouptable, name);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_value: no user/group named %s", name);
	return (value);
    }

    /* found the entry. Lookup value from attr=value */
    value = get_value(user, attr);

    if (value.pval || !recurse) {
	return (value);
    }
    /* no value. Check containing group */
    if (user->member)
	group = (USER *) hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_value: recurse group = %s",
		   group->name);

	value = get_value(group, attr);

	if (value.pval) {
	    return (value);
	}
	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *) hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    /* no value for this user or her containing groups */
    value.pval = NULL;
    return (value);
}


/* Wrappers for cfg_get_value */
int
cfg_get_intvalue(name, isuser, attr, recurse)
char *name;
int isuser, attr, recurse;
{
    int val = cfg_get_value(name, isuser, attr, recurse).intval;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_intvalue: returns %d", val);
    return(val);
}

char *
cfg_get_pvalue(name, isuser, attr, recurse)
char *name;
int isuser, attr, recurse;
{
    char *p = cfg_get_value(name, isuser, attr, recurse).pval;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_pvalue: returns %s", 
	       p ? p : "NULL");
    return(p);
}
/*
   Read the config file and do some basic sanity checking on
   it. Return 1 if we find any errors. */

cfg_read_config(cfile)
char *cfile;
{
    sym_line = 1;

    if ((cf = fopen(cfile, "r")) == NULL) {
	report(LOG_ERR, "read_config: fopen() error for file %s %s, exiting",
	       cfile, sys_errlist[errno]);
	return (1);
    }
    if (parse_decls() || sym_error) {
	fclose(cf);
	return (1);
    }

    if (circularity_check()) {
	fclose(cf);
	return (1);
    }

    fclose(cf);
    return (0);
}

/* return 1 if user exists, 0 otherwise */
int
cfg_user_exists(username)
char *username;
{
    USER *user = (USER *) hash_lookup(usertable, username);

    return (user != NULL);
}

/* return expiry string of user. If none, try groups she is a member
   on, and so on, recursively if recurse is non-zero */
char *
cfg_get_expires(username, recurse)
char *username;

{
    return (cfg_get_pvalue(username, TAC_IS_USER, S_expires, recurse));
}

/* return password string of user. If none, try groups she is a member
   on, and so on, recursively if recurse is non-zero */
char *
cfg_get_login_secret(user, recurse)
char *user;

{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_login, recurse));
}

/* return value of the nopasswd field. If none, try groups she is a member
   on, and so on, recursively if recurse is non-zero */
int
cfg_get_user_nopasswd(user, recurse)
    char *user;
{
    return (cfg_get_intvalue(user, TAC_IS_USER, S_nopasswd, recurse));
}

/* return user's secret. If none, try groups she is a member
   on, and so on, recursively if recurse is non-zero */
char *
cfg_get_arap_secret(user, recurse)
char *user;

{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_arap, recurse));
}

char *
cfg_get_chap_secret(user, recurse)
char *user;

{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_chap, recurse));
}

#ifdef MSCHAP
char *
cfg_get_mschap_secret(user, recurse)
char *user;

{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_mschap, recurse));
}
#endif /* MSCHAP */

char *
cfg_get_pap_secret(user, recurse)
char *user;
{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_pap, recurse));
}

char *
cfg_get_opap_secret(user, recurse)
char *user;
{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_opap, recurse));
}

/* return the global password for the user (or the group, etc.) */

char *
cfg_get_global_secret(user, recurse)
char *user;

{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_global, recurse));
}

/* Return a pointer to a node representing a given service
   authorization, taking care of recursion issues correctly. Protocol
   is only read if the type is N_svc_ppp. svcname is only read if type
   is N_svc.
*/

NODE *
cfg_get_svc_node(username, type, protocol, svcname, recurse)
char *username;
int type;
char *protocol, *svcname;
int recurse;
{
    USER *user, *group;
    NODE *svc;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, 
	       "cfg_get_svc_node: username=%s %s proto=%s svcname=%s rec=%d",
	       username, 
	       cfg_nodestring(type), 
	       protocol ? protocol : "", 
	       svcname ? svcname : "", 
	       recurse);

    /* find the user/group entry */
    user = (USER *) hash_lookup(usertable, username);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_svc_node: no user named %s", username);
	return (NULL);
    }

    /* found the user entry. Find svc node */
    for(svc = (NODE *) get_value(user, S_svc).pval; svc; svc = svc->next) {

	if (svc->type != type) 
	    continue;

	if (type == N_svc_ppp && !STREQ(svc->value1, protocol)) {
	    continue;
	}

	if (type == N_svc && !STREQ(svc->value1, svcname)) {
	    continue;
	}

	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, 
		   "cfg_get_svc_node: found %s proto=%s svcname=%s",
		   cfg_nodestring(type), 
		   protocol ? protocol : "", 
		   svcname ? svcname : "");

	return(svc);
    }

    if (!recurse) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_svc_node: returns NULL");
	return (NULL);
    }

    /* no matching node. Check containing group */
    if (user->member)
	group = (USER *) hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_svc_node: recurse group = %s",
		   group->name);

	for(svc = (NODE *) get_value(group, S_svc).pval; svc; svc = svc->next) {

	    if (svc->type != type) 
		continue;

	    if (type == N_svc_ppp && !STREQ(svc->value1, protocol)) {
		continue;
	    }

	    if (type == N_svc && !STREQ(svc->value1, svcname)) {
		continue;
	    }

	    if (debug & DEBUG_CONFIG_FLAG)
		report(LOG_DEBUG, 
		       "cfg_get_svc_node: found %s proto=%s svcname=%s",
		       cfg_nodestring(type), 
		       protocol ? protocol : "", 
		       svcname ? svcname : "");

	    return(svc);
	}

	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *) hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_svc_node: returns NULL");

    /* no matching svc node for this user or her containing groups */
    return (NULL);
}

/* Return a pointer to the node representing a set of command regexp
   matches for a user and command, handling recursion issues correctly */
NODE *
cfg_get_cmd_node(name, cmdname, recurse)
char *name, *cmdname;
int recurse;

{
    USER *user, *group;
    NODE *svc;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_cmd_node: name=%s cmdname=%s rec=%d",
	       name, cmdname, recurse);

    /* find the user/group entry */
    user = (USER *) hash_lookup(usertable, name);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_cmd_node: no user named %s", name);
	return (NULL);
    }
    /* found the user entry. Find svc node */
    svc = (NODE *) get_value(user, S_svc).pval;

    while (svc) {
	if (svc->type == N_svc_cmd && STREQ(svc->value, cmdname)) {
	    if (debug & DEBUG_CONFIG_FLAG)
		report(LOG_DEBUG, "cfg_get_cmd_node: found cmd %s %s node",
		       cmdname, cfg_nodestring(svc->type));
	    return (svc);
	}
	svc = svc->next;
    }

    if (!recurse) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_cmd_node: returns NULL");
	return (NULL);
    }
    /* no matching node. Check containing group */
    if (user->member)
	group = (USER *) hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_cmd_node: recurse group = %s",
		   group->name);

	svc = get_value(group, S_svc).pval;

	while (svc) {
	    if (svc->type == N_svc_cmd && STREQ(svc->value, cmdname)) {
		if (debug & DEBUG_CONFIG_FLAG)
		    report(LOG_DEBUG, "cfg_get_cmd_node: found cmd %s node %s",
			   cmdname, cfg_nodestring(svc->type));
		return (svc);
	    }
	    svc = svc->next;
	}

	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *) hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_cmd_node: returns NULL");

    /* no matching cmd node for this user or her containing groups */
    return (NULL);
}

/* Return an array of character strings representing configured AV
 * pairs, given a username and a service node. 
 *
 * In the AV strings returned, manipulate the separator character to
 * indicate which args are optional and which are mandatory.
 *
 * Lastly, indicate what default permission was configured by setting
 * denyp */

char **
cfg_get_svc_attrs(svcnode, denyp)
NODE *svcnode;
int *denyp;
{
    int i;
    NODE *node;
    char **args;

    *denyp = 1;

    if (!svcnode)
	return (NULL);

    *denyp = (svcnode->dflt == S_deny);

    i = 0;
    for (node = svcnode->value; node; node = node->next)
	i++;

    args = (char **) tac_malloc(sizeof(char *) * (i + 1));

    i = 0;
    for (node = svcnode->value; node; node = node->next) {
	char *arg = tac_strdup(node->value);
	char *p = index(arg, '=');

	if (p && node->type == N_optarg)
	    *p = '*';
	args[i++] = arg;
    }
    args[i] = NULL;
    return (args);
}


int
cfg_user_svc_default_is_permit(user)
char *user;

{
    int permit = cfg_get_intvalue(user, TAC_IS_USER, S_svc_dflt,
			       TAC_PLUS_RECURSE);

    switch (permit) {
    default:			/* default is deny */
    case S_deny:
	return (0);
    case S_permit:
	return (1);
    }
}

int
cfg_no_user_permitted()
{
    if (no_user_dflt == S_permit)
	return (1);
    return (0);
}


char *
cfg_get_authen_default()
{
    return (authen_default);
}

/* Return 1 if this user has any ppp services configured. Used for
   authorizing ppp/lcp requests */
int
cfg_ppp_is_configured(username, recurse)
    char *username;
    int recurse;
{
    USER *user, *group;
    NODE *svc;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_ppp_is_configured: username=%s rec=%d",
	       username, recurse);

    /* find the user/group entry */
    user = (USER *) hash_lookup(usertable, username);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: no user named %s", 
		   username);
	return (0);
    }

    /* found the user entry. Find svc node */
    for(svc = (NODE *) get_value(user, S_svc).pval; svc; svc = svc->next) {

	if (svc->type != N_svc_ppp) 
	    continue;

	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: found svc ppp %s node",
		   svc->value1);
	
	return(1);
    }

    if (!recurse) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: returns 0");
	return (0);
    }

    /* no matching node. Check containing group */
    if (user->member)
	group = (USER *) hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: recurse group = %s",
		   group->name);

	for(svc = (NODE *) get_value(group, S_svc).pval; svc; svc = svc->next) {

	    if (svc->type != N_svc_ppp)
		continue;

	    if (debug & DEBUG_CONFIG_FLAG)
		report(LOG_DEBUG, "cfg_ppp_is_configured: found svc ppp %s node",
		       svc->value1);
	
	    return(1);
	}

	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *) hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_ppp_is_configured: returns 0");

    /* no PPP svc nodes for this user or her containing groups */
    return (0);
}
