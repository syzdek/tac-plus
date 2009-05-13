# Please NOTE:  None of the TACACS code available here comes with any
# warranty or support.
# Copyright (c) 1995-2000 by Cisco systems, Inc.
# 
#
# Permission to use, copy, modify, and distribute modified and
# unmodified copies of this software for any purpose and without fee is
# hereby granted, provided that (a) this copyright and permission notice
# appear on all copies of the software and supporting documentation, (b)
# the name of Cisco Systems, Inc. not be used in advertising or
# publicity pertaining to distribution of the program without specific
# prior permission, and (c) notice be given in supporting documentation
# that use, modification, copying and distribution is by permission of
# Cisco Systems, Inc.
# 
# Cisco Systems, Inc. makes no representations about the suitability of this
# software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS IS''
# AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
# LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE. 

CC = gcc

# For AIX
# See /usr/lpp/bos/bsdport on your system for details of how to define bsdcc
# CC=bsdcc
# OS=-DAIX

# For HP/UX uncomment the following line
# OS=-DHPUX

# For MIPS, uncomment the following line
# OS=-DMIPS

# For Solaris (SUNOS 5.3, 5.4, 5.5, 5.6) uncomment the following two lines
OS=-DSOLARIS
OSLIBS=-lsocket -lnsl

# For FreeBSD
# OS=-DFREEBSD
# You may also need to add:
# OSLIBS=-lcrypt
# NOTE: If you want your password encryption to be compatible with
# e.g. SunOS, you may need to instead use:
# OSLIBS=-ldescrypt

# For LINUX
# OS=-DLINUX
#
# On REDHAT 5.0 systems, or systems that use the new glibc,
# you might instead need the following:
# OS=-DLINUX -DGLIBC
# OSLIBS=-lcrypt


# Athough invoked as root, most of the time you don't want tac_plus to
# be running as root. If USERID and GROUPID are set, tac_plus will
# attempt change to run as that user & group after reading the
# configuration file and obtaining a privileged socket. If you always
# want tac_plus to run as root, then just comment out the FLAGS line.

# USERID  = 1500
# GROUPID = 25
# FLAGS   = -DTAC_PLUS_USERID=$(USERID) -DTAC_PLUS_GROUPID=$(GROUPID)

# Definitions for SKEY functionality
# DEFINES = -DSKEY
# LIBS = ../crimelab/skey/src/libskey.a
# INCLUDES = -I../crimelab/skey/src

# Debugging flags
DEBUG = -g

# Enforce a limit on maximum sessions per user. See the user's guide
# for more information.
MAXSESS = -DMAXSESS

# Microsoft CHAP extension support. See the user's guide for more
# information.
# MSCHAP = -DMSCHAP
# MSCHAP_DES = -DMSCHAP_DES
# MSCHAP_MD4_SRC = md4.c

# On startup, tac_plus creates the file /etc/tac_plus.pid (if
# possible), containing its process id. Uncomment and modify the
# following line to change this filename

# PIDFILE = -DTAC_PLUS_PIDFILE=\"/var/run/tac_plus.pid\" 

#
# End of customisable section of Makefile
#

CFLAGS = $(DEBUG) $(DEFINES) $(INCLUDES) $(FLAGS) $(OS) $(PIDFILE) $(MAXSESS)

HFILES = expire.h parse.h regmagic.h md5.h regexp.h tac_plus.h 

SRCS =	acct.c authen.c author.c choose_authen.c config.c do_acct.c \
	do_author.c dump.c encrypt.c expire.c $(MSCHAP_MD4_SRC) md5.c \
	packet.c report.c sendauth.c tac_plus.c utils.c pw.c hash.c \
	parse.c regexp.c programs.c enable.c pwlib.c default_fn.c \
	skey_fn.c default_v0_fn.c sendpass.c maxsess.c

OBJS = $(SRCS:.c=.o)

all:
	@echo "Please edit the Makefile and then make tac_plus"

tac_plus: $(OBJS) $(LIBS) generate_passwd
	$(CC) -o tac_plus $(CFLAGS) $(OBJS) $(LIBS) $(OSLIBS)

purecov: $(OBJS) $(LIBS)
	purecov -follow-child-processes -handle-signals=SIGTERM \
	    -append-logfile -log-file=purecov.log \
	    -cache-dir=`pwd` \
	    $(CC) -o tac_plus $(CFLAGS) $(OBJS) $(LIBS) $(OSLIBS)

purify: $(OBJS) $(LIBS)
	purify -follow-child-processes=yes -log-file=./tac_plus_purify.log \
	    -handle-signals=SIGTERM -cache-dir=. \
	    $(CC) -o tac_plus $(CFLAGS) $(OBJS) $(LIBS) $(OSLIBS)

generate_passwd:
	$(CC) $(CFLAGS) -o generate_passwd generate_passwd.c $(OSLIBS)

saber:
	#load -C $(CFLAGS) $(SRCS) $(LIBS)

clean:
	-rm -f *.o *~ *.BAK tac_plus generate_passwd

install:
	cp tac_plus /usr/local/bin
	cp tac_plus.1 /usr/man/manl/tac_plus.1

depend:
	makedepend $(CFLAGS) $(SRCS)

# DO NOT DELETE THIS LINE -- make depend depends on it.

