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

/* Program to des encrypt a password like Unix 
   It prompts for the password to encrypt. 
   You can optionally supply a salt to verify a password.
   Usage: a.out [salt]
*/

#define NULL 0

main(argc, argv)
char **argv;
{
    char *crypt();
    char pass[25], *salt, buf[24];
    char *result;
    int n;
    char *prompt = "Password to be encrypted: ";

    salt = NULL;

    if (argc == 2) {
	salt = argv[1];
    }

    write(1, prompt, strlen(prompt));
    n = read(0, pass, sizeof(pass));
    pass[n-1] = NULL;

    if (!salt) {
	int i, r, r1, r2;

	srand(time(0));

	for(i=0; i <= 1; i++) {

	    r = rand();

	    r = r & 127;

	    if (r < 46)
		r += 46;

	    if (r > 57 && r < 65)
		r += 7;

	    if (r > 90 && r < 97) 
		r += 6;

	    if (r > 122)
		r -= 5;

	    if (i == 0)
		r1 = r;

	    if (i == 1)
		r2 = r;
	}

	sprintf(buf, "%c%c", r1, r2);
	salt = buf;
    }

    result = crypt(pass, salt);

    write(1, result, strlen(result));
    write(1, "\n", 1);
}





