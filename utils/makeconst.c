/*
 * Copyright (c) 2013 Jachym Holecek <freza@circlewave.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>

#include <crypto_box.h>
/* XXXmissing #include <crypto_scalarmult.h> */
#include <crypto_scalarmult_curve25519.h>
#include <crypto_sign.h>
#include <crypto_secretbox.h>
#include <crypto_stream.h>
#include <crypto_auth.h>
#include <crypto_onetimeauth.h>
#include <crypto_hash.h>
#include <crypto_verify_16.h>
#include <crypto_verify_32.h>

int
main(int argc, char *argv[])
{
	printf("%%%%%% Copyright (c) 2013 Jachym Holecek <freza@circlewave.net>\n");
	printf("%%%%%% All rights reserved.\n");
	printf("%%%%%%\n");
	printf("%%%%%% Redistribution and use in source and binary forms, with or without\n");
	printf("%%%%%% modification, are permitted provided that the following conditions\n");
	printf("%%%%%% are met:\n");
	printf("%%%%%%\n");
	printf("%%%%%% 1. Redistributions of source code must retain the above copyright\n");
	printf("%%%%%%    notice, this list of conditions and the following disclaimer.\n");
	printf("%%%%%% 2. Redistributions in binary form must reproduce the above copyright\n");
	printf("%%%%%%    notice, this list of conditions and the following disclaimer in\n");
	printf("%%%%%%    the documentation and/or other materials provided with the\n");
	printf("%%%%%%    distribution.\n");
	printf("%%%%%%\n");
	printf("%%%%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n");
	printf("%%%%%% \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n");
	printf("%%%%%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS\n");
	printf("%%%%%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE\n");
	printf("%%%%%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,\n");
	printf("%%%%%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,\n");
	printf("%%%%%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;\n");
	printf("%%%%%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER\n");
	printf("%%%%%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT\n");
	printf("%%%%%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN\n");
	printf("%%%%%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n");
	printf("%%%%%% POSSIBILITY OF SUCH DAMAGE.\n");
	printf("\n");

	printf("-ifndef(SALT_HRL).\n");
	printf("-define(SALT_HRL, included).\n");
	printf("\n");

	printf("-define(CRYPTO_BOX_PUBLICKEYBYTES, 		%d).\n", crypto_box_PUBLICKEYBYTES);
	printf("-define(CRYPTO_BOX_SECRETKEYBYTES, 		%d).\n", crypto_box_SECRETKEYBYTES);
	printf("-define(CRYPTO_BOX_BEFORENMBYTES, 		%d).\n", crypto_box_BEFORENMBYTES);
	printf("-define(CRYPTO_BOX_NONCEBYTES, 			%d).\n", crypto_box_NONCEBYTES);
	printf("-define(CRYPTO_BOX_ZEROBYTES, 			%d).\n", crypto_box_ZEROBYTES);
	printf("-define(CRYPTO_BOX_BOXZEROBYTES, 		%d).\n", crypto_box_BOXZEROBYTES);
	printf("-define(CRYPTO_BOX_PRIMITIVE, 			%s).\n", crypto_box_PRIMITIVE);
	// printf("-define(CRYPTO_BOX_IMPLEMENTATION, 		\"%s\").\n", crypto_box_IMPLEMENTATION);
	// printf("-define(CRYPTO_BOX_VERSION, 			\"%s\").\n", crypto_box_VERSION);
	printf("\n");

	/* XXX crypto_scalarmult.h is missing! Using curve25519 directly. */
	printf("-define(CRYPTO_SCALARMULT_BYTES, 		%d).\n", crypto_scalarmult_curve25519_BYTES);
	printf("-define(CRYPTO_SCALARMULT_SCALARBYTES, 		%d).\n", crypto_scalarmult_curve25519_SCALARBYTES);
	// printf("-define(CRYPTO_SCALARMULT_IMPLEMENTATION, 	\"%s\").\n", crypto_scalarmult_curve25519_IMPLEMENTATION);
	// printf("-define(CRYPTO_SCALARMULT_VERSION, 		\"%s\").\n", crypto_scalarmult_curve25519_VERSION);
	printf("\n");

	printf("-define(CRYPTO_SIGN_BYTES, 			%d).\n", crypto_sign_BYTES);
	printf("-define(CRYPTO_SIGN_PUBLICKEYBYTES, 		%d).\n", crypto_sign_PUBLICKEYBYTES);
	printf("-define(CRYPTO_SIGN_SECRETKEYBYTES, 		%d).\n", crypto_sign_SECRETKEYBYTES);
	printf("-define(CRYPTO_SIGN_PRIMITIVE, 			%s).\n", crypto_sign_PRIMITIVE);
	// printf("-define(CRYPTO_SIGN_IMPLEMENTATION, 		\"%s\").\n", crypto_sign_IMPLEMENTATION);
	// printf("-define(CRYPTO_SIGN_VERSION, 			\"%s\").\n", crypto_sign_VERSION);
	printf("\n");

	printf("-define(CRYPTO_SECRETBOX_KEYBYTES, 		%d).\n", crypto_secretbox_KEYBYTES);
	printf("-define(CRYPTO_SECRETBOX_NONCEBYTES, 		%d).\n", crypto_secretbox_NONCEBYTES);
	printf("-define(CRYPTO_SECRETBOX_ZEROBYTES, 		%d).\n", crypto_secretbox_ZEROBYTES);
	printf("-define(CRYPTO_SECRETBOX_BOXZEROBYTES, 		%d).\n", crypto_secretbox_BOXZEROBYTES);
	printf("-define(CRYPTO_SECRETBOX_PRIMITIVE, 		%s).\n", crypto_secretbox_PRIMITIVE);
	// printf("-define(CRYPTO_SECRETBOX_IMPLEMENTATION, 	\"%s\").\n", crypto_secretbox_IMPLEMENTATION);
	// printf("-define(CRYPTO_SECRETBOX_VERSION, 		\"%s\").\n", crypto_secretbox_VERSION);
	printf("\n");

	printf("-define(CRYPTO_STREAM_KEYBYTES, 		%d).\n", crypto_stream_KEYBYTES);
	printf("-define(CRYPTO_STREAM_NONCEBYTES, 		%d).\n", crypto_stream_NONCEBYTES);
	printf("-define(CRYPTO_STREAM_PRIMITIVE, 		%s).\n", crypto_stream_PRIMITIVE);
	// printf("-define(CRYPTO_STREAM_IMPLEMENTATION, 		\"%s\").\n", crypto_stream_IMPLEMENTATION);
	// printf("-define(CRYPTO_STREAM_VERSION, 			\"%s\").\n", crypto_stream_VERSION);
	printf("\n");

	printf("-define(CRYPTO_AUTH_BYTES, 			%d).\n", crypto_auth_BYTES);
	printf("-define(CRYPTO_AUTH_KEYBYTES, 			%d).\n", crypto_auth_KEYBYTES);
	printf("-define(CRYPTO_AUTH_PRIMITIVE, 			%s).\n", crypto_auth_PRIMITIVE);
	// printf("-define(CRYPTO_AUTH_IMPLEMENTATION, 		\"%s\").\n", crypto_auth_IMPLEMENTATION);
	// printf("-define(CRYPTO_AUTH_VERSION, 			\"%s\").\n", crypto_auth_VERSION);
	printf("\n");

	printf("-define(CRYPTO_ONETIMEAUTH_BYTES, 		%d).\n", crypto_onetimeauth_BYTES);
	printf("-define(CRYPTO_ONETIMEAUTH_KEYBYTES, 		%d).\n", crypto_onetimeauth_KEYBYTES);
	printf("-define(CRYPTO_ONETIMEAUTH_PRIMITIVE, 		%s).\n", crypto_onetimeauth_PRIMITIVE);
	// printf("-define(CRYPTO_ONETIMEAUTH_IMPLEMENTATION, 	\"%s\").\n", crypto_onetimeauth_IMPLEMENTATION);
	// printf("-define(CRYPTO_ONETIMEAUTH_VERSION, 		\"%s\").\n", crypto_onetimeauth_VERSION);
	printf("\n");

	printf("-define(CRYPTO_HASH_BYTES, 			%d).\n", crypto_hash_BYTES);
	printf("-define(CRYPTO_HASH_PRIMITIVE, 			%s).\n", crypto_hash_PRIMITIVE);
	// printf("-define(CRYPTO_HASH_IMPLEMENTATION, 		\"%s\").\n", crypto_hash_IMPLEMENTATION);
	// printf("-define(CRYPTO_HASH_VERSION, 			\"%s\").\n", crypto_hash_VERSION);
	printf("\n");

	printf("-endif.\n");
	return (0);
}
