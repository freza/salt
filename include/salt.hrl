%%% Copyright (c) 2013 Jachym Holecek <freza@circlewave.net>
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%%
%%% 1. Redistributions of source code must retain the above copyright
%%%    notice, this list of conditions and the following disclaimer.
%%% 2. Redistributions in binary form must reproduce the above copyright
%%%    notice, this list of conditions and the following disclaimer in
%%%    the documentation and/or other materials provided with the
%%%    distribution.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%%% POSSIBILITY OF SUCH DAMAGE.

-ifndef(SALT_HRL).
-define(SALT_HRL, included).

-define(CRYPTO_BOX_PUBLICKEYBYTES, 		32).
-define(CRYPTO_BOX_SECRETKEYBYTES, 		32).
-define(CRYPTO_BOX_BEFORENMBYTES, 		32).
-define(CRYPTO_BOX_NONCEBYTES, 			24).
-define(CRYPTO_BOX_ZEROBYTES, 			32).
-define(CRYPTO_BOX_BOXZEROBYTES, 		16).
-define(CRYPTO_BOX_PRIMITIVE, 			curve25519xsalsa20poly1305).

-define(CRYPTO_SCALARMULT_BYTES, 		32).
-define(CRYPTO_SCALARMULT_SCALARBYTES, 		32).

-define(CRYPTO_SIGN_BYTES, 			64).
-define(CRYPTO_SIGN_PUBLICKEYBYTES, 		32).
-define(CRYPTO_SIGN_SECRETKEYBYTES, 		64).
-define(CRYPTO_SIGN_PRIMITIVE, 			ed25519).

-define(CRYPTO_SECRETBOX_KEYBYTES, 		32).
-define(CRYPTO_SECRETBOX_NONCEBYTES, 		24).
-define(CRYPTO_SECRETBOX_ZEROBYTES, 		32).
-define(CRYPTO_SECRETBOX_BOXZEROBYTES, 		16).
-define(CRYPTO_SECRETBOX_PRIMITIVE, 		xsalsa20poly1305).

-define(CRYPTO_STREAM_KEYBYTES, 		32).
-define(CRYPTO_STREAM_NONCEBYTES, 		24).
-define(CRYPTO_STREAM_PRIMITIVE, 		xsalsa20).

-define(CRYPTO_AUTH_BYTES, 			32).
-define(CRYPTO_AUTH_KEYBYTES, 			32).
-define(CRYPTO_AUTH_PRIMITIVE, 			hmacsha512256).

-define(CRYPTO_ONETIMEAUTH_BYTES, 		16).
-define(CRYPTO_ONETIMEAUTH_KEYBYTES, 		32).
-define(CRYPTO_ONETIMEAUTH_PRIMITIVE, 		poly1305).

-define(CRYPTO_HASH_BYTES, 			64).
-define(CRYPTO_HASH_PRIMITIVE, 			sha512).

-endif.
