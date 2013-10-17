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

-module(salt).

-export([crypto_box_keypair/0, crypto_box/4, crypto_box_open/4, crypto_box_beforenm/2]).
-export([crypto_box_afternm/3, crypto_box_open_afternm/3]).
-export([crypto_scalarmult/2, crypto_scalarmult_base/1]).
-export([crypto_sign_keypair/0, crypto_sign/2, crypto_sign_open/2]).

-export([crypto_secretbox/3, crypto_secretbox_open/3]).
-export([crypto_stream/3, crypto_stream_xor/3]).
-export([crypto_auth/2, crypto_auth_verify/3]).
-export([crypto_onetimeauth/2, crypto_onetimeauth_verify/3]).

-export([crypto_hash/1, crypto_verify_16/2, crypto_verify_32/2]).

-include_lib("salt/include/salt.hrl").

%%% Public-key cryptography.

%% Public-key authenticated encryption.
crypto_box_keypair() ->
    salt_server:make_box_keypair().

crypto_box(Plain_text, Nonce, Public_key, Secret_key) ->
    salt_nif:salt_box([crypto_box_zerobytes() | Plain_text], Nonce, Public_key, Secret_key).

crypto_box_open(Cipher_text, Nonce, Public_key, Secret_key) ->
    salt_nif:salt_box_open([crypto_box_boxzerobytes() | Cipher_text], Nonce, Public_key, Secret_key).

crypto_box_beforenm(Public_key, Secret_key) ->
    salt_nif:salt_box_beforenm(Public_key, Secret_key).

crypto_box_afternm(Plain_text, Nonce, Context) ->
    salt_nif:salt_box_afternm([crypto_box_zerobytes() | Plain_text], Nonce, Context).

crypto_box_open_afternm(Cipher_text, Nonce, Context) ->
    salt_nif:salt_box_open_afternm(Cipher_text, Nonce, Context).

%% Scalar multiplication. NB: Opaque representation of integers and group elements on fixed-length octet strings.
crypto_scalarmult(Integer, Group_p) ->
    salt_nif:salt_scalarmult(Integer, Group_p).

crypto_scalarmult_base(Integer) ->
    salt_nif:salt_scalarmult(Integer).

%% Signatures.
crypto_sign_keypair() ->
    salt_server:make_sign_keypair().

crypto_sign(Message, Secret_key) ->
    salt_nif:salt_sign(Message, Secret_key).

crypto_sign_open(Signed_msg, Public_key) ->
    salt_nif:salt_sign_open(Signed_msg, Public_key).

%%% Secret-key cryptography.

%% Authenticated encryption.
crypto_secretbox(Plain_text, Nonce, Secret_key) ->
    salt_nif:salt_secretbox([crypto_secretbox_zerobytes() | Plain_text], Nonce, Secret_key).

crypto_secretbox_open(Cipher_text, Nonce, Secret_key) ->
    salt_nif:salt_secretbox_open([crypto_secretbox_boxzerobytes() | Cipher_text], Nonce, Secret_key).

%% Encryption.
crypto_stream(Byte_cnt, Nonce, Secret_key) ->
    salt_nif:salt_stream(Byte_cnt, Nonce, Secret_key).

crypto_stream_xor(Plain_text, Nonce, Secret_key) ->
    salt_nif:salt_stream_xor(Plain_text, Nonce, Secret_key).

%% Message authentication.
crypto_auth(Message, Secret_key) ->
    salt_nif:salt_auth(Message, Secret_key).

crypto_auth_verify(Authenticator, Message, Secret_key) ->
    salt_nif:salt_auth_verify(Authenticator, Message, Secret_key).

%% Single-message authentication.
crypto_onetimeauth(Message, Secret_key) ->
    salt_nif:salt_onetimeauth(Message, Secret_key).

crypto_onetimeauth_verify(Authenticator, Message, Secret_key) ->
    salt_nif:salt_onetimeauth_verify(Authenticator, Message, Secret_key).

%%% Low-level functions.

%% Hashing.
crypto_hash(Message) ->
    salt_nif:salt_hash(Message).

%% String comparison.
crypto_verify_16(Bin_x, Bin_y) ->
    salt_nif:salt_verify_16(Bin_x, Bin_y).

crypto_verify_32(Bin_x, Bin_y) ->
    salt_nif:salt_verify_32(Bin_x, Bin_y).

%%% Implementation.

crypto_secretbox_zerobytes() ->
    <<0:?CRYPTO_SECRETBOX_ZEROBYTES/integer-unit:8>>.

crypto_secretbox_boxzerobytes() ->
    <<0:?CRYPTO_SECRETBOX_BOXZEROBYTES/integer-unit:8>>.

crypto_box_zerobytes() ->
    <<0:?CRYPTO_BOX_ZEROBYTES/integer-unit:8>>.

crypto_box_boxzerobytes() ->
    <<0:?CRYPTO_BOX_BOXZEROBYTES/integer-unit:8>>.
