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

-module(salt_nif).

-export([load/0, start/0]).

-export([salt_box_keypair/3, salt_box/4, salt_box_open/4, salt_box_beforenm/2]).
-export([salt_box_afternm/3, salt_box_open_afternm/3]).
-export([salt_scalarmult/2, salt_scalarmult_base/1]).
-export([salt_sign_keypair/3, salt_sign/2, salt_sign_open/2]).

-export([salt_secretbox/3, salt_secretbox_open/3]).
-export([salt_stream/3, salt_stream_xor/3]).
-export([salt_auth/2, salt_auth_verify/3]).
-export([salt_onetimeauth/2, salt_onetimeauth_verify/3]).

-export([salt_hash/1, salt_verify_16/2, salt_verify_32/2]).
-export([salt_random_bytes/4]).

%%%

load() ->
    Path = filename:join([code:priv_dir(salt), erlang:system_info(system_architecture), "salt_nif"]),
    erlang:load_nif(Path, 0).

%%% Exported from salt_nif.c.

start() ->
    error(salt_not_loaded).

salt_box_keypair(_, _, _) ->
    error(salt_not_loaded).

salt_box(_, _, _, _) ->
    error(salt_not_loaded).

salt_box_open(_, _, _, _) ->
    error(salt_not_loaded).

salt_box_beforenm(_, _) ->
    error(salt_not_loaded).

salt_box_afternm(_, _, _) ->
    error(salt_not_loaded).

salt_box_open_afternm(_, _, _) ->
    error(salt_not_loaded).

salt_scalarmult(_, _) ->
    error(salt_not_loaded).

salt_scalarmult_base(_) ->
    error(salt_not_loaded).

salt_sign_keypair(_, _, _) ->
    error(salt_not_loaded).

salt_sign(_, _) ->
    error(salt_not_loaded).

salt_sign_open(_, _) ->
    error(salt_not_loaded).

salt_secretbox(_, _, _) ->
    error(salt_not_loaded).

salt_secretbox_open(_, _, _) ->
    error(salt_not_loaded).

salt_stream(_, _, _) ->
    error(salt_not_loaded).

salt_stream_xor(_, _, _) ->
    error(salt_not_loaded).

salt_auth(_, _) ->
    error(salt_not_loaded).

salt_auth_verify(_, _, _) ->
    error(salt_not_loaded).

salt_onetimeauth(_, _) ->
    error(salt_not_loaded).

salt_onetimeauth_verify(_, _, _) ->
    error(salt_not_loaded).

salt_hash(_) ->
    error(salt_not_loaded).

salt_verify_16(_, _) ->
    error(salt_not_loaded).

salt_verify_32(_, _) ->
    error(salt_not_loaded).

salt_random_bytes(_, _, _, _) ->
    error(salt_not_loaded).
