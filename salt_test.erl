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

-module(salt_test).
-export([all/0]).

all() ->
    case application:start(salt) of
	ok ->
	    orly();
	{error, {already_started, _}} ->
	    orly();
	Else ->
	    Else
    end.

orly() ->
    io:nl(), io:nl(),
    title("Trying out crypto_box functions."),
    box(),
    %% XXX how to test crypto_scalarmult?
    title("Trying out crypto_sign functions."),
    sign(),
    title("Trying out crypto_secretbox functions."),
    secretbox(),
    title("Trying out crypto_stream functions."),
    stream(),
    title("Trying out crypto_auth functions."),
    auth(),
    title("Trying out crypto_onetimeauth functions."),
    onetimeauth(),
    title("Success.").

%%%

box() ->
    {Apk, Ask} = verbose(salt, crypto_box_keypair, []),
    {Bpk, Bsk} = verbose(salt, crypto_box_keypair, []),
    Nc = <<1:24/integer-unit:8>>,
    Pt = <<"Hello Bob, message from Alice.">>,
    boxself(Apk, Ask, Nc, Pt),
    boxpeer(Apk, Ask, Bpk, Bsk, Nc, Pt),
    boxprec(Apk, Ask, Bpk, Bsk, Nc, Pt).

boxself(Apk, Ask, Nc, Pt) ->
    Ct = verbose(salt, crypto_box, [Pt, Nc, Apk, Ask]),
    compare({ok, Pt}, verbose(salt, crypto_box_open, [Ct, Nc, Apk, Ask])).

boxpeer(Apk, Ask, Bpk, Bsk, Nc, Pt) ->
    Ct = verbose(salt, crypto_box, [Pt, Nc, Bpk, Ask]),
    compare({ok, Pt}, verbose(salt, crypto_box_open, [Ct, Nc, Apk, Bsk])).

boxprec(Apk, Ask, Bpk, Bsk, Nc, Pt) ->
    Ac = verbose(salt, crypto_box_beforenm, [Bpk, Ask]),
    Bc = verbose(salt, crypto_box_beforenm, [Apk, Bsk]),
    Ct = verbose(salt, crypto_box_afternm, [Pt, Nc, Ac]),
    compare({ok, Pt}, verbose(salt, crypto_box_open_afternm, [Ct, Nc, Bc])).

sign() ->
    {Pk, Sk} = verbose(salt, crypto_sign_keypair, []),
    Pm = <<"Plain text to be signed.">>,
    Sm = verbose(salt, crypto_sign, [Pm, Sk]),
    compare({ok, Pm}, verbose(salt, crypto_sign_open, [Sm, Pk])).

secretbox() ->
    Sk = <<1:32/integer-unit:8>>,
    Nc = <<1:24/integer-unit:8>>,
    Pt = <<"Secret message.">>,
    Ct = verbose(salt, crypto_secretbox, [Pt, Nc, Sk]),
    compare({ok, Pt}, verbose(salt, crypto_secretbox_open, [Ct, Nc, Sk])).

stream() ->
    Sk = <<1:32/integer-unit:8>>,
    Nc = <<1:24/integer-unit:8>>,
    Pt = <<"Secret message.">>,
    Ct = verbose(salt, crypto_stream_xor, [Pt, Nc, Sk]),
    compare(Pt, verbose(salt, crypto_stream_xor, [Ct, Nc, Sk])).

auth() ->
    Sk = <<1:32/integer-unit:8>>,
    Pt = <<"Authentic message.">>,
    Au = verbose(salt, crypto_auth, [Pt, Sk]),
    compare(authenticated, verbose(salt, crypto_auth_verify, [Au, Pt, Sk])).

onetimeauth() ->
    Sk = <<1:32/integer-unit:8>>,
    Pt = <<"Authentic message.">>,
    Au = verbose(salt, crypto_onetimeauth, [Pt, Sk]),
    compare(authenticated, verbose(salt, crypto_onetimeauth_verify, [Au, Pt, Sk])).

%%%

compare(X, Y) when X /= Y ->
    io:format("==== Unexpected result. ====~n~s~s~n~n", [format(X, "LHS: "), format(Y, "RHS: ")]),
    exit(salt_tests_failed);
compare(_, _) ->
    ok.

verbose(M, F, A) ->
    R = (catch apply(M, F, A)),
    io:format("< ~s:~s/~w~n~s~s~n", [M, F, length(A), [formati(X) || X <- A], formato(R)]),
    R.

formati(X) ->
    format(X, "< ").

formato(X) ->
    format(X, "> ").

format(B, S) when is_binary(B) ->
    io_lib:format("~s~s (~wB)~n", [S, bytes(B), byte_size(B)]);
format({A, B}, S) when is_binary(A), is_binary(B) ->
    io_lib:format("~s{~s, (~wB)~n~s ~s} (~wB)~n", [S, bytes(A), byte_size(A), S, bytes(B), byte_size(B)]);
format({A, B}, S) when is_atom(A), is_binary(B) ->
    io_lib:format("~s{~s, ~s} (~wB)~n", [S, A, bytes(B), byte_size(B)]);
format(X, S) ->
    io_lib:format("~s~132p~n", [S, X]).

title(S) ->
    io:format("==== ~s ====~n~n", [S]).

bytes(B) ->
    [$0, $x | hexdump(B)].

hexdump(<<A:4, B:4, R/binary>>) ->
    [nibble(A), nibble(B) | hexdump(R)];
hexdump(<<>>) ->
    [].

nibble(N) when N >= 0, N =< 9 ->
    $0 + N;
nibble(N) when N >= 10, N =< 15 ->
    $A + (N - 10).
