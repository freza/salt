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

-module(salt_server).
-behaviour(gen_server).

-export([start_link/0]).
-export([make_box_keypair/0, make_sign_keypair/0, make_random_bytes/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%%%

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

make_box_keypair() ->
    case gen_server:call(?MODULE, make_box_keypair) of
	{ok, Pk_sk} ->
	    Pk_sk;
	{error, Rsn} ->
	    exit({salt, crypto_box_keypair, Rsn})
    end.

make_sign_keypair() ->
    case gen_server:call(?MODULE, make_sign_keypair) of
	{ok, Pk_sk} ->
	    Pk_sk;
	{error, Rsn} ->
	    exit({salt, crypto_sign_keypair, Rsn})
    end.

make_random_bytes(Cnt) ->
    case gen_server:call(?MODULE, {make_random_bytes, Cnt}) of
	{ok, Bytes} ->
	    Bytes;
	{error, Rsn} ->
	    exit({salt, crypto_random_bytes, Rsn})
    end.

%%%

-record(state, {
	  pcb 			%% NIF worker thread context. 			:: pcb()
	 }).

init([]) ->
    ok = salt_nif:load(),
    Pcb = salt_nif:start(),
    {ok, #state{pcb = Pcb}}.

handle_call(make_box_keypair, {Pid, Mref}, #state{pcb = Pcb} = State) ->
    try salt_nif:salt_box_keypair(Pcb, Pid, Mref) of
	enqueued ->
	    {noreply, State};
	Error ->
	    {reply, {error, Error}, State}
    catch
	error : badarg ->
	    {reply, {error, badarg}, State}
    end;
handle_call(make_sign_keypair, {Pid, Mref}, #state{pcb = Pcb} = State) ->
    try salt_nif:salt_sign_keypair(Pcb, Pid, Mref) of
	enqueued ->
	    {noreply, State};
	Error ->
	    {reply, {error, Error}, State}
    catch
	error : badarg ->
	    {reply, {error, badarg}, State}
    end;
handle_call({make_random_bytes, Cnt}, {Pid, Mref}, #state{pcb = Pcb} = State) ->
    try salt_nif:salt_random_bytes(Pcb, Pid, Mref, Cnt) of
	enqueued ->
	    {noreply, State};
	Error ->
	    {reply, {error, Error}, State}
    catch
	error : badarg ->
	    {reply, {error, badarg}, State}
    end;
handle_call(_, _, State) ->
    {reply, {error, bad_request}, State}.

handle_cast(_, State) ->
    {noreply, State}.

handle_info(_, State) ->
    {noreply, State}.

code_change(_, State, _) ->
    {ok, State}.

terminate(_, _) ->
    ok.

%%%
