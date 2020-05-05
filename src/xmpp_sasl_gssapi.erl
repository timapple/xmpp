%%%-------------------------------------------------------------------
%%%
%%% Copyright (C) 2002-2020 ProcessOne, SARL. All Rights Reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------
-module(xmpp_sasl_gssapi).
-behaviour(xmpp_sasl).
-author('itimapple@gmail.com').
-dialyzer({no_match, [get_local_fqdn/1]}).

-export([mech_new/4, mech_step/2, format_error/1]).

-include_lib("kernel/include/logger.hrl").

-type error_reason() :: not_authorized | gssapi_error | parser_failed.
-export_type([error_reason/0]).

-record(state, {pid,
                ctx,
                needsmore = true,
                step = 0,
                host,
                hostfqdn,
                user,
                check_password}).

-spec format_error(error_reason()) -> {atom(), binary()}.
format_error(not_authorized) ->
    {'not-authorized', <<"User unauthorized">>};
format_error(gssapi_error) ->
    {'gssapi-error', <<"User authenticated">>};
format_error(parser_failed) ->
    {'bad-protocol', <<"User decoding failed">>}.

mech_new(Host, _GetPassword, CheckPassword, _CheckPasswordDigest) ->
    {ok, Pid} = egssapi:start_link(),
    #state{
        step = 1,
        host = Host,
        hostfqdn = get_local_fqdn(Host),
        pid = Pid,
        check_password = CheckPassword}.

mech_step(State, ClientIn) ->
    catch do_step(State, ClientIn).

do_step(State, ClientIn) when State#state.needsmore == false ->
    handle_step_ok(State, ClientIn);

do_step(State, ClientIn) when State#state.needsmore == true ->
    ?LOG_DEBUG("do_step: ClientIn [~p]~n", [ClientIn]),
    try egssapi:accept_sec_context(State#state.pid, ClientIn) of
        {ok, {Ctx, User, _Ccname, ServerOut}} ->
            ?LOG_DEBUG("do_step: ok [~p]~n", [User]),
            State1 = State#state{ctx = Ctx, user = list_to_binary(User)},
            handle_step_ok(State1, ServerOut);
        {needsmore, {Ctx, ServerOut}} ->
            ?LOG_DEBUG("do_step: needsmore~n", []),
            State1 = State#state{ctx = Ctx, step = State#state.step + 1},
            {continue, ServerOut, State1};
        {error, Reason} ->
            ?LOG_DEBUG("do_step: error [~p]~n", [Reason]),
            {error, gssapi_error}
    catch
        {'EXIT',{Reason,_Stack}} ->
            ?LOG_ERROR("do_step: error [~p]~n", [Reason]),
            {error, gssapi_error};
        Reason ->
            ?LOG_ERROR("do_step: error [~p]~n", [Reason]),
            {error, gssapi_error}
    end.

handle_step_ok(State, <<>>) ->
    check_user(State);

handle_step_ok(State, ServerOut) ->
    ?LOG_DEBUG("continue~n", []),
    State1 = State#state{needsmore = false, step = State#state.step + 1},
    {continue, ServerOut, State1}.

check_user(#state{host = Host, user = UserMaybeDomain} = State) ->
    ?LOG_DEBUG("checkuser: ~p ~p~n", [UserMaybeDomain, Host]),
    case parse_authzid(UserMaybeDomain) of
        {ok, User} ->
            ?LOG_DEBUG("GSSAPI authenticated as ~p~n", [User]),
            case (State#state.check_password)(User, User, <<>>) of
                {true, AuthModule} ->
                    {ok, [{username, User},
                          {authzid, User},
                          {auth_module, AuthModule}]};
                _ ->
                    {error, not_authorized, User}
            end;
        _ ->
            {error, parser_failed, UserMaybeDomain}
    end.

get_local_fqdn(Host) ->
    {ok, FQDNs} = xmpp_config:fqdn(Host),
    case FQDNs of
        [] -> [Host];
        _ -> FQDNs
    end.

-spec parse_authzid(binary() | [_]) -> {ok, binary() | [_]} | error.
parse_authzid(S) when is_binary(S) ->
    case binary:split(S, <<$@>>) of
        [User] -> {ok, User};
        [User, _Domain] -> {ok, User};
        _ -> error
    end;
parse_authzid(S) when is_list(S) ->
    case lists:splitwith(fun (A) -> A /= $@ end, S) of
        {User, []} -> {ok, User};
        {User, _ADomain} -> {ok, User};
        Error ->
            ?LOG_ERROR("parse error ~p -> ~p~n", [S, Error]),
            error
    end.
