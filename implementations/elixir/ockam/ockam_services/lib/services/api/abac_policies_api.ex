defmodule Ockam.Services.API.ABAC.PoliciesApi do
  ## TODO: move to ockam_abac after moving Ockam.Services.API to ockam
  use Ockam.Services.API

  alias Ockam.API.Request

  alias Ockam.ABAC.PolicyStorage
  alias Ockam.ABAC.Policy

  @impl true
  def setup(_options, state) do
    {:ok, state}
  end

  @impl true
  def handle_request(%Request{method: :get, path: ""}, state) do
    ## TODO: different access permissions for policies
    with {:ok, policies} <- PolicyStorage.list() do
      ## FIXME: figure out if to encode rules or action_id + rules
      response = Policy.encode_list(policies)
      {:reply, :ok, response, state}
    end
  end

  def handle_request(%Request{method: :get, path: path}, state) do
    with_action_path(path, fn(action_id) ->
      with {:ok, policy} <- PolicyStorage.get_policy(action_id) do
        ## FIXME: figure out if to encode rules or action_id + rules
        response = Policy.encode(policy)
        {:reply, :ok, response, state}
      end
    end)
  end

  def handle_request(%Request{method: :put, path: path, body: data}, state) do
    with_action_path(path, fn(action_id) ->
      case Policy.decode(data, action_id) do
        {:ok, policy} ->
          with :ok <- PolicyStorage.put_policy(policy) do
            response = Policy.encode(policy)
            {:reply, :ok, response, state}
          end
        {:error, _decode_error} ->
          {:error, {:bad_request, :cannot_decode_policy}}
      end
    end)
  end

  def handle_request(%Request{method: :delete, path: path}, state) do
    with_action_path(path, fn(action_id) ->
      with :ok <- PolicyStorage.delete_policy(action_id) do
        {:reply, :ok, nil, state}
      end
    end)
  end

  def with_action_path(path, fun) do
    case parse_path_action_id(path) do
      {:ok, action_id} ->
        fun.(action_id)
      {:error, :invalid_path} ->
        {:error, {:bad_request, :invalid_path}}
    end
  end
end
