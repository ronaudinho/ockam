defmodule Ockam.ABAC.AttributeRules do
  @moduledoc """
  Attribute rules matching AST for Ockam.ABAC
  """

  alias Ockam.ABAC.Request

  ## Only binaries for now
  ## TODO: support more types for lt/gt
  @type attribute_source() :: :resource | :action | :subject
  @type key() :: {source :: attribute_source(), name :: binary()}
  @type value() :: binary()

  @type rule() ::
          true
          | false
          | {:eq, key(), value()}
          | {:eq, key(), key()}
          | {:member, key(), [value()]}
          | {:member, key(), key()}
          | {:lt, key(), value()}
          | {:lt, key(), key()}
          | {:gt, key(), value()}
          | {:gt, key(), key()}
          | {:not, rule()}
          | {:and, [rule()]}
          | {:or, [rule()]}

  defguard is_key(key)
           when is_tuple(key) and tuple_size(key) == 2 and
                  (elem(key, 0) == :resource or elem(key, 0) == :action or
                     elem(key, 0) == :subject)

  ## TODO: support more value types for gt/lt
  defguard is_value(value) when is_binary(value)

  def match_rules?({:eq, k, v}, %Request{} = request) when is_key(k) and is_value(v) do
    case fetch_attribute(request, k) do
      {:ok, val} -> val == v
      :error -> false
    end
  end

  def match_rules?({:eq, k1, k2}, %Request{} = request) when is_key(k1) and is_key(k2) do
    with {:ok, val1} <- fetch_attribute(request, k1),
         {:ok, val2} <- fetch_attribute(request, k2) do
      val1 == val2
    else
      _other ->
        ## TODO: improve match failure reporting
        false
    end
  end

  def match_rules?({:member, k, list}, %Request{} = request) when is_key(k) and is_list(list) do
    case fetch_attribute(request, k) do
      {:ok, val} ->
        Enum.member?(list, val)

      :error ->
        false
    end
  end

  def match_rules?({:member, k1, k2}, %Request{} = request) when is_key(k1) and is_key(k2) do
    with {:ok, list} when is_list(list) <- fetch_attribute(request, k2),
         {:ok, val} <- fetch_attribute(request, k1) do
      Enum.member?(list, val)
    else
      _other ->
        ## TODO: improve match failure reporting
        false
    end
  end

  def match_rules?({:gt, _k, _v}, %Request{} = _request) do
    raise "gt not implemented"
  end

  def match_rules?({:lt, _k, _v}, %Request{} = _request) do
    raise "gt not implemented"
  end

  def match_rules?({:not, rules}, %Request{} = request) do
    not match_rules?(rules, request)
  end

  def match_rules?({:and, rules_list}, %Request{} = request) do
    Enum.all?(rules_list, fn rules -> match_rules?(rules, request) end)
  end

  def match_rules?({:or, rules_list}, %Request{} = request) do
    Enum.any?(rules_list, fn rules -> match_rules?(rules, request) end)
  end

  def match_rules?(true, _request) do
    true
  end

  def match_rules?(false, _request) do
    false
  end

  def fetch_attribute(%Request{} = request, {type, name}) do
    request
    |> Map.get(atrtibute_field(type), %{})
    |> Map.fetch(name)
  end

  def atrtibute_field(:resource), do: :resource_attributes
  def atrtibute_field(:action), do: :action_attributes
  def atrtibute_field(:subject), do: :subject_attributes
end
