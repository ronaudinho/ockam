defmodule Ockam.ABAC.AttributeRules do
  @moduledoc """
  Attribute rules matching AST for Ockam.ABAC
  """

  alias Ockam.ABAC.AttributeRules.Formatter
  alias Ockam.ABAC.AttributeRules.Parser

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
          | {:if, rule(), rule(), rule()}

  defstruct [:rule]

  defguard is_key(key)
           when is_tuple(key) and tuple_size(key) == 2 and
                  (elem(key, 0) == :resource or elem(key, 0) == :action or
                     elem(key, 0) == :subject)

  ## TODO: support more value types for gt/lt
  defguard is_value(value) when is_binary(value) or is_boolean(value) or is_number(value)

  defguard is_filter(filter)
           when filter == :eq or filter == :lt or filter == :gt or filter == :neq

  def parse(string) do
    case Parser.parse(string) do
      {:ok, rule} -> new(rule)
      {:error, reason} -> {:error, reason}
    end
  end

  def format(%__MODULE__{rule: rule}) do
    Formatter.format(rule)
  end

  def new(rules_def) do
    case validate(rules_def) do
      :ok ->
        {:ok, %__MODULE__{rule: rules_def}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def match_rules?(%__MODULE__{rule: rule}, %Request{} = request) do
    do_match_rules?(rule, request)
  end

  defp do_match_rules?({op, key, value}, request)
       when is_filter(op) and is_key(key) and is_value(value) do
    case fetch_attribute(request, key) do
      {:ok, attribute_value} -> compare(op, attribute_value, value)
      :error -> false
    end
  end

  defp do_match_rules?({op, key1, key2}, request)
       when is_filter(op) and is_key(key1) and is_key(key2) do
    with {:ok, val1} <- fetch_attribute(request, key1),
         {:ok, val2} <- fetch_attribute(request, key2) do
      compare(op, val1, val2)
    else
      _other ->
        ## TODO: improve match failure reporting
        false
    end
  end

  defp do_match_rules?({:member, element, list}, request) do
    with {:ok, element} <- member_element(element, request),
         {:ok, list} <- member_list(list, request) do
      Enum.member?(list, element)
    else
      _other ->
        ## TODO: improve match failure reporting
        false
    end
  end

  defp do_match_rules?({:not, rules}, request) do
    not do_match_rules?(rules, request)
  end

  defp do_match_rules?({:and, rules_list}, request) do
    Enum.all?(rules_list, fn rules -> do_match_rules?(rules, request) end)
  end

  defp do_match_rules?({:or, rules_list}, request) do
    Enum.any?(rules_list, fn rules -> do_match_rules?(rules, request) end)
  end

  defp do_match_rules?({:if, condition, true_rule, false_rule}, request) do
    case do_match_rules?(condition, request) do
      true ->
        do_match_rules?(true_rule, request)

      false ->
        do_match_rules?(false_rule, request)
    end
  end

  defp do_match_rules?(true, _request) do
    true
  end

  defp do_match_rules?(false, _request) do
    false
  end

  defp do_match_rules?(_rule, _request) do
    false
  end

  defp compare(:eq, val1, val2), do: val1 == val2
  defp compare(:neq, val1, val2), do: val1 == val2
  defp compare(:gt, val1, val2), do: val1 > val2
  defp compare(:lt, val1, val2), do: val1 < val2

  defp member_element(key, request) when is_key(key) do
    fetch_attribute(request, key)
  end

  defp member_element(value, _request) when is_value(value) do
    {:ok, value}
  end

  defp member_list(key, request) when is_key(key) do
    case fetch_attribute(request, key) do
      {:ok, list} when is_list(list) -> {:ok, list}
      _other -> :error
    end
  end

  defp member_list(list, _request) when is_list(list) do
    {:ok, list}
  end

  def fetch_attribute(%Request{} = request, {type, name}) do
    request
    |> Map.get(atrtibute_field(type), %{})
    |> Map.fetch(name)
  end

  defp atrtibute_field(:resource), do: :resource_attributes
  defp atrtibute_field(:action), do: :action_attributes
  defp atrtibute_field(:subject), do: :subject_attributes

  defp validate(bool) when is_boolean(bool) do
    :ok
  end

  defp validate({filter, key, key_or_value})
       when is_filter(filter) and is_key(key) and (is_key(key_or_value) or is_value(key_or_value)) do
    :ok
  end

  defp validate({:member, key_or_value, key})
       when is_key(key) and (is_key(key_or_value) or is_value(key_or_value)) do
    :ok
  end

  defp validate({:member, key_or_value, list} = rule)
       when is_list(list) and (is_key(key_or_value) or is_value(key_or_value)) do
    valid_elements = Enum.all?(list, fn el -> is_value(el) end)

    case valid_elements do
      true ->
        :ok

      false ->
        {:error, {:invalid_list_elements, rule}}
    end
  end

  defp validate({comb, [_rule1, _rule2 | _other] = rules}) when comb == :and or comb == :or do
    errors =
      rules
      |> Enum.map(fn rule -> validate(rule) end)
      |> Enum.filter(fn
        :ok -> false
        _error -> true
      end)

    case errors do
      [] -> :ok
      errors -> {:error, {:internal_rules_invalid, errors}}
    end
  end

  defp validate({:not, rule}) do
    validate(rule)
  end

  defp validate({:if, condition, true_rule, false_rule}) do
    errors =
      [condition, true_rule, false_rule]
      |> Enum.map(fn rule -> validate(rule) end)
      |> Enum.filter(fn
        :ok -> false
        _error -> true
      end)

    case errors do
      [] -> :ok
      errors -> {:error, {:internal_rules_invalid, errors}}
    end
  end

  defp validate(invalid) do
    {:error, {:invalid_rule, invalid}}
  end
end
