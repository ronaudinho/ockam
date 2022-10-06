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

  def format(rule) do
    to_s_expr(rule)
    |> SymbolicExpression.Writer.write()
  end

  def parse(string) do
    SymbolicExpression.Parser.parse(string)
    |> from_s_expr()
  end

  def to_s_expr(simple) when is_boolean(simple) do
    [simple]
  end
  def to_s_expr({op, key, val}) when is_key(key) and is_value(val) do
    [op, to_s_expr(key), val]
  end
  def to_s_expr({op, key1, key2}) when is_key(key1) and is_key(key2) do
    [op, to_s_expr(key1), to_s_expr(key2)]
  end
  def to_s_expr({:member, key, list}) when is_key(key) and is_list(list) do
    [:member, to_s_expr(key), [:list, list]]
  end
  def to_s_expr({:not, rule}) when is_boolean(rule) or is_tuple(rule) do
    [:not, to_s_expr(rule)]
  end
  def to_s_expr({op, rules}) when (op == :and or op == :or) and is_list(rules) do
    [op, [:list, Enum.map(rules, fn(rule) -> to_s_expr(rule) end)]]
  end
  def to_s_expr({type, val} = key) when is_key(key) do
    [type, val]
  end

  def from_s_expr(expr) do
    expr
  end

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
