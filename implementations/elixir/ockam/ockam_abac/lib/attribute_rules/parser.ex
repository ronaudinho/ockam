defmodule Ockam.ABAC.AttributeRules.Parser do
  @moduledoc """
  Parser module for Ockam.ABAC.AttributeRules
  Converts string to rules
  """

  def parse(string) do
    case :attribute_rules_grammar.parse(string) do
      {:fail, _reason} ->
        {:error, {:cannot_parse_rule, string}}

      parsed ->
        {:ok, from_parsed(parsed)}
    end
  end

  def from_parsed(bool) when is_boolean(bool) do
    bool
  end

  ## TODO: use = < > in AttributeRules?
  def from_parsed({:=, arg1, arg2}) do
    {:eq, arg1, arg2}
  end

  def from_parsed({:!=, arg1, arg2}) do
    {:neq, arg1, arg2}
  end

  def from_parsed({:>, arg1, arg2}) do
    {:gt, arg1, arg2}
  end

  def from_parsed({:<, arg1, arg2}) do
    {:lt, arg1, arg2}
  end

  def from_parsed({:in, arg1, arg2}) do
    {:member, arg1, arg2}
  end

  def from_parsed({comb, rules}) when comb == :and or comb == :or do
    {comb, Enum.map(rules, fn rule -> from_parsed(rule) end)}
  end

  def from_parsed({:not, rule}) do
    {:not, from_parsed(rule)}
  end

  def from_parsed({:if, condition, true_rule, false_rule}) do
    {:if, from_parsed(condition), from_parsed(true_rule), from_parsed(false_rule)}
  end

  def from_parsed(other) do
    raise "Invalid rule #{inspect(other)}"
  end
end
