defmodule Ockam.ABAC.Policy do
  @moduledoc """
  Policy data structore for Ockam ABAC
  """

  alias Ockam.ABAC.ActionId
  alias Ockam.ABAC.AttributeRules
  alias Ockam.ABAC.Request

  @keys [:action_id, :attribute_rules]
  @enforce_keys @keys
  defstruct @keys

  @type t() :: %__MODULE__{
          action_id: ActionId.t(),
          attribute_rules: AttributeRules.t()
        }

  def match_policy?(%__MODULE__{} = policy, %Request{} = request) do
    case ActionId.match_action_id?(policy.action_id, request.action_id) do
      true ->
        AttributeRules.match_rules?(policy.attribute_rules, request)

      false ->
        false
    end
  end

  def from_rules_string(rules_str, action_id) do
    with {:ok, attribute_rules} <- AttributeRules.parse(rules_str) do
      {:ok, %__MODULE__{action_id: action_id, attribute_rules: attribute_rules}}
    end
  end

  def to_rules_string(%__MODULE__{attribute_rules: attribute_rules}) do
    AttributeRules.format(attribute_rules)
  end
end
