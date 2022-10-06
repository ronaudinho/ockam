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

  @schema {:struct, __MODULE__, %{
    action_id: %{key: 1, required: true, schema: ActionId.minicbor_schema()},
    attribute_rules: %{key: 2, required: true, schema: :string}
  }}

  def encode(%__MODULE__{} = policy) do
    policy_data = prepare_policy_data(policy)
    Ockam.TypedCBOR.encode!(@schema, policy_data)
  end

  def encode_list(policies) do
    policies_data = Enum.map(policies, fn(policy) -> prepare_policy_data(policy) end)
    Ockam.TypedCBOR.encode!({:list, @schema}, policies_data)
  end

  def prepare_policy_data(%__MODULE__{attribute_rules: attribute_rules} = policy) do
    attribute_rules_string = AttributeRules.format(attribute_rules)
    Map.put(policy, :attribute_rules, attribute_rules_string)
  end

  def decode(data) do
    with {:ok, policy_data} <- Ockam.TypedCBOR.decode_strict(@schema, data),
         {:ok, attribute_rules} <- AttributeRules.parse(Map.get(policy_data, :attribute_rules)) do
      {:ok, Map.put(policy_data, :attribute_rules, attribute_rules)}
    end
  end

  def decode_list(data) do
    with {:ok, policies_data} <- Ockam.TypedCBOR.decode_strict({:list, @schema}, data) do
      parse_results = Enum.map(policies_data, fn(policy_data) ->
        with {:ok, attribute_rules} <- AttributeRules.parse(Map.get(policy_data, :attribute_rules)) do
          {:ok, Map.put(policy_data, :attribute_rules, attribute_rules)}
        end
      end)

      Enum.reduce(parse_results, {:ok, []},
        fn({:ok, policy}, {:ok, policies}) ->
            {:ok, policies ++ [policy]}
          ({:error, reason}, _) ->
            {:error, reason}
          (_result, {:error, reason}) ->
            {:error, reason}
        end)
    end
  end
end
