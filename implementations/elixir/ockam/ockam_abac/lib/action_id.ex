defmodule Ockam.ABAC.ActionId do
  @moduledoc """
  Data structure serving for association between ABAC.Request and ABAC.Policy
  In order to match, both Request and Policy should have the same ActionId

  Contains :resource and :action components.
  """
  defstruct [:resource, :action]

  def new(resource, action) do
    %__MODULE__{resource: resource, action: action}
  end

  def match_action_id?(%__MODULE__{} = pattern, %__MODULE__{} = action) do
    match_resource?(pattern, action) and match_action?(pattern, action)
  end

  def match_resource?(%__MODULE__{resource: pattern}, %__MODULE__{resource: resource}) do
    String.match?(resource, Regex.compile!(pattern))
  end

  def match_action?(%__MODULE__{action: pattern}, %__MODULE__{action: action}) do
    String.match?(action, Regex.compile!(pattern))
  end
end
