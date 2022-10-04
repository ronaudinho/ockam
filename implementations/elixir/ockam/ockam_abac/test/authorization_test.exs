defmodule Ockam.ABAC.Authorization.Tests do
  use ExUnit.Case

  alias Ockam.ABAC.ActionId
  alias Ockam.ABAC.Policy
  alias Ockam.ABAC.Authorization

  alias Ockam.Message

  alias Ockam.Tests.Helpers.Echoer

  describe "ABAC Authorization" do
    test "to/from as action attributes" do
      {:ok, me1} = Ockam.Node.register_random_address()
      {:ok, me2} = Ockam.Node.register_random_address()

      policy = %Policy{
        action_id: ActionId.new("echoer1", "handle_message"),
        attribute_rules:
          {:or,
           [
             ## Rule to accept messages on address echoer1 from address me1
             {:and,
              [
                {:eq, {:action, "to"}, "echoer1"},
                {:eq, {:action, "from"}, me1}
              ]},

             ## Rule to accept messages on address echoer2 from address me2

             {:and,
              [
                {:eq, {:action, "to"}, "echoer2"},
                {:eq, {:action, "from"}, me2}
              ]}
           ]}
      }

      ## Set up echoer with both policies
      {:ok, _echoer} =
        Echoer.create(
          address: "echoer1",
          extra_addresses: ["echoer2"],
          authorization: [
            {Authorization, :with_policy_check, [:message, :state, [policy]]}
          ]
        )

      on_exit(fn ->
        Ockam.Node.stop("echoer1")
      end)

      Ockam.Router.route("HI1", ["echoer1"], [me1])
      assert_receive %Message{onward_route: [^me1], payload: "HI1"}

      Ockam.Router.route("HI2", ["echoer2"], [me2])
      assert_receive %Message{onward_route: [^me2], payload: "HI2"}

      Ockam.Router.route("HI3", ["echoer1"], [me2])
      refute_receive %Message{onward_route: [^me2], payload: "HI3"}

      Ockam.Router.route("HI4", ["echoer2"], [me1])
      refute_receive %Message{onward_route: [^me1], payload: "HI4"}
    end

    test "worker attributes as resource and local metadata as action attributes" do
      policy = %Policy{
        action_id: ActionId.new("echoer", "handle_message"),
        attribute_rules: {:member, {:action, "domain"}, {:resource, "domains"}}
      }

      {:ok, echoer} =
        Echoer.create(
          address: "echoer",
          attributes: %{domains: ["foo", "bar"]},
          authorization: [
            {Authorization, :with_policy_check, [:message, :state, [policy]]}
          ]
        )

      on_exit(fn ->
        Ockam.Node.stop("echoer")
      end)

      {:ok, me} = Ockam.Node.register_random_address()

      Ockam.Router.route("HI1", [echoer], [me], %{domain: "foo"})
      assert_receive %Message{onward_route: [^me], payload: "HI1"}

      Ockam.Router.route("HI2", [echoer], [me], %{domain: "bar"})
      assert_receive %Message{onward_route: [^me], payload: "HI2"}

      Ockam.Router.route("HI3", [echoer], [me], %{domain: "baz"})
      refute_receive %Message{onward_route: [^me], payload: "HI3"}
    end

    test "identity_id is a subject attribute" do
      policy = %Policy{
        action_id: ActionId.new("echoer", "handle_message"),
        attribute_rules: {:eq, {:subject, "identity_id"}, "foo"}
      }

      {:ok, echoer} =
        Echoer.create(
          address: "echoer",
          authorization: [
            {Authorization, :with_policy_check, [:message, :state, [policy]]}
          ]
        )

      on_exit(fn ->
        Ockam.Node.stop("echoer")
      end)

      {:ok, me} = Ockam.Node.register_random_address()

      Ockam.Router.route("HI1", [echoer], [me], %{identity_id: "foo"})
      assert_receive %Message{onward_route: [^me], payload: "HI1"}

      Ockam.Router.route("HI2", [echoer], [me], %{identity_id: "bar"})
      refute_receive %Message{onward_route: [^me], payload: "HI2"}
    end
  end
end
