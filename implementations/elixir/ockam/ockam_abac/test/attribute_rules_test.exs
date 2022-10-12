defmodule Ockam.ABAC.AttributeRules.Tests do
  use ExUnit.Case

  alias Ockam.ABAC.ActionId
  alias Ockam.ABAC.AttributeRules
  alias Ockam.ABAC.Request

  describe "single attribute rules" do
    test "eq rule" do
      request_matching = %Request{
        action_id: ActionId.new("", ""),
        resource_attributes: %{},
        subject_attributes: %{"foo" => "bar"},
        action_attributes: %{}
      }

      request_not_matching = %Request{
        action_id: ActionId.new("", ""),
        resource_attributes: %{},
        subject_attributes: %{"foo" => "baz"},
        action_attributes: %{}
      }

      {:ok, rule} = AttributeRules.new({:eq, {:subject, "foo"}, "bar"})
      assert AttributeRules.match_rules?(rule, request_matching)
      refute AttributeRules.match_rules?(rule, request_not_matching)
    end

    @tag :skip
    test "gt rule" do
      ## TODO: implement gt
    end

    @tag :skip
    test "lt rule" do
      ## TODO: implement lt
    end

    test "member rule" do
      request_matching1 = %Request{
        action_id: ActionId.new("", ""),
        resource_attributes: %{},
        subject_attributes: %{"foo" => "bar"},
        action_attributes: %{}
      }

      request_matching2 = %Request{
        action_id: ActionId.new("", ""),
        resource_attributes: %{},
        subject_attributes: %{"foo" => "baf"},
        action_attributes: %{}
      }

      request_not_matching = %Request{
        action_id: ActionId.new("", ""),
        resource_attributes: %{},
        subject_attributes: %{"foo" => "baz"},
        action_attributes: %{}
      }

      {:ok, rule} = AttributeRules.new({:member, {:subject, "foo"}, ["bar", "baf"]})
      assert AttributeRules.match_rules?(rule, request_matching1)
      assert AttributeRules.match_rules?(rule, request_matching2)
      refute AttributeRules.match_rules?(rule, request_not_matching)
    end
  end

  describe "multi attribute rules" do
    test "eq rule" do
      request_matching = %Request{
        action_id: ActionId.new("", ""),
        resource_attributes: %{},
        subject_attributes: %{"foo1" => "bar"},
        action_attributes: %{"foo2" => "bar"}
      }

      request_not_matching = %Request{
        action_id: ActionId.new("", ""),
        resource_attributes: %{},
        subject_attributes: %{"foo1" => "bar"},
        action_attributes: %{"foo2" => "not_bar"}
      }

      {:ok, rule} = AttributeRules.new({:eq, {:subject, "foo1"}, {:action, "foo2"}})
      assert AttributeRules.match_rules?(rule, request_matching)
      refute AttributeRules.match_rules?(rule, request_not_matching)
    end

    @tag :skip
    test "gt rule" do
      ## TODO: implement gt
    end

    @tag :skip
    test "lt rule" do
      ## TODO: implement lt
    end

    test "member rule" do
      request_matching1 = %Request{
        action_id: ActionId.new("", ""),
        resource_attributes: %{},
        subject_attributes: %{"foo" => "bar"},
        action_attributes: %{"foo_list" => ["bar", "baf"]}
      }

      request_matching2 = %Request{
        action_id: ActionId.new("", ""),
        resource_attributes: %{},
        subject_attributes: %{"foo" => "baf"},
        action_attributes: %{"foo_list" => ["bar", "baf"]}
      }

      request_not_matching = %Request{
        action_id: ActionId.new("", ""),
        resource_attributes: %{},
        subject_attributes: %{"foo" => "baz"},
        action_attributes: %{}
      }

      {:ok, rule} = AttributeRules.new({:member, {:subject, "foo"}, {:action, "foo_list"}})

      assert AttributeRules.match_rules?(rule, request_matching1)
      assert AttributeRules.match_rules?(rule, request_matching2)
      refute AttributeRules.match_rules?(rule, request_not_matching)
    end
  end

  describe "logic rules" do
    test "simple rules" do
      empty_request = %Request{
        action_id: ActionId.new("", ""),
        subject_attributes: %{},
        action_attributes: %{},
        resource_attributes: %{}
      }

      {:ok, true_rule} = AttributeRules.new(true)
      assert AttributeRules.match_rules?(true_rule, empty_request)

      {:ok, false_rule} = AttributeRules.new(false)
      refute AttributeRules.match_rules?(false_rule, empty_request)

      {:ok, and_rule} = AttributeRules.new({:and, [true, false]})
      refute AttributeRules.match_rules?(and_rule, empty_request)

      {:ok, or_rule} = AttributeRules.new({:or, [true, false]})
      assert AttributeRules.match_rules?(or_rule, empty_request)

      {:ok, not_rule} = AttributeRules.new({:not, false})
      assert AttributeRules.match_rules?(not_rule, empty_request)
    end

    test "combination rules" do
      request_matching = %Request{
        action_id: ActionId.new("", ""),
        subject_attributes: %{"name" => "Ivan"},
        action_attributes: %{"method" => "get"},
        resource_attributes: %{"people" => ["Ivan", "Marya"]}
      }

      request_not_matching1 = %Request{
        action_id: ActionId.new("", ""),
        subject_attributes: %{"name" => "Ivan"},
        action_attributes: %{"method" => "post"},
        resource_attributes: %{"people" => ["Ivan", "Marya"]}
      }

      request_not_matching2 = %Request{
        action_id: ActionId.new("", ""),
        subject_attributes: %{"name" => "Sergey"},
        action_attributes: %{"method" => "get"},
        resource_attributes: %{"people" => ["Ivan", "Marya"]}
      }

      {:ok, rule} =
        AttributeRules.new(
          {:and,
           [
             {:eq, {:action, "method"}, "get"},
             {:member, {:subject, "name"}, {:resource, "people"}}
           ]}
        )

      assert AttributeRules.match_rules?(rule, request_matching)
      refute AttributeRules.match_rules?(rule, request_not_matching1)
      refute AttributeRules.match_rules?(rule, request_not_matching2)
    end
  end
end
