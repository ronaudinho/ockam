defmodule Ockam.ABAC.AttributeRules.Tests do
  use ExUnit.Case

  alias Ockam.ABAC.AttributeRules
  alias Ockam.ABAC.ActionId
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

      rule = {:eq, {:subject, "foo"}, "bar"}
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

      rule = {:member, {:subject, "foo"}, ["bar", "baf"]}
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

      rule = {:eq, {:subject, "foo1"}, {:action, "foo2"}}
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

      rule = {:member, {:subject, "foo"}, {:action, "foo_list"}}

      assert AttributeRules.match_rules?(rule, request_matching1)
      assert AttributeRules.match_rules?(rule, request_matching2)
      refute AttributeRules.match_rules?(rule, request_not_matching)
    end
  end

  describe "logic rules" do
    test "simple rules" do
      ## true and false are valid rules
      true_rule = true
      false_rule = false

      empty_request = %Request{
        action_id: ActionId.new("", ""),
        subject_attributes: %{},
        action_attributes: %{},
        resource_attributes: %{}
      }

      assert AttributeRules.match_rules?(true_rule, empty_request)
      refute AttributeRules.match_rules?(false_rule, empty_request)

      and_rule = {:and, [true_rule, false_rule]}
      refute AttributeRules.match_rules?(and_rule, empty_request)

      or_rule = {:or, [true_rule, false_rule]}
      assert AttributeRules.match_rules?(or_rule, empty_request)

      not_rule = {:not, false_rule}
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

      rule =
        {:and,
         [
           {:eq, {:action, "method"}, "get"},
           {:member, {:subject, "name"}, {:resource, "people"}}
         ]}

      assert AttributeRules.match_rules?(rule, request_matching)
      refute AttributeRules.match_rules?(rule, request_not_matching1)
      refute AttributeRules.match_rules?(rule, request_not_matching2)
    end
  end
end
