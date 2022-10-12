defmodule Mix.Tasks.CompileRules do
  @moduledoc """
  A Mix task to compile attribute rules grammar parser
  """
  use Mix.Task

  @requirements ["compile"]

  @impl Mix.Task
  def run(_args) do
    dir = :code.priv_dir(:ockam_abac)
    file = Path.join(dir, "attribute_rules_grammar.peg")
    IO.puts("Generating parser")
    :neotoma.file(to_charlist(file), output: 'src')
    Mix.Task.rerun("compile.erlang")
  end
end
