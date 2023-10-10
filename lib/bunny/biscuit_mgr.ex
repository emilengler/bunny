defmodule Bunny.BiscuitMgr do
  alias Bunny.Crypto
  use GenServer

  @moduledoc """
  Encrypts and decrypts biscuits by managing the biscuit keys.
  """

  @type state :: %{ctr: non_neg_integer(), keys: list(Crypto.key()), time: DateTime.t()}

  @spec refresh_keys(state()) :: state()
  defp refresh_keys(state) do
    # Generate a new key every two minutes, keep the old one, delete the old old.
    if DateTime.diff(DateTime.utc_now(), state.time) > 120 do
      keys = [Crypto.random_biscuit_key()] ++ state.keys
      keys = Enum.slice(keys, 0..1)
      state |> Map.put(:keys, keys) |> Map.put(:time, DateTime.utc_now())
    else
      state
    end
  end

  @impl true
  def init(_init_arg) do
    {:ok, %{ctr: 0, keys: [Crypto.random_biscuit_key()], time: DateTime.utc_now()}}
  end

  @doc """
  Starts the biscuit manager server.
  """
  @spec start() :: {:error, any()} | {:ok, pid()}
  def start() do
    GenServer.start(__MODULE__, nil)
  end
end
