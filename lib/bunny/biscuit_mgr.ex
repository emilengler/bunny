defmodule Bunny.BiscuitMgr do
  alias Bunny.Crypto.SKEM
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

  @impl true
  def handle_call({:store_biscuit, ck, spki, spkr, sidi, sidr}, _from, state) do
    state = refresh_keys(state)

    {ck, ctr, nct} = Crypto.store_biscuit(ck, state.ctr, hd(state.keys), spki, spkr, sidi, sidr)

    state = state |> Map.put(:ctr, ctr)
    {:reply, {:ok, ck, nct}, state}
  end

  @doc """
  Starts the biscuit manager server.
  """
  @spec start() :: {:error, any()} | {:ok, pid()}
  def start() do
    GenServer.start(__MODULE__, nil)
  end

  @doc """
  Encrypts a biscuit, returning the updated chaining key with the ciphertext.
  """
  @spec store_biscuit(
          pid(),
          Crypto.chaining_key(),
          SKEM.public_key(),
          SKEM.public_key(),
          Crypto.session_id(),
          Crypto.session_id()
        ) :: {:ok, Crypto.chaining_key(), Crypto.biscuit_ct()}
  def store_biscuit(server, ck, spki, spkr, sidi, sidr) do
    GenServer.call(server, {:store_biscuit, ck, spki, spkr, sidi, sidr})
  end
end
