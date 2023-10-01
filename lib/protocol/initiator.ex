defmodule Bunny.Protocol.Initiator do
  @moduledoc """
  The Rosenpass protocol initiator.
  """
  require Logger
  alias Bunny.Crypto.SKEM
  alias Bunny.Envelope
  alias Bunny.Crypto.EKEM
  alias Bunny.Crypto

  @type psk :: <<_::256>>
  @type state :: any()

  @doc """
  Initializes the state with all keys.
  """
  @spec init({SKEM.public_key(), SKEM.secret_key()}, SKEM.public_key(), psk()) :: state()
  def init({spki, sski}, spkr, psk) do
    %{
      spki: spki,
      spkr: spkr,
      sski: sski,
      psk: psk
    }
  end

  @doc """
  Performs the `InitHello` by updating the state and returning the appropriate envelope.

  TODO: Only return the payload, that is, Envelope.InitHello.t()
  """
  @spec init_hello(state()) :: {state(), Envelope.t()}
  def init_hello(state) do
    # IHI1
    ck = Crypto.hash(Crypto.lhash("chaining key init"), state.spkr)
    # IHI2
    sidi = Crypto.random_session_id()
    # IHI3
    {epki, eski} = EKEM.gen_key()
    # IHI4
    ck = Crypto.mix(ck, sidi)
    ck = Crypto.mix(ck, epki)
    # IHI5
    {ck, sctr} = Crypto.encaps_and_mix(:skem, ck, state.spkr)
    # IHI6
    pidi = Crypto.hash(Crypto.lhash("peer id"), state.spki)
    {ck, pidiC} = Crypto.encrypt_and_mix(ck, pidi)
    # IHI7
    ck = Crypto.mix(ck, state.spki)
    ck = Crypto.mix(ck, state.psk)
    # IHI8
    {ck, auth} = Crypto.encrypt_and_mix(ck, <<>>)

    envelope = %Envelope{
      type: :init_hello,
      payload: %Envelope.InitHello{
        sidi: sidi,
        epki: epki,
        sctr: sctr,
        pidiC: pidiC,
        auth: auth
      },
      mac: <<0::128>>,
      cookie: <<0::128>>
    }

    Logger.debug("Generated InitHello #{inspect(envelope)}")
    envelope = Envelope.seal(state.spkr, envelope)
    Logger.debug("Sealed InitHello with MAC #{inspect(envelope.mac)}")

    Logger.info("Generated InitHello")

    state = Map.put(state, :ck, ck)
    state = Map.put(state, :epki, epki)
    state = Map.put(state, :eski, eski)
    state = Map.put(state, :sidi, sidi)

    {state, envelope}
  end
end
