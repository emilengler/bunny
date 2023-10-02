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
  Performs the `InitHello` by updating the state and returning the appropriate payload.
  """
  @spec init_hello(state()) :: {state(), Envelope.InitHello.t()}
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

    envelope = %Envelope.InitHello{
      sidi: sidi,
      epki: epki,
      sctr: sctr,
      pidiC: pidiC,
      auth: auth
    }

    Logger.info("Generated InitHello")

    state = Map.put(state, :ck, ck)
    state = Map.put(state, :epki, epki)
    state = Map.put(state, :eski, eski)
    state = Map.put(state, :sidi, sidi)

    {state, envelope}
  end

  @spec resp_hello(state(), Envelope.RespHello.t()) :: state()
  def resp_hello(state, rh) do
    ck = state.ck

    # RHI3
    ck = Crypto.mix(ck, rh.sidr)
    ck = Crypto.mix(ck, state.sidi)

    # RHI4
    ck = Crypto.decaps_and_mix(:ekem, ck, state.eski, state.epki, rh.ecti)

    # RHI5
    ck = Crypto.decaps_and_mix(:skem, ck, state.sski, state.spki, rh.scti)

    # RHI6
    ck = Crypto.mix(ck, rh.biscuit)

    # RHI7
    {ck, _} = Crypto.decrypt_and_mix(ck, rh.auth)

    Logger.info("Handled RespHello")

    state = Map.put(state, :ck, ck)
    state = Map.put(state, :biscuit, rh.biscuit)
    state = Map.put(state, :sidr, rh.sidr)

    state
  end

  @spec init_conf(state()) :: {state(), Envelope.InitConf.t()}
  def init_conf(state) do
    ck = state.ck

    # ICI3
    ck = Crypto.mix(ck, state.sidi)
    ck = Crypto.mix(ck, state.sidr)

    # ICI4
    {ck, auth} = Crypto.encrypt_and_mix(ck, <<>>)
    IO.inspect(ck)

    # ICI7
    # TODO

    payload = %Envelope.InitConf{
      sidi: state.sidi,
      sidr: state.sidr,
      biscuit: state.biscuit,
      auth: auth
    }

    state = %{ck: ck}

    {state, payload}
  end
end
