defmodule Bunny.Protocol.Initiator do
  @moduledoc """
  The Rosenpass protocol initiator.
  """
  require Logger
  alias Bunny.Crypto.SKEM
  alias Bunny.Envelope
  alias Bunny.Crypto.EKEM
  alias Bunny.Crypto

  @type keys :: %{osk: Crypto.key(), txki: Crypto.key(), txkr: Crypto.key()}
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
    ck = Crypto.lhash("chaining key init") |> Crypto.hash(state.spkr)

    # IHI2
    sidi = Crypto.random_session_id()

    # IHI3
    {epki, eski} = EKEM.gen_key()

    # IHI4
    ck = ck |> Crypto.mix(sidi) |> Crypto.mix(epki)

    # IHI5
    {ck, sctr} = Crypto.encaps_and_mix(:skem, ck, state.spkr)

    # IHI6
    pidi = Crypto.hash(Crypto.lhash("peer id"), state.spki)
    {ck, pidiC} = Crypto.encrypt_and_mix(ck, pidi)

    # IHI7
    ck = ck |> Crypto.mix(state.spki) |> Crypto.mix(state.psk)

    # IHI8
    {ck, auth} = Crypto.encrypt_and_mix(ck, <<>>)

    payload = %Envelope.InitHello{
      sidi: sidi,
      epki: epki,
      sctr: sctr,
      pidiC: pidiC,
      auth: auth
    }

    Logger.info("Generated InitHello")

    state =
      state
      |> Map.put(:ck, ck)
      |> Map.put(:epki, epki)
      |> Map.put(:eski, eski)
      |> Map.put(:sidi, sidi)

    {state, payload}
  end

  @spec resp_hello(state(), Envelope.RespHello.t()) :: state()
  def resp_hello(state, rh) do
    ck = state.ck

    # RHI3
    ck = ck |> Crypto.mix(rh.sidr) |> Crypto.mix(state.sidi)

    # RHI4
    ck = Crypto.decaps_and_mix(:ekem, ck, state.eski, state.epki, rh.ecti)

    # RHI5
    ck = Crypto.decaps_and_mix(:skem, ck, state.sski, state.spki, rh.scti)

    # RHI6
    ck = ck |> Crypto.mix(rh.biscuit)

    # RHI7
    {ck, _} = Crypto.decrypt_and_mix(ck, rh.auth)

    Logger.info("Handled RespHello")

    state |> Map.put(:ck, ck) |> Map.put(:biscuit, rh.biscuit) |> Map.put(:sidr, rh.sidr)
  end

  @spec init_conf(state()) :: {state(), Envelope.InitConf.t()}
  def init_conf(state) do
    ck = state.ck

    # ICI3
    ck = ck |> Crypto.mix(state.sidi) |> Crypto.mix(state.sidr)

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

    Logger.info("Generated InitConf")

    state = %{ck: ck}

    {state, payload}
  end

  @spec final(state()) :: keys()
  def final(state) do
    osk =
      state.ck |> Crypto.hash(Crypto.export_key("rosenpass.eu") |> Crypto.hash("wireguard psk"))

    txki = state.ck |> Crypto.hash(Crypto.extract_key("initiator payload encryption"))
    txkr = state.ck |> Crypto.hash(Crypto.extract_key("responder payload encryption"))

    %{osk: osk, txki: txki, txkr: txkr}
  end
end
