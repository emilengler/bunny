defmodule Bunny.Initiator do
  require Logger
  alias Bunny.Crypto.SKEM
  alias Bunny.Envelope
  alias Bunny.Crypto.EKEM
  alias Bunny.Crypto

  @moduledoc """
  The Rosenpass protocol initiator.
  """

  @type keys :: %{osk: Crypto.key(), txki: Crypto.key(), txkr: Crypto.key()}
  @type psk :: Crypto.key()
  @type state :: any()

  @spec init({SKEM.public_key(), SKEM.secret_key()}, SKEM.public_key(), psk()) :: state()
  defp init({spki, sski}, spkr, psk) do
    %{
      spki: spki,
      spkr: spkr,
      sski: sski,
      psk: psk
    }
  end

  @spec init_hello(state()) :: {state(), Envelope.InitHello.t()}
  defp init_hello(state) do
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
  defp resp_hello(state, rh) do
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
  defp init_conf(state) do
    ck = state.ck

    # ICI3
    ck = ck |> Crypto.mix(state.sidi) |> Crypto.mix(state.sidr)

    # ICI4
    {ck, auth} = Crypto.encrypt_and_mix(ck, <<>>)

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
  defp final(state) do
    osk =
      state.ck |> Crypto.hash(Crypto.export_key("rosenpass.eu") |> Crypto.hash("wireguard psk"))

    txki = state.ck |> Crypto.hash(Crypto.extract_key("initiator payload encryption"))
    txkr = state.ck |> Crypto.hash(Crypto.extract_key("responder payload encryption"))

    %{osk: osk, txki: txki, txkr: txkr}
  end

  @spec recv(:socket.socket(), Envelope.type(), SKEM.public_key()) :: Envelope.payload()
  defp recv(socket, type, spkm) do
    {:ok, data} = :socket.recv(socket, [], 8000)
    envelope = Envelope.decode(data)
    ^type = envelope.type
    true = Envelope.verify(envelope, spkm)
    envelope.payload
  end

  @spec send(:socket.socket(), Envelope.type(), Envelope.payload(), SKEM.public_key()) :: :ok
  defp send(socket, type, payload, spkt) do
    envelope = %Envelope{type: type, payload: payload, mac: <<0::128>>, cookie: <<0::128>>}
    envelope = Envelope.seal(envelope, spkt)
    :ok = :socket.send(socket, Envelope.encode(envelope))
    :ok
  end

  @doc """
  Initiates a Rosenpass handshake on an existing UDP `socket`.
  """
  @spec initiate(
          :socket.socket(),
          {SKEM.public_key(), SKEM.secret_key()},
          SKEM.public_key(),
          psk()
        ) :: keys()
  def initiate(socket, {spki, sski}, spkr, psk) do
    state = init({spki, sski}, spkr, psk)

    {state, payload} = init_hello(state)
    :ok = send(socket, :init_hello, payload, spkr)
    Logger.debug("Sent InitHello")

    payload = recv(socket, :resp_hello, spki)
    state = resp_hello(state, payload)
    Logger.debug("Received RespHello")

    {state, payload} = init_conf(state)
    :ok = send(socket, :init_conf, payload, spkr)
    Logger.debug("Sent InitConf")

    _ = recv(socket, :empty_data, spki)
    Logger.debug("Received EmptyData")

    Logger.notice("Finished handshake")

    final(state)
  end
end