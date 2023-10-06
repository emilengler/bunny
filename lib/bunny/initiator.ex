defmodule Bunny.Initiator do
  require Logger
  alias Bunny.Envelope.RespHello
  alias Bunny.Config.Peer
  alias Bunny.Envelope
  alias Bunny.Crypto.SKEM
  alias Bunny.Envelope.InitConf
  alias Bunny.Envelope.InitHello
  alias Bunny.Crypto.EKEM
  alias Bunny.Crypto
  use GenServer

  @moduledoc """
  The Rosenpass protocol initiator.
  """

  # TODO: Consider enforcing that a GenServer, once initialized, can only be used
  #       with one specific peer that was provided during the initialization.

  # TODO: Implement some sort of hiberation.

  @type state :: any()

  @spec init({SKEM.public_key(), SKEM.secret_key()}, SKEM.public_key(), Crypto.key()) :: state()
  defp init({spki, sski}, spkr, psk) do
    %{spki: spki, spkr: spkr, sski: sski, psk: psk}
  end

  @spec init_hello(state()) :: {state(), InitHello.t()}
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

    ih = %InitHello{sidi: sidi, epki: epki, sctr: sctr, pidiC: pidiC, auth: auth}

    state = %{ck: ck, spki: state.spki, sski: state.sski, epki: epki, eski: eski, sidi: sidi}
    {state, ih}
  end

  @spec resp_hello(state(), RespHello.t()) :: state()
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

    %{biscuit: rh.biscuit, ck: ck, sidi: state.sidi, sidr: rh.sidr}
  end

  @spec init_conf(state()) :: {state(), InitConf.t()}
  defp init_conf(state) do
    ck = state.ck

    # ICI3
    ck = ck |> Crypto.mix(state.sidi) |> Crypto.mix(state.sidr)

    # ICI4
    {ck, auth} = Crypto.encrypt_and_mix(ck, <<>>)

    # ICI7
    # TODO

    ic = %InitConf{sidi: state.sidi, sidr: state.sidr, biscuit: state.biscuit, auth: auth}

    state = %{ck: ck}
    {state, ic}
  end

  @spec final(state()) :: Crypto.key()
  defp final(state) do
    state.ck |> Crypto.hash(Crypto.export_key("rosenpass.eu") |> Crypto.hash("wireguard psk"))
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

  @impl true
  def init(_init_arg) do
    {:ok, nil}
  end

  @impl true
  def handle_cast({:handshake, {spki, sski}, peer}, _state) do
    {host, port} = peer.endpoint

    {domain, addr} =
      try do
        {:ok, addr} = :inet.getaddr(host, :inet6)
        {:inet6, addr}
      rescue
        MatchError ->
          {:ok, addr} = :inet.getaddr(host, :inet)
          {:inet, addr}
      end

    {:ok, socket} = :socket.open(domain, :dgram, :default)
    :ok = :socket.connect(socket, %{family: domain, addr: addr, port: port})

    state = init({spki, sski}, peer.spkt, peer.psk)

    {state, ih} = init_hello(state)
    :ok = send(socket, :init_hello, ih, peer.spkt)
    Logger.debug("Sent InitHello")

    rh = recv(socket, :resp_hello, spki)
    state = resp_hello(state, rh)
    Logger.debug("Received RespHello")

    {state, ic} = init_conf(state)
    :ok = send(socket, :init_conf, ic, peer.spkt)
    Logger.debug("Sent InitConf")

    _ = recv(socket, :empty_data, spki)
    Logger.debug("Received EmptyData")
    :socket.close(socket)

    osk = final(state)
    File.write!(peer.output, Base.encode64(osk))

    Logger.info("Finished handshake")

    {:noreply, nil}
  end

  @doc """
  Starts an initiator server.
  """
  @spec start() :: {:error, any()} | {:ok, pid()}
  def start() do
    GenServer.start(__MODULE__, nil)
  end

  @doc """
  Initiates an asynchronous handshake with peer.

  The resulting shared secret will be written to the appropriate file, once finished
  """
  @spec handshake(pid(), {SKEM.public_key(), SKEM.secret_key()}, Peer.t()) :: :ok
  def handshake(server, {spki, sski}, peer) do
    GenServer.cast(server, {:handshake, {spki, sski}, peer})
  end
end
