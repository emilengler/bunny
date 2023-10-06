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

  @type hs_state :: any()

  @spec init(SKEM.public_key(), SKEM.secret_key(), SKEM.public_key(), Crypto.key()) :: hs_state()
  defp init(spki, sski, spkr, psk) do
    %{spki: spki, spkr: spkr, sski: sski, psk: psk}
  end

  @spec init_hello(hs_state()) :: {hs_state(), InitHello.t()}
  defp init_hello(hs_state) do
    # IHI1
    ck = Crypto.lhash("chaining key init") |> Crypto.hash(hs_state.spkr)

    # IHI2
    sidi = Crypto.random_session_id()

    # IHI3
    {epki, eski} = EKEM.gen_key()

    # IHI4
    ck = ck |> Crypto.mix(sidi) |> Crypto.mix(epki)

    # IHI5
    {ck, sctr} = Crypto.encaps_and_mix(:skem, ck, hs_state.spkr)

    # IHI6
    pidi = Crypto.hash(Crypto.lhash("peer id"), hs_state.spki)
    {ck, pidiC} = Crypto.encrypt_and_mix(ck, pidi)

    # IHI7
    ck = ck |> Crypto.mix(hs_state.spki) |> Crypto.mix(hs_state.psk)

    # IHI8
    {ck, auth} = Crypto.encrypt_and_mix(ck, <<>>)

    ih = %InitHello{sidi: sidi, epki: epki, sctr: sctr, pidiC: pidiC, auth: auth}

    hs_state = %{
      ck: ck,
      spki: hs_state.spki,
      sski: hs_state.sski,
      epki: epki,
      eski: eski,
      sidi: sidi
    }

    {hs_state, ih}
  end

  @spec resp_hello(hs_state(), RespHello.t()) :: hs_state()
  defp resp_hello(hs_state, rh) do
    ck = hs_state.ck

    # RHI3
    ck = ck |> Crypto.mix(rh.sidr) |> Crypto.mix(hs_state.sidi)

    # RHI4
    ck = Crypto.decaps_and_mix(:ekem, ck, hs_state.eski, hs_state.epki, rh.ecti)

    # RHI5
    ck = Crypto.decaps_and_mix(:skem, ck, hs_state.sski, hs_state.spki, rh.scti)

    # RHI6
    ck = ck |> Crypto.mix(rh.biscuit)

    # RHI7
    {ck, _} = Crypto.decrypt_and_mix(ck, rh.auth)

    %{biscuit: rh.biscuit, ck: ck, sidi: hs_state.sidi, sidr: rh.sidr}
  end

  @spec init_conf(hs_state()) :: {hs_state(), InitConf.t()}
  defp init_conf(hs_state) do
    ck = hs_state.ck

    # ICI3
    ck = ck |> Crypto.mix(hs_state.sidi) |> Crypto.mix(hs_state.sidr)

    # ICI4
    {ck, auth} = Crypto.encrypt_and_mix(ck, <<>>)

    # ICI7
    # TODO

    ic = %InitConf{
      sidi: hs_state.sidi,
      sidr: hs_state.sidr,
      biscuit: hs_state.biscuit,
      auth: auth
    }

    hs_state = %{ck: ck}
    {hs_state, ic}
  end

  @spec final(hs_state()) :: Crypto.key()
  defp final(hs_state) do
    hs_state.ck |> Crypto.hash(Crypto.export_key("rosenpass.eu") |> Crypto.hash("wireguard psk"))
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
    envelope = %Envelope{type: type, payload: payload, mac: <<0::128>>}
    envelope = Envelope.seal(envelope, spkt)
    :ok = :socket.send(socket, Envelope.encode(envelope))
    :ok
  end

  @impl true
  def init(_init_arg) do
    {:ok, nil}
  end

  @impl true
  def handle_cast({:handshake, spki, sski, peer}, _hs_state) do
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

    hs_state = init(spki, sski, peer.spkt, peer.psk)

    {hs_state, ih} = init_hello(hs_state)
    :ok = send(socket, :init_hello, ih, peer.spkt)
    Logger.debug("Sent InitHello")

    rh = recv(socket, :resp_hello, spki)
    hs_state = resp_hello(hs_state, rh)
    Logger.debug("Received RespHello")

    {hs_state, ic} = init_conf(hs_state)
    :ok = send(socket, :init_conf, ic, peer.spkt)
    Logger.debug("Sent InitConf")

    _ = recv(socket, :empty_data, spki)
    Logger.debug("Received EmptyData")
    :socket.close(socket)

    osk = final(hs_state)
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
  @spec handshake(pid(), SKEM.public_key(), SKEM.secret_key(), Peer.t()) :: :ok
  def handshake(server, spki, sski, peer) do
    GenServer.cast(server, {:handshake, spki, sski, peer})
  end
end
