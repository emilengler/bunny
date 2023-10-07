defmodule Bunny.Config do
  alias Bunny.Crypto
  alias Bunny.Config
  alias Bunny.Config.Peer
  alias Bunny.Crypto.SKEM

  defstruct spkm: nil,
            sskm: nil,
            listen: nil,
            peers: nil

  @moduledoc """
  Representation of the configuration.
  """

  @type hostname :: String.t()
  @type ip_address :: :inet.ip_address()
  @type host :: hostname() | ip_address()
  @type addrport :: {host(), :inet.port_number()}
  @type peers :: map()

  @type t :: %Config{
          spkm: SKEM.public_key(),
          sskm: SKEM.secret_key(),
          listen: addrport() | nil,
          peers: peers()
        }

  @spec peers_from_list(list(Peer.t())) :: peers()
  def peers_from_list(peers) do
    # Converts peers into a tuple with {pidt, peer}
    peers =
      Enum.map(peers, fn peer ->
        pidt = Crypto.lhash("peer id") |> Crypto.hash(peer.spkt)
        {pidt, peer}
      end)

    # Converts the tuple into a map
    Enum.into(peers, %{})
  end
end
