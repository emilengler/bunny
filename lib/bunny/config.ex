defmodule Bunny.Config do
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

  @type t :: %Config{
          spkm: SKEM.public_key(),
          sskm: SKEM.secret_key(),
          listen: addrport() | nil,
          peers: list(Peer)
        }
end
