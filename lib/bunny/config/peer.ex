defmodule Bunny.Config.Peer do
  alias Bunny.Crypto
  alias Bunny.Crypto.SKEM
  alias Bunny.Config.Peer

  defstruct spkt: nil,
            endpoint: nil,
            psk: nil,
            output: nil

  @moduledoc """
  Representation of a peer.
  """

  @type t :: %Peer{
          spkt: SKEM.public_key(),
          endpoint: Config.addrport() | nil,
          psk: Crypto.key(),
          output: File.io_device()
        }
end
