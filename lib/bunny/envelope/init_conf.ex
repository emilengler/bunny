defmodule Bunny.Envelope.InitConf do
  alias Bunny.Envelope.InitConf

  defstruct sidi: nil,
            sidr: nil,
            biscuit: nil,
            auth: nil

  @moduledoc """
  Provides functions for dealing with `InitConf` payloads.
  """

  @type sidi :: <<_::32>>
  @type sidr :: <<_::32>>
  @type biscuit :: <<_::928>>
  @type auth :: <<_::128>>

  @type packet :: <<_::1120>>

  @type t :: %InitConf{
          sidi: sidi(),
          sidr: sidr(),
          biscuit: biscuit(),
          auth: auth()
        }

  @spec decode(packet()) :: t()
  def decode(packet) do
    <<sidi::binary-size(4), sidr::binary-size(4), biscuit::binary-size(116),
      auth::binary-size(16)>> = packet

    %InitConf{
      sidi: sidi,
      sidr: sidr,
      biscuit: biscuit,
      auth: auth
    }
  end

  @spec encode(t()) :: packet()
  def encode(payload) do
    payload.sidi <> payload.sidr <> payload.biscuit <> payload.auth
  end
end
