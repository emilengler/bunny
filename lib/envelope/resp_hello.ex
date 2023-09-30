defmodule Bunny.Envelope.RespHello do
  alias Bunny.Envelope.RespHello

  defstruct sidr: nil,
            sidi: nil,
            ecti: nil,
            scti: nil,
            biscuit: nil,
            auth: nil

  @type t :: %RespHello{
          sidr: binary(),
          sidi: binary(),
          ecti: binary(),
          scti: binary(),
          biscuit: binary(),
          auth: binary()
        }

  @spec decode(binary()) :: t()
  def decode(packet) do
    remaining = packet
    <<sidr::binary-size(4), remaining::binary>> = remaining
    <<sidi::binary-size(4), remaining::binary>> = remaining
    <<ecti::binary-size(768), remaining::binary>> = remaining
    <<scti::binary-size(188), remaining::binary>> = remaining
    <<biscuit::binary-size(116), remaining::binary>> = remaining
    <<auth::binary-size(16), remaining::binary>> = remaining
    true = byte_size(remaining) == 0

    %RespHello{
      sidr: sidr,
      sidi: sidi,
      ecti: ecti,
      scti: scti,
      biscuit: biscuit,
      auth: auth
    }
  end

  @spec encode(t()) :: binary()
  def encode(payload) do
    encoded =
      payload.sidr <>
        payload.sidi <> payload.ecti <> payload.scti <> payload.biscuit <> payload.auth

    true = byte_size(encoded) == 1096
    encoded
  end
end
