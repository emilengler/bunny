defmodule Bunny.Envelope.InitConf do
  defstruct sidi: nil,
            sidr: nil,
            biscuit: nil,
            auth: nil

  @type t :: %Bunny.Envelope.InitConf{
          sidi: binary(),
          sidr: binary(),
          biscuit: binary(),
          auth: binary()
        }

  @spec decode(binary()) :: t()
  def decode(packet) do
    remaining = packet
    <<sidi::binary-size(4), remaining::binary>> = remaining
    <<sidr::binary-size(4), remaining::binary>> = remaining
    <<biscuit::binary-size(116), remaining::binary>> = remaining
    <<auth::binary-size(16), remaining::binary>> = remaining
    true = byte_size(remaining) == 0

    %Bunny.Envelope.InitConf{
      sidi: sidi,
      sidr: sidr,
      biscuit: biscuit,
      auth: auth
    }
  end

  @spec encode(t()) :: binary()
  def encode(payload) do
    encoded = payload.sidi <> payload.sidr <> payload.biscuit <> payload.auth
    true = byte_size(encoded) == 140
    encoded
  end
end
