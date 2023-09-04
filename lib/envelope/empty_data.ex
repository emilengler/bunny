defmodule Bunny.Envelope.EmptyData do
  defstruct sid: nil,
            ctr: nil,
            auth: nil

  @type t :: %Bunny.Envelope.EmptyData{
          sid: binary(),
          ctr: binary(),
          auth: binary()
        }

  @spec decode(binary()) :: t()
  def decode(packet) do
    remaining = packet
    <<sid::binary-size(4), remaining::binary>> = remaining
    <<ctr::binary-size(8), remaining::binary>> = remaining
    <<auth::binary-size(16), remaining::binary>> = remaining
    true = byte_size(remaining) == 0

    %Bunny.Envelope.EmptyData{
      sid: sid,
      ctr: ctr,
      auth: auth
    }
  end

  @spec encode(t()) :: binary()
  def encode(payload) do
    encoded = payload.sid <> payload.ctr <> payload.auth
    true = byte_size(encoded) == 28
    encoded
  end
end
