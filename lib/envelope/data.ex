defmodule Bunny.Envelope.Data do
  alias Bunny.Envelope.Data

  defstruct sid: nil,
            ctr: nil,
            data: nil

  @type t :: %Data{
          sid: binary(),
          ctr: binary(),
          data: binary()
        }

  @spec decode(binary()) :: t()
  def decode(packet) do
    remaining = packet
    <<sid::binary-size(4), remaining::binary>> = remaining
    <<ctr::binary-size(8), remaining::binary>> = remaining
    data = remaining
    true = byte_size(data) >= 16

    %Data{
      sid: sid,
      ctr: ctr,
      data: data
    }
  end

  @spec encode(t()) :: binary()
  def encode(payload) do
    encoded = payload.sid <> payload.ctr <> payload.data
    true = byte_size(encoded) >= 28
    encoded
  end
end
