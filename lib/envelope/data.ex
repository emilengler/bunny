defmodule Bunny.Envelope.Data do
  alias Bunny.Envelope.Data

  defstruct sid: nil,
            ctr: nil,
            data: nil

  @moduledoc """
  Provides functions for dealing with `Data` payloads.
  """

  @type sid :: <<_::32>>
  @type ctr :: <<_::64>>
  @type data :: binary()

  @type packet :: binary()

  @type t :: %Data{
          sid: sid(),
          ctr: ctr(),
          data: data()
        }

  @spec decode(packet()) :: t()
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

  @spec encode(t()) :: packet()
  def encode(payload) do
    encoded = payload.sid <> payload.ctr <> payload.data
    true = byte_size(encoded) >= 28
    encoded
  end
end
