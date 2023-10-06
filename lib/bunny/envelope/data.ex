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
    <<sid::binary-size(4), ctr::binary-size(8), data::binary>> = packet

    %Data{
      sid: sid,
      ctr: ctr,
      data: data
    }
  end

  @spec encode(t()) :: packet()
  def encode(payload) do
    payload.sid <> payload.ctr <> payload.data
  end
end
