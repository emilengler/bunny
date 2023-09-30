defmodule Bunny.Envelope.InitHello do
  alias Bunny.Envelope.InitHello

  defstruct sidi: nil,
            epki: nil,
            sctr: nil,
            pidiC: nil,
            auth: nil

  @type t :: %InitHello{
          sidi: binary(),
          epki: binary(),
          sctr: binary(),
          pidiC: binary(),
          auth: binary()
        }

  @spec decode(binary()) :: t()
  def decode(packet) do
    remaining = packet
    <<sidi::binary-size(4), remaining::binary>> = remaining
    <<epki::binary-size(800), remaining::binary>> = remaining
    <<sctr::binary-size(188), remaining::binary>> = remaining
    <<pidiC::binary-size(48), remaining::binary>> = remaining
    <<auth::binary-size(16), remaining::binary>> = remaining
    true = byte_size(remaining) == 0

    %InitHello{
      sidi: sidi,
      epki: epki,
      sctr: sctr,
      pidiC: pidiC,
      auth: auth
    }
  end

  @spec encode(t()) :: binary()
  def encode(payload) do
    encoded = payload.sidi <> payload.epki <> payload.sctr <> payload.pidiC <> payload.auth
    true = byte_size(encoded) == 1056
    encoded
  end
end
