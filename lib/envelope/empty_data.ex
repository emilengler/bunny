defmodule Bunny.Envelope.EmptyData do
  alias Bunny.Envelope.EmptyData

  defstruct sid: nil,
            ctr: nil,
            auth: nil

  @type sid :: <<_::32>>
  @type ctr :: <<_::64>>
  @type auth :: <<_::128>>

  @type packet :: <<_::224>>

  @type t :: %EmptyData{
          sid: sid(),
          ctr: ctr(),
          auth: auth()
        }

  @spec decode(packet()) :: t()
  def decode(packet) do
    remaining = packet
    <<sid::binary-size(4), remaining::binary>> = remaining
    <<ctr::binary-size(8), remaining::binary>> = remaining
    <<auth::binary-size(16), _::binary>> = remaining

    %EmptyData{
      sid: sid,
      ctr: ctr,
      auth: auth
    }
  end

  @spec encode(t()) :: packet()
  def encode(payload) do
    payload.sid <> payload.ctr <> payload.auth
  end
end
