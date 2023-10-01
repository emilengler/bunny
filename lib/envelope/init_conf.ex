defmodule Bunny.Envelope.InitConf do
  alias Bunny.Envelope.InitConf

  defstruct sidi: nil,
            sidr: nil,
            biscuit: nil,
            auth: nil

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
    remaining = packet
    <<sidi::binary-size(4), remaining::binary>> = remaining
    <<sidr::binary-size(4), remaining::binary>> = remaining
    <<biscuit::binary-size(116), remaining::binary>> = remaining
    <<auth::binary-size(16), _::binary>> = remaining

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
