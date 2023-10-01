defmodule Bunny.Envelope.RespHello do
  alias Bunny.Envelope.RespHello

  defstruct sidr: nil,
            sidi: nil,
            ecti: nil,
            scti: nil,
            biscuit: nil,
            auth: nil

  @type sidr :: <<_::32>>
  @type sidi :: <<_::32>>
  @type ecti :: <<_::6144>>
  @type scti :: <<_::1504>>
  @type biscuit :: <<_::928>>
  @type auth :: <<_::128>>

  @type packet :: <<_::8768>>

  @type t :: %RespHello{
          sidr: sidr(),
          sidi: sidi(),
          ecti: ecti(),
          scti: scti(),
          biscuit: biscuit(),
          auth: auth()
        }

  @spec decode(packet()) :: t()
  def decode(packet) do
    remaining = packet
    <<sidr::binary-size(4), remaining::binary>> = remaining
    <<sidi::binary-size(4), remaining::binary>> = remaining
    <<ecti::binary-size(768), remaining::binary>> = remaining
    <<scti::binary-size(188), remaining::binary>> = remaining
    <<auth::binary-size(16), remaining::binary>> = remaining
    <<biscuit::binary-size(116), _::binary>> = remaining

    %RespHello{
      sidr: sidr,
      sidi: sidi,
      ecti: ecti,
      scti: scti,
      biscuit: biscuit,
      auth: auth
    }
  end

  @spec encode(t()) :: packet()
  def encode(payload) do
    payload.sidr <>
      payload.sidi <> payload.ecti <> payload.scti <> payload.auth <> payload.biscuit
  end
end
