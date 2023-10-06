defmodule Bunny.Envelope.InitHello do
  alias Bunny.Envelope.InitHello

  defstruct sidi: nil,
            epki: nil,
            sctr: nil,
            pidiC: nil,
            auth: nil

  @moduledoc """
  Provides functions for dealing with `InitHello` payloads.
  """

  @type sidi :: <<_::32>>
  @type epki :: <<_::6400>>
  @type sctr :: <<_::1504>>
  @type pidiC :: <<_::384>>
  @type auth :: <<_::128>>

  @type packet :: <<_::8448>>

  @type t :: %InitHello{
          sidi: sidi(),
          epki: epki(),
          sctr: sctr(),
          pidiC: pidiC(),
          auth: auth()
        }

  @spec decode(packet()) :: t()
  def decode(packet) do
    remaining = packet
    <<sidi::binary-size(4), remaining::binary>> = remaining
    <<epki::binary-size(800), remaining::binary>> = remaining
    <<sctr::binary-size(188), remaining::binary>> = remaining
    <<pidiC::binary-size(48), remaining::binary>> = remaining
    <<auth::binary-size(16), _::binary>> = remaining

    %InitHello{
      sidi: sidi,
      epki: epki,
      sctr: sctr,
      pidiC: pidiC,
      auth: auth
    }
  end

  @spec encode(t()) :: packet()
  def encode(payload) do
    payload.sidi <> payload.epki <> payload.sctr <> payload.pidiC <> payload.auth
  end
end
