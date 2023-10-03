defmodule Bunny.Envelope.Biscuit do
  alias Bunny.Envelope.Biscuit

  defstruct pidi: nil,
            biscuit_no: nil,
            ck: nil

  @moduledoc """
  Provides functions for dealing with the biscuit.
  """

  @type pidi :: <<_::256>>
  @type biscuit_no :: <<_::96>>
  @type chaining_key :: <<_::256>>

  @type packet :: <<_::928>>

  @type t :: %Biscuit{
          pidi: pidi(),
          biscuit_no: biscuit_no(),
          ck: chaining_key()
        }

  @spec decode(packet()) :: t()
  def decode(packet) do
    remaining = packet
    <<pidi::binary-size(32), remaining::binary>> = remaining
    <<biscuit_no::binary-size(12), remaining::binary>> = remaining
    <<ck::binary-size(32), _::binary>> = remaining

    %Biscuit{
      pidi: pidi,
      biscuit_no: biscuit_no,
      ck: ck
    }
  end

  @spec encode(t()) :: packet()
  def encode(payload) do
    payload.pidi <> payload.biscuit_no <> payload.ck
  end
end
