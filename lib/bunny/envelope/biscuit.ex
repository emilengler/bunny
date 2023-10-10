defmodule Bunny.Envelope.Biscuit do
  alias Bunny.Envelope.Biscuit

  defstruct pidi: nil,
            biscuit_no: nil,
            ck: nil

  @moduledoc """
  Provides functions for dealing with the biscuit.
  """

  @type pidi :: <<_::256>>
  @type biscuit_no :: non_neg_integer()
  @type chaining_key :: <<_::256>>

  @type packet :: <<_::608>>

  @type t :: %Biscuit{
          pidi: pidi(),
          biscuit_no: biscuit_no(),
          ck: chaining_key()
        }

  @spec decode(packet()) :: t()
  def decode(packet) do
    <<pidi::binary-size(32), biscuit_no::96-little, ck::binary-size(32)>> = packet

    %Biscuit{
      pidi: pidi,
      biscuit_no: biscuit_no,
      ck: ck
    }
  end

  @spec encode(t()) :: packet()
  def encode(payload) do
    payload.pidi <> <<payload.biscuit_no::96-little>> <> payload.ck
  end
end
