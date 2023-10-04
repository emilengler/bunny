defmodule Bunny.Envelope.RespHelloTest do
  alias Bunny.Envelope.RespHello
  use ExUnit.Case, async: true
  doctest RespHello

  test "decodes an envelope of type RespHello" do
    packet =
      <<42::32, 69::32, 0::integer-size(768)-unit(8), 0::integer-size(188)-unit(8), 42::128,
        42::integer-size(116)-unit(8)>>

    envelope = RespHello.decode(packet)

    assert envelope == %RespHello{
             sidr: <<42::32>>,
             sidi: <<69::32>>,
             ecti: <<0::integer-size(768)-unit(8)>>,
             scti: <<0::integer-size(188)-unit(8)>>,
             auth: <<42::128>>,
             biscuit: <<42::integer-size(116)-unit(8)>>
           }
  end

  test "encodes an envelope of type RespHello" do
    envelope = %RespHello{
      sidr: <<42::32>>,
      sidi: <<69::32>>,
      ecti: <<0::integer-size(768)-unit(8)>>,
      scti: <<0::integer-size(188)-unit(8)>>,
      auth: <<42::128>>,
      biscuit: <<42::integer-size(116)-unit(8)>>
    }

    packet = RespHello.encode(envelope)

    assert packet ==
             <<42::32, 69::32, 0::integer-size(768)-unit(8), 0::integer-size(188)-unit(8),
               42::128, 42::integer-size(116)-unit(8)>>
  end
end
