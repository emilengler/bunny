defmodule BunnyTest.Envelope.RespHello do
  use ExUnit.Case, async: true
  doctest Bunny

  test "decodes an envelope of type RespHello" do
    packet =
      <<42::32, 69::32, 0::integer-size(768)-unit(8), 0::integer-size(188)-unit(8), 42::128,
        42::integer-size(116)-unit(8)>>

    envelope = Bunny.Envelope.RespHello.decode(packet)

    assert envelope == %Bunny.Envelope.RespHello{
             sidr: <<42::32>>,
             sidi: <<69::32>>,
             ecti: <<0::integer-size(768)-unit(8)>>,
             scti: <<0::integer-size(188)-unit(8)>>,
             auth: <<42::128>>,
             biscuit: <<42::integer-size(116)-unit(8)>>
           }
  end

  test "encodes an envelope of type RespHello" do
    envelope = %Bunny.Envelope.RespHello{
      sidr: <<42::32>>,
      sidi: <<69::32>>,
      ecti: <<0::integer-size(768)-unit(8)>>,
      scti: <<0::integer-size(188)-unit(8)>>,
      auth: <<42::128>>,
      biscuit: <<42::integer-size(116)-unit(8)>>
    }

    packet = Bunny.Envelope.RespHello.encode(envelope)

    assert packet ==
             <<42::32, 69::32, 0::integer-size(768)-unit(8), 0::integer-size(188)-unit(8),
               42::128, 42::integer-size(116)-unit(8)>>
  end
end
