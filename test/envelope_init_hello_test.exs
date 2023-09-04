defmodule BunnyTest.Envelope.InitHello do
  use ExUnit.Case, async: true
  doctest Bunny

  test "decodes an envelope of type InitHello" do
    packet =
      <<0::32, 0::integer-size(800)-unit(8), 0::integer-size(188)-unit(8),
        42::integer-size(48)-unit(8), 69::128>>

    envelope = Bunny.Envelope.InitHello.decode(packet)

    assert envelope == %Bunny.Envelope.InitHello{
             sidi: <<0::32>>,
             epki: <<0::integer-size(800)-unit(8)>>,
             sctr: <<0::integer-size(188)-unit(8)>>,
             pidiC: <<42::integer-size(48)-unit(8)>>,
             auth: <<69::128>>
           }
  end

  test "encodes an envelope of type InitHello" do
    envelope = %Bunny.Envelope.InitHello{
      sidi: <<0::32>>,
      epki: <<0::integer-size(800)-unit(8)>>,
      sctr: <<0::integer-size(188)-unit(8)>>,
      pidiC: <<42::integer-size(48)-unit(8)>>,
      auth: <<69::128>>
    }

    packet = Bunny.Envelope.InitHello.encode(envelope)

    assert packet ==
             <<0::32, 0::integer-size(800)-unit(8), 0::integer-size(188)-unit(8),
               42::integer-size(48)-unit(8), 69::128>>
  end
end
