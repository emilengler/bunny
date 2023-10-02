defmodule BunnyTest.Envelope.InitHello do
  alias Bunny.Envelope.InitHello
  use ExUnit.Case, async: true
  doctest InitHello

  test "decodes an envelope of type InitHello" do
    packet =
      <<0::32, 0::integer-size(800)-unit(8), 0::integer-size(188)-unit(8),
        42::integer-size(48)-unit(8), 69::128>>

    envelope = InitHello.decode(packet)

    assert envelope == %InitHello{
             sidi: <<0::32>>,
             epki: <<0::integer-size(800)-unit(8)>>,
             sctr: <<0::integer-size(188)-unit(8)>>,
             pidiC: <<42::integer-size(48)-unit(8)>>,
             auth: <<69::128>>
           }
  end

  test "encodes an envelope of type InitHello" do
    envelope = %InitHello{
      sidi: <<0::32>>,
      epki: <<0::integer-size(800)-unit(8)>>,
      sctr: <<0::integer-size(188)-unit(8)>>,
      pidiC: <<42::integer-size(48)-unit(8)>>,
      auth: <<69::128>>
    }

    packet = InitHello.encode(envelope)

    assert packet ==
             <<0::32, 0::integer-size(800)-unit(8), 0::integer-size(188)-unit(8),
               42::integer-size(48)-unit(8), 69::128>>
  end
end
