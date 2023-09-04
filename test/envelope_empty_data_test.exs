defmodule BunnyTest.Envelope.EmptyData do
  use ExUnit.Case, async: true
  doctest Bunny

  test "decodes an envelope of type RespHello" do
    packet = <<0::32, 42::64, 69::128>>
    envelope = Bunny.Envelope.EmptyData.decode(packet)

    assert envelope == %Bunny.Envelope.EmptyData{
             sid: <<0::32>>,
             ctr: <<42::64>>,
             auth: <<69::128>>
           }
  end

  test "encodes an envelope of type RespHello" do
    envelope = %Bunny.Envelope.EmptyData{
      sid: <<0::32>>,
      ctr: <<42::64>>,
      auth: <<69::128>>
    }

    packet = Bunny.Envelope.EmptyData.encode(envelope)
    assert packet == <<0::32, 42::64, 69::128>>
  end
end
