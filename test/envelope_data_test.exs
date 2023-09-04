defmodule BunnyTest.Envelope.Data do
  use ExUnit.Case, async: true
  doctest Bunny

  test "decodes an envelope with type Data" do
    packet = <<42::32, 69::64, 0::256>>
    envelope = Bunny.Envelope.Data.decode(packet)

    assert envelope == %Bunny.Envelope.Data{
             sid: <<42::32>>,
             ctr: <<69::64>>,
             data: <<0::256>>
           }
  end

  test "encodes an envelope with type Data" do
    envelope = %Bunny.Envelope.Data{
      sid: <<42::32>>,
      ctr: <<69::64>>,
      data: <<0::256>>
    }

    packet = Bunny.Envelope.Data.encode(envelope)
    assert packet == <<42::32, 69::64, 0::256>>
  end
end
