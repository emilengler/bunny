defmodule BunnyTest.Envelope.EmptyData do
  alias Bunny.Envelope.EmptyData
  use ExUnit.Case, async: true
  doctest Bunny

  test "decodes an envelope of type RespHello" do
    packet = <<0::32, 42::64, 69::128>>
    envelope = EmptyData.decode(packet)

    assert envelope == %EmptyData{
             sid: <<0::32>>,
             ctr: <<42::64>>,
             auth: <<69::128>>
           }
  end

  test "encodes an envelope of type RespHello" do
    envelope = %EmptyData{
      sid: <<0::32>>,
      ctr: <<42::64>>,
      auth: <<69::128>>
    }

    packet = EmptyData.encode(envelope)
    assert packet == <<0::32, 42::64, 69::128>>
  end
end
