defmodule BunnyTest.Envelope do
  use ExUnit.Case, async: true
  doctest Bunny

  test "decodes an envelope" do
    packet = <<0x85, 0, 0, 0, 42::32, 69::64, 0::256, 0::128, 0::128>>
    envelope = Bunny.Envelope.decode(packet)

    assert envelope == %Bunny.Envelope{
             type: :data,
             payload: %Bunny.Envelope.Data{
               sid: <<42::32>>,
               ctr: <<69::64>>,
               data: <<0::256>>
             },
             mac: <<0::128>>,
             cookie: <<0::128>>
           }
  end

  test "encodes an envelope" do
    envelope = %Bunny.Envelope{
      type: :data,
      payload: %Bunny.Envelope.Data{
        sid: <<42::32>>,
        ctr: <<69::64>>,
        data: <<0::256>>
      },
      mac: <<0::128>>,
      cookie: <<0::128>>
    }

    packet = Bunny.Envelope.encode(envelope)
    assert packet == <<0x85, 0, 0, 0, 42::32, 69::64, 0::256, 0::128, 0::128>>
  end
end
