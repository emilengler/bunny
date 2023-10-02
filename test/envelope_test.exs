defmodule BunnyTest.Envelope do
  alias Bunny.Envelope
  use ExUnit.Case, async: true
  doctest Envelope

  test "decodes an envelope" do
    packet = <<0x85, 0, 0, 0, 42::32, 69::64, 0::256, 0::128, 0::128>>
    envelope = Envelope.decode(packet)

    assert envelope == %Envelope{
             type: :data,
             payload: %Envelope.Data{
               sid: <<42::32>>,
               ctr: <<69::64>>,
               data: <<0::256>>
             },
             mac: <<0::128>>,
             cookie: <<0::128>>
           }
  end

  test "encodes an envelope" do
    envelope = %Envelope{
      type: :data,
      payload: %Envelope.Data{
        sid: <<42::32>>,
        ctr: <<69::64>>,
        data: <<0::256>>
      },
      mac: <<0::128>>,
      cookie: <<0::128>>
    }

    packet = Envelope.encode(envelope)
    assert packet == <<0x85, 0, 0, 0, 42::32, 69::64, 0::256, 0::128, 0::128>>
  end
end
