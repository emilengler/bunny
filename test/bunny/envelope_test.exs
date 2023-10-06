defmodule Bunny.EnvelopeTest do
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
             mac: <<0::128>>
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
      mac: <<0::128>>
    }

    packet = Envelope.encode(envelope)
    assert packet == <<0x85, 0, 0, 0, 42::32, 69::64, 0::256, 0::128, 0::128>>
  end

  test "seals and verifies an envelope (random key)" do
    pk = :enacl.randombytes(512_000)

    envelope = %Envelope{
      type: :data,
      payload: %Envelope.Data{
        sid: <<42::32>>,
        ctr: <<69::64>>,
        data: <<0::256>>
      },
      mac: <<0::128>>
    }

    envelope_sealed = Envelope.seal(envelope, pk)
    assert Envelope.verify(envelope_sealed, pk)
    assert !Envelope.verify(envelope, pk)
  end

  test "seals and verifies an envelope (static key)" do
    pk = <<42::4_096_000>>

    envelope = %Envelope{
      type: :data,
      payload: %Envelope.Data{
        sid: <<42::32>>,
        ctr: <<69::64>>,
        data: <<0::256>>
      },
      mac: <<0::128>>
    }

    envelope_sealed = Envelope.seal(envelope, pk)

    assert envelope_sealed.mac ==
             <<206, 249, 25, 6, 26, 71, 24, 175, 19, 1, 188, 124, 152, 53, 185, 183>>

    assert Envelope.verify(envelope_sealed, pk)
    assert !Envelope.verify(envelope, pk)
  end
end
