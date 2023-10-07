defmodule Bunny.EnvelopeTest do
  alias Bunny.Envelope.Data
  alias Bunny.Envelope.EmptyData
  alias Bunny.Envelope.RespHello
  alias Bunny.Envelope.InitHello
  alias Bunny.Envelope
  use ExUnit.Case, async: true
  doctest Envelope

  test "decodes an envelope of type InitHello" do
    packet =
      <<0x81, 0, 0, 0>> <>
        <<0::32, 0::integer-size(800)-unit(8), 0::integer-size(188)-unit(8),
          42::integer-size(48)-unit(8), 69::128>> <> <<0::128, 0::128>>

    envelope = Envelope.decode(packet)

    assert envelope == %Envelope{
             type: :init_hello,
             payload: %InitHello{
               sidi: <<0::32>>,
               epki: <<0::integer-size(800)-unit(8)>>,
               sctr: <<0::integer-size(188)-unit(8)>>,
               pidiC: <<42::integer-size(48)-unit(8)>>,
               auth: <<69::128>>
             },
             mac: <<0::128>>
           }
  end

  test "encodes an envelope of type InitHello" do
    envelope = %Envelope{
      type: :init_hello,
      payload: %InitHello{
        sidi: <<0::32>>,
        epki: <<0::integer-size(800)-unit(8)>>,
        sctr: <<0::integer-size(188)-unit(8)>>,
        pidiC: <<42::integer-size(48)-unit(8)>>,
        auth: <<69::128>>
      },
      mac: <<0::128>>
    }

    packet = Envelope.encode(envelope)

    assert packet ==
             <<0x81, 0, 0, 0>> <>
               <<0::32, 0::integer-size(800)-unit(8), 0::integer-size(188)-unit(8),
                 42::integer-size(48)-unit(8), 69::128>> <> <<0::128, 0::128>>
  end

  test "decodes an envelope of type RespHello" do
    packet =
      <<0x82, 0, 0, 0>> <>
        <<42::32, 69::32, 0::integer-size(768)-unit(8), 0::integer-size(188)-unit(8), 42::128,
          42::integer-size(116)-unit(8)>> <> <<0::128, 0::128>>

    envelope = Envelope.decode(packet)

    assert envelope == %Envelope{
             type: :resp_hello,
             payload: %RespHello{
               sidr: <<42::32>>,
               sidi: <<69::32>>,
               ecti: <<0::integer-size(768)-unit(8)>>,
               scti: <<0::integer-size(188)-unit(8)>>,
               auth: <<42::128>>,
               biscuit: <<42::integer-size(116)-unit(8)>>
             },
             mac: <<0::128>>
           }
  end

  test "encodes an envelope of type RespHello" do
    envelope = %Envelope{
      type: :resp_hello,
      payload: %RespHello{
        sidr: <<42::32>>,
        sidi: <<69::32>>,
        ecti: <<0::integer-size(768)-unit(8)>>,
        scti: <<0::integer-size(188)-unit(8)>>,
        auth: <<42::128>>,
        biscuit: <<42::integer-size(116)-unit(8)>>
      },
      mac: <<0::128>>
    }

    packet = Envelope.encode(envelope)

    assert packet ==
             <<0x82, 0, 0, 0>> <>
               <<42::32, 69::32, 0::integer-size(768)-unit(8), 0::integer-size(188)-unit(8),
                 42::128, 42::integer-size(116)-unit(8)>> <> <<0::128, 0::128>>
  end

  test "decodes an envelope of type EmptyData" do
    packet = <<0x84, 0, 0, 0>> <> <<0::32, 42::64, 69::128>> <> <<0::128, 0::128>>
    envelope = Envelope.decode(packet)

    assert envelope == %Envelope{
             type: :empty_data,
             payload: %EmptyData{
               sid: <<0::32>>,
               ctr: <<42::64>>,
               auth: <<69::128>>
             },
             mac: <<0::128>>
           }
  end

  test "encodes an envelope of type EmptyData" do
    envelope = %Envelope{
      type: :empty_data,
      payload: %EmptyData{
        sid: <<0::32>>,
        ctr: <<42::64>>,
        auth: <<69::128>>
      },
      mac: <<0::128>>
    }

    packet = Envelope.encode(envelope)
    assert packet == <<0x84, 0, 0, 0>> <> <<0::32, 42::64, 69::128>> <> <<0::128, 0::128>>
  end

  test "decodes an envelope with type Data" do
    packet = <<0x85, 0, 0, 0>> <> <<42::32, 69::64, 0::256>> <> <<0::128, 0::128>>
    envelope = Envelope.decode(packet)

    assert envelope == %Envelope{
             type: :data,
             payload: %Data{
               sid: <<42::32>>,
               ctr: <<69::64>>,
               data: <<0::256>>
             },
             mac: <<0::128>>
           }
  end

  test "encodes an envelope with type Data" do
    envelope = %Envelope{
      type: :data,
      payload: %Data{
        sid: <<42::32>>,
        ctr: <<69::64>>,
        data: <<0::256>>
      },
      mac: <<0::128>>
    }

    packet = Envelope.encode(envelope)
    assert packet == <<0x85, 0, 0, 0>> <> <<42::32, 69::64, 0::256>> <> <<0::128, 0::128>>
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
