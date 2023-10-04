defmodule Bunny.Envelope do
  alias Bunny.Crypto.SKEM
  alias Bunny.Crypto
  alias Bunny.Envelope.Data
  alias Bunny.Envelope.EmptyData
  alias Bunny.Envelope.InitConf
  alias Bunny.Envelope.RespHello
  alias Bunny.Envelope.InitHello
  alias Bunny.Envelope

  defstruct type: nil,
            payload: nil,
            mac: nil,
            cookie: nil

  @moduledoc """
  Provides functions for dealing with envelopes.
  """

  @type t :: %Envelope{
          type: type(),
          payload: payload(),
          mac: mac(),
          cookie: cookie()
        }

  @type type :: :init_hello | :resp_hello | :init_conf | :empty_data | :data
  @type payload ::
          InitHello.t()
          | RespHello.t()
          | InitConf.t()
          | EmptyData.t()
          | Data.t()
  @type mac :: <<_::128>>
  @type cookie :: <<_::128>>

  @spec decode_type(integer()) :: type()
  defp decode_type(type) do
    case type do
      0x81 -> :init_hello
      0x82 -> :resp_hello
      0x83 -> :init_conf
      0x84 -> :empty_data
      0x85 -> :data
    end
  end

  @spec encode_type(type()) :: integer()
  defp encode_type(type) do
    case type do
      :init_hello -> 0x81
      :resp_hello -> 0x82
      :init_conf -> 0x83
      :empty_data -> 0x84
      :data -> 0x85
    end
  end

  @spec decode_payload(type(), binary()) :: payload()
  defp decode_payload(type, packet) do
    case type do
      :init_hello -> InitHello.decode(packet)
      :resp_hello -> RespHello.decode(packet)
      :empty_data -> EmptyData.decode(packet)
      :data -> Data.decode(packet)
    end
  end

  @spec decode(binary()) :: t()
  def decode(packet) do
    remaining = packet
    <<type, remaining::binary>> = remaining
    <<_::binary-size(3), remaining::binary>> = remaining
    n = byte_size(remaining) - 16 - 16
    <<payload::binary-size(n), remaining::binary>> = remaining
    <<mac::binary-size(16), remaining::binary>> = remaining
    <<cookie::binary-size(16), remaining::binary>> = remaining
    true = byte_size(remaining) == 0

    type = decode_type(type)
    payload = decode_payload(type, payload)

    %Envelope{
      type: type,
      payload: payload,
      mac: mac,
      cookie: cookie
    }
  end

  @spec encode(t()) :: binary()
  def encode(payload) do
    type = <<encode_type(payload.type)>>

    payload_enc =
      case payload.type do
        :init_hello -> InitHello.encode(payload.payload)
        :resp_hello -> RespHello.encode(payload.payload)
        :init_conf -> InitConf.encode(payload.payload)
        :empty_data -> EmptyData.encode(payload.payload)
        :data -> Data.encode(payload.payload)
      end

    encoded = type <> <<0, 0, 0>> <> payload_enc <> payload.mac <> payload.cookie
    encoded
  end

  @doc """
  Seals the envelope by returning an updated version of it containing the MAC.
  """
  @spec seal(t(), SKEM.public_key()) :: t()
  def seal(envelope, spkt) do
    encoded = encode(envelope)
    mac_wire_data = :binary.part(encoded, {0, byte_size(encoded) - 32})

    mac =
      :binary.part(
        Crypto.lhash("mac") |> Crypto.hash(spkt) |> Crypto.hash(mac_wire_data),
        {0, 16}
      )

    Map.replace!(envelope, :mac, mac)
  end

  @spec verify(t(), SKEM.public_key()) :: boolean()
  def verify(envelope, spkm) do
    encoded = encode(envelope)
    mac_wire_data = :binary.part(encoded, {0, byte_size(encoded) - 32})

    mac =
      :binary.part(
        Crypto.lhash("mac") |> Crypto.hash(spkm) |> Crypto.hash(mac_wire_data),
        {0, 16}
      )

    envelope.mac == mac
  end
end
