defmodule Bunny.Envelope do
  defstruct type: nil,
            payload: nil,
            mac: nil,
            cookie: nil

  @type t :: %Bunny.Envelope{
          type: type(),
          payload: payload(),
          mac: mac(),
          cookie: cookie()
        }

  @type type :: :init_hello | :resp_hello | :init_conf | :empty_data | :data
  @type payload ::
          Bunny.Envelope.InitHello.t()
          | Bunny.Envelope.RespHello.t()
          | Bunny.Envelope.InitConf.t()
          | Bunny.Envelope.EmptyData.t()
          | Bunny.Envelope.Data.t()
  @type mac :: binary()
  @type cookie :: binary()

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
      :init_hello -> Bunny.Envelope.InitHello.decode(packet)
      :resp_hello -> Bunny.Envelope.RespHello.decode(packet)
      :empty_data -> Bunny.Envelope.EmptyData.decode(packet)
      :data -> Bunny.Envelope.Data.decode(packet)
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

    %Bunny.Envelope{
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
        :init_hello -> Bunny.Envelope.InitHello.encode(payload.payload)
        :resp_hello -> Bunny.Envelope.RespHello.encode(payload.payload)
        :init_conf -> Bunny.Envelope.InitConf.encode(payload.payload)
        :empty_data -> Bunny.Envelope.EmptyData.encode(payload.payload)
        :data -> Bunny.Envelope.Data.encode(payload.payload)
      end

    encoded = type <> <<0, 0, 0>> <> payload_enc <> payload.mac <> payload.cookie
    encoded
  end
end