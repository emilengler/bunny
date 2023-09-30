defmodule Bunny.Crypto do
  @type hash :: binary()
  @type key :: binary()

  @doc """
  A keyed hash function with one 32-byte input, one variable-size input, and one 32-byte output.
  As keyed hash function we use the HMAC construction with BLAKE2s as the inner hash function.
  """
  @spec hash(key(), binary()) :: hash()
  def hash(key, data) do
    true = byte_size(key) == 32
    :crypto.mac(:hmac, :blake2s, key, data)
  end
end
