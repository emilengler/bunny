defmodule Bunny.Crypto do
  alias Bunny.Crypto.AEAD

  @type chaining_key :: key()
  @type hash :: binary()
  @type key :: binary()
  @type session_id :: binary()

  @doc """
  A keyed hash function with one 32-byte input, one variable-size input, and one 32-byte output.
  As keyed hash function we use the HMAC construction with BLAKE2s as the inner hash function.
  """
  @spec hash(key(), binary()) :: hash()
  def hash(key, data) do
    true = byte_size(key) == 32
    :crypto.mac(:hmac, :blake2s, key, data)
  end

  @doc """
  A shorthand hash function derived from the protocol identifier.
  """
  @spec lhash(binary()) :: hash()
  def lhash(data) do
    hash(
      hash(
        <<0::256>>,
        "rosenpass 1 rosenpass.eu aead=chachapoly1305 hash=blake2s ekem=kyber512 skem=mceliece460896 xaead=xchachapoly1305"
      ),
      data
    )
  end

  @doc """
  Derives a key from the chaining key.
  """
  @spec extract_key(chaining_key(), binary()) :: key()
  def extract_key(ck, data) do
    hash(ck, lhash("chaining key extract" <> data))
  end

  @doc """
  Derives a key even further from the chaining key.
  """
  @spec export_key(chaining_key(), binary()) :: key()
  def export_key(ck, data) do
    extract_key(ck, "user" <> data)
  end

  @doc """
  Mixes secrets and public values into the chaining key.
  """
  @spec mix(chaining_key(), binary()) :: chaining_key()
  def mix(ck, data) do
    hash(ck, hash(extract_key(ck, "mix"), data))
  end

  @doc """
  Encrypts data based on the current chaining key.
  """
  @spec encrypt_and_mix(chaining_key(), binary()) :: {chaining_key(), binary()}
  def encrypt_and_mix(ck, pt) do
    k = extract_key(ck, "handshake encryption")
    n = <<0::96>>
    ad = <<>>
    ct = AEAD.enc(k, n, pt, ad)
    ck = mix(ck, ct)
    {ck, ct}
  end

  @doc """
  Decrypts data based on the current chaining key.
  """
  @spec decrypt_and_mix(chaining_key(), binary()) :: {chaining_key(), binary()}
  def decrypt_and_mix(ck, ct) do
    k = extract_key(ck, "handshake encryption")
    n = <<0::96>>
    ad = <<>>
    pt = AEAD.dec(k, n, ct, ad)
    ck = mix(ck, pt)
    {ck, pt}
  end

  @doc """
  Generates a random session ID in a cryptographic strong fashion.
  """
  @spec random_session_id() :: session_id()
  def random_session_id() do
    :crypto.strong_rand_bytes(4)
  end
end
