defmodule Bunny.Crypto do
  alias Bunny.Crypto.SKEM
  alias Bunny.Crypto.EKEM
  alias Bunny.Crypto.AEAD

  @type chaining_key :: key()
  @type hash :: binary()
  @type kem :: :ekem | :skem
  @type kem_ct :: EKEM.cipher_text() | SKEM.cipher_text()
  @type kem_pk :: EKEM.public_key() | SKEM.public_key()
  @type kem_sk :: EKEM.secret_key() | SKEM.secret_key()
  @type key :: binary()
  @type session_id :: binary()

  @doc """
  A keyed hash function with one 32-byte input, one variable-size input, and one 32-byte output.
  As keyed hash function we use the HMAC construction with BLAKE2s as the inner hash function.
  """
  @spec hash(key(), binary()) :: hash()
  def hash(key, data) do
    true = byte_size(key) == 32

    ipad = :binary.list_to_bin(List.duplicate(0x36, 32))
    opad = :binary.list_to_bin(List.duplicate(0x5C, 32))

    ikey = :crypto.exor(key, ipad)
    okey = :crypto.exor(key, opad)

    outer_data = Blake2.hash2b(data, 32, ikey)
    Blake2.hash2b(outer_data, 32, okey)
  end

  @doc """
  A shorthand hash function derived from the protocol identifier.
  """
  @spec lhash(binary()) :: hash()
  def lhash(data) do
    hash(hash(<<0::256>>, "Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 BLAKE2s"), data)
  end

  @doc """
  A shorthand hash function derived from the chaining key extract.
  """
  @spec extract_key(binary()) :: key()
  def extract_key(data) do
    hash(lhash("chaining key extract"), data)
  end

  @doc """
  A shorthand hash function derived from the user.
  """
  @spec export_key(binary()) :: key()
  def export_key(data) do
    hash(extract_key("user"), data)
  end

  @doc """
  Mixes secrets and public values into the chaining key.
  """
  @spec mix(chaining_key(), binary()) :: chaining_key()
  def mix(ck, data) do
    hash(hash(ck, extract_key("mix")), data)
  end

  @doc """
  Encrypts data based on the current chaining key.
  """
  @spec encrypt_and_mix(chaining_key(), binary()) :: {chaining_key(), binary()}
  def encrypt_and_mix(ck, pt) do
    k = hash(ck, extract_key("handshake encryption"))
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
    k = hash(ck, extract_key("handshake encryption"))
    n = <<0::96>>
    ad = <<>>
    pt = AEAD.dec(k, n, ct, ad)
    ck = mix(ck, pt)
    {ck, pt}
  end

  @doc """
  Encapsulates the key using a KEM.
  """
  @spec encaps_and_mix(kem(), chaining_key(), kem_pk()) :: {chaining_key(), kem_ct()}
  def encaps_and_mix(kem, ck, pk) do
    {ct, shk} =
      case kem do
        :ekem -> EKEM.enc(pk)
        :skem -> SKEM.enc(pk)
      end

    ck = mix(ck, pk)
    ck = mix(ck, shk)
    ck = mix(ck, ct)
    {ck, ct}
  end

  @doc """
  Decapsulates the key using a KEM.
  """
  @spec decaps_and_mix(kem(), chaining_key(), kem_sk(), kem_pk(), kem_ct()) :: chaining_key()
  def decaps_and_mix(kem, ck, sk, pk, ct) do
    shk =
      case kem do
        :ekem -> EKEM.dec(sk, ct)
        :skem -> SKEM.dec(sk, ct)
      end

    ck = mix(ck, pk)
    ck = mix(ck, shk)
    ck = mix(ck, ct)
    ck
  end

  @doc """
  Generates a random session ID in a cryptographic strong fashion.
  """
  @spec random_session_id() :: session_id()
  def random_session_id() do
    :crypto.strong_rand_bytes(4)
  end
end
