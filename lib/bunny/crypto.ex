defmodule Bunny.Crypto do
  alias Bunny.Crypto.XAEAD
  alias Bunny.Envelope.Biscuit
  alias Bunny.Crypto.SKEM
  alias Bunny.Crypto.EKEM
  alias Bunny.Crypto.AEAD

  @moduledoc """
  Provides basic cryptographic helper functions, most of them being defined in the whitepaper.
  """

  @type biscuit_ct :: <<_::800>>
  @type biscuit_ctr :: Biscuit.biscuit_no()
  @type chaining_key :: key()
  @type hash :: <<_::256>>
  @type kem :: :ekem | :skem
  @type kem_ct :: EKEM.cipher_text() | SKEM.cipher_text()
  @type kem_pk :: EKEM.public_key() | SKEM.public_key()
  @type kem_sk :: EKEM.secret_key() | SKEM.secret_key()
  @type key :: <<_::256>>
  @type session_id :: <<_::32>>

  @doc """
  A keyed hash function with one 32-byte input, one variable-size input, and one 32-byte output.
  As keyed hash function we use the HMAC construction with BLAKE2s as the inner hash function.
  """
  @spec hash(key(), binary()) :: hash()
  def hash(key, data) do
    ipad = :binary.list_to_bin(List.duplicate(0x36, 32))
    opad = :binary.list_to_bin(List.duplicate(0x5C, 32))

    ikey = :crypto.exor(key, ipad)
    okey = :crypto.exor(key, opad)

    :enacl.generichash(32, :enacl.generichash(32, data, ikey), okey)
  end

  @doc """
  A shorthand hash function derived from the protocol identifier.
  """
  @spec lhash(binary()) :: hash()
  def lhash(data) do
    hash(<<0::256>>, "Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 BLAKE2s") |> hash(data)
  end

  @doc """
  A shorthand hash function derived from the chaining key extract.
  """
  @spec extract_key(binary()) :: key()
  def extract_key(data) do
    lhash("chaining key extract") |> hash(data)
  end

  @doc """
  A shorthand hash function derived from the user.
  """
  @spec export_key(binary()) :: key()
  def export_key(data) do
    extract_key("user") |> hash(data)
  end

  @doc """
  Mixes secrets and public values into the chaining key.
  """
  @spec mix(chaining_key(), binary()) :: chaining_key()
  def mix(ck, data) do
    ck |> hash(extract_key("mix")) |> hash(data)
  end

  @doc """
  Encrypts data based on the current chaining key.
  """
  @spec encrypt_and_mix(chaining_key(), binary()) :: {chaining_key(), binary()}
  def encrypt_and_mix(ck, pt) do
    k = ck |> hash(extract_key("handshake encryption"))
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
    k = ck |> hash(extract_key("handshake encryption"))
    n = <<0::96>>
    ad = <<>>
    <<pt::binary>> = AEAD.dec(k, n, ct, ad)
    ck = mix(ck, ct)
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

    ck = ck |> mix(pk) |> mix(shk) |> mix(ct)
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

    ck |> mix(pk) |> mix(shk) |> mix(ct)
  end

  @spec store_biscuit(
          chaining_key(),
          biscuit_ctr(),
          key(),
          SKEM.public_key(),
          SKEM.public_key(),
          session_id(),
          session_id()
        ) :: {chaining_key(), biscuit_ctr(), biscuit_ct()}
  def store_biscuit(ck, ctr, k, spki, spkr, sidi, sidr) do
    ctr = ctr + 1

    n = :enacl.randombytes(24)

    pt =
      Biscuit.encode(%Biscuit{
        pidi: lhash("peer id") |> hash(spki),
        biscuit_no: ctr,
        ck: ck
      })

    ad = lhash("biscuit additional data") |> hash(spkr) |> hash(sidi) |> hash(sidr)
    ct = XAEAD.enc(k, n, pt, ad)
    nct = n <> ct

    ck = ck |> mix(nct)
    {ck, ctr, nct}
  end

  @doc """
  Generates a random biscuit key in a cryptographic strong fashion.
  """
  @spec random_biscuit_key() :: key()
  def random_biscuit_key() do
    :enacl.randombytes(32)
  end

  @doc """
  Generates a random session ID in a cryptographic strong fashion.
  """
  @spec random_session_id() :: session_id()
  def random_session_id() do
    :enacl.randombytes(4)
  end
end
