defmodule Bunny.CryptoTest do
  alias Bunny.Crypto.SKEM
  alias Bunny.Crypto.EKEM
  alias Bunny.Crypto
  use ExUnit.Case, async: true
  doctest Crypto

  test "computes a hash" do
    assert Crypto.lhash("foo") ==
             <<112, 52, 139, 163, 205, 14, 141, 28, 7, 60, 237, 160, 177, 226, 204, 188, 220, 73,
               169, 243, 12, 114, 32, 228, 26, 176, 28, 167, 213, 31, 88, 173>>
  end

  test "extracts a key" do
    assert Crypto.extract_key("foo") ==
             <<27, 128, 62, 119, 138, 249, 122, 13, 187, 86, 76, 245, 132, 87, 229, 23, 79, 112,
               44, 87, 104, 151, 243, 248, 176, 183, 158, 19, 32, 81, 178, 99>>
  end

  test "exports a key" do
    assert Crypto.export_key("foo") ==
             <<228, 65, 221, 101, 139, 229, 237, 188, 129, 234, 9, 98, 220, 97, 236, 243, 14, 204,
               144, 6, 139, 68, 5, 86, 176, 36, 64, 105, 12, 12, 116, 255>>
  end

  test "mixes a value" do
    assert Crypto.mix(Crypto.lhash(""), "foo") ==
             <<52, 229, 118, 1, 191, 107, 5, 80, 228, 139, 179, 143, 246, 70, 170, 114, 183, 220,
               130, 249, 121, 178, 32, 200, 207, 75, 134, 204, 44, 181, 122, 154>>
  end

  test "encrypt and decrypt" do
    ck = :enacl.randombytes(32)
    pt = :enacl.randombytes(64)
    {ck_new, ct} = Crypto.encrypt_and_mix(ck, pt)

    assert Crypto.decrypt_and_mix(ck, ct) == {ck_new, pt}
  end

  test "encaps and decaps (EKEM)" do
    {pk, sk} = EKEM.gen_key()
    ck = :enacl.randombytes(32)
    {ck_new, ct} = Crypto.encaps_and_mix(:ekem, ck, pk)

    assert Crypto.decaps_and_mix(:ekem, ck, sk, pk, ct) == ck_new
  end

  test "encaps and decaps (SKEM)" do
    {pk, sk} = SKEM.gen_key()
    ck = :enacl.randombytes(32)
    {ck_new, ct} = Crypto.encaps_and_mix(:skem, ck, pk)

    assert Crypto.decaps_and_mix(:skem, ck, sk, pk, ct) == ck_new
  end

  test "generates a random session id" do
    sid = Crypto.random_session_id()
    assert byte_size(sid) == 4
  end
end
