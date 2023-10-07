defmodule Bunny.Envelope.BiscuitTest do
  alias Bunny.Envelope.Biscuit
  use ExUnit.Case, async: true
  doctest Biscuit

  test "encodes a biscuit" do
    pidi = :enacl.randombytes(32)
    ck = :enacl.randombytes(32)

    biscuit = %Biscuit{
      pidi: pidi,
      biscuit_no: <<42::96>>,
      ck: ck
    }

    assert Biscuit.encode(biscuit) == pidi <> <<42::96>> <> ck
  end

  test "encodes a biscuit with an overflowed counter" do
    pidi = :enacl.randombytes(32)
    ck = :enacl.randombytes(32)

    biscuit = %Biscuit{pidi: pidi, biscuit_no: <<2 ** 96 + 69::96>>, ck: ck}

    assert Biscuit.encode(biscuit) == pidi <> <<69::96>> <> ck
  end

  test "decodes a biscuit" do
    pidi = :enacl.randombytes(32)
    ck = :enacl.randombytes(32)

    biscuit = Biscuit.decode(pidi <> <<42::96>> <> ck)

    assert biscuit == %Biscuit{pidi: pidi, biscuit_no: <<42::96>>, ck: ck}
  end

  test "decodes a biscuit with an overflowed counter" do
    pidi = :enacl.randombytes(32)
    ck = :enacl.randombytes(32)

    biscuit = Biscuit.decode(pidi <> <<2 ** 96 + 69::96>> <> ck)

    assert biscuit == %Biscuit{pidi: pidi, biscuit_no: <<2 ** 96 + 69::96>>, ck: ck}
  end
end
