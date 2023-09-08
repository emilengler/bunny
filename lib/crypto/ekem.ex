defmodule Bunny.Crypto.EKEM do
  @type public_key :: :pqclean_nif.kyber512_public_key()
  @type secret_key :: :pqclean_nif.kyber512_secret_key()
  @type cipher_text :: :pqclean_nif.kyber512_cipher_text()
  @type shared_secret :: :pqclean_nif.kyber512_shared_secret()

  @spec enc(public_key()) :: {cipher_text(), shared_secret()}
  def enc(public_key) do
    :pqclean_nif.kyber512_encapsulate(public_key)
  end

  @spec dec(secret_key(), cipher_text()) :: shared_secret()
  def dec(secret_key, ciphertext) do
    :pqclean_nif.kyber512_decapsulate(ciphertext, secret_key)
  end

  @spec gen_key() :: {public_key(), secret_key()}
  def gen_key() do
    :pqclean_nif.kyber512_keypair()
  end
end
