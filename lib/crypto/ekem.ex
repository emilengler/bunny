defmodule Bunny.Crypto.EKEM do
  @spec enc(:pqclean_nif.kyber512_public_key()) ::
          {:pqclean_nif.kyber512_cipher_text(), :pqclean_nif.kyber512_shared_secret()}
  def enc(public_key) do
    :pqclean_nif.kyber512_encapsulate(public_key)
  end

  @spec dec(:pqclean_nif.kyber512_secret_key(), :pqclean_nif.kyber512_cipher_text()) ::
          :pqclean_nif.kyber512_shared_secret()
  def dec(secret_key, ciphertext) do
    :pqclean_nif.kyber512_decapsulate(ciphertext, secret_key)
  end
end
