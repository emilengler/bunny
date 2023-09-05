defmodule Bunny.Crypto.SKEM do
  @moduledoc """
  We use Classic McEliece 460896 which claims to be as hard to break as 192-bit AES.
  As one of the oldest post-quantum-secure KEMs, it enjoys wide trust among cryptographers, but it has not been chosen for standardization by NIST.
  Its ciphertexts and private keys are small (188 bytes and 13568 bytes), and its public keys are large (524160 bytes).
  This fits our use case: public keys are exchanged out-of-band, and only the small ciphertexts have to be transmitted during the handshake.
  """

  @spec enc(:pqclean_nif.mceliece460896_public_key()) ::
          {:pqclean_nif.mceliece460896_cipher_text(), :pqclean_nif.mceliece460896_shared_secret()}
  def enc(public_key) do
    :pqclean_nif.mceliece460896_encapsulate(public_key)
  end

  @spec dec(:pqclean_nif.mceliece460896_secret_key(), :pqclean_nif.mceliece460896_cipher_text()) ::
          :pqclean_nif.mceliece460896_shared_secret()
  def dec(secret_key, ciphertext) do
    :pqclean_nif.mceliece460896_decapsulate(ciphertext, secret_key)
  end
end
