defmodule Bunny.Crypto.EKEM do
  @moduledoc """
  We use Kyber-512 [7], which has been selected in the NIST post-quantum
  cryptography competition and claims to be as hard to break as 128-bit AES.
  Its ciphertexts, public keys, and private keys are 768, 800, and 1632 bytes
  long, respectively, providing a good balance for our use case as both a public
  key and a ciphertext have to be transmitted during the handshake.
  """
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
