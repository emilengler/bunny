defmodule Bunny.Crypto.AEAD do
  @moduledoc """
  Authenticated encryption with additional data for use with sequential nonces.
  We use ChaCha20Poly1305 in the implementation.
  """

  @spec enc(binary(), binary(), binary(), binary()) :: binary()
  def enc(key, nonce, plaintext, additional_data) do
    true = byte_size(key) == 32
    true = byte_size(nonce) == 12

    :enacl.aead_chacha20poly1305_ietf_encrypt(plaintext, additional_data, nonce, key)
  end

  @spec dec(binary(), binary(), binary(), binary()) :: binary()
  def dec(key, nonce, ciphertext, additional_data) do
    true = byte_size(key) == 32
    true = byte_size(nonce) == 12

    :enacl.aead_chacha20poly1305_ietf_decrypt(ciphertext, additional_data, nonce, key)
  end
end
