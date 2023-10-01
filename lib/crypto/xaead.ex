defmodule Bunny.Crypto.XAEAD do
  @moduledoc """
  Authenticated encryption with additional data for use with random nonces.
  We use XChaCha20Poly1305 in the implementation, a construction also used by WireGuard.
  """

  @key_len 32
  @nonce_len 24

  @spec enc(binary(), binary(), binary(), binary()) :: binary()
  def enc(key, nonce, plaintext, additional_data) do
    true = byte_size(key) == @key_len
    true = byte_size(nonce) == @nonce_len

    :enacl.aead_xchacha20poly1305_ietf_encrypt(plaintext, additional_data, nonce, key)
  end

  @spec dec(binary(), binary(), binary(), binary()) :: binary()
  def dec(key, nonce, ciphertext, additional_data) do
    true = byte_size(key) == @key_len
    true = byte_size(nonce) == @nonce_len

    :enacl.aead_xchacha20poly1305_ietf_decrypt(ciphertext, additional_data, nonce, key)
  end
end
