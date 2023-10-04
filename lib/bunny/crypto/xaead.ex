defmodule Bunny.Crypto.XAEAD do
  @moduledoc """
  Authenticated encryption with additional data for use with random nonces.
  We use XChaCha20Poly1305 in the implementation, a construction also used by WireGuard.
  """

  @type secret_key :: <<_::256>>
  @type nonce :: <<_::192>>

  @spec enc(secret_key(), nonce(), binary(), binary()) :: binary()
  def enc(key, nonce, plaintext, additional_data) do
    :enacl.aead_xchacha20poly1305_ietf_encrypt(plaintext, additional_data, nonce, key)
  end

  @spec dec(secret_key(), nonce(), binary(), binary()) :: binary()
  def dec(key, nonce, ciphertext, additional_data) do
    :enacl.aead_xchacha20poly1305_ietf_decrypt(ciphertext, additional_data, nonce, key)
  end
end
