defmodule Bunny.Protocol.Initiator do
  @moduledoc """
  The Rosenpass protocol initiator.
  """
  alias Bunny.Crypto.SKEM
  alias Bunny.Envelope
  alias Bunny.Crypto.EKEM
  alias Bunny.Crypto

  @type state :: %{ck: Crypto.chaining_key(), eski: EKEM.secret_key(), epki: EKEM.public_key()}

  @spec init_hello(SKEM.public_key(), SKEM.public_key(), binary()) :: {state(), Envelope.t()}
  def init_hello(spki, spkr, psk) do
    # TODO: Check lengths
    # TODO: Add logging

    # IHI1
    ck = Crypto.hash(Crypto.lhash("chaining key init"), spkr)
    # IHI2
    sidi = Crypto.random_session_id()
    # IHI3
    {epki, eski} = EKEM.gen_key()
    # IHI4
    ck = Crypto.mix(ck, sidi)
    ck = Crypto.mix(ck, epki)
    # IHI5
    {ck, sctr} = Crypto.encaps_and_mix(:skem, ck, spkr)
    # IHI6
    pidi = Crypto.hash(Crypto.lhash("peer id"), spki)
    {ck, pidiC} = Crypto.encrypt_and_mix(ck, pidi)
    # IHI7
    ck = Crypto.mix(ck, spki)
    ck = Crypto.mix(ck, psk)
    # IHI8
    {ck, auth} = Crypto.encrypt_and_mix(ck, <<>>)

    envelope = %Envelope{
      type: :init_hello,
      payload: %Envelope.InitHello{
        sidi: sidi,
        epki: epki,
        sctr: sctr,
        pidiC: pidiC,
        auth: auth
      },
      mac: <<0::128>>,
      cookie: <<0::128>>
    }

    envelope = Envelope.seal(spkr, envelope)

    {%{ck: ck, eski: eski, epki: epki}, envelope}
  end
end