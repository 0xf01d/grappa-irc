defmodule Grappa.Auth.Oidc.TransactionTest do
  @moduledoc """
  `Grappa.Auth.Oidc.Transaction`: the single-use round-trip store — the
  take-consumes-it semantics that close authorization-code replay, the
  TTL, and the browser-binder requirement on a `:login` transaction.
  """

  use ExUnit.Case, async: false

  alias Grappa.Auth.Oidc.Transaction

  describe "put/3" do
    test "a :login transaction carries a verifier, nonce and binder" do
      %{id: id, transaction: txn} = Transaction.put(:login, nil, "browser-binder")

      assert is_binary(id)
      assert txn.intent == :login
      assert txn.user_id == nil
      assert txn.binder == "browser-binder"
      assert is_binary(txn.verifier)
      assert is_binary(txn.nonce)
    end

    test "a :link transaction carries the account and no binder" do
      user_id = Ecto.UUID.generate()
      %{transaction: txn} = Transaction.put(:link, user_id, nil)

      assert txn.intent == :link
      assert txn.user_id == user_id
      assert txn.binder == nil
    end

    test "a :login transaction without a binder is refused" do
      assert_raise FunctionClauseError, fn -> Transaction.put(:login, nil, "") end
    end

    test "the verifier and nonce are fresh per transaction" do
      a = Transaction.put(:login, nil, "b").transaction
      b = Transaction.put(:login, nil, "b").transaction

      refute a.verifier == b.verifier
      refute a.nonce == b.nonce
    end

    test "the PKCE verifier is a 43..128-char base64url string (RFC 7636)" do
      verifier = Transaction.put(:login, nil, "b").transaction.verifier

      assert byte_size(verifier) in 43..128
      assert verifier == Base.url_encode64(Base.url_decode64!(verifier, padding: false), padding: false)
    end
  end

  describe "take/1,2" do
    test "a transaction is consumed exactly once" do
      %{id: id, transaction: txn} = Transaction.put(:login, nil, "b")
      now = System.monotonic_time(:second)

      assert {:ok, ^txn} = Transaction.take(id, now)
      assert {:error, :invalid_transaction} = Transaction.take(id, now)
    end

    test "an unknown id is refused" do
      assert {:error, :invalid_transaction} =
               Transaction.take(Ecto.UUID.generate(), System.monotonic_time(:second))
    end

    test "a transaction past its TTL is refused and swept" do
      %{id: id} = Transaction.put(:login, nil, "b")
      future = System.monotonic_time(:second) + Transaction.ttl_seconds() + 1

      assert {:error, :invalid_transaction} = Transaction.take(id, future)
    end
  end

  describe "ttl_seconds/0" do
    test "is the module's compile-time singleton" do
      assert Transaction.ttl_seconds() == 300
    end
  end
end
