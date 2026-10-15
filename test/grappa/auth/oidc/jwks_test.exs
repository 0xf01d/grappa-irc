defmodule Grappa.Auth.Oidc.JwksTest do
  @moduledoc """
  `Grappa.Auth.Oidc.Jwks`: the signing-key filter that keeps a
  provider's ENCRYPTION keys out of the verifier's key set, the cache,
  and the named transport/shape refusals (review L2/L3).

  `async: false` — the cache is a global `:persistent_term` slot keyed by
  `jwks_uri`.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Grappa.Auth.Oidc.{Discovery, Jwks}

  defp discovery(jwks_uri) do
    %Discovery{
      issuer: "https://idm.example.com/oauth2/openid/grappa",
      authorization_endpoint: "https://idm.example.com/authorize",
      token_endpoint: "https://idm.example.com/token",
      jwks_uri: jwks_uri
    }
  end

  defp rsa_public_map do
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    {_, public} = JOSE.JWK.to_public_map(jwk)
    public
  end

  describe "filter_signing_keys/1" do
    test "a bare signing key is eligible" do
      key = rsa_public_map()
      assert {:ok, [^key]} = Jwks.filter_signing_keys([key])
    end

    test "use:\"sig\" is eligible" do
      key = Map.put(rsa_public_map(), "use", "sig")
      assert {:ok, [^key]} = Jwks.filter_signing_keys([key])
    end

    test "a use:\"enc\" key is dropped" do
      enc = Map.put(rsa_public_map(), "use", "enc")
      sig = rsa_public_map()
      assert {:ok, [^sig]} = Jwks.filter_signing_keys([enc, sig])
    end

    test "key_ops including verify is eligible" do
      key = Map.put(rsa_public_map(), "key_ops", ["verify"])
      assert {:ok, [^key]} = Jwks.filter_signing_keys([key])
    end

    test "key_ops without verify is dropped" do
      key = Map.put(rsa_public_map(), "key_ops", ["encrypt"])
      sig = rsa_public_map()
      assert {:ok, [^sig]} = Jwks.filter_signing_keys([key, sig])
    end

    test "a non-list key_ops is dropped" do
      key = Map.put(rsa_public_map(), "key_ops", "verify")
      assert {:error, :provider_unavailable} = Jwks.filter_signing_keys([key])
    end

    test "a key with no kty is dropped" do
      key = Map.delete(rsa_public_map(), "kty")
      assert {:error, :provider_unavailable} = Jwks.filter_signing_keys([key])
    end

    test "an empty key set is a provider-unavailable, not an empty success" do
      assert {:error, :provider_unavailable} = Jwks.filter_signing_keys([])
    end

    test "a non-list is a provider-unavailable" do
      assert {:error, :provider_unavailable} = Jwks.filter_signing_keys(%{"keys" => []})
    end
  end

  describe "signing_keys/1 — cache" do
    test "a freshly cached key set is served without any network" do
      uri = "https://idm.example.com/jwks/#{System.unique_integer([:positive])}"
      key = rsa_public_map()
      Jwks.put_test_keys(uri, [key])
      on_exit(fn -> :persistent_term.erase({Jwks, uri}) end)

      assert {:ok, [^key]} = Jwks.signing_keys(discovery(uri))
    end
  end

  describe "refresh/1 — transport and shape refusals are named (review L2/L3)" do
    setup do
      bypass = Bypass.open()
      uri = "http://localhost:#{bypass.port}/jwks"
      on_exit(fn -> :persistent_term.erase({Jwks, uri}) end)
      {:ok, bypass: bypass, uri: uri}
    end

    test "a valid key set is fetched, filtered and cached", %{bypass: bypass, uri: uri} do
      sig = Map.put(rsa_public_map(), "kid", "k1")

      Bypass.expect(bypass, "GET", "/jwks", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{"keys" => [sig]}))
      end)

      assert {:ok, [^sig]} = Jwks.refresh(discovery(uri))
      assert {:ok, [_]} = Jwks.signing_keys(discovery(uri))
    end

    test "a key set with only enc keys is refused and the reason logged", %{
      bypass: bypass,
      uri: uri
    } do
      enc = Map.put(rsa_public_map(), "use", "enc")

      Bypass.expect(bypass, "GET", "/jwks", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{"keys" => [enc]}))
      end)

      log = capture_log(fn -> assert {:error, :provider_unavailable} = Jwks.refresh(discovery(uri)) end)
      assert log =~ "publishes no signing keys"
    end

    test "a 200 without a keys member is refused and named", %{bypass: bypass, uri: uri} do
      Bypass.expect(bypass, "GET", "/jwks", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, ~s({"not_keys": []}))
      end)

      log = capture_log(fn -> assert {:error, :provider_unavailable} = Jwks.refresh(discovery(uri)) end)
      assert log =~ "without a keys member"
    end

    test "a non-200 is refused and the status is named", %{bypass: bypass, uri: uri} do
      Bypass.expect(bypass, "GET", "/jwks", fn conn -> Plug.Conn.resp(conn, 503, "") end)

      log = capture_log(fn -> assert {:error, :provider_unavailable} = Jwks.refresh(discovery(uri)) end)
      assert log =~ "HTTP 503"
    end

    test "an unreachable provider is refused and the cause is logged", %{bypass: bypass, uri: uri} do
      Bypass.down(bypass)

      log = capture_log(fn -> assert {:error, :provider_unavailable} = Jwks.refresh(discovery(uri)) end)
      assert log =~ "oidc jwks:"
    end

    test "a jwks_uri carrying a newline cannot forge a log line (review L3)" do
      injected = "http://localhost:1/x\r\noidc jwks: FORGED ADMIN LINE"

      log = capture_log(fn -> assert {:error, :provider_unavailable} = Jwks.refresh(discovery(injected)) end)

      refute log =~ "\noidc jwks: FORGED ADMIN LINE"
      assert log =~ "FORGED ADMIN LINE"
    end
  end
end
