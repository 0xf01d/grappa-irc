defmodule Grappa.Auth.Oidc.IdTokenTest do
  @moduledoc """
  Adversarial tests for `Grappa.Auth.Oidc.IdToken`: every refusal the
  module claims to make is driven with a token that MUST be refused, so
  losing the check turns a green here red.

  `async: false` throughout: the JWKS cache the signing-key lookups read
  is a global `:persistent_term` slot, and these tests install into it.
  """

  use ExUnit.Case, async: false

  alias Grappa.Auth.Oidc.{Config, Discovery, IdToken, Jwks}

  @issuer "https://idp.example.com/oauth2/openid/grappa"
  @client_id "grappa"
  @nonce "the-nonce"
  @now 1_700_000_000

  defp config do
    %Config{
      issuer: @issuer,
      client_id: @client_id,
      client_secret: "s3cret",
      redirect_uri: "https://app.example.com/auth/oidc/callback",
      scopes: "openid profile email",
      users_group: nil,
      admins_group: nil
    }
  end

  defp discovery(jwks_uri) do
    %Discovery{
      issuer: @issuer,
      authorization_endpoint: @issuer <> "/authorize",
      token_endpoint: @issuer <> "/token",
      jwks_uri: jwks_uri
    }
  end

  # A fresh RSA keypair plus the PUBLIC JWK map (with the `kid` the
  # verifier keys on) a JWKS would publish.
  defp pair(kid) do
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    {_, public} = JOSE.JWK.to_public_map(jwk)
    %{jwk: jwk, public: Map.put(public, "kid", kid)}
  end

  defp claims(overrides) do
    Map.merge(
      %{
        "iss" => @issuer,
        "aud" => @client_id,
        "exp" => @now + 300,
        "nonce" => @nonce,
        "sub" => "user-uuid"
      },
      overrides
    )
  end

  defp without(key), do: Map.delete(claims(%{}), key)

  # Installs a unique JWKS cache slot for this test and returns a
  # discovery struct pointing at it. Uniqueness (not just cleanup) keeps a
  # later test from inheriting an earlier one's keys.
  defp with_keys(keys) do
    jwks_uri = "https://idp.example.com/jwks/" <> Integer.to_string(System.unique_integer([:positive]))
    Jwks.put_test_keys(jwks_uri, keys)
    disc = discovery(jwks_uri)
    on_exit(fn -> :persistent_term.erase({Jwks, jwks_uri}) end)
    disc
  end

  defp sign(pair, override_claims, override_header) do
    header = Map.merge(%{"alg" => "RS256", "kid" => pair.public["kid"]}, override_header)
    compact(JOSE.JWT.sign(pair.jwk, header, claims(override_claims)))
  end

  defp sign_without_kid(pair, override_claims) do
    compact(JOSE.JWT.sign(pair.jwk, %{"alg" => "RS256"}, claims(override_claims)))
  end

  # `JOSE.JWT.sign/3` hands back the flattened JWS representation; the
  # compact `a.b.c` serialization is its `protected.payload.signature`.
  defp compact({_, jws}) do
    {_, compact} = JOSE.JWS.compact(jws)
    compact
  end

  defp none_token(override_claims) do
    header = %{"alg" => "none"} |> Jason.encode!() |> Base.url_encode64(padding: false)
    payload = override_claims |> claims() |> Jason.encode!() |> Base.url_encode64(padding: false)
    header <> "." <> payload <> "."
  end

  describe "verify/5 — signature and algorithm" do
    test "a well-signed RS256 token with the full claim set verifies" do
      p = pair("k1")
      disc = with_keys([p.public])

      assert {:ok, %IdToken{subject: "user-uuid", claims: claims}} =
               IdToken.verify(sign(p, %{}, %{}), config(), disc, @nonce, @now)

      assert claims["iss"] == @issuer
    end

    test "alg:none is refused even with a signing key installed" do
      p = pair("k1")
      disc = with_keys([p.public])

      assert {:error, :invalid_token} =
               IdToken.verify(none_token(%{}), config(), disc, @nonce, @now)
    end

    test "an HS256 header is refused before the RSA key is selected (algorithm confusion)" do
      p = pair("k1")
      disc = with_keys([p.public])

      # A genuinely HS256-signed token wearing the RSA key's `kid`: the
      # allowlist refuses the alg, so the RSA public key is never treated
      # as an HMAC secret.
      oct = JOSE.JWK.generate_key({:oct, 32})
      hs = compact(JOSE.JWT.sign(oct, %{"alg" => "HS256", "kid" => "k1"}, claims(%{})))

      assert {:error, :invalid_token} = IdToken.verify(hs, config(), disc, @nonce, @now)
    end

    test "a tampered payload leaves the signature invalid" do
      p = pair("k1")
      disc = with_keys([p.public])
      [h, _, sig] = String.split(sign(p, %{}, %{}), ".")

      forged_payload =
        %{"sub" => "attacker"} |> claims() |> Jason.encode!() |> Base.url_encode64(padding: false)

      assert {:error, :invalid_token} =
               IdToken.verify(h <> "." <> forged_payload <> "." <> sig, config(), disc, @nonce, @now)
    end

    test "a malformed compact serialization refuses rather than raising" do
      disc = with_keys([])

      assert {:error, :invalid_token} = IdToken.verify("not-a-jwt", config(), disc, @nonce, @now)
      assert {:error, :invalid_token} = IdToken.verify("a.b", config(), disc, @nonce, @now)
    end

    test "a protected header that is not a JSON object refuses" do
      disc = with_keys([])
      header = Base.url_encode64("[1,2]", padding: false)

      assert {:error, :invalid_token} =
               IdToken.verify(header <> ".payload.sig", config(), disc, @nonce, @now)
    end
  end

  describe "verify/5 — key selection" do
    test "an unknown kid is refused" do
      p = pair("k1")
      disc = with_keys([p.public])

      assert {:error, :invalid_token} =
               IdToken.verify(sign(p, %{}, %{"kid" => "nope"}), config(), disc, @nonce, @now)
    end

    test "a duplicate kid is refused as ambiguous" do
      p = pair("k1")
      disc = with_keys([p.public, p.public])

      assert {:error, :invalid_token} = IdToken.verify(sign(p, %{}, %{}), config(), disc, @nonce, @now)
    end

    test "no kid with a single published key verifies (the common deployment)" do
      p = pair("k1")
      disc = with_keys([p.public])

      assert {:ok, %IdToken{}} =
               IdToken.verify(sign_without_kid(p, %{}), config(), disc, @nonce, @now)
    end

    test "no kid with two published keys is refused as ambiguous" do
      p = pair("k1")
      q = pair("k2")
      disc = with_keys([p.public, q.public])

      assert {:error, :invalid_token} =
               IdToken.verify(sign_without_kid(p, %{}), config(), disc, @nonce, @now)
    end

    test "a rotated JWKS stops verifying the old key and accepts the new one" do
      old = pair("k1")
      new = pair("k1")
      disc = with_keys([old.public])
      old_token = sign(old, %{}, %{})
      assert {:ok, %IdToken{}} = IdToken.verify(old_token, config(), disc, @nonce, @now)

      Jwks.put_test_keys(disc.jwks_uri, [new.public])

      assert {:error, :invalid_token} = IdToken.verify(old_token, config(), disc, @nonce, @now)
      assert {:ok, %IdToken{}} = IdToken.verify(sign(new, %{}, %{}), config(), disc, @nonce, @now)
    end

    test "an enc-purpose key is dropped before key selection" do
      bypass = Bypass.open()
      signing = pair("sig")
      encryption = pair("enc")

      Bypass.expect(bypass, "GET", "/jwks", fn conn ->
        keys = [Map.put(encryption.public, "use", "enc"), signing.public]

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{"keys" => keys}))
      end)

      jwks_uri = "http://localhost:#{bypass.port}/jwks"
      on_exit(fn -> :persistent_term.erase({Jwks, jwks_uri}) end)
      disc = discovery(jwks_uri)

      # The enc key cannot sign as far as this verifier is concerned ...
      assert {:error, :invalid_token} =
               IdToken.verify(sign(encryption, %{}, %{}), config(), disc, @nonce, @now)

      # ... but the real signing key beside it still verifies.
      assert {:ok, %IdToken{}} = IdToken.verify(sign(signing, %{}, %{}), config(), disc, @nonce, @now)
    end
  end

  describe "verify_claims/5 — claim forgery" do
    test "a well-formed claim set verifies" do
      assert {:ok, %IdToken{subject: "sub-1"}} =
               IdToken.verify_claims(claims(%{"sub" => "sub-1"}), config(), discovery("x"), @nonce, @now)
    end

    test "a trailing-slash issuer is still the same issuer" do
      assert {:ok, %IdToken{}} =
               IdToken.verify_claims(
                 claims(%{"iss" => @issuer <> "/"}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "a wrong issuer is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 claims(%{"iss" => "https://evil.example.com"}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "a missing issuer is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(without("iss"), config(), discovery("x"), @nonce, @now)
    end

    test "a wrong audience is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 claims(%{"aud" => "somebody-else"}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "a non-string audience is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(claims(%{"aud" => 42}), config(), discovery("x"), @nonce, @now)
    end

    test "multi-audience with azp naming this client verifies" do
      assert {:ok, %IdToken{}} =
               IdToken.verify_claims(
                 claims(%{"aud" => ["grappa", "other"], "azp" => @client_id}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "multi-audience carrying this client but NO azp is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 claims(%{"aud" => ["grappa", "other"]}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "multi-audience with a foreign azp is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 claims(%{"aud" => ["grappa", "other"], "azp" => "other"}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "multi-audience missing this client is refused even with azp" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 claims(%{"aud" => ["other", "another"], "azp" => @client_id}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "a single-audience token with a foreign azp is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 claims(%{"azp" => "other"}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "a missing exp is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 without("exp"),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "an expired token is :expired_token, past the leeway" do
      assert {:error, :expired_token} =
               IdToken.verify_claims(
                 claims(%{"exp" => @now - 61}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "an exp inside the leeway is still accepted" do
      assert {:ok, %IdToken{}} =
               IdToken.verify_claims(
                 claims(%{"exp" => @now - 30}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "a non-integer exp is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 claims(%{"exp" => "soon"}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "an nbf beyond the leeway is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 claims(%{"nbf" => @now + 61}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "an nbf inside the leeway is accepted" do
      assert {:ok, %IdToken{}} =
               IdToken.verify_claims(
                 claims(%{"nbf" => @now + 30}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "an absent nbf is accepted" do
      assert {:ok, %IdToken{}} = IdToken.verify_claims(claims(%{}), config(), discovery("x"), @nonce, @now)
    end

    test "a wildly stale iat is accepted: iat is not a freshness gate" do
      assert {:ok, %IdToken{}} =
               IdToken.verify_claims(
                 claims(%{"iat" => @now - 86_400}),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "a mismatched nonce is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(claims(%{"nonce" => "other"}), config(), discovery("x"), @nonce, @now)
    end

    test "a missing nonce is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 without("nonce"),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "a non-string nonce is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(claims(%{"nonce" => 5}), config(), discovery("x"), @nonce, @now)
    end

    test "a missing subject is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(
                 without("sub"),
                 config(),
                 discovery("x"),
                 @nonce,
                 @now
               )
    end

    test "an empty subject is refused" do
      assert {:error, :invalid_token} =
               IdToken.verify_claims(claims(%{"sub" => ""}), config(), discovery("x"), @nonce, @now)
    end
  end
end
