defmodule GrappaWeb.OidcControllerTest do
  @moduledoc """
  The browser legs of the OIDC door (#1911): capability probe, the
  browser-binder requirement on a login navigation, the forged/foreign
  `state` refusal on the callback, and the password gate on the
  credential-changing `/me/oidc` writes.

  `async: false` — the enabled/disabled door is read from a global
  `:persistent_term` slot, and the throttle window is global ETS.
  """

  use GrappaWeb.ConnCase, async: false

  import Grappa.AuthFixtures

  alias Grappa.Accounts.{TOTP, User}
  alias Grappa.Auth.Oidc
  alias Grappa.Auth.Oidc.{Config, Discovery, Jwks}
  alias Grappa.RateLimit.FailureWindow

  @issuer "https://idm.example.com/oauth2/openid/grappa"
  @password "correct-horse-battery-staple"

  setup do
    original = :persistent_term.get({Config, :config}, :__unset__)

    on_exit(fn ->
      case original do
        :__unset__ -> :persistent_term.erase({Config, :config})
        cfg -> Config.put_test_config(cfg)
      end

      :persistent_term.erase({Discovery, @issuer})
      FailureWindow.clear(:oidc_login, "127.0.0.1")
    end)

    FailureWindow.clear(:oidc_login, "127.0.0.1")
    :ok
  end

  defp enable_oidc do
    Config.put_test_config(%Config{
      issuer: @issuer,
      client_id: "grappa",
      client_secret: "s3cret",
      redirect_uri: "https://app.example.com/auth/oidc/callback",
      scopes: "openid profile email",
      users_group: nil,
      admins_group: nil
    })

    Discovery.put_test_discovery(@issuer, %Discovery{
      issuer: @issuer,
      authorization_endpoint: @issuer <> "/authorize",
      token_endpoint: @issuer <> "/token",
      jwks_uri: @issuer <> "/jwks"
    })

    :ok
  end

  defp fragment(conn) do
    location = conn |> get_resp_header("location") |> List.first()
    "/login#oidc=" <> encoded = location
    encoded |> Base.url_decode64!(padding: false) |> Jason.decode!()
  end

  defp oidc_config(overrides) do
    struct!(
      %Config{
        issuer: @issuer,
        client_id: "grappa",
        client_secret: "s3cret",
        redirect_uri: "https://app.example.com/auth/oidc/callback",
        scopes: "openid profile email",
        users_group: nil,
        admins_group: nil
      },
      overrides
    )
  end

  # A full round trip needs a reached provider: the discovery document is
  # installed directly with its token_endpoint at a Bypass server and its
  # jwks_uri holding a test signing key. Returns the bypass, the private
  # signing key, and the public JWKS `kid`.
  defp enable_round_trip(overrides) do
    bypass = Bypass.open()
    key = JOSE.JWK.generate_key({:rsa, 2048})
    {_, public} = JOSE.JWK.to_public_map(key)
    jwks_key = Map.put(public, "kid", "k1")
    jwks_uri = "https://idp.example.com/jwks/round-trip"

    Jwks.put_test_keys(jwks_uri, [jwks_key])
    on_exit(fn -> :persistent_term.erase({Jwks, jwks_uri}) end)

    Config.put_test_config(oidc_config(overrides))

    Discovery.put_test_discovery(@issuer, %Discovery{
      issuer: @issuer,
      authorization_endpoint: @issuer <> "/authorize",
      token_endpoint: "http://localhost:#{bypass.port}/token",
      jwks_uri: jwks_uri
    })

    {bypass, key}
  end

  defp id_claims(nonce, overrides) do
    Map.merge(
      %{
        "iss" => @issuer,
        "aud" => "grappa",
        "exp" => System.system_time(:second) + 300,
        "nonce" => nonce,
        "sub" => "sub-1"
      },
      overrides
    )
  end

  defp id_token(key, claims) do
    {_, jws} = JOSE.JWT.sign(key, %{"alg" => "RS256", "kid" => "k1"}, claims)
    {_, compact} = JOSE.JWS.compact(jws)
    compact
  end

  defp expect_token(bypass, body) do
    Bypass.expect(bypass, "POST", "/token", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(body))
    end)
  end

  # Runs the authorize door and lifts the state + nonce the server minted
  # out of the provider redirect, so a test can complete the round trip.
  defp begin_login(conn) do
    conn = get(conn, "/auth/oidc/authorize?bind=browser-binder")
    location = conn |> get_resp_header("location") |> List.first()
    query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    {query["state"], query["nonce"]}
  end

  defp lift(url) do
    query = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    {query["state"], query["nonce"]}
  end

  defp arm_totp(%User{} = user) do
    enrollment = TOTP.new_enrollment(user, "Grappa test")
    previous_step = System.system_time(:second) - 30
    {:ok, code} = TOTP.code_at(enrollment.secret, previous_step)
    {:ok, _} = TOTP.confirm_enrollment(user, enrollment.secret, code, previous_step)
    Grappa.Accounts.get_user(user.id)
  end

  defp set_passkey_mode(%User{} = user, mode) do
    {:ok, updated} =
      user |> User.passkey_mode_changeset(%{passkey_mode: mode}) |> Grappa.Repo.update()

    updated
  end

  describe "GET /auth/oidc/authorize" do
    test "is a 404 when no provider is configured", %{conn: conn} do
      assert conn |> get("/auth/oidc/authorize") |> response(404)
    end

    test "?probe answers 200 without minting anything", %{conn: conn} do
      enable_oidc()
      assert conn |> get("/auth/oidc/authorize?probe=1") |> response(200)
    end

    test "a login navigation without a binder is refused", %{conn: conn} do
      enable_oidc()
      conn = get(conn, "/auth/oidc/authorize")

      assert fragment(conn) == %{"kind" => "error", "code" => "invalid_request"}
    end

    test "a bound navigation 302s to the provider with PKCE S256", %{conn: conn} do
      enable_oidc()
      conn = get(conn, "/auth/oidc/authorize?bind=browser-value")

      assert 302 = conn.status
      location = conn |> get_resp_header("location") |> List.first()
      assert String.starts_with?(location, @issuer <> "/authorize?")

      query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      assert query["code_challenge_method"] == "S256"
      assert query["redirect_uri"] == "https://app.example.com/auth/oidc/callback"
    end

    test "a request-supplied redirect_uri cannot choose where the code lands", %{conn: conn} do
      enable_oidc()

      conn =
        get(conn, "/auth/oidc/authorize?bind=b&redirect_uri=https://evil.example.com/steal")

      location = conn |> get_resp_header("location") |> List.first()
      query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

      assert query["redirect_uri"] == "https://app.example.com/auth/oidc/callback"
    end
  end

  describe "GET /auth/oidc/callback" do
    test "is a 404 when no provider is configured", %{conn: conn} do
      assert conn |> get("/auth/oidc/callback?code=x&state=y") |> response(404)
    end

    test "a forged state is refused", %{conn: conn} do
      enable_oidc()
      conn = get(conn, "/auth/oidc/callback?code=x&state=bogus")

      assert fragment(conn) == %{"kind" => "error", "code" => "invalid_state"}
    end

    test "a callback with neither code nor error is refused", %{conn: conn} do
      enable_oidc()
      conn = get(conn, "/auth/oidc/callback")

      assert fragment(conn) == %{"kind" => "error", "code" => "invalid_state"}
    end

    test "a provider error is surfaced as provider_refused", %{conn: conn} do
      enable_oidc()
      conn = get(conn, "/auth/oidc/callback?error=access_denied&state=x")

      assert fragment(conn) == %{"kind" => "error", "code" => "provider_refused"}
    end
  end

  describe "GET /me/oidc" do
    test "requires a bearer", %{conn: conn} do
      assert conn |> get("/me/oidc") |> response(401)
    end

    test "answers identity: nil when the account holds no link", %{conn: conn} do
      enable_oidc()
      {_, session} = user_and_session()

      body = conn |> put_bearer(session.id) |> get("/me/oidc") |> json_response(200)
      assert body == %{"identity" => nil}
    end

    test "shows the label of an existing link", %{conn: conn} do
      enable_oidc()
      {user, session} = user_and_session()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "subject-1", "Alice")

      body = conn |> put_bearer(session.id) |> get("/me/oidc") |> json_response(200)
      assert %{"identity" => %{"label" => "Alice"}} = body
    end

    test "is a 404 when no provider is configured", %{conn: conn} do
      {_, session} = user_and_session()
      assert conn |> put_bearer(session.id) |> get("/me/oidc") |> response(404)
    end
  end

  describe "POST /me/oidc/link" do
    test "requires the account password", %{conn: conn} do
      enable_oidc()
      {_, session} = user_and_session()

      assert conn
             |> put_bearer(session.id)
             |> post("/me/oidc/link", %{})
             |> response(400)
    end

    test "a wrong password is refused", %{conn: conn} do
      enable_oidc()
      {_, session} = user_and_session()

      assert conn
             |> put_bearer(session.id)
             |> post("/me/oidc/link", %{"password" => "wrong"})
             |> json_response(401) == %{"error" => "invalid_credentials"}
    end

    test "the right password mints a link round trip", %{conn: conn} do
      enable_oidc()
      {_, session} = user_and_session()

      body =
        conn
        |> put_bearer(session.id)
        |> post("/me/oidc/link", %{"password" => @password})
        |> json_response(200)

      assert String.starts_with?(body["authorize_url"], @issuer <> "/authorize?")
    end
  end

  describe "DELETE /me/oidc" do
    test "requires the account password", %{conn: conn} do
      enable_oidc()
      {_, session} = user_and_session()

      assert conn
             |> put_bearer(session.id)
             |> delete("/me/oidc", %{})
             |> response(400)
    end

    test "a wrong password is refused", %{conn: conn} do
      enable_oidc()
      {_, session} = user_and_session()

      assert conn
             |> put_bearer(session.id)
             |> delete("/me/oidc", %{"password" => "wrong"})
             |> json_response(401) == %{"error" => "invalid_credentials"}
    end

    test "the right password removes the link", %{conn: conn} do
      enable_oidc()
      {user, session} = user_and_session()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "subject-1", "Alice")

      body =
        conn
        |> put_bearer(session.id)
        |> delete("/me/oidc", %{"password" => @password})
        |> json_response(200)

      assert body == %{"identity" => nil}
      assert {:error, :not_found} = Oidc.find_identity(@issuer, "subject-1")
    end

    test "an account with no link gets 404", %{conn: conn} do
      enable_oidc()
      {_, session} = user_and_session()

      assert conn
             |> put_bearer(session.id)
             |> delete("/me/oidc", %{"password" => @password})
             |> response(404)
    end
  end

  describe "GET /auth/oidc/callback — full round trip" do
    test "a pre-linked account logs in and mints a working session", %{conn: conn} do
      {bypass, key} = enable_round_trip([])
      user = user_fixture()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "sub-1", "Alice")

      {state, nonce} = begin_login(conn)

      expect_token(bypass, %{
        "id_token" => id_token(key, id_claims(nonce, %{"preferred_username" => "alice"}))
      })

      frag = conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment()
      assert %{"kind" => "session", "token" => token} = frag

      body =
        build_conn() |> put_bearer(token) |> get("/me/oidc") |> json_response(200)

      # The label is synced from the verified claim on the login leg.
      assert %{"identity" => %{"label" => "alice"}} = body
    end

    test "a token minted for another audience is refused", %{conn: conn} do
      {bypass, key} = enable_round_trip([])
      user = user_fixture()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "sub-1", "Alice")

      {state, nonce} = begin_login(conn)
      expect_token(bypass, %{"id_token" => id_token(key, id_claims(nonce, %{"aud" => "other-client"}))})

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "error", "code" => "invalid_token"}
    end

    test "an expired token is refused", %{conn: conn} do
      {bypass, key} = enable_round_trip([])
      user = user_fixture()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "sub-1", "Alice")

      {state, nonce} = begin_login(conn)

      expect_token(bypass, %{
        "id_token" => id_token(key, id_claims(nonce, %{"exp" => System.system_time(:second) - 120}))
      })

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "error", "code" => "expired_token"}
    end

    test "a token-endpoint refusal of the code is invalid_code", %{conn: conn} do
      {bypass, _} = enable_round_trip([])
      user = user_fixture()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "sub-1", "Alice")
      {state, _} = begin_login(conn)

      Bypass.expect(bypass, "POST", "/token", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(400, ~s({"error":"invalid_grant"}))
      end)

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "error", "code" => "invalid_code"}
    end

    test "a broken token endpoint is a provider_unavailable", %{conn: conn} do
      {bypass, _} = enable_round_trip([])
      user = user_fixture()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "sub-1", "Alice")
      {state, _} = begin_login(conn)

      Bypass.expect(bypass, "POST", "/token", fn conn -> Plug.Conn.resp(conn, 500, "boom") end)

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "error", "code" => "provider_unavailable"}
    end

    test "an unseen member of the users group is provisioned", %{conn: conn} do
      {bypass, key} = enable_round_trip(users_group: "grappa_users")

      {state, nonce} = begin_login(conn)

      expect_token(bypass, %{
        "id_token" =>
          id_token(
            key,
            id_claims(nonce, %{
              "sub" => "brand-new",
              "preferred_username" => "newbie@localhost",
              "groups" => ["grappa_users"]
            })
          )
      })

      frag = conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment()
      assert %{"kind" => "session"} = frag

      {:ok, identity} = Oidc.find_identity(@issuer, "brand-new")
      assert Grappa.Accounts.get_user(identity.user_id).name == "newbie"
    end

    test "an unseen sub is refused not_linked when provisioning is off", %{conn: conn} do
      {bypass, key} = enable_round_trip([])

      {state, nonce} = begin_login(conn)

      expect_token(bypass, %{
        "id_token" => id_token(key, id_claims(nonce, %{"sub" => "nobody", "groups" => ["grappa_users"]}))
      })

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "error", "code" => "not_linked"}
    end

    test "an unseen sub outside the users group is refused not_linked", %{conn: conn} do
      {bypass, key} = enable_round_trip(users_group: "grappa_users")

      {state, nonce} = begin_login(conn)

      expect_token(bypass, %{
        "id_token" => id_token(key, id_claims(nonce, %{"sub" => "outsider", "groups" => []}))
      })

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "error", "code" => "not_linked"}
    end

    test "provisioning under a name grappa rejects is refused", %{conn: conn} do
      {bypass, key} = enable_round_trip(users_group: "grappa_users")

      {state, nonce} = begin_login(conn)

      expect_token(bypass, %{
        "id_token" =>
          id_token(
            key,
            id_claims(nonce, %{
              "sub" => "bad-name",
              "preferred_username" => "9no-leading-digit@localhost",
              "groups" => ["grappa_users"]
            })
          )
      })

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "error", "code" => "provisioning_refused"}
    end

    test "provisioning onto a taken name is refused by name", %{conn: conn} do
      {bypass, key} = enable_round_trip(users_group: "grappa_users")
      user_fixture(name: "taken")

      {state, nonce} = begin_login(conn)

      expect_token(bypass, %{
        "id_token" =>
          id_token(
            key,
            id_claims(nonce, %{
              "sub" => "name-clash",
              "preferred_username" => "taken@localhost",
              "groups" => ["grappa_users"]
            })
          )
      })

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "error", "code" => "name_taken"}
    end

    test "an admins-group login grants is_admin", %{conn: conn} do
      {bypass, key} = enable_round_trip(admins_group: "grappa_admins")
      user = user_fixture(is_admin: false)
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "sub-1", "Alice")

      {state, nonce} = begin_login(conn)

      expect_token(bypass, %{
        "id_token" => id_token(key, id_claims(nonce, %{"groups" => ["grappa_admins"]}))
      })

      assert %{"kind" => "session"} = conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment()
      assert Grappa.Accounts.get_user(user.id).is_admin == true
    end

    test "a :link round trip writes the identity and lands on linked", %{conn: conn} do
      {bypass, key} = enable_round_trip([])
      {user, session} = user_and_session()

      authorize_url =
        conn
        |> put_bearer(session.id)
        |> post("/me/oidc/link", %{"password" => @password})
        |> json_response(200)
        |> Map.fetch!("authorize_url")

      {state, nonce} = lift(authorize_url)

      expect_token(bypass, %{
        "id_token" => id_token(key, id_claims(nonce, %{"sub" => "sub-1", "preferred_username" => "alice"}))
      })

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "linked", "label" => "alice"}

      assert {:ok, identity} = Oidc.find_identity(@issuer, "sub-1")
      assert identity.user_id == user.id
    end

    test "a :link round trip onto an already-linked subject is refused", %{conn: conn} do
      {bypass, key} = enable_round_trip([])
      owner = user_fixture()
      {:ok, _} = Oidc.link_identity(owner.id, @issuer, "sub-1", "Alice")
      {_, session} = user_and_session()

      authorize_url =
        conn
        |> put_bearer(session.id)
        |> post("/me/oidc/link", %{"password" => @password})
        |> json_response(200)
        |> Map.fetch!("authorize_url")

      {state, nonce} = lift(authorize_url)
      expect_token(bypass, %{"id_token" => id_token(key, id_claims(nonce, %{"sub" => "sub-1"}))})

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "error", "code" => "already_linked"}
    end

    test "a passkey-only second factor refuses the login", %{conn: conn} do
      {bypass, key} = enable_round_trip([])
      user = user_fixture()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "sub-1", "Alice")
      set_passkey_mode(user, :second_factor)

      {state, nonce} = begin_login(conn)
      expect_token(bypass, %{"id_token" => id_token(key, id_claims(nonce, %{}))})

      assert conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment() ==
               %{"kind" => "error", "code" => "second_factor_unsupported"}
    end

    test "an armed TOTP second factor hands off a challenge instead of a session", %{conn: conn} do
      {bypass, key} = enable_round_trip([])
      user = user_fixture()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "sub-1", "Alice")
      arm_totp(user)

      {state, nonce} = begin_login(conn)
      expect_token(bypass, %{"id_token" => id_token(key, id_claims(nonce, %{}))})

      assert %{"kind" => "totp", "challenge_token" => token, "bind" => "browser-binder"} =
               conn |> get("/auth/oidc/callback?code=c&state=#{state}") |> fragment()

      assert is_binary(token)
    end
  end
end
