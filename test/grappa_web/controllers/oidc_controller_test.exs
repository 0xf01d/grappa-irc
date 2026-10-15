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

  alias Grappa.Auth.Oidc
  alias Grappa.Auth.Oidc.{Config, Discovery}
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
      {_user, session} = user_and_session()

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
      {_user, session} = user_and_session()
      assert conn |> put_bearer(session.id) |> get("/me/oidc") |> response(404)
    end
  end

  describe "POST /me/oidc/link" do
    test "requires the account password", %{conn: conn} do
      enable_oidc()
      {_user, session} = user_and_session()

      assert conn
             |> put_bearer(session.id)
             |> post("/me/oidc/link", %{})
             |> response(400)
    end

    test "a wrong password is refused", %{conn: conn} do
      enable_oidc()
      {_user, session} = user_and_session()

      assert conn
             |> put_bearer(session.id)
             |> post("/me/oidc/link", %{"password" => "wrong"})
             |> json_response(401) == %{"error" => "invalid_credentials"}
    end

    test "the right password mints a link round trip", %{conn: conn} do
      enable_oidc()
      {_user, session} = user_and_session()

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
      {_user, session} = user_and_session()

      assert conn
             |> put_bearer(session.id)
             |> delete("/me/oidc", %{})
             |> response(400)
    end

    test "a wrong password is refused", %{conn: conn} do
      enable_oidc()
      {_user, session} = user_and_session()

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
      {_user, session} = user_and_session()

      assert conn
             |> put_bearer(session.id)
             |> delete("/me/oidc", %{"password" => @password})
             |> response(404)
    end
  end
end
