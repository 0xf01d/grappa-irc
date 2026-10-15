defmodule Grappa.Auth.Oidc.DiscoveryTest do
  @moduledoc """
  `Grappa.Auth.Oidc.Discovery`: the issuer-match check that anchors the
  whole trust chain, the HTTPS requirement on every provider-supplied
  endpoint (review H2), and the named transport/shape refusals (review
  L2/L3).

  `async: false` — the cache these tests exercise is a global
  `:persistent_term` slot keyed by issuer.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Grappa.Auth.Oidc.{Config, Discovery}

  @issuer "https://idm.example.com/oauth2/openid/grappa"

  defp config(issuer) do
    %Config{
      issuer: issuer,
      client_id: "grappa",
      client_secret: "s3cret",
      redirect_uri: "https://app.example.com/auth/oidc/callback",
      scopes: "openid profile email",
      users_group: nil,
      admins_group: nil
    }
  end

  defp document(overrides) do
    Map.merge(
      %{
        "issuer" => @issuer,
        "authorization_endpoint" => @issuer <> "/authorize",
        "token_endpoint" => @issuer <> "/token",
        "jwks_uri" => @issuer <> "/jwks"
      },
      overrides
    )
  end

  describe "build/2 — issuer" do
    test "a document describing the configured issuer builds" do
      assert {:ok, %Discovery{issuer: @issuer}} = Discovery.build(config(@issuer), document(%{}))
    end

    test "a trailing-slash difference is tolerated" do
      assert {:ok, %Discovery{issuer: @issuer}} =
               Discovery.build(config(@issuer), document(%{"issuer" => @issuer <> "/"}))
    end

    test "a mismatched issuer is refused, and the refusal is logged" do
      log =
        capture_log(fn ->
          assert {:error, :provider_unavailable} =
                   Discovery.build(config(@issuer), document(%{"issuer" => "https://evil.example.com"}))
        end)

      assert log =~ "does not match the configured"
    end

    test "a missing issuer is refused" do
      assert {:error, :provider_unavailable} =
               Discovery.build(config(@issuer), Map.delete(document(%{}), "issuer"))
    end

    test "a blank issuer is refused" do
      assert {:error, :provider_unavailable} =
               Discovery.build(config(@issuer), document(%{"issuer" => ""}))
    end

    test "a non-string issuer is refused" do
      assert {:error, :provider_unavailable} =
               Discovery.build(config(@issuer), document(%{"issuer" => 7}))
    end
  end

  describe "build/2 — provider endpoints must be https (review H2)" do
    test "an http authorization_endpoint is refused" do
      assert {:error, :provider_unavailable} =
               Discovery.build(
                 config(@issuer),
                 document(%{"authorization_endpoint" => "http://idm.example.com/authorize"})
               )
    end

    test "an http token_endpoint is refused" do
      assert {:error, :provider_unavailable} =
               Discovery.build(
                 config(@issuer),
                 document(%{"token_endpoint" => "http://idm.example.com/token"})
               )
    end

    test "an http jwks_uri is refused" do
      assert {:error, :provider_unavailable} =
               Discovery.build(config(@issuer), document(%{"jwks_uri" => "http://idm.example.com/jwks"}))
    end

    test "an endpoint with no host is refused" do
      assert {:error, :provider_unavailable} =
               Discovery.build(config(@issuer), document(%{"token_endpoint" => "https://"}))
    end

    test "a missing endpoint is refused" do
      assert {:error, :provider_unavailable} =
               Discovery.build(config(@issuer), Map.delete(document(%{}), "jwks_uri"))
    end
  end

  describe "fetch/1 — cache" do
    test "a freshly cached document is served without any network" do
      doc = %Discovery{
        issuer: @issuer,
        authorization_endpoint: @issuer <> "/authorize",
        token_endpoint: @issuer <> "/token",
        jwks_uri: @issuer <> "/jwks"
      }

      Discovery.put_test_discovery(@issuer, doc)
      on_exit(fn -> :persistent_term.erase({Discovery, @issuer}) end)

      assert {:ok, ^doc} = Discovery.fetch(config(@issuer))
    end
  end

  describe "refresh/1 — transport and shape refusals are named (review L2)" do
    setup do
      bypass = Bypass.open()
      issuer = "http://localhost:#{bypass.port}"
      on_exit(fn -> :persistent_term.erase({Discovery, issuer}) end)
      {:ok, bypass: bypass, issuer: issuer}
    end

    test "a valid document is fetched and cached", %{bypass: bypass, issuer: issuer} do
      Bypass.expect(bypass, "GET", "/.well-known/openid-configuration", fn conn ->
        # Bypass speaks http; the issuer (a config value, compared only)
        # may be http, but every provider endpoint must be https or the
        # build refuses before the cache is written.
        body =
          Jason.encode!(%{
            "issuer" => issuer,
            "authorization_endpoint" => "https://idm.example.com/authorize",
            "token_endpoint" => "https://idm.example.com/token",
            "jwks_uri" => "https://idm.example.com/jwks"
          })

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, body)
      end)

      assert {:ok, %Discovery{issuer: ^issuer}} = Discovery.refresh(config(issuer))
      assert {:ok, %Discovery{}} = Discovery.fetch(config(issuer))
    end

    test "a non-200 is refused and the status is named in the log", %{
      bypass: bypass,
      issuer: issuer
    } do
      Bypass.expect(bypass, "GET", "/.well-known/openid-configuration", fn conn ->
        Plug.Conn.resp(conn, 500, "boom")
      end)

      log = capture_log(fn -> assert {:error, :provider_unavailable} = Discovery.refresh(config(issuer)) end)
      assert log =~ "HTTP 500"
    end

    test "a 200 whose body is not a JSON object is refused", %{bypass: bypass, issuer: issuer} do
      Bypass.expect(bypass, "GET", "/.well-known/openid-configuration", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, "[1,2,3]")
      end)

      assert {:error, :provider_unavailable} = Discovery.refresh(config(issuer))
    end

    test "a matching issuer with an http endpoint is refused", %{
      bypass: bypass,
      issuer: issuer
    } do
      Bypass.expect(bypass, "GET", "/.well-known/openid-configuration", fn conn ->
        body =
          Jason.encode!(%{
            "issuer" => issuer,
            "authorization_endpoint" => issuer <> "/authorize",
            "token_endpoint" => "http://idm.example.com/token",
            "jwks_uri" => issuer <> "/jwks"
          })

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, body)
      end)

      assert {:error, :provider_unavailable} = Discovery.refresh(config(issuer))
    end

    test "an unreachable provider is refused and the cause is logged", %{
      bypass: bypass,
      issuer: issuer
    } do
      Bypass.down(bypass)

      log =
        capture_log(fn -> assert {:error, :provider_unavailable} = Discovery.refresh(config(issuer)) end)

      assert log =~ "oidc discovery:"
    end
  end
end
