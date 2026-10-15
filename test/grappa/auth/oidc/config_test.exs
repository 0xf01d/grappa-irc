defmodule Grappa.Auth.Oidc.ConfigTest do
  @moduledoc """
  `Grappa.Auth.Oidc.Config` boot-time validation: the HTTPS issuer guard
  (review H2), the forced `openid` scope, the empty-string-reads-as-nil
  group gates, and the crash-loud required keys.

  `async: false` — `boot/0` writes the global `:persistent_term` slot
  every `GrappaWeb.OidcController` door reads.
  """

  use ExUnit.Case, async: false

  alias Grappa.Auth.Oidc.Config

  @pt_key {Config, :config}

  setup do
    original_env = Application.get_env(:grappa, :oidc, :__unset__)
    original_pt = :persistent_term.get(@pt_key, :__unset__)

    on_exit(fn ->
      case original_env do
        :__unset__ -> Application.delete_env(:grappa, :oidc)
        env -> Application.put_env(:grappa, :oidc, env)
      end

      case original_pt do
        :__unset__ -> :persistent_term.erase(@pt_key)
        cfg -> :persistent_term.put(@pt_key, cfg)
      end
    end)

    :ok
  end

  defp valid_raw do
    [
      issuer: "https://idm.example.com/oauth2/openid/grappa",
      client_id: "grappa",
      client_secret: "s3cret",
      redirect_uri: "https://app.example.com/auth/oidc/callback",
      scopes: "openid profile email"
    ]
  end

  describe "boot/0 + config/0" do
    test "an unset issuer is the off state: config nil, enabled? false" do
      Application.delete_env(:grappa, :oidc)

      assert :ok = Config.boot()
      assert Config.config() == nil
      refute Config.enabled?()
    end

    test "a valid configuration boots and normalizes the issuer trailing slash" do
      Application.put_env(
        :grappa,
        :oidc,
        Keyword.put(valid_raw(), :issuer, "https://idm.example.com/oauth2/openid/grappa/")
      )

      assert :ok = Config.boot()
      config = Config.config()
      assert %Config{} = config
      assert config.issuer == "https://idm.example.com/oauth2/openid/grappa"
      assert config.client_id == "grappa"
      assert config.client_secret == "s3cret"
      assert config.redirect_uri == "https://app.example.com/auth/oidc/callback"
      assert config.users_group == nil
      assert config.admins_group == nil
    end

    test "openid is forced on and the scope list is de-duplicated" do
      Application.put_env(:grappa, :oidc, Keyword.put(valid_raw(), :scopes, "profile email profile"))

      Config.boot()
      assert Config.config().scopes == "openid profile email"
    end

    test "a blank scope string falls back to the default scopes" do
      Application.put_env(:grappa, :oidc, Keyword.put(valid_raw(), :scopes, "   "))

      Config.boot()
      assert Config.config().scopes == "openid profile email"
    end

    test "an empty group string reads as nil (the gate switched off)" do
      Application.put_env(
        :grappa,
        :oidc,
        valid_raw() ++ [users_group: "", admins_group: "grappa_admins"]
      )

      Config.boot()
      assert Config.config().users_group == nil
      assert Config.config().admins_group == "grappa_admins"
    end
  end

  describe "boot/0 — the HTTPS issuer guard (review H2)" do
    test "an http:// issuer refuses to boot" do
      Application.put_env(:grappa, :oidc, Keyword.put(valid_raw(), :issuer, "http://idm.example.com"))

      assert_raise ArgumentError, ~r/oidc_issuer must be an https/, fn -> Config.boot() end
    end

    test "an issuer with no host refuses to boot" do
      Application.put_env(:grappa, :oidc, Keyword.put(valid_raw(), :issuer, "https://"))

      assert_raise ArgumentError, ~r/oidc_issuer must be an https/, fn -> Config.boot() end
    end

    test "a non-URL issuer refuses to boot" do
      Application.put_env(:grappa, :oidc, Keyword.put(valid_raw(), :issuer, "idm.example.com"))

      assert_raise ArgumentError, ~r/oidc_issuer must be an https/, fn -> Config.boot() end
    end
  end

  describe "boot/0 — required keys crash loud" do
    test "a missing client_id refuses to boot" do
      Application.put_env(:grappa, :oidc, Keyword.delete(valid_raw(), :client_id))

      assert_raise ArgumentError, ~r/oidc_client_id is required/, fn -> Config.boot() end
    end

    test "a blank client_secret refuses to boot" do
      Application.put_env(:grappa, :oidc, Keyword.put(valid_raw(), :client_secret, ""))

      assert_raise ArgumentError, ~r/oidc_client_secret is required/, fn -> Config.boot() end
    end

    test "a missing redirect_uri refuses to boot" do
      Application.put_env(:grappa, :oidc, Keyword.delete(valid_raw(), :redirect_uri))

      assert_raise ArgumentError, ~r/oidc_redirect_uri is required/, fn -> Config.boot() end
    end
  end

  describe "normalize_issuer/1" do
    test "trims only trailing slashes" do
      assert Config.normalize_issuer("https://idm.example.com/") == "https://idm.example.com"
      assert Config.normalize_issuer("https://idm.example.com") == "https://idm.example.com"

      assert Config.normalize_issuer("https://idm.example.com//") == "https://idm.example.com"

      assert Config.normalize_issuer("https://idm.example.com/a/b") ==
               "https://idm.example.com/a/b"
    end
  end

  describe "default_scopes/0" do
    test "forces openid and names profile + email" do
      assert Config.default_scopes() == "openid profile email"
    end
  end

  describe "put_test_config/1" do
    test "substitutes the config in the test env" do
      override = %Config{
        issuer: "https://override.example.com",
        client_id: "c",
        client_secret: "s",
        redirect_uri: "https://app.example.com/cb",
        scopes: "openid",
        users_group: nil,
        admins_group: nil
      }

      Config.put_test_config(override)
      assert Config.config() == override
      assert Config.enabled?()
    end
  end
end
