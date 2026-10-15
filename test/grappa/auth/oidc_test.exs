defmodule Grappa.Auth.OidcTest do
  @moduledoc """
  `Grappa.Auth.Oidc`: the pure claim/name helpers, the PKCE challenge and
  authorization-URL construction (PKCE downgrade + open-redirect
  surface), and the `(issuer, subject)` link table — including the
  rename-stability property: the display label moves, the match key does
  not.
  """

  use Grappa.DataCase, async: false

  import Grappa.AuthFixtures

  alias Grappa.Auth.Oidc
  alias Grappa.Auth.Oidc.{Config, Discovery, Identity}

  @issuer "https://idm.example.com/oauth2/openid/grappa"

  defp config do
    %Config{
      issuer: @issuer,
      client_id: "grappa",
      client_secret: "s3cret",
      redirect_uri: "https://app.example.com/auth/oidc/callback",
      scopes: "openid profile email",
      users_group: nil,
      admins_group: nil
    }
  end

  describe "pkce_challenge/1" do
    test "matches the RFC 7636 Appendix B vector" do
      verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      assert Oidc.pkce_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    end
  end

  describe "claim_groups/1" do
    test "keeps the binary entries and drops everything else" do
      assert Oidc.claim_groups(%{"groups" => ["a", 1, "b", nil]}) == ["a", "b"]
    end

    test "an absent claim reads as membership of nothing" do
      assert Oidc.claim_groups(%{}) == []
    end

    test "a non-list claim reads as membership of nothing" do
      assert Oidc.claim_groups(%{"groups" => "grappa_users"}) == []
    end
  end

  describe "group_member?/2" do
    test "matches a bare name" do
      assert Oidc.group_member?(["grappa_users"], "grappa_users")
    end

    test "matches the spn spelling" do
      assert Oidc.group_member?(["grappa_users@localhost"], "grappa_users")
    end

    test "a uuid entry cannot false-match a group name" do
      refute Oidc.group_member?(["e6f0b6a8-2b0f-4a5e-9e2c-2c1f2a1b0c9d"], "grappa_users")
    end

    test "a superstring entry does not match" do
      refute Oidc.group_member?(["not_grappa_users"], "grappa_users")
    end

    test "a non-member is refused" do
      refute Oidc.group_member?(["grappa_admins"], "grappa_users")
    end
  end

  describe "provisioning_name/1" do
    test "splits the spn's local part" do
      assert Oidc.provisioning_name("alice@localhost") == "alice"
    end

    test "a bare name is unchanged" do
      assert Oidc.provisioning_name("alice") == "alice"
    end

    test "an absent username yields nil (provisioning refuses)" do
      assert Oidc.provisioning_name(nil) == nil
    end
  end

  describe "display_label/1" do
    test "prefers preferred_username, then email, then name" do
      assert Oidc.display_label(%{"preferred_username" => "alice", "email" => "a@b.c"}) == "alice"
      assert Oidc.display_label(%{"email" => "a@b.c", "name" => "Alice"}) == "a@b.c"
      assert Oidc.display_label(%{"name" => "Alice"}) == "Alice"
    end

    test "skips empty strings and answers nil when nothing usable is present" do
      assert Oidc.display_label(%{"preferred_username" => "", "email" => "a@b.c"}) == "a@b.c"
      assert Oidc.display_label(%{}) == nil
    end
  end

  describe "authorize_url/2" do
    test "pins redirect_uri and PKCE S256 from the configuration, never the request" do
      doc = %Discovery{
        issuer: @issuer,
        authorization_endpoint: @issuer <> "/authorize",
        token_endpoint: @issuer <> "/token",
        jwks_uri: @issuer <> "/jwks"
      }

      Discovery.put_test_discovery(@issuer, doc)
      on_exit(fn -> :persistent_term.erase({Discovery, @issuer}) end)

      assert {:ok, url} =
               Oidc.authorize_url(config(), %{state: "s", nonce: "n", challenge: "c"})

      query = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

      assert String.starts_with?(url, @issuer <> "/authorize?")
      assert query["redirect_uri"] == "https://app.example.com/auth/oidc/callback"
      assert query["code_challenge_method"] == "S256"
      assert query["code_challenge"] == "c"
      assert query["client_id"] == "grappa"
      assert query["nonce"] == "n"
    end
  end

  describe "the link table" do
    test "links a user to (issuer, subject) and finds it back" do
      user = user_fixture()

      assert {:ok, %Identity{label: "Alice"}} =
               Oidc.link_identity(user.id, @issuer, "subject-1", "Alice")

      assert {:ok, %Identity{user_id: user_id}} = Oidc.find_identity(@issuer, "subject-1")
      assert user_id == user.id
    end

    test "an unknown subject is not found" do
      assert {:error, :not_found} = Oidc.find_identity(@issuer, "nobody")
    end

    test "a second account cannot claim an already-linked subject" do
      a = user_fixture()
      b = user_fixture()
      {:ok, _} = Oidc.link_identity(a.id, @issuer, "subject-1", nil)

      assert {:error, :already_linked} = Oidc.link_identity(b.id, @issuer, "subject-1", nil)
    end

    test "an over-long subject is refused as an invalid identity" do
      user = user_fixture()
      assert {:error, :invalid_identity} = Oidc.link_identity(user.id, @issuer, String.duplicate("x", 256), nil)
    end

    test "a rename refreshes the label and the match key still resolves" do
      user = user_fixture()
      {:ok, identity} = Oidc.link_identity(user.id, @issuer, "subject-1", "Alice")

      assert {:ok, %Identity{label: "Alice Smith"}} = Oidc.update_identity_label(identity, "Alice Smith")

      # Same (issuer, subject) → same row, same account; only the label moved.
      assert {:ok, %Identity{user_id: user_id, label: "Alice Smith"}} =
               Oidc.find_identity(@issuer, "subject-1")

      assert user_id == user.id

      # And a row whose LABEL happens to collide resolves nothing by name.
      assert {:error, :not_found} = Oidc.find_identity(@issuer, "Alice Smith")
    end

    test "unlink is idempotent-refused, not idempotent-ok" do
      user = user_fixture()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "subject-1", nil)

      assert :ok = Oidc.unlink_identity(user.id, @issuer)
      assert {:error, :not_found} = Oidc.unlink_identity(user.id, @issuer)
    end

    test "list_identities returns the account's links" do
      user = user_fixture()
      {:ok, _} = Oidc.link_identity(user.id, @issuer, "subject-1", nil)

      assert [%Identity{subject: "subject-1"}] = Oidc.list_identities(user.id)
      assert [] = Oidc.list_identities(Ecto.UUID.generate())
    end
  end
end
