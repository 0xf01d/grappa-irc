// #1911 — the browser half of the OIDC round trip.
//
// grappa owns the provider conversation (discovery, PKCE, the token
// exchange); cicchetto owns exactly two moves:
//
//   * leaving — `window.location` at `GET /auth/oidc/authorize`, which
//     302s on to the provider. The navigation is performed by the
//     BROWSER and not by `fetch` on purpose: a same-origin
//     `redirect: "manual"` fetch answers an opaque-redirect response
//     whose `Location` header is unreadable by design, so a fetch-based
//     "get the URL, then navigate" shape cannot exist. The server is the
//     only party that knows the URL anyway — it minted the state.
//
//   * coming back — reading the landing the callback redirects to.
//     `GET /auth/oidc/callback` is a NAVIGATION, not a REST call: the
//     provider 302s the browser at it mid-flow, so it cannot answer
//     JSON to a human standing in a blank tab. It therefore sends the
//     browser home to `/login#oidc=<base64url json>` and this module
//     decodes that. A FRAGMENT rather than a query string is the #1404
//     move: the bearer inside a `session` landing is a live credential,
//     and a fragment is never transmitted with a request and never
//     reaches `Referer` or the server's access log.
//
//   * arming — before leaving, a random `bind` binder is minted into
//     sessionStorage and carried on the authorize navigation; the
//     landing that comes back echoes it, and a landing whose binder
//     does not match the stored copy installs NOTHING. This is the
//     login-CSRF cure. The fragment is public material — anyone can
//     write `/login#oidc=<base64url>` and a `session` landing inside it
//     is otherwise indistinguishable from a real one; the binder is the
//     one value the forger cannot know, because it lived only in this
//     browser's sessionStorage and was minted on the way out of a
//     navigation the forger did not start. The stored copy is consumed
//     by the FIRST matching landing, so a landing is single-use the
//     same way the server's transaction is.
//
// The landing shapes are the mirror of `GrappaWeb.OidcController`'s
// `finish/2` payloads. They are deliberately NOT part of the generated
// wire contract (`wireTypes.ts`): the controller answers `json/2` and a
// redirect, which `mix grappa.wire_pin` does not digest — a gap that
// moduledoc records as DEBT rather than an exemption. That is exactly
// why the decode below narrows on `unknown` with shape predicates and
// refuses anything else: there is no generated schema standing between
// the wire and this module, so this one is the boundary.

import type { Subject } from "./api";

// What the callback can send the SPA home with, one arm per outcome:
//
//   * `session` — a full login (`AuthenticatedLoginResponse` envelope,
//     the same shape `POST /auth/login` returns), for an account whose
//     second factor asked nothing further. Carries the `bind` echo.
//   * `totp` — the account's local factor is still armed; spend the
//     challenge at the ordinary TOTP form. Carries the `bind` echo too:
//     it installs nothing by itself, but any landing that cannot prove
//     it is ours refuses at the same gate.
//   * `linked` — the settings-initiated link round trip came back good.
//     No binder: that round trip is started by an authenticated fetch
//     and installs nothing.
//   * `error` — refused; `code` is a stable snake_case token.
export type OidcLanding =
  | { kind: "session"; token: string; subject: Subject; bind: string }
  | { kind: "totp"; challenge_token: string; bind: string }
  | { kind: "linked"; label: string | null }
  | { kind: "error"; code: string };

const FRAGMENT_KEY = "oidc";

// The browser half of the login-CSRF cure: minted at the start of a
// login round trip, held until the landing comes back. sessionStorage
// because a binder that survives a browser restart is a binder an
// attacker-pasted landing can still match hours later; tab-scoped
// storage dies with the tab, which is exactly the lifetime a round
// trip has.
const BINDER_KEY = "grappa-oidc-binder";

// 32 random bytes, base64url — the same entropy class as the server's
// own PKCE verifier, and never sent anywhere but the authorize URL of
// the round trip it arms.
function mintBinder(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  const binder = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  sessionStorage.setItem(BINDER_KEY, binder);
  return binder;
}

// The landing gate. TRUE only when `expected` matches the stored
// binder, and a match CONSUMES the stored copy: one binder arms one
// landing, so a captured landing URL cannot be re-driven into a second
// install. A MISMATCH keeps the stored copy — a poisoned link landing
// in the middle of a real round trip must not burn the user's own
// still-armed binder.
export function verifyOidcBinder(expected: string): boolean {
  const held = sessionStorage.getItem(BINDER_KEY);
  if (held === null || held !== expected) return false;
  sessionStorage.removeItem(BINDER_KEY);
  return true;
}

// The one read of the landing. `hash` is the raw `location.hash` (with
// or without its leading `#`); anything that is not a well-formed
// `oidc=` landing of a recognised kind answers `null`, which the caller
// reads as "this is an ordinary visit to /login".
export function readOidcLanding(hash: string): OidcLanding | null {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const encoded = params.get(FRAGMENT_KEY);
  if (encoded === null || encoded === "") return null;

  const json = base64UrlDecode(encoded);
  if (json === null) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }

  if (!isOidcLanding(parsed)) return null;
  return parsed;
}

// Scrub the landing out of the address bar once it has been read. A
// `session` landing carries a live bearer: leaving it in `location` and
// in browser history means a reload re-runs the landing (harmless — it
// installs the same token again) and, worse, a shared or screenshotted
// URL carries the credential. Same scrub `ShareConsume` performs on its
// one-shot token.
export function clearOidcLanding(): void {
  if (window.location.hash === "") return;
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
}

// Whether this deployment offers the door at all. Probed rather than
// configured, because `/api/config` does not publish it (the wire-pin
// debt named above): `?probe` asks the question WITHOUT minting a
// transaction — a plain navigation here would grow the server's
// ceremony store on every login-page view — so a 200 means the door
// exists and a 404 means the button would only tease.
export async function oidcLoginAvailable(): Promise<boolean> {
  try {
    const res = await fetch("/auth/oidc/authorize?probe=1");
    return res.ok;
  } catch {
    // An unreachable server is not a missing door: no probe result is
    // better than a wrong one, so the button stays hidden and the next
    // login screen render asks again.
    return false;
  }
}

export function beginOidcLogin(): void {
  const binder = mintBinder();
  window.location.assign(`/auth/oidc/authorize?bind=${encodeURIComponent(binder)}`);
}

// base64url → UTF-8 string, `null` for anything that does not decode.
// `fatal: true` is the point of `TextDecoder` here: a mangled payload
// must fail the decode rather than arrive as replacement characters and
// then fail JSON parsing with a less specific cause.
function base64UrlDecode(value: string): string | null {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);

  try {
    const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function isOidcLanding(value: unknown): value is OidcLanding {
  if (typeof value !== "object" || value === null) return false;
  const landing = value as Record<string, unknown>;

  switch (landing.kind) {
    case "session":
      return isSessionLanding(landing);
    case "totp":
      return (
        typeof landing.challenge_token === "string" &&
        landing.challenge_token !== "" &&
        typeof landing.bind === "string" &&
        landing.bind !== ""
      );
    case "linked":
      return landing.label === null || typeof landing.label === "string";
    case "error":
      return typeof landing.code === "string" && landing.code !== "";
    default:
      return false;
  }
}

// Same narrowing posture as `auth.ts`'s `isValidSubject`: the subject
// rides an unauthenticated fragment, so its shape is checked here rather
// than trusted. An unrecognised shape poisons the WHOLE landing — a
// bearer with no subject is not installable. The `bind` echo is part of
// the shape for the same reason: a landing that cannot even claim a
// binder is refused before `verifyOidcBinder` is ever asked.
function isSessionLanding(landing: Record<string, unknown>): boolean {
  if (typeof landing.token !== "string" || landing.token === "") return false;
  if (typeof landing.bind !== "string" || landing.bind === "") return false;
  const subject = landing.subject;
  if (typeof subject !== "object" || subject === null) return false;
  const candidate = subject as Record<string, unknown>;

  return (
    (candidate.kind === "user" &&
      typeof candidate.id === "string" &&
      typeof candidate.name === "string") ||
    (candidate.kind === "visitor" && typeof candidate.id === "string")
  );
}
