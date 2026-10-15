import { beforeEach, describe, expect, it, vi } from "vitest";
import { confirmJoinChannel, switchToChannelWindow } from "../lib/channelJoin";
import {
  dismissInviteToast,
  inviteToasts,
  parseInviteLinkUrl,
  routeInviteTarget,
} from "../lib/inviteLink";

// #793 — shareable channel invite links: `irc.sindro.me/?go=azzurra/sniffo`.
//
// Two halves, both here: the QUERY parser and the ROUTE (what the parsed
// target does). The route delegates to the #648 join verb rather than
// reimplementing confirm-then-join, so these assertions are about DELEGATION,
// not about the modal's internals (ConfirmModal has its own tests).
//
// Half of the parse block is about what the BROWSER does to the value before
// this code ever sees it. `?go=` puts the channel inside a query param, where
// `#`, `&` and `+` each have a meaning of their own — those cases are pinned
// against measured behaviour (node's WHATWG URL), not against what the
// characters "should" do.

vi.mock("../lib/channelJoin", () => ({
  confirmJoinChannel: vi.fn(),
  switchToChannelWindow: vi.fn(),
}));

vi.mock("../lib/networks", () => ({
  // #1861 — casemappingForSlug (lib/casemapping.ts) resolves the fold
  // through this map, so the mock has to carry it.
  networkIdBySlug: () => undefined,
  networkBySlug: vi.fn((slug: string) =>
    slug === "azzurra" ? { id: 1, slug: "azzurra", kind: "user" } : undefined,
  ),
  channelsBySlug: vi.fn(() => ({ azzurra: [{ id: 10, name: "#bofh" }] })),
}));

describe("parseInviteLinkUrl", () => {
  it("reads ?go=<network>/<channel> and implies the # sigil", () => {
    expect(parseInviteLinkUrl("/?go=azzurra/sniffo")).toEqual({
      networkSlug: "azzurra",
      channelName: "#sniffo",
      kind: "channel",
    });
  });

  it("reads an absolute URL the same as a relative one", () => {
    // `location.href` is what the boot reader passes, and it is absolute.
    expect(parseInviteLinkUrl("https://irc.sindro.me/?go=azzurra/sniffo")?.channelName).toBe(
      "#sniffo",
    );
  });

  it("ignores the path — a two-segment path is no longer an invite", () => {
    // The retired form. `?go=` exists precisely so an invite cannot collide
    // with a client route, so the path must carry no meaning at all here.
    expect(parseInviteLinkUrl("/azzurra/sniffo")).toBeNull();
    expect(parseInviteLinkUrl("/share/abc123")).toBeNull();
  });

  it("takes a percent-encoded # sigil instead of doubling it", () => {
    expect(parseInviteLinkUrl("/?go=azzurra/%23sniffo")?.channelName).toBe("#sniffo");
  });

  it("gets nothing from a LITERAL # — the browser eats it as the fragment", () => {
    // Measured: `new URL("/?go=azzurra/#sniffo")` has search `?go=azzurra/`
    // and hash `#sniffo`. The channel never reaches the app, so the value is
    // one segment and the whole invite is refused rather than half-read.
    // This is #755's lesson in a query param: the room segment is the one URL
    // component people forget to encode.
    expect(parseInviteLinkUrl("/?go=azzurra/#sniffo")).toBeNull();
  });

  it("gets nothing from a LITERAL & — the browser reads it as the next param", () => {
    // Same shape as the `#` case, different delimiter: `&local` starts a
    // second query param and `go` truncates to `azzurra/`.
    expect(parseInviteLinkUrl("/?go=azzurra/&local")).toBeNull();
  });

  it("reads a literal + as a SPACE, and a space is refused", () => {
    // `application/x-www-form-urlencoded` decoding turns `+` into a space —
    // the one delimiter that does NOT truncate the value but silently
    // rewrites it. A space cannot appear in a channel name, so the forbidden
    // -byte scan catches it. Encoded (`%2B`), the sigil arrives intact.
    expect(parseInviteLinkUrl("/?go=azzurra/+modeless")).toBeNull();
    expect(parseInviteLinkUrl("/?go=azzurra/%2Bmodeless")?.channelName).toBe("+modeless");
  });

  it("takes the non-# chantypes sigils when they are encoded", () => {
    expect(parseInviteLinkUrl("/?go=azzurra/%26local")?.channelName).toBe("&local");
    expect(parseInviteLinkUrl("/?go=azzurra/!ABCDEsecret")?.channelName).toBe("!ABCDEsecret");
  });

  it("reads a wholly-encoded value, separator slash included", () => {
    // `encodeURIComponent("azzurra/#sniffo")` escapes the separator too. The
    // decode restores it, so the over-careful writer gets the same target as
    // the minimal one.
    expect(parseInviteLinkUrl(`/?go=${encodeURIComponent("azzurra/#sniffo")}`)).toEqual({
      networkSlug: "azzurra",
      channelName: "#sniffo",
      kind: "channel",
    });
  });

  it("percent-decodes a non-ASCII channel name", () => {
    expect(parseInviteLinkUrl("/?go=azzurra/caff%C3%A8")?.channelName).toBe("#caffè");
  });

  it("preserves the raw casing (the display spelling goes on the wire)", () => {
    expect(parseInviteLinkUrl("/?go=azzurra/Sniffo")?.channelName).toBe("#Sniffo");
  });

  it("tolerates a trailing slash", () => {
    expect(parseInviteLinkUrl("/?go=azzurra/sniffo/")?.channelName).toBe("#sniffo");
  });

  it("rejects a value that is not exactly two segments", () => {
    expect(parseInviteLinkUrl("/?go=azzurra")).toBeNull();
    expect(parseInviteLinkUrl("/?go=azzurra/sniffo/extra")).toBeNull();
  });

  it("returns null when there is no go param at all", () => {
    expect(parseInviteLinkUrl("/")).toBeNull();
    expect(parseInviteLinkUrl("/?network=azzurra&channel=%23sniffo")).toBeNull();
    expect(parseInviteLinkUrl("/?go=")).toBeNull();
  });

  it("returns null on an unparseable URL instead of throwing", () => {
    expect(parseInviteLinkUrl("http://[")).toBeNull();
  });

  it("rejects a channel segment carrying a comma", () => {
    // JOIN takes a comma-separated LIST: an unfiltered comma turns one
    // invite into a multi-channel join the sender never wrote.
    expect(parseInviteLinkUrl("/?go=azzurra/sniffo,bofh")).toBeNull();
    expect(parseInviteLinkUrl("/?go=azzurra/sniffo%2Cbofh")).toBeNull();
  });

  it("rejects a channel segment carrying whitespace or control bytes", () => {
    expect(parseInviteLinkUrl("/?go=azzurra/sniffo%20bofh")).toBeNull();
    expect(parseInviteLinkUrl("/?go=azzurra/sniffo%0D%0AQUIT")).toBeNull();
    expect(parseInviteLinkUrl("/?go=azzurra/sniffo%07")).toBeNull();
  });

  it("keeps a malformed percent-escape verbatim rather than throwing", () => {
    // Measured, and a DELIBERATE change from the path reader, which decoded
    // by hand and got a URIError for `%ZZ`. `URLSearchParams` follows WHATWG
    // and leaves an undecodable sequence as its own bytes, so a typo names a
    // legal-if-silly channel instead of being refused. Safe because the
    // consent modal prints the channel it is about to join: the human reads
    // `#%ZZ` and says no.
    expect(parseInviteLinkUrl("/?go=azzurra/%ZZ")?.channelName).toBe("#%ZZ");
  });

  // Issue 2424 — a lone `#` or `&` is an ordinary channel upstream, and the
  // server's `Identifier.valid_channel?/1` now says so. An invite to one used
  // to be thrown away here as "a bare sigil names nothing".
  it("takes a lone # or & as the channel it names (issue 2424)", () => {
    expect(parseInviteLinkUrl("/?go=azzurra/%23")).toEqual({
      networkSlug: "azzurra",
      channelName: "#",
      kind: "channel",
    });
    expect(parseInviteLinkUrl("/?go=azzurra/%26")?.channelName).toBe("&");
  });

  it("rejects a lone + or !, which names no channel", () => {
    expect(parseInviteLinkUrl("/?go=azzurra/%2B")).toBeNull();
    expect(parseInviteLinkUrl("/?go=azzurra/!")).toBeNull();
  });
});

describe("routeInviteTarget", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    for (const t of inviteToasts()) dismissInviteToast(t.id);
  });

  it("delegates an unjoined channel to the #648 confirm-then-join verb", () => {
    routeInviteTarget({ networkSlug: "azzurra", channelName: "#sniffo", kind: "channel" });
    expect(confirmJoinChannel).toHaveBeenCalledWith("azzurra", "#sniffo");
    expect(switchToChannelWindow).not.toHaveBeenCalled();
  });

  it("switches with NO modal when the channel is already in the server's list", () => {
    routeInviteTarget({ networkSlug: "azzurra", channelName: "#bofh", kind: "channel" });
    expect(switchToChannelWindow).toHaveBeenCalledWith("azzurra", "#bofh");
    expect(confirmJoinChannel).not.toHaveBeenCalled();
  });

  it("folds the already-in comparison (a link is spelled by a human)", () => {
    routeInviteTarget({ networkSlug: "azzurra", channelName: "#BoFH", kind: "channel" });
    expect(switchToChannelWindow).toHaveBeenCalledWith("azzurra", "#BoFH");
    expect(confirmJoinChannel).not.toHaveBeenCalled();
  });

  it("says so, visibly, when the network is not bound for this recipient", () => {
    // Open decision 1 of #793 — cross-user network identity is unresolved, so
    // this branch deliberately does NOT join anything. What it must not do is
    // fail silently: the recipient clicked a link and is owed an answer.
    routeInviteTarget({ networkSlug: "libera", channelName: "#sniffo", kind: "channel" });
    expect(confirmJoinChannel).not.toHaveBeenCalled();
    expect(switchToChannelWindow).not.toHaveBeenCalled();
    const toasts = inviteToasts();
    expect(toasts).toHaveLength(1);
    expect(toasts[0]?.networkSlug).toBe("libera");
  });
});
