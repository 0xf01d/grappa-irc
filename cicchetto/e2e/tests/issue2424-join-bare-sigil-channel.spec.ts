// issue 2424 — `/join #` must join the channel named `#`. A lone `#` is an
// ordinary channel on bahamut (`IsChannelName` reads the first byte only), but
// the server's channel predicate demanded a byte after the sigil, so the JOIN
// came back as "The request was malformed." and no window opened. A raw
// `/quote join #` got past that, and then every read of the window it opened
// (`/channels/%23/...`) answered 400 the same way.
//
// So the spec walks both doors in one channel, against the live ircd:
//   * the JOIN door — `/join #` opens a window that actually JOINS (the
//     `ownNick` arm of `selectChannel` needs the self-JOIN line and the
//     per-channel WS join ack, which only a `:joined` window produces);
//   * the per-channel doors a joined window uses — an own PRIVMSG posts to
//     `/channels/%23/messages` and renders, and after a reload the same line
//     comes back from the REST read of `%23`.
//
// `#` is one name on a shared testnet, not a per-run channel: no stamp can be
// added to it. Nothing else joins it, and the per-spec subject's teardown
// parts it with the session; the `finally` parts it early anyway.
import { composeSend, loginAs, scrollbackLine, selectChannel } from "../fixtures/cicchettoPage";
import { partChannel } from "../fixtures/grappaApi";
import { AUTOJOIN_CHANNELS, NETWORK_SLUG } from "../fixtures/seedData";
import { expect, specNick, specUser, test } from "../fixtures/test";

const BARE = "#";

test("issue2424 — /join # joins the bare-sigil channel and its reads and sends work", async ({
  page,
}) => {
  if (!AUTOJOIN_CHANNELS[0]) throw new Error("AUTOJOIN_CHANNELS empty");
  const user = specUser();
  const body = `issue2424 in the bare channel ${Date.now()}`;

  await loginAs(page, user);
  await selectChannel(page, NETWORK_SLUG, AUTOJOIN_CHANNELS[0], { ownNick: specNick() });

  try {
    await composeSend(page, `/join ${BARE}`);
    await selectChannel(page, NETWORK_SLUG, BARE, { ownNick: specNick() });

    await composeSend(page, body);
    await expect(scrollbackLine(page, "privmsg", body)).toBeVisible({ timeout: 10_000 });

    // The reload drops every in-memory row, so the line below can only come
    // from `GET /channels/%23/messages` — the read the raw JOIN used to 400.
    await page.reload();
    await loginAs(page, user);
    await selectChannel(page, NETWORK_SLUG, BARE);
    await expect(scrollbackLine(page, "privmsg", body)).toBeVisible({ timeout: 10_000 });
  } finally {
    await partChannel(user.token, NETWORK_SLUG, BARE).catch(() => {});
  }
});
