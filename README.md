# basic-nostr
A simple way to use NOSTR from Python: Keys, DMs, Posts, & Products.

## Description
`basic-nostr` does exactly these things:

- Generate Nostr keys
- Send and read direct messages (in both formats [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md) and [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md))
- Post and read [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) notes (kind 1)
- Post and read [NIP-99](https://github.com/nostr-protocol/nips/blob/master/99.md) products (kind 30402)
- Read [NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md) deletion events (kind 5, signature-verified)
- Read [NIP-15](https://github.com/nostr-protocol/nips/blob/master/15.md) marketplace stalls (kind 30017)
- Optionally route all relay connections through a SOCKS5 proxy (e.g. Tor)

I made `basic-nostr` because no other Python packages make it this simple.

If it does exactly what you need → great, use it.
If it doesn't → don't use it. Simple as that.


## Install

```bash
pip install basic-nostr
```

## Usage

All functions take keys as bech32 `nsec1...`/`npub1...` strings (you never need to think about hex).

### NostrClient (recommended)

`NostrClient` handles relay connections and async internals for you. No `asyncio` knowledge needed. Connects automatically on first use.

```python
from basic_nostr import make_keys, NostrClient

npub, nsec = make_keys()
print(npub)  # npub1...  (share this)
print(nsec)  # nsec1...  (keep secret — paste into Amethyst to log in)

nostr = NostrClient(nsec)

# Post a note
nostr.make_post("Hello Nostr!", tags=[["t", "introduction"]])

# Read posts — filter by author, hashtag, or both
posts = nostr.read_posts(authors=[npub], limit=20)
posts = nostr.read_posts(tag_filters={"t": ["monero"]})

# Send DM (NIP-17 by default — sender hidden from relays)
nostr.send_dm(their_npub, "hey!")
nostr.send_dm(their_npub, "hey!", protocol="nip04")  # legacy (older clients)
nostr.send_dm(their_npub, "hey!", protocol="both")   # maximum compatibility

# Read DMs (reads both NIP-17 and NIP-04 by default)
dms = nostr.read_dms()
for dm in dms:
    print(f"From: {dm['sender']}")       # npub1...
    print(f"Message: {dm['message']}")
    print(f"Protocol: NIP-{dm['nip']}")  # 17 or 4
    print(f"Time: {dm['timestamp']}")    # unix timestamp

# List a product — shows up on Shopstr, Plebeian Market, etc.
nostr.list_product(
    title="Vintage Keyboard",
    description="Cherry MX Blues, great condition.",
    price=75,
    currency="USD",
    image_urls=["https://example.com/keyboard.jpg"],
    categories=["electronics"],
    condition="used",
    location="US",
)

# Read products and parse tags
products = nostr.read_products(limit=50)
for product in products:
    tags = {t[0]: t[1:] for t in product["tags"]}
    print(f"{tags['title'][0]} — {tags['price'][0]} {tags['price'][1]}")

# Read marketplace stalls (NIP-15, kind 30017) — a seller's shop metadata
from basic_nostr import parse_stall
for event in nostr.read_stalls(limit=20):
    stall = parse_stall(event)  # None if the content isn't valid stall JSON
    if stall:
        print(f"{stall['name']} ({stall['currency']})")

# Read deletion requests (NIP-09, kind 5) — signature-verified, forged events dropped
from basic_nostr import deletion_targets
for event in nostr.read_deletions(limit=50):
    targets = deletion_targets(event)
    # only honor deletions of events by the SAME pubkey
    print(f"{targets['pubkey']} deletes {targets['event_ids']} {targets['addresses']}")

# Close when done (or use context manager below)
nostr.close()
```

Read-only usage (no private key needed):
```python
nostr = NostrClient()
posts = nostr.read_posts(tag_filters={"t": ["monero"]})
products = nostr.read_products(limit=10)
nostr.close()
```

Context manager works too (auto-closes):
```python
with NostrClient(nsec) as nostr:
    nostr.make_post("Hello!")
```

Custom relays:
```python
nostr = NostrClient(nsec, relay_urls=["wss://relay.damus.io", "wss://nos.lol"])
nostr.make_post("Hello from custom relays!")
```

### Tor / SOCKS5 proxy (optional)

Route every relay connection through a SOCKS5 proxy. Needs the optional extra:

```bash
pip install basic-nostr[proxy]
```

```python
nostr = NostrClient(nsec, proxy="socks5h://127.0.0.1:9050")
nostr.make_post("Hello over Tor!")
```

Any SOCKS5 URL works — system Tor (`9050`), Tor Browser (`9150`), or one you get
programmatically, e.g. from [`basic-tor`](https://github.com/lukeprofits/basic-tor):

```python
import basic_tor
nostr = NostrClient(nsec, proxy=basic_tor.ensure_running())
```

Use `socks5h://` (not `socks5://`) so relay hostnames resolve *through* the proxy —
no DNS leak, and `.onion` relays work. Without `proxy=`, nothing changes: no proxy
dependencies are needed and connections go out directly, same as always.

### Async API

All async functions are also exported if you need them directly:

```python
import asyncio
from basic_nostr import make_keys, connect_to_relays, close_relays, make_post, read_posts

async def main():
    npub, nsec = make_keys()
    relays = await connect_to_relays()
    try:
        await make_post(relays, "Hello Nostr!", [["t", "introduction"]], nsec)
        posts = await read_posts(relays, authors=[npub], limit=20)
    finally:
        await close_relays(relays)

asyncio.run(main())
```

Available async functions: `connect_to_relays`, `close_relays`, `make_post`, `read_posts`, `list_product`, `read_products`, `read_deletions`, `read_stalls`, `send_dm`, `read_dms`, `read_events_from_relays`.

Sync helpers (no relay connection needed): `deletion_targets` (what a kind-5 event deletes), `parse_stall` (parse kind-30017 content), `verify_event` (full NIP-01 validation: recomputes the event id **and** checks the Schnorr signature — `read_deletions` already applies it).


## Contributing
If you want to add more functionality to this, open a PR. I'll merge it if it keeps it simple and matches the patterns.
