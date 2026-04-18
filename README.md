# basic-nostr
An intentionally tiny NOSTR library for Python: Keys, DMs, Posts, & Products.

## Description
`basic-nostr` does exactly four things:

- Generate Nostr keys
- Send and read direct messages (in both formats [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md) and [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md))
- Post and read [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) notes (kind 1)
- Post and read [NIP-99](https://github.com/nostr-protocol/nips/blob/master/99.md) products (kind 30402)

I made `basic-nostr` because no other Python packages make it this simple.

If it does exactly what you need → great, use it.  
If it doesn’t → don’t use it. Simple as that.


## Install

```bash
pip install basic-nostr
```

## Usage

All functions take keys as bech32 `nsec1...`/`npub1...` strings (you never need to think about hex). Everything is async. 

Import everything at once:
```python
import basic_nostr
basic_nostr.make_keys()
```

Or import just what you need:
```python
from basic_nostr import make_keys, send_dm, read_dms
```

### Generate keys

```python
from basic_nostr import make_keys

npub, nsec = make_keys()
print(npub)  # npub1...  (share this)
print(nsec)  # nsec1...  (keep this secret, paste into Amethyst to log in)
```

### Connect to relays

```python
from basic_nostr import connect_to_relays, close_relays

relays = await connect_to_relays()  # uses default relays

# or pick your own:
custom_relays = ["wss://relay.damus.io", "wss://nos.lol"]
relays = await connect_to_relays(custom_relays)

# when you're done:
await close_relays(relays)
```

### Make Post

```python
from basic_nostr import make_post

event, responses = await make_post(
    relays,
    content="Hello Nostr!",
    tags=[["t", "introduction"]],
    private_key=nsec,
)
```

### Read Posts

```python
from basic_nostr import read_posts

# Get someone's recent posts
posts = await read_posts(relays, authors=[npub], limit=20)

# Search by hashtag
posts = await read_posts(relays, tag_filters={"t": ["monero"]})

# Combine filters
posts = await read_posts(relays, authors=[npub], tag_filters={"t": ["monero"]})
```

### Send DM

```python
from basic_nostr import send_dm

# NIP-17 (modern, private — sender hidden from relays)
await send_dm(relays, nsec, their_npub, "hey!")

# NIP-04 (legacy — works with older clients)
await send_dm(relays, nsec, their_npub, "hey!", protocol="nip04")

# Send both (maximum compatibility)
await send_dm(relays, nsec, their_npub, "hey!", protocol="both")
```

### Read DMs

```python
from basic_nostr import read_dms

# Reads both NIP-17 and NIP-04 messages by default
dms = await read_dms(relays, nsec)

for dm in dms:
    print(f"From: {dm['sender']}")     # npub1...
    print(f"Message: {dm['message']}")
    print(f"Protocol: NIP-{dm['nip']}")  # 17 or 4
```

### List Product

Shows up on [Shopstr](https://shopstr.store), [Plebeian Market](https://plebeian.market), and other Nostr marketplaces.

```python
from basic_nostr import list_product

await list_product(
    relays,
    private_key=nsec,
    title="Vintage Keyboard",
    description="Cherry MX Blues, great condition.",
    price=75,
    currency="USD",
    image_urls=["https://example.com/keyboard.jpg"],
    categories=["electronics"],
    condition="used",
    location="US",
)
```

### Read Product Listings

```python
from basic_nostr import read_products

products = await read_products(relays, limit=50)

for product in products:
    tags = {t[0]: t[1:] for t in product["tags"]}
    print(f"{tags['title'][0]} — {tags['price'][0]} {tags['price'][1]}")
```


## Contributing
If you want to add more functionality to this, open a PR. I'll merge it if it keeps it simple and matches the patterns.
