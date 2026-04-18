"""
Simple Nostr implementation in Python — no Nostr-specific libraries.

Implements:
  - NIP-01: Core protocol (events, signing, relay communication)
  - NIP-04: Legacy direct messages (AES-encrypted, kind 4)
  - NIP-17: Private direct messages (gift-wrapped, NIP-44 encrypted, kind 1059)
  - NIP-19: bech32 key encoding (nsec/npub)
  - NIP-44: Versioned encryption (ChaCha20 + HMAC, used by NIP-17)
  - NIP-99: Classified listings / marketplace (kind 30402)

Install:
  pip install basic-nostr

KEY FORMAT NOTE:
  All public functions in this module accept keys in bech32 format:
    - Private keys: nsec1...  (what you paste into Amethyst)
    - Public keys:  npub1...  (what you share with others)

  You never need to think about hex keys. The functions handle conversion
  internally. If you DO pass hex (64-char string), it will also work —
  but bech32 is the expected default.

  make_keys() returns bech32 by default:
    npub, nsec = make_keys()
"""

import asyncio
import base64
import hashlib
import hmac as hmac_module
import json
import math
import secrets
import ssl
import time
import uuid

import websockets
from bech32 import bech32_encode, bech32_decode, convertbits
from coincurve import PrivateKey, PublicKeyXOnly
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# ─── Default relays ──────────────────────────────────────────────────────────

DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://relay.noswhere.com",
    "wss://nostr.mom",
    "wss://offchain.pub",
    "wss://nostr-pub.wellorder.net",
    "wss://nostr.oxtr.dev",
]


# ─── Key format conversion helpers ───────────────────────────────────────────
#
# WHY THIS EXISTS:
# Nostr has two key formats that confused everyone (including us) for too long:
#   - bech32: nsec1.../npub1... — human-readable, what Amethyst/Damus use
#   - hex: 64-character hex string — what the Nostr wire protocol uses internally
#
# All PUBLIC functions in this module accept bech32 (nsec/npub).
# All INTERNAL functions work with hex (because that's what goes on the wire).
# These helpers bridge the gap so you never have to think about it.
#
# THREE PITFALLS with bech32 encoding (documented here so we don't forget):
#   1. bech32 vs bech32m — NIP-19 mandates bech32 (checksum constant=1),
#      NOT bech32m (constant=0x2bc830a3). We use the fiatjaf bech32 package
#      which only supports bech32, so this pitfall is avoided by default.
#   2. No witness version — Bitcoin segwit prepends a version byte. Nostr
#      does NOT. If you accidentally include one, Amethyst's regex won't match.
#   3. Padding byte — convertbits(5→8) adds a trailing zero byte. Must strip
#      with [:-1] when decoding.
# ─────────────────────────────────────────────────────────────────────────────


def _privkey_to_hex(private_key):
    """Convert a private key (nsec or hex) to hex format.

    Accepts:
      - nsec1... bech32 string (the standard user-facing format)
      - 64-char hex string (for backwards compatibility / internal use)

    This is called internally by every public function that takes a private key,
    so callers never need to worry about format conversion.
    """
    if private_key.startswith("nsec1"):
        hrp, data = bech32_decode(private_key)
        if hrp != "nsec" or data is None:
            raise ValueError(f"Invalid nsec key")
        # convertbits 5→8 adds trailing padding byte — must strip it
        return bytes(convertbits(data, 5, 8)[:-1]).hex()
    elif len(private_key) == 64:
        # Already hex
        return private_key.lower()
    else:
        raise ValueError(
            f"Expected nsec1... (bech32) or 64-char hex string, "
            f"got: {private_key[:20]}..."
        )


def _pubkey_to_hex(public_key):
    """Convert a public key (npub or hex) to hex format.

    Accepts:
      - npub1... bech32 string (the standard user-facing format)
      - 64-char hex string (for backwards compatibility / internal use)

    This is called internally by every public function that takes a public key,
    so callers never need to worry about format conversion.
    """
    if public_key.startswith("npub1"):
        hrp, data = bech32_decode(public_key)
        if hrp != "npub" or data is None:
            raise ValueError(f"Invalid npub key")
        # convertbits 5→8 adds trailing padding byte — must strip it
        return bytes(convertbits(data, 5, 8)[:-1]).hex()
    elif len(public_key) == 64:
        # Already hex
        return public_key.lower()
    else:
        raise ValueError(
            f"Expected npub1... (bech32) or 64-char hex string, "
            f"got: {public_key[:20]}..."
        )


def _hex_to_npub(pubkey_hex):
    """Convert a hex public key to npub bech32 format."""
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    return bech32_encode("npub", convertbits(pubkey_bytes, 8, 5))


# ─── 1. Key generation ───────────────────────────────────────────────────────


def make_keys(format="bech32"):
    """Generate a new Nostr keypair.

    Args:
        format: Return format for the keys.
            "bech32" — (npub, nsec)  Default. Paste nsec into Amethyst to log in.
                       Pass directly to all functions in this module.
            "hex"    — (pubkey_hex, privkey_hex)  64-char hex strings.
            "bytes"  — (pubkey_bytes, privkey_bytes)  Raw 32-byte values.
            "all"    — dict with every format at once.

    Returns:
        (public_key, private_key) tuple, or dict if format="all".
    """
    if format not in ("hex", "bech32", "bytes", "all"):
        raise ValueError(f"format must be 'hex', 'bech32', 'bytes', or 'all', got '{format}'")

    privkey_bytes = secrets.token_bytes(32)

    # coincurve validates the key is in [1, n-1] where n is the secp256k1
    # curve order. Invalid keys (all zeros, >= n) raise ValueError.
    PrivateKey(privkey_bytes)

    # x-only public key (32 bytes) — the format Nostr uses everywhere.
    # This is the x-coordinate of the EC point, with y implicitly even (BIP-340).
    xonly_pubkey = PublicKeyXOnly.from_secret(privkey_bytes)
    pubkey_bytes = xonly_pubkey.format()  # 32 bytes

    if format == "bytes":
        return (pubkey_bytes, privkey_bytes)

    if format == "hex":
        return (pubkey_bytes.hex(), privkey_bytes.hex())

    # bech32 encode — NOT bech32m, NO witness version byte.
    # See module-level comment for the three pitfalls.
    nsec = bech32_encode("nsec", convertbits(privkey_bytes, 8, 5))
    npub = bech32_encode("npub", convertbits(pubkey_bytes, 8, 5))

    # Sanity check: Amethyst expects "nsec1"/"npub1" + 58 chars = 63 total
    assert len(nsec) == 63, f"nsec wrong length: {len(nsec)} (expected 63)"
    assert len(npub) == 63, f"npub wrong length: {len(npub)} (expected 63)"

    if format == "all":
        return {
            "public_key_hex": pubkey_bytes.hex(),
            "private_key_hex": privkey_bytes.hex(),
            "npub": npub,
            "nsec": nsec,
            "public_key_bytes": pubkey_bytes,
            "private_key_bytes": privkey_bytes,
        }

    # format == "bech32"
    return (npub, nsec)


def keys_from_nsec(nsec, format="bech32"):
    """Recover keypair from an nsec1... bech32 string.

    Args:
        nsec: bech32-encoded private key string (nsec1...)
        format: Return format — "bech32" (default), "hex", "bytes", or "all".

    Returns:
        (public_key, private_key) tuple, or dict if format="all".
    """
    if format not in ("hex", "bech32", "bytes", "all"):
        raise ValueError(f"format must be 'hex', 'bech32', 'bytes', or 'all', got '{format}'")

    hrp, data = bech32_decode(nsec)
    if hrp != "nsec" or data is None:
        raise ValueError(f"Invalid nsec: expected hrp='nsec', got '{hrp}'")
    # convertbits(data, 5, 8) produces a trailing padding byte — strip it
    privkey_bytes = bytes(convertbits(data, 5, 8)[:-1])
    if len(privkey_bytes) != 32:
        raise ValueError(f"Decoded key is {len(privkey_bytes)} bytes, expected 32")

    xonly_pubkey = PublicKeyXOnly.from_secret(privkey_bytes)
    pubkey_bytes = xonly_pubkey.format()

    if format == "bytes":
        return (pubkey_bytes, privkey_bytes)

    if format == "hex":
        return (pubkey_bytes.hex(), privkey_bytes.hex())

    npub = bech32_encode("npub", convertbits(pubkey_bytes, 8, 5))

    if format == "all":
        return {
            "public_key_hex": pubkey_bytes.hex(),
            "private_key_hex": privkey_bytes.hex(),
            "npub": npub,
            "nsec": nsec,
            "public_key_bytes": pubkey_bytes,
            "private_key_bytes": privkey_bytes,
        }

    # format == "bech32"
    return (npub, nsec)


# ─── 2. Internal event helpers ───────────────────────────────────────────────


def _pubkey_hex_from_privkey_hex(private_key_hex):
    """Derive the x-only public key hex from a private key hex string."""
    xonly = PublicKeyXOnly.from_secret(bytes.fromhex(private_key_hex))
    return xonly.format().hex()


def _build_event(pubkey_hex, kind, content, tags, created_at=None):
    """Build a Nostr event dict and compute its ID (NIP-01).

    The event ID is SHA-256 of the JSON-serialized array:
      [0, <pubkey>, <created_at>, <kind>, <tags>, <content>]

    Returns the event dict WITHOUT a signature (caller must sign separately).
    """
    if created_at is None:
        created_at = int(time.time())

    # Serialization must be minified JSON, UTF-8, no whitespace.
    # The leading 0 is a reserved version field.
    serialized = json.dumps(
        [0, pubkey_hex, created_at, kind, tags, content],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    event_id = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    return {
        "id": event_id,
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
    }


def _sign_event(event_dict, private_key_hex):
    """Sign a Nostr event with BIP-340 Schnorr signature.

    Mutates event_dict by adding the 'sig' field. Returns the event.
    """
    privkey = PrivateKey(bytes.fromhex(private_key_hex))
    event_id_bytes = bytes.fromhex(event_dict["id"])
    sig = privkey.sign_schnorr(event_id_bytes)
    event_dict["sig"] = sig.hex()
    return event_dict


def _verify_event_signature(event_dict):
    """Verify a Nostr event's Schnorr signature. Returns True/False."""
    try:
        pubkey = PublicKeyXOnly(bytes.fromhex(event_dict["pubkey"]))
        sig = bytes.fromhex(event_dict["sig"])
        msg = bytes.fromhex(event_dict["id"])
        return pubkey.verify(sig, msg)
    except Exception:
        return False


# ─── 3. Relay connection ─────────────────────────────────────────────────────


async def connect_to_relays(relay_urls=None):
    """Connect to Nostr relays via WebSocket.

    Connects concurrently. Skips relays that fail to connect (logs warning).
    Returns list of (url, websocket) tuples for successful connections.
    """
    if relay_urls is None:
        relay_urls = DEFAULT_RELAYS

    # Build SSL context with certifi certs (fixes macOS Python.org SSL issues)
    ssl_context = ssl.create_default_context()
    try:
        import certifi

        ssl_context.load_verify_locations(certifi.where())
    except ImportError:
        pass  # Use system certs if certifi not installed

    async def _try_connect(url):
        try:
            ws = await websockets.connect(url, ssl=ssl_context)
            return (url, ws)
        except Exception as e:
            print(f"[WARN] Failed to connect to {url}: {e}")
            return None

    results = await asyncio.gather(*[_try_connect(url) for url in relay_urls])
    relays = [r for r in results if r is not None]

    if not relays:
        raise ConnectionError("Could not connect to any relay")

    print(f"Connected to {len(relays)} relay(s): {[r[0] for r in relays]}")
    return relays


async def close_relays(relays):
    """Close all relay WebSocket connections."""
    for url, ws in relays:
        try:
            await ws.close()
        except Exception:
            pass


async def _send_to_relays(relays, message):
    """Send a JSON message to all connected relays. Returns list of responses.

    Handles relays that send AUTH challenges or other messages before the OK
    response — keeps reading until we get an OK for our event ID or timeout.
    """
    msg_str = json.dumps(message)
    # EVENT messages have the event ID at message[1]["id"]
    event_id = message[1]["id"] if isinstance(message[1], dict) else None

    async def _send_one(url, ws):
        try:
            await ws.send(msg_str)
            # Loop until we get the OK for our event, skipping AUTH/NOTICE/etc
            deadline = asyncio.get_event_loop().time() + 5.0
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    return (url, ["ERROR", "timeout waiting for OK"])
                raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                response = json.loads(raw)
                # OK response for our event
                if response[0] == "OK" and (event_id is None or response[1] == event_id):
                    return (url, response)
                # Skip AUTH, NOTICE, and other non-OK messages
                if response[0] in ("AUTH", "NOTICE"):
                    continue
                # Unknown message type — return it rather than loop forever
                return (url, response)
        except Exception as e:
            return (url, ["ERROR", str(e)])

    results = await asyncio.gather(*[_send_one(url, ws) for url, ws in relays])
    return results


# ─── 4. Make post (NIP-01 kind 1 text note) ──────────────────────────────────


async def make_post(relays, content, tags, private_key):
    """Publish a text post (kind 1 note) to relays.

    Args:
        relays: List of (url, ws) tuples from connect_to_relays()
        content: Text content of the post
        tags: List of tag arrays, e.g. [["t", "nostr"], ["p", "<npub>"]]
        private_key: Your nsec1... key (or hex, but nsec is the expected format)

    Returns:
        (event_dict, relay_responses)
    """
    # Convert bech32 → hex internally (all wire protocol operations use hex)
    privkey_hex = _privkey_to_hex(private_key)
    pubkey_hex = _pubkey_hex_from_privkey_hex(privkey_hex)

    event = _build_event(pubkey_hex, kind=1, content=content, tags=tags)
    _sign_event(event, privkey_hex)

    responses = await _send_to_relays(relays, ["EVENT", event])
    return event, responses


# ─── 5. List product (NIP-99 kind 30402) ─────────────────────────────────────


async def list_product(
    relays,
    private_key,
    title,
    description,
    price,
    currency,
    image_urls,
    categories=None,
    location=None,
    shipping=None,
    quantity=None,
    condition=None,
    product_id=None,
):
    """Publish a product listing (NIP-99 kind 30402) to relays.

    This is the format used by Shopstr and Plebeian Market. NIP-15 (kind 30018)
    is deprecated — neither major marketplace client displays it anymore.

    Minimum tags for Shopstr visibility: d, title, price, image (at least 1).

    Args:
        relays: List of (url, ws) tuples
        private_key: Your nsec1... key (or hex)
        title: Product name
        description: Product description (markdown, goes in event content)
        price: Price as number
        currency: Currency code, e.g. "USD", "sat", "EUR"
        image_urls: List of image URL strings (at least 1 required)
        categories: Optional list of category strings (e.g. ["electronics", "used"])
        location: Optional location string (e.g. "Worldwide", "US")
        shipping: Optional list of [type, cost, currency] lists
                  e.g. [["Free Shipping", "0", "USD"], ["Express", "10", "USD"]]
        quantity: Optional integer stock count (None = unlimited/digital)
        condition: Optional "new" or "used"
        product_id: Optional stable ID. Auto-generated UUID if not provided.
                    Reuse the same ID to UPDATE a listing (addressable event).

    Returns:
        (event_dict, relay_responses)
    """
    if not image_urls:
        raise ValueError("At least one image URL is required for marketplace visibility")

    # Convert bech32 → hex internally
    privkey_hex = _privkey_to_hex(private_key)
    pubkey_hex = _pubkey_hex_from_privkey_hex(privkey_hex)

    if product_id is None:
        product_id = uuid.uuid4().hex

    # Tags carry structured data. Content is freeform markdown description.
    tags = [
        ["d", product_id],
        ["title", title],
        ["price", str(price), currency],
        ["status", "active"],
    ]
    tags += [["image", url] for url in image_urls]
    tags += [["t", cat] for cat in (categories or [])]
    if location:
        tags.append(["location", location])
    if quantity is not None:
        tags.append(["quantity", str(quantity)])
    if condition:
        tags.append(["condition", condition])
    if shipping:
        for s in shipping:
            tags.append(["shipping", s[0], s[1], s[2]])

    # Kind 30402 = parameterized replaceable event (NIP-33 range 30000-39999).
    # Publishing with same pubkey + kind + d-tag replaces the previous version.
    event = _build_event(pubkey_hex, kind=30402, content=description, tags=tags)
    _sign_event(event, privkey_hex)

    responses = await _send_to_relays(relays, ["EVENT", event])
    return event, responses


# ─── 6. Read events from relays ──────────────────────────────────────────────


async def read_events_from_relays(
    relays,
    authors=None,
    tag_filters=None,
    since=None,
    until=None,
    limit=100,
    kinds=None,
):
    """Subscribe to events matching filters and collect results.

    Args:
        relays: List of (url, ws) tuples
        authors: Optional list of public keys (npub1... or hex) to filter by
        tag_filters: Optional dict of tag filters, e.g. {"t": ["food"], "p": ["npub1..."]}
                     Keys are single letters, values are lists of strings.
                     Values starting with "npub1" are auto-converted to hex.
        since: Optional unix timestamp — only events >= this time
        until: Optional unix timestamp — only events <= this time
        limit: Max events per relay (default 100). Relay returns newest first.
        kinds: Optional list of event kind integers to filter by

    Returns:
        List of event dicts, deduplicated by ID, sorted newest first.

    Pagination:
        For next page, pass until=oldest_event["created_at"] - 1
        Repeat until 0 results returned.
    """
    # Build NIP-01 filter object
    filt = {}
    if authors:
        # Convert npub → hex for the wire protocol filter
        filt["authors"] = [_pubkey_to_hex(a) for a in authors]
    if kinds:
        filt["kinds"] = kinds
    if tag_filters:
        for letter, values in tag_filters.items():
            # Auto-convert npub values to hex (relay expects hex in filters)
            converted = [
                _pubkey_to_hex(v) if v.startswith("npub1") else v
                for v in values
            ]
            filt[f"#{letter}"] = converted
    if since is not None:
        filt["since"] = since
    if until is not None:
        filt["until"] = until
    filt["limit"] = limit

    sub_id = secrets.token_hex(8)

    # Send REQ to all relays concurrently, collect events until EOSE
    async def _read_from_relay(url, ws):
        events = []
        try:
            await ws.send(json.dumps(["REQ", sub_id, filt]))
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
                msg = json.loads(raw)
                if msg[0] == "EVENT" and msg[1] == sub_id:
                    events.append(msg[2])
                elif msg[0] == "EOSE" and msg[1] == sub_id:
                    break
                elif msg[0] == "CLOSED":
                    break
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            print(f"[WARN] Error reading from {url}: {e}")
        finally:
            try:
                await ws.send(json.dumps(["CLOSE", sub_id]))
            except Exception:
                pass
        return events

    results = await asyncio.gather(
        *[_read_from_relay(url, ws) for url, ws in relays]
    )

    # Deduplicate by event ID (same event from multiple relays)
    seen = set()
    deduped = []
    for relay_events in results:
        for event in relay_events:
            eid = event.get("id")
            if eid and eid not in seen:
                seen.add(eid)
                deduped.append(event)

    # Sort newest first
    deduped.sort(key=lambda e: e.get("created_at", 0), reverse=True)
    return deduped


# ─── 6b. Convenience readers ─────────────────────────────────────────────────


async def read_posts(relays, authors=None, tag_filters=None, since=None, until=None, limit=100):
    """Read text posts (kind 1) from relays.

    Same as read_events_from_relays() but defaults to kind 1 so you don't
    need to remember kind numbers.

    Args:
        relays: List of (url, ws) tuples
        authors: Optional list of npub1... keys to filter by
        tag_filters: Optional dict, e.g. {"t": ["bitcoin"]}
        since: Optional unix timestamp
        until: Optional unix timestamp
        limit: Max events (default 100)

    Returns:
        List of event dicts, deduplicated, sorted newest first.
    """
    return await read_events_from_relays(
        relays, authors=authors, tag_filters=tag_filters,
        since=since, until=until, limit=limit, kinds=[1],
    )


async def read_products(relays, authors=None, tag_filters=None, since=None, until=None, limit=100):
    """Read product listings (kind 30402) from relays.

    Same as read_events_from_relays() but defaults to kind 30402 so you don't
    need to remember kind numbers.

    Args:
        relays: List of (url, ws) tuples
        authors: Optional list of npub1... keys to filter by
        tag_filters: Optional dict, e.g. {"t": ["electronics"]}
        since: Optional unix timestamp
        until: Optional unix timestamp
        limit: Max events (default 100)

    Returns:
        List of event dicts, deduplicated, sorted newest first.
    """
    return await read_events_from_relays(
        relays, authors=authors, tag_filters=tag_filters,
        since=since, until=until, limit=limit, kinds=[30402],
    )


# ─── 7. NIP-44 encryption (for NIP-17 DMs) ───────────────────────────────────
#
# NIP-44 is the encryption scheme used by NIP-17 DMs. It uses:
#   - secp256k1 ECDH for shared secret derivation
#   - HKDF-SHA256 for key derivation
#   - ChaCha20 for encryption (NOT ChaCha20-Poly1305, NOT XChaCha20)
#   - HMAC-SHA256 for authentication
#   - Custom power-of-2 padding to reduce length leakage
#
# IMPORTANT: We use `cryptography` for ECDH (not `coincurve`) because
# coincurve's ecdh() returns SHA-256(shared_point) by default, but
# NIP-44 needs the RAW x-coordinate of the shared point, unhashed.
# ─────────────────────────────────────────────────────────────────────────────


def _get_conversation_key(privkey_hex, pubkey_hex):
    """Compute NIP-44 conversation key via ECDH + HKDF-extract.

    The conversation key is symmetric: conv(a, B) == conv(b, A).

    Steps:
    1. ECDH: multiply peer's public key by our private scalar → shared point
    2. Take the raw x-coordinate (32 bytes, NOT hashed)
    3. HKDF-extract with salt='nip44-v2' to derive the conversation key

    Uses `cryptography` library for ECDH because coincurve.PrivateKey.ecdh()
    returns SHA-256(shared_point) by default, which is wrong for NIP-44.
    """
    # Load our private key into cryptography's EC format
    privkey_int = int(privkey_hex, 16)
    private_key = ec.derive_private_key(privkey_int, ec.SECP256K1())

    # Convert x-only Nostr pubkey (32 bytes) to compressed EC point (33 bytes).
    # Prepend 0x02 because BIP-340 x-only keys have implicitly even y-coordinate.
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), b"\x02" + pubkey_bytes
    )

    # Raw ECDH → x-coordinate of the shared point (NOT hashed like coincurve does)
    shared_x = private_key.exchange(ec.ECDH(), peer_key)

    # HKDF-extract: salt='nip44-v2', IKM=shared_x → 32-byte conversation key
    # HKDF-extract is simply HMAC-SHA256(key=salt, data=IKM)
    conversation_key = hmac_module.new(b"nip44-v2", shared_x, hashlib.sha256).digest()
    return conversation_key


def _nip44_pad(plaintext_bytes):
    """Pad plaintext according to NIP-44's power-of-2 chunk scheme.

    Format: [plaintext_length as big-endian u16] [plaintext] [zero padding]
    Minimum padded size: 32 bytes. Sizes follow power-of-2 chunk rounding
    to reduce length leakage.

    This is NOT a standard padding scheme — it must be implemented exactly
    as specified or other clients won't be able to decrypt.
    """
    unpadded_len = len(plaintext_bytes)
    if unpadded_len < 1 or unpadded_len > 65535:
        raise ValueError(f"Plaintext must be 1-65535 bytes, got {unpadded_len}")

    if unpadded_len <= 32:
        padded_len = 32
    else:
        next_power = 1 << (math.floor(math.log2(unpadded_len - 1)) + 1)
        chunk = 32 if next_power <= 256 else next_power // 8
        padded_len = chunk * (math.floor((unpadded_len - 1) / chunk) + 1)

    # Prepend big-endian u16 length, then plaintext, then zero-pad
    return (
        unpadded_len.to_bytes(2, "big") + plaintext_bytes + b"\x00" * (padded_len - unpadded_len)
    )


def _nip44_unpad(padded_bytes):
    """Remove NIP-44 padding. Returns the original plaintext bytes."""
    if len(padded_bytes) < 2:
        raise ValueError("Padded data too short")
    plaintext_len = int.from_bytes(padded_bytes[:2], "big")
    if plaintext_len < 1 or plaintext_len > len(padded_bytes) - 2:
        raise ValueError(f"Invalid plaintext length: {plaintext_len}")

    plaintext = padded_bytes[2 : 2 + plaintext_len]

    # Verify remaining bytes are all zeros (padding integrity check)
    padding = padded_bytes[2 + plaintext_len :]
    if padding != b"\x00" * len(padding):
        raise ValueError("Non-zero padding bytes detected")

    return plaintext


def _nip44_encrypt(plaintext, conversation_key):
    """Encrypt a string using NIP-44 versioned encryption.

    Args:
        plaintext: String to encrypt
        conversation_key: 32-byte key from _get_conversation_key()

    Returns:
        Base64-encoded ciphertext string (what goes in the event content field)
    """
    plaintext_bytes = plaintext.encode("utf-8")

    # 1. Fresh random nonce for each message
    nonce = secrets.token_bytes(32)

    # 2. Derive message keys via HKDF-expand
    #    PRK=conversation_key, info=nonce, L=76 bytes
    hkdf_expand = HKDFExpand(algorithm=hashes.SHA256(), length=76, info=nonce)
    expanded = hkdf_expand.derive(conversation_key)

    chacha_key = expanded[0:32]
    chacha_nonce_12 = expanded[32:44]
    hmac_key = expanded[44:76]

    # 3. Pad the plaintext (NIP-44 custom padding)
    padded = _nip44_pad(plaintext_bytes)

    # 4. ChaCha20 encrypt.
    #    `cryptography` expects 16-byte nonce: 4-byte LE counter + 12-byte nonce.
    #    NIP-44 uses counter=0, so prepend 4 zero bytes.
    chacha_nonce_16 = b"\x00" * 4 + chacha_nonce_12
    cipher = Cipher(ChaCha20(chacha_key, chacha_nonce_16), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # 5. HMAC-SHA256 over (nonce || ciphertext) for authentication
    mac = hmac_module.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()

    # 6. Assemble: version(1) + nonce(32) + ciphertext(variable) + mac(32)
    payload = b"\x02" + nonce + ciphertext + mac

    return base64.b64encode(payload).decode("ascii")


def _nip44_decrypt(payload_b64, conversation_key):
    """Decrypt a NIP-44 encrypted payload.

    Args:
        payload_b64: Base64-encoded string from event content field
        conversation_key: 32-byte key from _get_conversation_key()

    Returns:
        Decrypted plaintext string
    """
    payload = base64.b64decode(payload_b64)

    # 1. Check version byte
    if len(payload) < 99:  # 1 + 32 + 32(min padded) + 2(len prefix) + 32 = 99
        raise ValueError("Payload too short")
    if payload[0] != 0x02:
        raise ValueError(f"Unsupported NIP-44 version: {payload[0]}")

    # 2. Extract components
    nonce = payload[1:33]
    mac = payload[-32:]
    ciphertext = payload[33:-32]

    # 3. Derive message keys (same as encrypt)
    hkdf_expand = HKDFExpand(algorithm=hashes.SHA256(), length=76, info=nonce)
    expanded = hkdf_expand.derive(conversation_key)

    chacha_key = expanded[0:32]
    chacha_nonce_12 = expanded[32:44]
    hmac_key = expanded[44:76]

    # 4. Verify HMAC — MUST use constant-time comparison to prevent timing attacks
    expected_mac = hmac_module.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac_module.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed — message tampered or wrong key")

    # 5. ChaCha20 decrypt
    chacha_nonce_16 = b"\x00" * 4 + chacha_nonce_12
    cipher = Cipher(ChaCha20(chacha_key, chacha_nonce_16), mode=None)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # 6. Remove padding, return plaintext
    plaintext_bytes = _nip44_unpad(padded)
    return plaintext_bytes.decode("utf-8")


# ─── 8. NIP-04 encryption (legacy DMs) ───────────────────────────────────────
#
# NIP-04 is the OLD DM format (kind 4). Deprecated but still widely used —
# Amethyst falls back to NIP-04 when the recipient has no kind 10050 DM relay
# list published.
#
# Much simpler than NIP-17: no gift wrapping, no ephemeral keys, no layers.
# Sender pubkey is visible to relays. Less private, but compatible everywhere.
#
# Content format: "base64(AES-256-CBC ciphertext)?iv=base64(iv)"
# Shared secret: raw ECDH x-coordinate (32 bytes), used directly as AES key.
# ─────────────────────────────────────────────────────────────────────────────


def _nip04_encrypt(plaintext, privkey_hex, peer_pubkey_hex):
    """Encrypt a message using NIP-04 (legacy AES-256-CBC).

    Args:
        plaintext: Message string
        privkey_hex: Our private key (hex)
        peer_pubkey_hex: Recipient's public key (hex)

    Returns:
        NIP-04 content string: "base64(ciphertext)?iv=base64(iv)"
    """
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    from cryptography.hazmat.primitives.ciphers.modes import CBC
    from cryptography.hazmat.primitives.padding import PKCS7

    # Shared secret: raw ECDH x-coordinate (same ECDH as NIP-44, but no HKDF)
    privkey_int = int(privkey_hex, 16)
    private_key = ec.derive_private_key(privkey_int, ec.SECP256K1())
    peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), b"\x02" + bytes.fromhex(peer_pubkey_hex)
    )
    shared_x = private_key.exchange(ec.ECDH(), peer_key)

    # AES-256-CBC with PKCS7 padding
    iv = secrets.token_bytes(16)
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(AES(shared_x), CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(ciphertext).decode() + "?iv=" + base64.b64encode(iv).decode()


def _nip04_decrypt(content, privkey_hex, peer_pubkey_hex):
    """Decrypt a NIP-04 message (legacy AES-256-CBC).

    Args:
        content: NIP-04 content string "base64(ciphertext)?iv=base64(iv)"
        privkey_hex: Our private key (hex)
        peer_pubkey_hex: Sender's public key (hex)

    Returns:
        Decrypted plaintext string
    """
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    from cryptography.hazmat.primitives.ciphers.modes import CBC
    from cryptography.hazmat.primitives.padding import PKCS7

    parts = content.split("?iv=")
    ciphertext = base64.b64decode(parts[0])
    iv = base64.b64decode(parts[1])

    # Shared secret: raw ECDH x-coordinate
    privkey_int = int(privkey_hex, 16)
    private_key = ec.derive_private_key(privkey_int, ec.SECP256K1())
    peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), b"\x02" + bytes.fromhex(peer_pubkey_hex)
    )
    shared_x = private_key.exchange(ec.ECDH(), peer_key)

    # AES-256-CBC decrypt
    cipher = Cipher(AES(shared_x), CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # PKCS7 unpad
    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


# ─── 9. Send DM ─────────────────────────────────────────────────────────────
#
# Two protocols supported:
#
# NIP-17 (default, modern, private):
#   Three nested layers: Rumor → Seal → Gift Wrap.
#   Sender is hidden from relays. Uses NIP-44 encryption.
#   Sends kind 1059 events.
#
# NIP-04 (legacy, compatible with everything):
#   Simple AES-256-CBC encrypted kind 4 event.
#   Sender pubkey is visible to relays. Less private but works everywhere.
#   Amethyst falls back to this when recipient has no kind 10050 relay list.
# ─────────────────────────────────────────────────────────────────────────────


async def _send_dm_nip17(relays, privkey_hex, recipient_hex, sender_hex, message):
    """Internal: send DM via NIP-17 (gift-wrapped, 3-layer encryption)."""
    rumor = _build_event(
        sender_hex, kind=14, content=message, tags=[["p", recipient_hex]]
    )
    # Rumors are never signed — deniability if leaked

    all_responses = []

    # Send a gift wrap to recipient + ourselves (so sent msgs show in our inbox)
    for target_hex in [recipient_hex, sender_hex]:
        # Layer 2: Seal (kind 13) — encrypt rumor, sign with sender's real key
        conv_key_seal = _get_conversation_key(privkey_hex, target_hex)
        encrypted_rumor = _nip44_encrypt(json.dumps(rumor), conv_key_seal)

        seal = _build_event(
            sender_hex, kind=13, content=encrypted_rumor,
            tags=[],  # ALWAYS empty — no metadata leakage
        )
        _sign_event(seal, privkey_hex)

        # Layer 3: Gift Wrap (kind 1059) — encrypt seal with fresh ephemeral key
        ephemeral_privkey_bytes = secrets.token_bytes(32)
        PrivateKey(ephemeral_privkey_bytes)  # validate
        ephemeral_privkey_hex = ephemeral_privkey_bytes.hex()
        ephemeral_pubkey_hex = _pubkey_hex_from_privkey_hex(ephemeral_privkey_hex)

        conv_key_wrap = _get_conversation_key(ephemeral_privkey_hex, target_hex)
        encrypted_seal = _nip44_encrypt(json.dumps(seal), conv_key_wrap)

        gift_wrap = _build_event(
            ephemeral_pubkey_hex, kind=1059, content=encrypted_seal,
            tags=[["p", target_hex]],
        )
        _sign_event(gift_wrap, ephemeral_privkey_hex)

        responses = await _send_to_relays(relays, ["EVENT", gift_wrap])
        all_responses.extend(responses)

    return all_responses


async def _send_dm_nip04(relays, privkey_hex, recipient_hex, sender_hex, message):
    """Internal: send DM via NIP-04 (legacy AES-encrypted kind 4)."""
    encrypted_content = _nip04_encrypt(message, privkey_hex, recipient_hex)

    event = _build_event(
        sender_hex, kind=4, content=encrypted_content,
        tags=[["p", recipient_hex]],
    )
    _sign_event(event, privkey_hex)

    responses = await _send_to_relays(relays, ["EVENT", event])
    return responses


async def send_dm(relays, private_key, recipient_pubkey, message, protocol="nip17"):
    """Send an encrypted direct message.

    Args:
        relays: List of (url, ws) tuples
        private_key: Your nsec1... key (or hex)
        recipient_pubkey: Recipient's npub1... key (or hex)
        message: Plaintext message string
        protocol: Which DM protocol to use:
            "nip17" (default) — Modern, private. Sender hidden from relays.
                                Uses gift-wrapped NIP-44 encryption (kind 1059).
            "nip04"           — Legacy, compatible with all clients.
                                Sender visible to relays (kind 4).
            "both"            — Sends both NIP-17 and NIP-04. Maximum
                                compatibility — recipient sees it regardless
                                of which protocol their client supports.

    Returns:
        List of (relay_url, response) tuples from all relays.
    """
    if protocol not in ("nip17", "nip04", "both"):
        raise ValueError(f"protocol must be 'nip17', 'nip04', or 'both', got '{protocol}'")

    # Convert bech32 → hex internally for all crypto operations
    privkey_hex = _privkey_to_hex(private_key)
    recipient_hex = _pubkey_to_hex(recipient_pubkey)
    sender_hex = _pubkey_hex_from_privkey_hex(privkey_hex)

    all_responses = []

    if protocol in ("nip17", "both"):
        responses = await _send_dm_nip17(
            relays, privkey_hex, recipient_hex, sender_hex, message
        )
        all_responses.extend(responses)

    if protocol in ("nip04", "both"):
        responses = await _send_dm_nip04(
            relays, privkey_hex, recipient_hex, sender_hex, message
        )
        all_responses.extend(responses)

    return all_responses


# ─── 10. Read DMs ───────────────────────────────────────────────────────────


async def read_dms(relays, private_key, since=None, limit=50, protocol="both"):
    """Read and decrypt incoming DMs.

    Args:
        relays: List of (url, ws) tuples
        private_key: Your nsec1... key (or hex)
        since: Optional unix timestamp — only messages after this time
        limit: Max messages to fetch per protocol (default 50)
        protocol: Which DM protocols to read:
            "both"  (default) — Read NIP-17 (kind 1059) and NIP-04 (kind 4).
            "nip17"           — Only modern gift-wrapped DMs.
            "nip04"           — Only legacy AES-encrypted DMs.

    Returns:
        List of dicts, sorted newest first:
        [{"sender": "npub1...", "message": str, "timestamp": int, "nip": 17|4}, ...]
        The "nip" field tells you which protocol the message used.
    """
    if protocol not in ("nip17", "nip04", "both"):
        raise ValueError(f"protocol must be 'nip17', 'nip04', or 'both', got '{protocol}'")

    # Convert bech32 → hex internally
    privkey_hex = _privkey_to_hex(private_key)
    my_pubkey_hex = _pubkey_hex_from_privkey_hex(privkey_hex)

    messages = []

    # ── NIP-17 (kind 1059 gift wraps) ──
    if protocol in ("nip17", "both"):
        gift_wraps = await read_events_from_relays(
            relays,
            tag_filters={"p": [my_pubkey_hex]},
            kinds=[1059],
            since=since,
            limit=limit,
        )

        for wrap_event in gift_wraps:
            try:
                conv_key_wrap = _get_conversation_key(
                    privkey_hex, wrap_event["pubkey"]
                )
                seal_json = _nip44_decrypt(wrap_event["content"], conv_key_wrap)
                seal = json.loads(seal_json)

                # CRITICAL: Verify seal signature (anti-forgery)
                if not _verify_event_signature(seal):
                    continue

                conv_key_seal = _get_conversation_key(privkey_hex, seal["pubkey"])
                rumor_json = _nip44_decrypt(seal["content"], conv_key_seal)
                rumor = json.loads(rumor_json)

                # Verify seal pubkey matches rumor pubkey (anti-impersonation)
                if seal["pubkey"] != rumor["pubkey"]:
                    continue

                messages.append(
                    {
                        "sender": _hex_to_npub(rumor["pubkey"]),
                        "message": rumor["content"],
                        "timestamp": rumor.get("created_at", 0),
                        "nip": 17,
                    }
                )
            except Exception:
                continue

    # ── NIP-04 (kind 4 legacy DMs) ──
    if protocol in ("nip04", "both"):
        nip04_events = await read_events_from_relays(
            relays,
            tag_filters={"p": [my_pubkey_hex]},
            kinds=[4],
            since=since,
            limit=limit,
        )

        for event in nip04_events:
            try:
                plaintext = _nip04_decrypt(
                    event["content"], privkey_hex, event["pubkey"]
                )
                messages.append(
                    {
                        "sender": _hex_to_npub(event["pubkey"]),
                        "message": plaintext,
                        "timestamp": event.get("created_at", 0),
                        "nip": 4,
                    }
                )
            except Exception:
                continue

    # Sort newest first
    messages.sort(key=lambda m: m["timestamp"], reverse=True)
    return messages
