"""
Synchronous Nostr client — hides all async complexity.

Usage:
    from basic_nostr import make_keys, NostrClient

    npub, nsec = make_keys()
    nostr = NostrClient(nsec)

    nostr.make_post("Hello Nostr!", tags=[["t", "test"]])
    posts = nostr.read_posts(authors=[npub])
    nostr.send_dm(recipient_npub, "Secret message")
    dms = nostr.read_dms()
"""

import asyncio
import atexit
import queue
import threading

from . import basic_nostr as _async


# ─── Background event loop (module-level singleton) ──────────────────────────
#
# One daemon thread runs a persistent asyncio event loop. All NostrClient
# instances share it. WebSocket connections live on this loop and survive
# across method calls.

_loop = None
_thread = None
_lock = threading.Lock()


def _get_loop():
    """Get or create the shared background event loop."""
    global _loop, _thread
    with _lock:
        if _loop is None or _loop.is_closed():
            _loop = asyncio.new_event_loop()
            _thread = threading.Thread(
                target=_loop.run_forever,
                daemon=True,
                name="basic_nostr_event_loop",
            )
            _thread.start()
            atexit.register(_shutdown_loop)
    return _loop


def _shutdown_loop():
    """Clean shutdown: stop the loop and join the thread."""
    global _loop, _thread
    if _loop is not None and not _loop.is_closed():
        _loop.call_soon_threadsafe(_loop.stop)
        if _thread is not None:
            _thread.join(timeout=5)
        _loop.close()
        _loop = None
        _thread = None


def _run(coro):
    """Submit a coroutine to the background loop and block until done."""
    loop = _get_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result()


# ─── NostrClient ─────────────────────────────────────────────────────────────


class NostrClient:
    """Synchronous Nostr client. Manages relay connections and provides
    a simple blocking API for all Nostr operations.

    Connects automatically on first use. Call close() when done,
    or use as a context manager for auto-cleanup.

    Args:
        private_key: Your nsec1... key (or hex). Optional — needed for
                     write operations (post, DM, list_product) but not
                     for read-only usage.
        relay_urls:  List of relay WebSocket URLs. Defaults to DEFAULT_RELAYS.

    Usage:
        nostr = NostrClient(nsec)
        nostr.make_post("Hello!")
        nostr.close()

    Or with context manager:
        with NostrClient(nsec) as nostr:
            nostr.make_post("Hello!")
    """

    def __init__(self, private_key=None, relay_urls=None, proxy=None):
        self._private_key = private_key
        self._relay_urls = relay_urls
        self._proxy = proxy  # e.g. "socks5h://127.0.0.1:9050" to route via Tor
        self._relays = None
        self._listening = []  # stop functions of listeners still running

    # ── Connection lifecycle ────────────────────────────────────────────

    def connect(self, relay_urls=None):
        """Connect to relays. Called automatically on first use."""
        urls = relay_urls or self._relay_urls
        self._relays = _run(_async.connect_to_relays(urls, proxy=self._proxy))
        return self

    def close(self):
        """Close all relay connections. Called automatically by __exit__."""
        for stop in list(self._listening):
            stop()
        if self._relays:
            _run(_async.close_relays(self._relays))
            self._relays = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    # ── Property guards ──────────────────────────────────────────────────

    @property
    def relays(self):
        if self._relays is None:
            self.connect()
        return self._relays

    @property
    def private_key(self):
        if self._private_key is None:
            raise RuntimeError(
                "No private key set. Pass nsec to NostrClient(nsec) "
                "for write operations."
            )
        return self._private_key

    # ── Write operations ─────────────────────────────────────────────────

    def make_post(self, content, tags=None):
        """Publish a text post (kind 1) to connected relays."""
        return _run(_async.make_post(
            self.relays, content, tags or [], self.private_key
        ))

    def list_product(self, title, description, price, currency, image_urls,
                     categories=None, location=None, shipping=None,
                     quantity=None, condition=None, product_id=None):
        """Publish a product listing (kind 30402) to connected relays."""
        return _run(_async.list_product(
            self.relays, self.private_key, title, description,
            price, currency, image_urls, categories=categories,
            location=location, shipping=shipping, quantity=quantity,
            condition=condition, product_id=product_id,
        ))

    def send_dm(self, recipient_pubkey, message, protocol="nip17"):
        """Send an encrypted direct message."""
        return _run(_async.send_dm(
            self.relays, self.private_key, recipient_pubkey,
            message, protocol=protocol,
        ))

    def publish(self, kind, content, tags=None):
        """Publish one event of any kind to connected relays."""
        return _run(_async.publish_event(
            self.relays, self.private_key, kind, content, tags or []
        ))

    # ── Hearing events as they arrive ────────────────────────────────────

    def listen(self, on_event, kinds=None, authors=None, tag_filters=None,
               since=None, backlog=1000):
        """Call on_event(event) for every matching event from now on.

        Returns a function; call it to stop. close() stops every listener.

        Events are verified, and one that several relays send is passed on
        once. on_event runs on a thread of its own, so it may take its time
        and may use this client. If it falls more than `backlog` events
        behind, the newest are dropped.
        """
        events = queue.Queue(maxsize=backlog)
        done = object()

        def _take(event):
            try:
                events.put_nowait(event)
            except queue.Full:
                pass

        def _work():
            while True:
                event = events.get()
                if event is done:
                    return
                try:
                    on_event(event)
                except Exception as e:
                    print(f"[WARN] on_event raised: {e}")

        worker = threading.Thread(
            target=_work, daemon=True, name="basic_nostr_listener"
        )
        worker.start()
        task = asyncio.run_coroutine_threadsafe(
            _async.listen(
                self._relay_urls, _take, kinds=kinds, authors=authors,
                tag_filters=tag_filters, since=since, proxy=self._proxy,
            ),
            _get_loop(),
        )

        def stop():
            if stop in self._listening:
                self._listening.remove(stop)
                task.cancel()
                while True:  # make room for the marker if the queue is full
                    try:
                        events.put_nowait(done)
                        return
                    except queue.Full:
                        try:
                            events.get_nowait()
                        except queue.Empty:
                            pass

        self._listening.append(stop)
        return stop

    # ── Read operations ──────────────────────────────────────────────────

    def read_posts(self, authors=None, tag_filters=None,
                   since=None, until=None, limit=100):
        """Read text posts (kind 1) from connected relays."""
        return _run(_async.read_posts(
            self.relays, authors=authors, tag_filters=tag_filters,
            since=since, until=until, limit=limit,
        ))

    def read_products(self, authors=None, tag_filters=None,
                      since=None, until=None, limit=100):
        """Read product listings (kind 30402) from connected relays."""
        return _run(_async.read_products(
            self.relays, authors=authors, tag_filters=tag_filters,
            since=since, until=until, limit=limit,
        ))

    def read_deletions(self, authors=None, since=None, until=None, limit=100):
        """Read NIP-09 deletion events (kind 5). See deletion_targets()."""
        return _run(_async.read_deletions(
            self.relays, authors=authors, since=since, until=until, limit=limit,
        ))

    def read_stalls(self, authors=None, since=None, until=None, limit=100):
        """Read NIP-15 stall metadata (kind 30017). See parse_stall()."""
        return _run(_async.read_stalls(
            self.relays, authors=authors, since=since, until=until, limit=limit,
        ))

    def read_dms(self, since=None, limit=50, protocol="both"):
        """Read and decrypt incoming DMs."""
        return _run(_async.read_dms(
            self.relays, self.private_key, since=since,
            limit=limit, protocol=protocol,
        ))

    def read_events(self, authors=None, tag_filters=None,
                    since=None, until=None, limit=100, kinds=None):
        """Read arbitrary events from connected relays."""
        return _run(_async.read_events_from_relays(
            self.relays, authors=authors, tag_filters=tag_filters,
            since=since, until=until, limit=limit, kinds=kinds,
        ))
