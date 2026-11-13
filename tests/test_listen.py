"""publish() and listen(), against a small relay running in this process.

No internet: the relay here speaks just enough NIP-01 (EVENT, REQ, CLOSE) to
carry an event from one client to another, and can be told to misbehave.

Run with:  python -m pytest tests -v
"""

import asyncio
import json
import threading
import time

import pytest
import websockets

from basic_nostr import NostrClient, make_keys, verify_event


class Relay:
    """A relay on 127.0.0.1. `url` is where; `inject(event)` sends anything."""

    def __init__(self):
        self.subs = {}  # websocket -> {sub id: filter}
        self.kept = []  # events a REQ is answered with
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        assert self.ready.wait(10)

    def _run(self):
        asyncio.set_event_loop(self.loop)

        async def start():
            self.server = await websockets.serve(self._client, "127.0.0.1", 0)
            port = self.server.sockets[0].getsockname()[1]
            self.url = f"ws://127.0.0.1:{port}"
            self.ready.set()

        self.loop.run_until_complete(start())
        self.loop.run_forever()

    @staticmethod
    def _fits(event, filt):
        if "kinds" in filt and event["kind"] not in filt["kinds"]:
            return False
        for key, wanted in filt.items():
            if key.startswith("#"):
                have = {t[1] for t in event["tags"] if t[0] == key[1:]}
                if not have.intersection(wanted):
                    return False
        return True

    async def _client(self, ws):
        self.subs[ws] = {}
        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg[0] == "REQ":
                    self.subs[ws][msg[1]] = msg[2]
                    for event in self.kept:
                        if self._fits(event, msg[2]):
                            await ws.send(json.dumps(["EVENT", msg[1], event]))
                    await ws.send(json.dumps(["EOSE", msg[1]]))
                elif msg[0] == "CLOSE":
                    self.subs[ws].pop(msg[1], None)
                elif msg[0] == "EVENT":
                    await ws.send(json.dumps(["OK", msg[1]["id"], True, ""]))
                    await self._fan_out(msg[1], honest=True)
        finally:
            self.subs.pop(ws, None)

    async def _fan_out(self, event, honest):
        for ws, subs in list(self.subs.items()):
            for sub_id, filt in subs.items():
                if not honest or self._fits(event, filt):
                    try:
                        await ws.send(json.dumps(["EVENT", sub_id, event]))
                    except Exception:
                        pass

    def inject(self, event):
        """Send `event` to every subscriber, whether or not it fits."""
        asyncio.run_coroutine_threadsafe(
            self._fan_out(event, honest=False), self.loop
        ).result(10)

    def listeners(self):
        return sum(len(s) for s in self.subs.values())

    def drop_everyone(self):
        async def drop():
            for ws in list(self.subs):
                await ws.close()

        asyncio.run_coroutine_threadsafe(drop(), self.loop).result(10)

    def stop(self):
        async def shut():
            self.server.close(close_connections=True)
            await self.server.wait_closed()

        asyncio.run_coroutine_threadsafe(shut(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)


def until(condition, seconds=10.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def relays():
    made = [Relay(), Relay()]
    yield made
    for relay in made:
        relay.stop()


@pytest.fixture
def pair(relays):
    urls = [r.url for r in relays]
    _, nsec = make_keys()
    speaker = NostrClient(nsec, relay_urls=urls)
    hearer = NostrClient(relay_urls=urls)
    yield speaker, hearer
    speaker.close()
    hearer.close()


def test_what_one_publishes_another_hears_once(relays, pair):
    speaker, hearer = pair
    heard = []
    hearer.listen(heard.append, kinds=[20078], tag_filters={"t": ["weather"]})
    assert until(lambda: all(r.listeners() == 1 for r in relays))
    event, responses = speaker.publish(20078, "rain", tags=[["t", "weather"]])
    assert all(r[1][0] == "OK" for r in responses)
    assert until(lambda: heard)
    time.sleep(0.2)  # both relays have sent it by now
    assert heard == [event]
    assert verify_event(heard[0]) and heard[0]["kind"] == 20078


def test_other_kinds_and_tags_are_not_heard(relays, pair):
    speaker, hearer = pair
    heard = []
    hearer.listen(heard.append, kinds=[20078], tag_filters={"t": ["weather"]})
    assert until(lambda: all(r.listeners() == 1 for r in relays))
    speaker.publish(20078, "no", tags=[["t", "sport"]])
    speaker.publish(1, "no", tags=[["t", "weather"]])
    speaker.publish(20078, "yes", tags=[["t", "weather"]])
    assert until(lambda: heard)
    time.sleep(0.2)
    assert [e["content"] for e in heard] == ["yes"]


def test_a_relay_that_lies_is_not_believed(relays, pair):
    speaker, hearer = pair
    heard = []
    hearer.listen(heard.append, kinds=[20078], tag_filters={"t": ["weather"]})
    assert until(lambda: all(r.listeners() == 1 for r in relays))
    real, _ = speaker.publish(20078, "rain", tags=[["t", "weather"]])
    assert until(lambda: heard)
    forged = dict(real, content="sun")  # a real id and signature, other words
    wrong_kind, _ = speaker.publish(1, "a note", tags=[["t", "weather"]])
    relays[0].inject(forged)
    relays[0].inject(wrong_kind)
    relays[0].inject("not an event")
    relays[0].inject({"id": "00"})
    after, _ = speaker.publish(20078, "still rain", tags=[["t", "weather"]])
    assert until(lambda: len(heard) == 2)
    assert heard == [real, after]


def test_stop_stops_and_close_stops_the_rest(relays, pair):
    speaker, hearer = pair
    first, second = [], []
    stop = hearer.listen(first.append, kinds=[20078])
    hearer.listen(second.append, kinds=[20078])
    assert until(lambda: all(r.listeners() == 2 for r in relays))
    stop()
    stop()  # twice is fine
    assert until(lambda: all(r.listeners() == 1 for r in relays))
    speaker.publish(20078, "one")
    assert until(lambda: second)
    assert first == []
    hearer.close()
    assert until(lambda: all(r.listeners() == 0 for r in relays))


def test_a_dropped_relay_is_joined_again(relays, pair):
    speaker, hearer = pair
    heard = []
    hearer.listen(heard.append, kinds=[20078])
    assert until(lambda: all(r.listeners() == 1 for r in relays))
    for relay in relays:
        relay.drop_everyone()
    assert until(lambda: all(r.listeners() == 1 for r in relays), 15)
    # the speaker's connections were dropped too, and it makes new ones
    _, responses = speaker.publish(20078, "back")
    assert all(r[1][0] == "OK" for r in responses)
    assert until(lambda: heard)


def test_publishing_without_waiting_is_heard_all_the_same(relays, pair):
    speaker, hearer = pair
    heard = []
    hearer.listen(heard.append, kinds=[20078])
    assert until(lambda: all(r.listeners() == 1 for r in relays))
    started = time.time()
    for n in range(40):
        _, responses = speaker.publish(20078, str(n), wait=False)
        assert all(r[1] == ["SENT"] for r in responses)
    assert time.time() - started < 5
    assert until(lambda: len(heard) == 40)
    # and the connection is still good for a call that does wait
    _, responses = speaker.publish(20078, "last")
    assert all(r[1][0] == "OK" for r in responses)


def test_reading_after_the_relays_dropped_connects_again(relays, pair):
    speaker, hearer = pair
    kept, _ = speaker.publish(30078, "kept", tags=[["d", "x"]])
    for relay in relays:
        relay.kept = [kept]
    assert [e["id"] for e in hearer.read_events(kinds=[30078])] == [kept["id"]]
    for relay in relays:
        relay.drop_everyone()
    assert until(lambda: all(ws.close_code is not None for _, ws in hearer._relays))
    assert [e["id"] for e in hearer.read_events(kinds=[30078])] == [kept["id"]]


def test_the_callback_may_take_its_time_and_use_the_client(relays, pair):
    speaker, hearer = pair
    _, nsec = make_keys()
    answerer = NostrClient(nsec, relay_urls=[r.url for r in relays])
    replies = []
    hearer.listen(replies.append, kinds=[20079])

    def answer(event):
        time.sleep(0.1)
        answerer.publish(20079, "re:" + event["content"])

    answerer.listen(answer, kinds=[20078])
    assert until(lambda: all(r.listeners() == 2 for r in relays))
    speaker.publish(20078, "ping")
    assert until(lambda: replies)
    assert replies[0]["content"] == "re:ping"
    answerer.close()


def test_a_callback_that_raises_does_not_end_the_listening(relays, pair):
    speaker, hearer = pair
    heard = []

    def fussy(event):
        if event["content"] == "bad":
            raise ValueError("no")
        heard.append(event["content"])

    hearer.listen(fussy, kinds=[20078])
    assert until(lambda: all(r.listeners() == 1 for r in relays))
    speaker.publish(20078, "bad")
    speaker.publish(20078, "good")
    assert until(lambda: heard == ["good"])
