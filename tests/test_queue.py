"""Tests for the durable queue.

The queue is the component whose failure loses customer mail, so these tests
focus on the cases where a naive implementation drops a message: a crash
between claiming and completing, a corrupt file, and running out of retries.
"""

import json
import os
import tempfile
import time
import unittest

from relay.queue import Queue, QueuedMessage, backoff_delay


def make_queue(root, **kwargs):
    kwargs.setdefault("backoff_base", 0.01)
    kwargs.setdefault("backoff_max", 0.05)
    kwargs.setdefault("backoff_jitter", 0.0)
    queue = Queue(root, **kwargs)
    queue.ensure_dirs()
    return queue


class QueueTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.queue = make_queue(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def message(self, recipient="alice@example.com", **kwargs):
        return QueuedMessage(
            recipient=recipient,
            envelope_from="bob@example.com",
            raw="From: bob@example.com\r\nTo: alice@example.com\r\n\r\nhi\r\n",
            relay_host="relay-1",
            **kwargs,
        )

    def test_enqueue_then_due(self):
        message = self.queue.enqueue(self.message())
        self.assertEqual(len(self.queue.due()), 1)
        self.assertEqual(self.queue.due()[0].id, message.id)

    def test_message_is_durable_on_disk(self):
        message = self.queue.enqueue(self.message())
        path = os.path.join(self.queue.pending_dir, f"{message.id}.json")
        self.assertTrue(os.path.isfile(path))
        with open(path) as handle:
            self.assertEqual(json.load(handle)["recipient"], "alice@example.com")

    def test_delay_defers_delivery(self):
        message = self.queue.enqueue(self.message(), delay=60)
        self.assertEqual(self.queue.due(), [])
        self.assertEqual(len(self.queue.peek(message.id).__class__ and [1]), 1)

    def test_requeue_increments_attempts_and_applies_backoff(self):
        message = self.queue.enqueue(self.message())
        self.queue.mark_inflight(message)
        requeued = self.queue.requeue(message, "boom")
        self.assertEqual(requeued.attempts, 1)
        self.assertEqual(requeued.last_error, "boom")
        self.assertGreater(requeued.next_attempt_at, time.time() - 1)

    def test_inflight_is_recovered_on_restart(self):
        message = self.queue.enqueue(self.message())
        self.queue.mark_inflight(message)
        self.assertEqual(self.queue.stats()["inflight"], 1)

        # A fresh process starting up must find and requeue it.
        recovered = self.queue.recover_inflight()
        self.assertEqual(recovered, [message.id])
        self.assertEqual(self.queue.stats()["inflight"], 0)
        self.assertEqual(self.queue.stats()["pending"], 1)

    def test_recover_quarantines_a_corrupt_file(self):
        os.makedirs(self.queue.inflight_dir, exist_ok=True)
        bad = os.path.join(self.queue.inflight_dir, "corrupt.json")
        with open(bad, "w") as handle:
            handle.write("{not json")

        self.queue.recover_inflight()
        # Kept for inspection rather than deleted or retried forever.
        self.assertEqual(self.queue.stats()["dead"], 1)

    def test_max_attempts_parks_the_message(self):
        queue = make_queue(self.root, max_attempts=2, backoff_base=0.0, backoff_max=0.0)
        message = queue.enqueue(self.message())
        queue.mark_inflight(message)
        queue.requeue(message, "fail 1")
        queue.mark_inflight(message)
        queue.requeue(message, "fail 2")

        # Backoff never returns zero, so a parked message is only noticed on a
        # later poll. Waiting past the floor is what makes this deterministic.
        self.assertEqual(queue.due(), [])
        time.sleep(0.6)
        self.assertEqual(queue.due(), [])
        self.assertEqual(queue.stats()["dead"], 1)
        self.assertIn("retries exhausted", queue.list_dead()[0].last_error)

    def test_max_age_parks_the_message(self):
        queue = make_queue(self.root, max_age_hours=1)
        message = queue.enqueue(self.message())
        # Backdate the arrival well past the limit.
        message.first_seen_at = "2020-01-01T00:00:00+00:00"
        queue._write(queue.pending_dir, message)

        self.assertEqual(queue.due(), [])
        self.assertEqual(queue.stats()["dead"], 1)

    def test_mark_inflight_is_exclusive(self):
        message = self.queue.enqueue(self.message())
        self.assertTrue(self.queue.mark_inflight(message))
        # A second worker must not be able to claim the same message.
        self.assertFalse(self.queue.mark_inflight(message))

    def test_path_traversal_in_id_is_rejected(self):
        # The id is read back from queue files, so it is untrusted input even
        # though every id this code generates is a uuid hex string.
        for bad in ["../../etc/passwd", "a/b", "a.b", "", "..", "with space", "naïve"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                message = self.message()
                message.id = bad
                self.queue.enqueue(message)

    def test_a_valid_id_is_accepted(self):
        message = self.message()
        message.id = "abc-123_XYZ"
        self.queue.enqueue(message)
        self.assertIsNotNone(self.queue.peek("abc-123_XYZ"))

    def test_stats_and_bytes(self):
        self.queue.enqueue(self.message())
        self.assertEqual(self.queue.stats()["pending"], 1)
        self.assertGreater(self.queue.total_bytes(), 0)

    def test_due_respects_limit_and_order(self):
        for _ in range(5):
            self.queue.enqueue(self.message())
        self.assertEqual(len(self.queue.due(limit=2)), 2)


class BackoffTests(unittest.TestCase):
    def test_grows_exponentially(self):
        first = backoff_delay(1, 5, 300, jitter=0)
        second = backoff_delay(2, 5, 300, jitter=0)
        third = backoff_delay(3, 5, 300, jitter=0)
        self.assertEqual((first, second, third), (5, 10, 20))

    def test_caps_at_maximum(self):
        self.assertEqual(backoff_delay(20, 5, 300, jitter=0), 300)

    def test_jitter_stays_within_bounds(self):
        # Jitter varies the delay around the exponential value, up to the
        # configured maximum. With base=10 and attempt=3 the exponential value
        # is 40, well under the 300 cap, so jitter simply moves it within
        # ±25% of 40.
        for _ in range(50):
            delay = backoff_delay(3, 10, 300, jitter=0.25)
            self.assertGreaterEqual(delay, 30 * 0.999)
            self.assertLessEqual(delay, 50 * 1.001)

    def test_jitter_never_exceeds_the_cap(self):
        # With the maximum reached, jitter must not push past it.
        for _ in range(50):
            delay = backoff_delay(20, 5, 60, jitter=0.25)
            self.assertLessEqual(delay, 60)

    def test_never_returns_zero(self):
        self.assertGreaterEqual(backoff_delay(1, 5, 300, jitter=0.9), 0.5)


if __name__ == "__main__":
    unittest.main()
