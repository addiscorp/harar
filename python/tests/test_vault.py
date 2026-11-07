# The client against a stand-in harar on a unix socket: the requests it
# sends are the ones harar's `hosts` and `send` take (the harar crate's
# PrimaryRequest::Hosts { key } and Send { key, host }, tag "op"), and every
# way harar can say no is an error naming why. The same cases as js/test.
import json
import os
import socket
import tempfile
import threading
import unittest

from harar import HararError, vault


class Harar:
    """A stand-in harar answering each request with reply(request)."""

    def __init__(self, reply):
        self.dir = tempfile.TemporaryDirectory(prefix="harar-py-")
        self.socket = os.path.join(self.dir.name, "h.sock")
        self.requests = []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.socket)
        self.server.listen()
        self.reply = reply
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                body = b""
                while chunk := conn.recv(65536):
                    body += chunk
                request = json.loads(body)
                self.requests.append(request)
                try:
                    conn.sendall(self.reply(request).encode("utf-8"))
                except OSError:
                    pass  # the client stopped reading: too long an answer

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.server.close()
        self.dir.cleanup()


def stripe(r):
    if r["op"] == "hosts":
        return json.dumps({"ok": True, "hosts": ["api.stripe.com", "*.stripe.com"]})
    if r["op"] == "send" and r["host"] == "api.stripe.com":
        return json.dumps({"ok": True, "value": "sk_live_real"})
    return json.dumps({"ok": False, "error": "not_allowed"})


class VaultTest(unittest.TestCase):
    def test_hosts_and_send_ask_harar_exactly_and_a_send_is_for_one_host(self):
        with Harar(stripe) as h:
            v = vault(socket=h.socket)
            self.assertEqual(v.hosts("prod/shop/STRIPE_KEY"), ["api.stripe.com", "*.stripe.com"])
            self.assertEqual(v.send("prod/shop/STRIPE_KEY", "api.stripe.com"), "sk_live_real")
            with self.assertRaisesRegex(
                HararError, r"harar refused prod/shop/STRIPE_KEY to evil\.example\.com: not_allowed"
            ):
                v.send("prod/shop/STRIPE_KEY", "evil.example.com")
            self.assertEqual(
                h.requests,
                [
                    {"op": "hosts", "key": "prod/shop/STRIPE_KEY"},
                    {"op": "send", "key": "prod/shop/STRIPE_KEY", "host": "api.stripe.com"},
                    {"op": "send", "key": "prod/shop/STRIPE_KEY", "host": "evil.example.com"},
                ],
            )

    def test_every_way_harar_can_fail_is_an_error_naming_why(self):
        for answer, why in [
            ("not json", r"did not answer with JSON"),
            ("null", r"did not answer with an object"),
            ("[1]", r"did not answer with an object"),
            (json.dumps({"ok": True}), r"no value|no hosts"),
            (json.dumps({"ok": False, "error": "locked"}), r"harar refused .*: locked"),
            ("x" * (1024 * 1024 + 1), r"too long an answer"),
        ]:
            with self.subTest(answer=answer[:20]), Harar(lambda _: answer) as h:
                v = vault(socket=h.socket)
                with self.assertRaisesRegex(HararError, why):
                    v.send("a/b", "x.example.com")
                with self.assertRaisesRegex(HararError, why):
                    v.hosts("a/b")
        with self.assertRaisesRegex(HararError, r"harar at /nonexistent/h\.sock"):
            vault(socket="/nonexistent/h.sock").hosts("a/b")
        with self.assertRaisesRegex(ValueError, r"absolute path"):
            vault(socket="relative.sock")


if __name__ == "__main__":
    unittest.main()
