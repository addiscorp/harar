# The client against a stand-in harar edge over HTTP: what it sends is the
# edge's POST /v1/resolve (docs/edge.md §5) with the service token, and every
# way the edge can say no is an error naming why. The same cases as
# js/test/edge.test.js.
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from harar import HararError, vault

TOKEN = "harar_edge_0123456789abcdef_" + "A" * 43
VALUES = {"harar://prod/shop/STRIPE_KEY": "sk_live_real", "harar://prod/shop/OTHER": "other"}


def stripe(body):
    refs = body["refs"]
    if all(r in VALUES for r in refs):
        return 200, json.dumps({"values": [VALUES[r] for r in refs]})
    return 403, json.dumps({"error": "not_allowed", "message": "this caller may not read prod/site/DATABASE_URL"})


class Edge:
    """A stand-in edge, mounted under /functions/v1/harar-edge as on Supabase."""

    def __init__(self, reply):
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                outer.requests.append(
                    {
                        "method": "POST",
                        "url": self.path,
                        "auth": self.headers["authorization"],
                        "type": self.headers["content-type"],
                        "body": body,
                    }
                )
                status, text = reply(body)
                data = text.encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except OSError:
                    pass  # the client stopped reading: too long an answer

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/functions/v1/harar-edge/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()


class EdgeTest(unittest.TestCase):
    def test_an_edge_vault_resolves_with_one_post_of_v1_resolve_the_service_token_as_its_bearer(self):
        with Edge(stripe) as e:
            v = vault(edge=e.url, token=TOKEN)
            self.assertEqual(v.secrets.resolve("harar://prod/shop/STRIPE_KEY"), "sk_live_real")
            self.assertEqual(
                v.secrets.resolve_all(["harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"]),
                ["sk_live_real", "other"],
            )
            self.assertEqual(v.secrets.resolve_all([]), [])
            with self.assertRaisesRegex(
                HararError, r"harar refused harar://prod/site/DATABASE_URL: not_allowed: this caller may not read"
            ):
                v.secrets.resolve("harar://prod/site/DATABASE_URL")
            for not_one in ["prod/shop/STRIPE_KEY", "op://Prod/Stripe/credential", "harar://", "harar://a b", None]:
                with self.assertRaisesRegex(HararError, r"not a harar:// reference"):
                    v.secrets.resolve(not_one)
            with self.assertRaisesRegex(HararError, r"not a harar:// reference: 'nope'"):
                v.secrets.resolve_all(["harar://prod/shop/OTHER", "nope"])
            expect = lambda refs: {
                "method": "POST",
                "url": "/functions/v1/harar-edge/v1/resolve",
                "auth": "Bearer " + TOKEN,
                "type": "application/json",
                "body": {"refs": refs},
            }
            self.assertEqual(
                e.requests,
                [
                    expect(["harar://prod/shop/STRIPE_KEY"]),
                    expect(["harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"]),
                    expect(["harar://prod/site/DATABASE_URL"]),
                ],
            )
            self.assertFalse(hasattr(v, "hosts") or hasattr(v, "send"), "an edge vault has no hosts or send")

    def test_every_way_an_edge_can_fail_is_an_error_naming_why_and_the_token_is_never_in_it(self):
        for status, text, why in [
            (200, "not json", r"did not answer with JSON \(200\)"),
            (502, "<html>bad gateway</html>", r"did not answer with JSON \(502\)"),
            (200, "[1]", r"did not answer with an object"),
            (200, json.dumps({"values": []}), r"no value for"),
            (200, json.dumps({"values": [7]}), r"no value for"),
            (401, json.dumps({"error": "revoked", "message": "this token was revoked"}), r"harar refused .*: revoked: this token was revoked"),
            (500, json.dumps({}), r"harar refused .*: 500"),
            (200, "x" * (1024 * 1024 + 1), r"too long an answer"),
        ]:
            with self.subTest(text=text[:20]), Edge(lambda _: (status, text)) as e:
                with self.assertRaisesRegex(HararError, why) as raised:
                    vault(edge=e.url, token=TOKEN).secrets.resolve("harar://a/b")
                self.assertNotIn(TOKEN[28:], str(raised.exception))
        with self.assertRaisesRegex(HararError, r"^harar at http://127.0.0.1:1: "):
            vault(edge="http://127.0.0.1:1", token=TOKEN).secrets.resolve("harar://a/b")

    def test_an_edge_is_https_its_token_a_harar_edge_token_and_it_is_one_or_the_other(self):
        with self.assertRaisesRegex(ValueError, r"the edge is an https:// URL"):
            vault(edge="http://edge.example", token=TOKEN)
        with self.assertRaisesRegex(ValueError, r"the edge is an https:// URL"):
            vault(edge="http://localhost.evil.example", token=TOKEN)
        with self.assertRaisesRegex(ValueError, r"service token"):
            vault(edge="https://edge.example")
        with self.assertRaises(ValueError) as raised:
            vault(edge="https://edge.example", token="sk_live_oops")
        self.assertNotIn("sk_live_oops", str(raised.exception))
        with self.assertRaisesRegex(ValueError, r"a socket or an edge, not both"):
            vault(socket="/run/harar.sock", edge="https://edge.example", token=TOKEN)
        self.assertTrue(vault(edge="https://harar-edge.you.workers.dev", token=TOKEN).secrets)
        self.assertTrue(vault(edge="http://localhost:8787", token=TOKEN).secrets)


if __name__ == "__main__":
    unittest.main()
